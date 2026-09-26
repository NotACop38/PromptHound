from __future__ import annotations

import json
import re
from typing import Any

import pytest
from sigma.collection import SigmaCollection

from prompthound import __version__, convert, fields, rules
from prompthound.backends import kusto_backend, kusto_pipeline, splunk_backend
from tests.conftest import RuleWriter
from tests.helpers import correlation_documents, load_one, selection_document


@pytest.fixture(scope="module")
def queries(pack: list[rules.Rule]) -> list[convert.Queries]:
    return [convert.convert(rule) for rule in pack]


def test_every_search_is_scoped_by_the_macro_and_every_query_by_the_table(
    queries: list[convert.Queries],
) -> None:
    for item in queries:
        assert item.spl.startswith("`prompthound_audit` "), item.rule.relpath
        assert item.kql.startswith("PromptHoundAuditLog_CL\n| where "), item.rule.relpath
        assert "\n\n" not in item.spl
        assert not item.spl.endswith("\n")


def test_queries_use_column_names_never_schema_names(queries: list[convert.Queries]) -> None:
    dotted = [name for name in fields.registry() if "." in name]
    for item in queries:
        for name in dotted:
            pattern = re.compile(rf"(?<![\w.]){re.escape(name)}(?![\w.])")
            assert not pattern.search(item.spl), (item.rule.relpath, name)
            assert not pattern.search(item.kql), (item.rule.relpath, name)


def test_splunk_names_array_fields_with_braces(queries: list[convert.Queries]) -> None:
    for item in queries:
        for name in item.rule.fields:
            field = fields.get(name)
            if field.is_string_array:
                assert f'"{field.column}{{}}"' in item.spl, (item.rule.relpath, name)


def test_kusto_tests_array_membership_and_compares_booleans_exactly(
    queries: list[convert.Queries],
) -> None:
    arrays = {f.column for f in fields.registry().values() if f.is_string_array}
    for item in queries:
        assert not re.search(r"[=!]~ (true|false)\b", item.kql), item.rule.relpath
        for column in arrays:
            assert not re.search(rf"\b{column}\b\s*(=~|in~|==|contains)", item.kql)


def test_correlations_aggregate_in_fixed_windows(queries: list[convert.Queries]) -> None:
    for item in queries:
        correlation = item.rule.correlation
        if correlation is None:
            assert "summarize" not in item.kql
            assert "| stats" not in item.spl
            continue
        columns = [fields.get(name).column for name in correlation.group_by]
        splunk_columns = [fields.get(name).splunk_name for name in correlation.group_by]
        seconds = correlation.timespan
        span = next(
            f"{seconds // size}{unit}"
            for unit, size in (("h", 3600), ("m", 60), ("s", 1))
            if seconds % size == 0
        )
        assert item.kql.splitlines()[-4:] == [
            "| where " + " and ".join(f"isnotempty({c})" for c in columns),
            f"// Fixed {span} UTC windows: a burst that straddles a window boundary is split.",
            f"| summarize event_count = count() by {', '.join(columns)}, bin(timestamp, {span})",
            f"| where event_count {correlation.symbol} {correlation.threshold}",
        ]
        assert item.spl.splitlines()[1:] == [
            f"| bin _time span={span}",
            f"| stats count as event_count by _time {' '.join(splunk_columns)}",
            f"| search event_count {correlation.symbol} {correlation.threshold}",
        ]


@pytest.mark.parametrize(("timespan", "span"), [("1h", "1h"), ("90s", "90s"), ("2m", "2m")])
def test_window_units(write_rule: RuleWriter, timespan: str, span: str) -> None:
    documents = correlation_documents(
        {"s": {"gen_ai.operation.name": "chat"}, "condition": "s"}, {"timespan": timespan}
    )
    rule = load_one(write_rule(documents))
    assert f"bin(timestamp, {span})" in convert.convert(rule).kql


def test_correlations_without_group_by_have_no_presence_filter(write_rule: RuleWriter) -> None:
    documents = correlation_documents(
        {"s": {"gen_ai.operation.name": "chat"}, "condition": "s"}, {"group-by": []}
    )
    kql = convert.convert(load_one(write_rule(documents))).kql
    assert "isnotempty" not in kql
    assert "| summarize event_count = count() by bin(timestamp, 5m)" in kql


def test_conversion_is_repeatable(pack: list[rules.Rule]) -> None:
    for rule in pack:
        assert convert.convert(rule) == convert.convert(rule)


def test_custom_macro_and_table(by_stem: dict[str, rules.Rule]) -> None:
    item = convert.convert(
        by_stem["denied_tool_retry_loop"], splunk_macro="llm_audit", sentinel_table="LlmAudit_CL"
    )
    assert item.spl.startswith("`llm_audit` ")
    assert item.kql.startswith("LlmAudit_CL\n")


@pytest.mark.parametrize(
    ("argument", "value"),
    [("splunk_macro", "bad macro"), ("splunk_macro", ""), ("sentinel_table", "T; drop")],
)
def test_invalid_names_are_rejected(pack: list[rules.Rule], argument: str, value: str) -> None:
    with pytest.raises(ValueError, match="not a valid"):
        convert.convert(pack[0], **{argument: value})


def test_a_backend_that_returns_several_queries_is_an_error(
    monkeypatch: pytest.MonkeyPatch, pack: list[rules.Rule]
) -> None:
    class TwoQueries:
        def convert(self, collection: SigmaCollection) -> list[str]:
            return ["a", "b"]

    monkeypatch.setattr(convert, "splunk_backend", TwoQueries)
    with pytest.raises(ValueError, match="expected one SPL query, got 2"):
        convert.convert(pack[0])


# --- backends -----------------------------------------------------------------


ARRAY = (
    'parse_json(translate("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", '
    "tostring(tool_call_chain)))"
)


def _convert(backend: Any, detection: dict[str, Any]) -> str:
    document = selection_document(detection)
    [query] = backend.convert(SigmaCollection.from_dicts([document]))
    return str(query)


@pytest.mark.parametrize(
    ("detection", "kql"),
    [
        (
            {"s": {"tool.call.chain": "Read_File"}, "condition": "s"},
            f'set_has_element({ARRAY}, "read_file")',
        ),
        (
            {"s": {"tool.call.chain": ["A", "b"]}, "condition": "s"},
            f'array_length(set_intersect({ARRAY}, dynamic(["a", "b"]))) > 0',
        ),
        (
            {"s": {"tool.call.chain|all": ["a", "b"]}, "condition": "s"},
            f'set_has_element({ARRAY}, "a") and set_has_element({ARRAY}, "b")',
        ),
        (
            {"s": {"user.id": 'É.b"*'}, "condition": "s"},
            'user_id matches regex "(?s)\\\\AÉ\\\\.[Bb]\\".*\\\\z"',
        ),
        (
            {"s": {"user.id": ["Élodie", "bob"]}, "condition": "s"},
            'user_id matches regex "(?s)\\\\AÉ[Ll][Oo][Dd][Ii][Ee]\\\\z" or user_id =~ "bob"',
        ),
        (
            {"s": {"user.id": ["*c*l*", "*o*b*"]}, "condition": "s"},
            'user_id matches regex "(?is)\\\\A.*c.*l.*\\\\z" or '
            'user_id matches regex "(?is)\\\\A.*o.*b.*\\\\z"',
        ),
        ({"s": {"output.rendered_unsanitized": False}, "condition": "s"}, "== false"),
        (
            {"s": {"gen_ai.input.messages|contains": "x =~ true"}, "condition": "s"},
            'gen_ai_input_messages contains "x =~ true"',
        ),
    ],
)
def test_kusto_backend(detection: dict[str, Any], kql: str) -> None:
    query = _convert(kusto_backend(), detection)
    assert query.startswith("PromptHoundAuditLog_CL\n| where ")
    assert kql in query


def test_kusto_regex_escapes_control_characters() -> None:
    query = _convert(kusto_backend(), {"s": {"user.id": "É\tb"}, "condition": "s"})
    assert query.endswith('user_id matches regex "(?s)\\\\AÉ\\\\x{9}[Bb]\\\\z"')


def test_kusto_backend_refuses_single_character_wildcards() -> None:
    with pytest.raises(NotImplementedError, match="unsupported special character"):
        _convert(kusto_backend(), {"s": {"user.id": "É?"}, "condition": "s"})


def test_kusto_backend_refuses_patterns_on_array_elements() -> None:
    with pytest.raises(NotImplementedError, match="exact element matching"):
        _convert(kusto_backend(), {"s": {"tool.call.chain|contains": "x"}, "condition": "s"})


def test_kusto_pipeline_validates_the_table_name() -> None:
    with pytest.raises(ValueError, match="not a valid table name"):
        kusto_pipeline("bad-name")


def test_splunk_backend_maps_fields() -> None:
    query = _convert(splunk_backend(), {"s": {"tool.call.chain": "x"}, "condition": "s"})
    assert query == '"tool_call_chain{}"="x"'
    query = _convert(splunk_backend(), {"s": {"user.tenant.id": "t"}, "condition": "s"})
    assert query == 'user_tenant_id="t"'


# --- deployment files -----------------------------------------------------------


def test_savedsearches_has_one_disabled_unscheduled_stanza_per_rule(
    queries: list[convert.Queries],
) -> None:
    text = convert.savedsearches_conf(queries)
    stanzas = re.findall(r"^\[(.+)\]$", text, flags=re.MULTILINE)
    assert stanzas == [f"PromptHound - {item.rule.title}" for item in queries]
    assert "[default]" not in text
    assert text.count("enableSched = 0\n") == len(queries)
    assert "cron_schedule" not in text
    assert "action." not in text
    for item in queries:
        assert f"Rule ID: {item.rule.id}." in text
        # Multi-line searches continue with a trailing backslash.
        continued = item.spl.replace("\n", " \\\n")
        assert f"search = {continued}\n" in text


def test_macro_definition() -> None:
    assert (
        'definition = index=prompthound sourcetype="prompthound:audit"\n' in convert.macros_conf()
    )
    custom = convert.macros_conf("llm_audit", index="genai")
    assert "[llm_audit]\n" in custom
    assert 'definition = index=genai sourcetype="prompthound:audit"\n' in custom


def test_props_keep_large_events_whole_and_extract_json() -> None:
    props = convert.props_conf()
    assert "[prompthound:audit]\n" in props
    for setting in ("TRUNCATE = 0", "KV_MODE = json", "SHOULD_LINEMERGE = false"):
        assert f"\n{setting}\n" in props
    assert "TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%Z\n" in props


def test_app_files_are_exported_and_versioned() -> None:
    assert "\nexport = system\n" in convert.default_meta()
    app = convert.app_conf()
    assert f"\nversion = {__version__}\n" in app
    assert f"\nid = {convert.SPLUNK_APP}\n" in app
    for text in (app, convert.default_meta(), convert.props_conf(), convert.macros_conf()):
        assert text.startswith(f"# Generated by PromptHound {__version__}.")


def test_sentinel_table_lists_every_column() -> None:
    table = json.loads(convert.sentinel_table())
    assert table["name"] == fields.DEFAULT_SENTINEL_TABLE
    columns = table["columns"]
    assert columns[0] == {"name": "TimeGenerated", "type": "datetime"}
    assert [c["name"] for c in columns[1:]] == [f.column for f in fields.registry().values()]
    allowed = {"string", "int", "long", "real", "boolean", "datetime", "dynamic", "guid"}
    assert {c["type"] for c in columns} <= allowed
    by_name = {c["name"]: c["type"] for c in columns}
    assert by_name["output_rendered_unsanitized"] == "boolean"
    assert by_name["tool_call_chain"] == "dynamic"
    assert json.loads(convert.sentinel_table("Custom_CL"))["name"] == "Custom_CL"
