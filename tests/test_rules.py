from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from prompthound import fields, rules
from prompthound.rules import RuleError, check_policy, load_rules
from tests.conftest import RuleWriter
from tests.helpers import correlation_documents, load_one, selection_document


def test_pack_loads_and_meets_the_publication_policy(pack: list[rules.Rule]) -> None:
    assert len(pack) == 16
    assert check_policy(pack) == []


def test_pack_structure(pack: list[rules.Rule]) -> None:
    categories = {rule.category for rule in pack}
    assert categories == {
        "agent_tool_abuse",
        "data_exfiltration",
        "dos_cost_abuse",
        "insecure_output",
        "jailbreak",
        "prompt_injection",
        "system_prompt_extraction",
    }
    for rule in pack:
        assert rule.relpath.endswith(".yml")
        assert list(rule.fields) == [n for n in fields.registry() if n in rule.fields]
        assert rule.level in rules.LEVELS


def test_derived_properties(by_stem: dict[str, rules.Rule]) -> None:
    markers = by_stem["direct_injection_markers"]
    assert markers.kind == "selection"
    assert markers.content_fields == ("gen_ai.input.messages",)
    assert markers.derived_fields == ("content.input.injection_markers",)
    assert markers.requires_content

    count = by_stem["direct_injection_marker_count"]
    assert not count.requires_content
    assert count.derived_fields == ("content.input.injection_markers",)

    denied = by_stem["denied_tool_retry_loop"]
    assert denied.kind == "correlation"
    assert denied.correlation is not None
    assert denied.correlation.group_by == ("user.tenant.id", "gen_ai.conversation.id")
    assert denied.title == "Repeated Denied Tool Calls in One Conversation"
    assert "user.tenant.id" in denied.fields


def test_attack_tags_become_mappings(by_stem: dict[str, rules.Rule]) -> None:
    mappings = by_stem["unsanitized_output_to_sink"].mappings
    assert mappings is not None
    assert mappings.attack == ("execution", "T1059")
    assert mappings.owasp_agentic == ("ASI05",)
    assert mappings.atlas == ()


def test_rules_without_a_metadata_block_load(write_rule: RuleWriter) -> None:
    document = selection_document({"s": {"user.id": "u"}, "condition": "s"})
    del document["prompthound"]
    rule = load_one(write_rule(document))
    assert rule.mappings is None
    assert any("OWASP Top 10 for LLM" in p for p in check_policy([rule]))


@pytest.mark.parametrize(
    ("detection", "message"),
    [
        ({"k": ["keyword"], "condition": "k"}, "keyword"),
        ({"s": {"user.name": "x"}, "condition": "s"}, "not a field of the audit-event schema"),
        ({"s": {"user.id|re": "x.*"}, "condition": "s"}, "unsupported modifier"),
        ({"s": {"user.id|cased": "x"}, "condition": "s"}, "unsupported modifier"),
        ({"s": {"timestamp": "x"}, "condition": "s"}, "timestamp cannot be used"),
        ({"s": {"tool.call.chain": "read*"}, "condition": "s"}, "exact element matching"),
        ({"s": {"tool.call.chain|contains": "read"}, "condition": "s"}, "exact element matching"),
        ({"s": {"user.id": "u?er"}, "condition": "s"}, "'?' wildcards"),
        ({"s": {"gen_ai.usage.input_tokens": "many"}, "condition": "s"}, "does not fit"),
        ({"s": {"user.id": True}, "condition": "s"}, "does not fit"),
        ({"s": {"output.rendered_unsanitized": "yes"}, "condition": "s"}, "does not fit"),
        ({"s": {"user.id|all": ["a", "b"]}, "condition": "s"}, "all modifier"),
        ({"s": {"user.id": None}, "condition": "s"}, "null checks are not supported"),
        ({"s": {"gen_ai.request.temperature": 0.5}, "condition": "not s"}, "negated condition"),
        (
            {"a": {"user.id": "u"}, "b": {"tool.call.chain": "x"}, "condition": "a and not b"},
            r"tool\.call\.chain: a negated condition",
        ),
        (
            {"a": {"user.id": "u"}, "b": {"cost.usd|gte": 1}, "condition": "not (a and b)"},
            r"cost\.usd: a negated condition",
        ),
        ({"s": {"tool.call.chain": "Élan"}, "condition": "s"}, "non-ASCII letters"),
        ({"s": {"user.id": "*"}, "condition": "s"}, "existence checks are not supported"),
        ({"s": {"user.id|contains": ""}, "condition": "s"}, "existence checks"),
        ({"s": {"tool.call.chain": ""}, "condition": "s"}, "existence checks"),
        ({"s": {"cost.usd|neq": 1}, "condition": "s"}, "unsupported modifier"),
    ],
)
def test_unsupported_detections_are_rejected(
    write_rule: RuleWriter, detection: dict[str, Any], message: str
) -> None:
    root = write_rule(selection_document(detection))
    with pytest.raises(RuleError, match=message):
        load_one(root)


def test_error_messages_name_the_file(write_rule: RuleWriter) -> None:
    root = write_rule(selection_document({"s": {"user.name": "x"}, "condition": "s"}), "x/bad.yml")
    with pytest.raises(RuleError, match=r"^x/bad\.yml: "):
        load_one(root, "x/bad.yml")


@pytest.mark.parametrize(
    "detection",
    [
        {"s": {"tool.call.chain|all": ["read_file", "send_email"]}, "condition": "s"},
        {"s": {"gen_ai.input.messages|contains|all": ["a", "b"]}, "condition": "s"},
        {
            "s": {"gen_ai.usage.input_tokens|gte": 5},
            "f": {"user.id": "u"},
            "condition": "s and not f",
        },
        {"s": {"output.rendered_unsanitized": True}, "condition": "not s"},
        {"s": {"gen_ai.input.messages|contains": "x"}, "condition": "not s"},
        {"s": [{"user.id": "a"}, {"user.id|contains": "b"}], "condition": "s"},
        {"s": {"user.id": "Élodie", "tool.call.chain": "日本"}, "condition": "s"},
    ],
)
def test_supported_detections_load(write_rule: RuleWriter, detection: dict[str, Any]) -> None:
    assert load_one(write_rule(selection_document(detection))).kind == "selection"


def test_logsource_must_be_the_gateway(write_rule: RuleWriter) -> None:
    root = write_rule(
        selection_document({"s": {"user.id": "u"}, "condition": "s"}, logsource={"product": "x"})
    )
    with pytest.raises(RuleError, match="llm_gateway"):
        load_one(root)


def test_a_file_holds_one_detection(write_rule: RuleWriter) -> None:
    first = selection_document({"s": {"user.id": "u"}, "condition": "s"})
    second = selection_document(
        {"s": {"user.id": "v"}, "condition": "s"},
        id="0e5b0d6c-2f3a-4b61-9c7d-1a2b3c4d5e69",
        title="Second",
    )
    with pytest.raises(RuleError, match="one detection"):
        load_one(write_rule([first, second]))


BASE = {"s": {"gen_ai.operation.name": "chat"}, "condition": "s"}


@pytest.mark.parametrize(
    ("correlation", "message"),
    [
        ({"type": "value_count", "condition": {"gte": 2, "field": "user.id"}}, "unsupported"),
        ({"condition": {"eq": 3}}, "unsupported correlation operator eq"),
        ({"group-by": ["user.name"]}, "not a field"),
        ({"group-by": ["tool.call.chain"]}, "must be a scalar"),
        ({"group-by": ["timestamp"]}, "must be a scalar"),
        ({"group-by": ["gen_ai.input.messages"]}, "must be a scalar"),
        ({"timespan": "7m"}, "divide one day"),
        ({"generate": True}, "generate: true"),
        ({"aliases": {"a": {"test_block": "user.id"}}}, "aliases"),
        ({"rules": ["test_block", "test_block"]}, "reference the detection in its own file"),
        ({"condition": {"gte": 2, "field": "user.id"}}, "unsupported correlation condition"),
    ],
)
def test_unsupported_correlations_are_rejected(
    write_rule: RuleWriter, correlation: dict[str, Any], message: str
) -> None:
    root = write_rule(correlation_documents(BASE, correlation))
    with pytest.raises(RuleError, match=message):
        load_one(root)


def test_correlation_operators(write_rule: RuleWriter) -> None:
    for operator in ("gte", "gt", "lte", "lt"):
        rule = load_one(write_rule(correlation_documents(BASE, {"condition": {operator: 2}})))
        assert rule.correlation is not None
        assert rule.correlation.operator == operator


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ([], "must be a mapping"),
        ({"owasp_llm": ["LLM01"], "tier": 1}, "unknown prompthound key"),
        ({"owasp_llm": "LLM01"}, "must be a list"),
        ({"owasp_llm": ["LLM11"]}, "not in OWASP Top 10 for LLM Applications 2025"),
        ({"owasp_llm": ["LLM01", "LLM01"]}, "twice"),
        ({"owasp_llm": ["LLM01"], "atlas": ["AML.T9999"]}, "not in MITRE ATLAS"),
        ({"owasp_llm": ["LLM01"], "owasp_agentic": ["T2"]}, "not in OWASP Top 10 for Agentic"),
    ],
)
def test_invalid_mappings_are_rejected(write_rule: RuleWriter, block: Any, message: str) -> None:
    document = selection_document({"s": {"user.id": "u"}, "condition": "s"}, prompthound=block)
    with pytest.raises(RuleError, match=message):
        load_one(write_rule(document))


def test_unknown_attack_tags_are_rejected(write_rule: RuleWriter) -> None:
    document = selection_document({"s": {"user.id": "u"}, "condition": "s"}, tags=["attack.t9999"])
    with pytest.raises(RuleError, match=r"attack\.t9999"):
        load_one(write_rule(document))


def test_unparseable_files_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    (root / "t").mkdir(parents=True)
    (root / "t" / "rule.yml").write_text("title: [unclosed\n")
    with pytest.raises(RuleError, match=r"t/rule\.yml"):
        load_rules(root)


def test_load_rules_rejects_duplicates_and_empty_packs(
    tmp_path: Path, write_rule: RuleWriter
) -> None:
    with pytest.raises(RuleError, match="no rule files"):
        load_rules(tmp_path)
    document = selection_document({"s": {"user.id": "u"}, "condition": "s"})
    write_rule(document, "a/one.yml")
    root = write_rule(document, "a/two.yml")
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules(root)


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"references": []}, "cite at least one reference"),
        ({"falsepositives": []}, "document false positives"),
        ({"level": "urgent"}, None),
        ({"status": "deprecated"}, "status must be"),
        ({"description": ""}, "missing description"),
        ({"modified": "2026-01-01"}, "modified precedes date"),
        ({"prompthound": {"owasp_llm": ["LLM01"]}}, "at least one ATLAS or ATT&CK"),
        ({"date": None}, "missing date"),
        ({"author": None}, "missing author"),
    ],
)
def test_policy_problems(
    write_rule: RuleWriter, changes: dict[str, Any], problem: str | None
) -> None:
    document = {**selection_document({"s": {"user.id": "u"}, "condition": "s"}), **changes}
    root = write_rule(document)
    if problem is None:  # pySigma itself rejects an unknown level
        with pytest.raises(RuleError):
            load_one(root)
        return
    assert any(problem in p for p in check_policy([load_one(root)]))


def test_policy_requires_agentic_mappings_for_agent_rules(write_rule: RuleWriter) -> None:
    document = selection_document({"s": {"user.id": "u"}, "condition": "s"})
    rule = load_one(write_rule(document, "agent_tool_abuse/x.yml"), "agent_tool_abuse/x.yml")
    assert any("OWASP Agentic Top 10" in p for p in check_policy([rule]))


def test_policy_requires_tenant_scoped_correlations(write_rule: RuleWriter) -> None:
    root = write_rule(correlation_documents(BASE, {"group-by": ["user.id"]}))
    assert any("group by user.tenant.id" in p for p in check_policy([load_one(root)]))


def test_policy_keeps_metadata_off_building_blocks(write_rule: RuleWriter) -> None:
    documents = correlation_documents(BASE, {})
    documents[0]["prompthound"] = {"owasp_llm": ["LLM01"]}
    assert any("not its base" in p for p in check_policy([load_one(write_rule(documents))]))


def test_policy_reports_pysigma_validator_findings(write_rule: RuleWriter) -> None:
    document = selection_document(
        {"s": {"user.id": "u"}, "condition": "s"}, tags=["attack.t1059", "attack.t1059"]
    )
    assert any("DuplicateTagIssue" in p for p in check_policy([load_one(write_rule(document))]))


@pytest.mark.parametrize("index", [0, 1])
def test_policy_requires_identifiers(write_rule: RuleWriter, index: int) -> None:
    documents = correlation_documents(BASE, {})
    del documents[index]["id"]
    assert any(
        "every document needs an id" in p for p in check_policy([load_one(write_rule(documents))])
    )


def test_identifiers_must_be_uuids(write_rule: RuleWriter) -> None:
    document = selection_document({"s": {"user.id": "u"}, "condition": "s"}, id="not-a-uuid")
    with pytest.raises(RuleError, match="must be an UUID"):
        load_one(write_rule(document))
