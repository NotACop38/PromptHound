"""Regression cases independent of the per-rule happy-path fixtures."""

from pathlib import Path

import pytest
import yaml
from sigma.rule import SigmaRule

from prompthound.convert import convert_rule
from prompthound.correlate import correlation_hits
from prompthound.matcher import rule_matches
from tests.test_correlate import CORRELATION_RULE

ROOT = Path(__file__).resolve().parent.parent


def _rule(field: str, value: object) -> SigmaRule:
    return SigmaRule.from_dict(
        {
            "title": "Matcher regression",
            "logsource": {"product": "llm_gateway"},
            "detection": {"selection": {field: value}, "condition": "selection"},
        }
    )


@pytest.mark.parametrize(
    ("field", "value", "text", "expected"),
    [
        ("field|startswith", "marker", "prefix marker suffix", False),
        ("field|endswith", "marker", "marker suffix", False),
        ("field", "mark?r", "prefix marker", False),
        ("field", "mark?r", "marker", True),
        ("field", "marker", "marker\n", False),
        ("field|contains", "marker", "prefix MARKER\nsuffix", True),
    ],
)
def test_sigma_wildcards_match_the_whole_value(field, value, text, expected) -> None:
    assert rule_matches(_rule(field, value), {"field": text}) is expected


@pytest.mark.parametrize("value", [None, True, 123])
def test_string_patterns_do_not_match_non_strings(value) -> None:
    assert not rule_matches(_rule("field", "*"), {"field": value})


def test_fixed_window_does_not_invent_a_cross_boundary_alert(tmp_path: Path) -> None:
    rule = tmp_path / "burst.yml"
    rule.write_text(CORRELATION_RULE)
    events = [
        {"event.action": "chat", "user.id": "u-1", "timestamp": time}
        for time in ["2026-06-11T12:04:00Z", "2026-06-11T12:04:30Z", "2026-06-11T12:05:00Z"]
    ]
    assert correlation_hits(rule, events) == []


def test_missing_identity_is_not_an_anonymous_correlation_group(tmp_path: Path) -> None:
    rule = tmp_path / "burst.yml"
    rule.write_text(CORRELATION_RULE)
    events = [{"event.action": "chat", "timestamp": "2026-06-11T12:00:00Z"}] * 3
    assert correlation_hits(rule, events) == []


def test_correlation_kql_contains_executable_threshold() -> None:
    rule = ROOT / "rules/agent_tool_abuse/denied_tool_retry_loop.yml"
    kql = "\n".join(convert_rule(rule).kql)
    executable = "\n".join(line for line in kql.splitlines() if not line.startswith("//"))
    assert "| summarize event_count = count()" in executable
    assert "| where event_count >= 3" in executable
    assert "user_tenant_id" in executable


def test_kql_array_equality_uses_membership() -> None:
    rule = ROOT / "rules/dos_cost_abuse/repeated_length_finish_loops.yml"
    kql = "\n".join(convert_rule(rule).kql)
    assert "set_has_element(" in kql
    assert 'gen_ai_response_finish_reasons =~ "length"' not in kql


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("user.roles", ["adm*n", "staff"]),
        ("user.roles|startswith", "adm"),
        ("user.roles|endswith", "min"),
        ("user.roles|contains", "adm*n"),
        ("user.roles|contains", "admin"),
    ],
)
def test_conversion_rejects_array_patterns_without_element_semantics(tmp_path, field, value):
    rule = tmp_path / "array.yml"
    rule.write_text(yaml.safe_dump(_rule(field, value).to_dict()))
    with pytest.raises(NotImplementedError, match="string-array"):
        convert_rule(rule)


@pytest.mark.parametrize(
    "field",
    [
        "user.roles",
        "gen_ai.input.messages",
        "tool.call.arguments",
        "tool.call.result",
        "timestamp",
        "unknown",
    ],
)
def test_dynamic_and_unknown_grouping_fails_before_conversion_or_evaluation(tmp_path, field):
    rule = tmp_path / "group.yml"
    rule.write_text(CORRELATION_RULE.replace("    - user.id", f"    - {field}"))
    with pytest.raises(NotImplementedError, match="scalar schema fields"):
        convert_rule(rule)
    with pytest.raises(NotImplementedError, match="scalar schema fields"):
        correlation_hits(rule, [])


def test_tool_chain_uses_exact_inventory_names():
    rule = SigmaRule.from_yaml(
        (ROOT / "rules/agent_tool_abuse/anomalous_tool_call_chain.yml").read_text()
    )
    assert rule_matches(
        rule, {"event.action": "execute_tool", "tool.call.chain": ["DB.QUERY", "send_email"]}
    )
    assert not rule_matches(
        rule,
        {"event.action": "execute_tool", "tool.call.chain": ["db.query_metadata", "send_email"]},
    )


def test_correlation_does_not_pool_tenants() -> None:
    rule = ROOT / "rules/agent_tool_abuse/denied_tool_retry_loop.yml"
    events = [
        {
            "event.action": "execute_tool",
            "tool.call.outcome": "denied",
            "gen_ai.conversation.id": "shared-local-id",
            "user.tenant.id": tenant,
            "timestamp": "2026-06-11T12:00:00Z",
        }
        for tenant in ["tenant-a", "tenant-a", "tenant-b"]
    ]
    assert correlation_hits(rule, events) == []
