from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest
import yaml

from prompthound import rules, scenarios
from prompthound.scenarios import Scenario, ScenarioError, load_scenario, load_scenarios
from tests.helpers import ROOT


def _cases() -> list[Any]:
    pack = rules.load_rules()
    return [
        pytest.param(scenario, index, id=f"{scenario.rule.stem}: {case.name}")
        for scenario in load_scenarios(pack)
        for index, case in enumerate(scenario.cases)
    ]


@pytest.mark.parametrize(("scenario", "index"), _cases())
def test_case(scenario: Scenario, index: int) -> None:
    result = scenarios.run(scenario)[index]
    assert result.passed, f"expected {result.case.expect}, got {result.alerts} alert(s)"


def test_every_rule_has_alerting_and_silent_cases(scenario_set: list[Scenario]) -> None:
    for scenario in scenario_set:
        outcomes = {case.expect for case in scenario.cases}
        assert outcomes == {"alert", "silent"}, scenario.rule.relpath


# --- mutation tests: weakening a rule must break at least one of its cases ----------

MUTATIONS = [
    ("dos_cost_abuse/request_rate_burst_per_principal.yml", "gte: 20", "gte: 19"),
    ("dos_cost_abuse/oversized_max_tokens.yml", "max_tokens|gte", "max_tokens|gt"),
    ("dos_cost_abuse/token_cost_spike_per_principal.yml", "gte: 8000", "gte: 7999"),
    ("dos_cost_abuse/repeated_length_finish_loops.yml", "gte: 5", "gte: 4"),
    ("prompt_injection/direct_injection_markers.yml", "scored and phrase", "phrase"),
    ("prompt_injection/direct_injection_marker_count.yml", "gte: 2", "gte: 1"),
    (
        "prompt_injection/indirect_injection_from_untrusted_source.yml",
        "untrusted_source and phrase and scored",
        "phrase and scored",
    ),
    ("system_prompt_extraction/extract_system_prompt_markers.yml", "scored and phrase", "phrase"),
    (
        "system_prompt_extraction/system_prompt_leaked_in_output.yml",
        "contains_system_prompt: true",
        "contains_system_prompt: false",
    ),
    (
        "system_prompt_extraction/system_prompt_disclosure_phrases.yml",
        "gen_ai.output.messages|contains",
        "gen_ai.input.messages|contains",
    ),
    (
        "jailbreak/persona_safety_bypass_loop.yml",
        "completion and phrase and filtered",
        "completion and phrase",
    ),
    (
        "data_exfiltration/pii_secret_exfiltration_in_output.yml",
        "condition: personal_data or credential",
        "condition: personal_data",
    ),
    (
        "agent_tool_abuse/anomalous_tool_call_chain.yml",
        "tool_operation and sensitive_read and egress",
        "tool_operation and sensitive_read",
    ),
    ("agent_tool_abuse/denied_tool_retry_loop.yml", "        - user.tenant.id\n", ""),
    ("agent_tool_abuse/tool_call_amplification_loop.yml", "gte: 15", "gte: 14"),
    ("insecure_output/unsanitized_output_to_sink.yml", "- 'code_eval'", "- 'markdown'"),
]


def test_every_rule_has_a_mutation_test(pack: list[rules.Rule]) -> None:
    assert {m[0] for m in MUTATIONS} == {rule.relpath for rule in pack}


@pytest.mark.parametrize(("relpath", "old", "new"), MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_weakened_rules_fail_their_scenarios(
    tmp_path: Path, scenario_set: list[Scenario], relpath: str, old: str, new: str
) -> None:
    text = (ROOT / "rules" / relpath).read_text(encoding="utf-8")
    assert old in text
    mutated_path = tmp_path / relpath
    mutated_path.parent.mkdir(parents=True)
    mutated_path.write_text(text.replace(old, new, 1), encoding="utf-8")
    mutant = rules.load_rule(mutated_path, tmp_path)
    original = next(s for s in scenario_set if s.rule.relpath == relpath)
    results = scenarios.run(Scenario(mutant, original.path, original.cases))
    assert not all(result.passed for result in results), "the scenarios do not detect this change"


# --- materialization -----------------------------------------------------------


def test_events_are_deterministic_and_spaced(scenario_set: list[Scenario]) -> None:
    scenario = next(s for s in scenario_set if s.rule.stem == "request_rate_burst_per_principal")
    first = scenarios.materialize(scenario, 0)
    assert first == scenarios.materialize(scenario, 0)
    assert len(first) == 20
    assert [e["timestamp"] for e in first[:3]] == [
        "2026-06-01T12:00:00Z",
        "2026-06-01T12:00:02Z",
        "2026-06-01T12:00:04Z",
    ]
    assert len({e["event.id"] for e in first}) == 20
    split = scenarios.materialize(scenario, 3)
    assert split[0]["timestamp"] == "2026-06-01T12:00:50Z"


def test_materialize_accepts_a_start_and_identity(scenario_set: list[Scenario]) -> None:
    scenario = scenario_set[0]
    start = dt.datetime(2030, 1, 1, tzinfo=dt.UTC)
    events = scenarios.materialize(scenario, 0, start=start, identity="custom")
    assert events[0]["timestamp"].startswith("2030-01-01T00:00")
    assert events[0]["user.id"] == "user-custom"


def test_base_events_depend_on_the_operation() -> None:
    chat = scenarios.base_event("x")
    tool = scenarios.base_event("x", "execute_tool")
    assert "gen_ai.input.messages" in chat
    assert "tool.call.chain" not in chat
    assert "tool.call.chain" in tool
    assert "gen_ai.usage.input_tokens" not in tool


def write_scenario(tmp_path: Path, rule: rules.Rule, document: Any, raw: str | None = None) -> Path:
    path = tmp_path / rule.relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw if raw is not None else yaml.safe_dump(document, sort_keys=False))
    return tmp_path


def case(**overrides: Any) -> dict[str, Any]:
    return {"name": "c", "expect": "silent", "events": [{}], **overrides}


def test_usage_fields_follow_token_overrides(tmp_path: Path, pack: list[rules.Rule]) -> None:
    rule = pack[0]
    root = write_scenario(
        tmp_path,
        rule,
        {
            "cases": [
                case(events=[{"set": {"gen_ai.usage.input_tokens": 1000}}]),
                case(
                    name="d", events=[{"set": {"gen_ai.usage.input_tokens": 10, "cost.usd": 9.5}}]
                ),
            ]
        },
    )
    scenario = load_scenario(rule, root)
    derived, explicit = scenarios.materialize(scenario, 0)[0], scenarios.materialize(scenario, 1)[0]
    assert derived["usage.total_tokens"] == 1180
    assert derived["cost.usd"] == pytest.approx(1000 * 0.000002 + 180 * 0.000008)
    assert explicit["cost.usd"] == 9.5


def test_shorthands_and_unset(tmp_path: Path, pack: list[rules.Rule]) -> None:
    rule = pack[0]
    document = {
        "x-anchor": {"user.id": "shared"},
        "cases": [
            case(
                events=[
                    {
                        "messages": [
                            {"role": "user", "text": "hi"},
                            {"role": "tool", "text": "doc"},
                        ],
                        "response": "hello",
                        "unset": ["policy.decision"],
                        "at": "1m",
                        "interval": 30,
                        "repeat": 2,
                    }
                ]
            )
        ],
    }
    scenario = load_scenario(rule, write_scenario(tmp_path, rule, document))
    events = scenarios.materialize(scenario, 0)
    assert [m["role"] for m in events[0]["gen_ai.input.messages"]] == ["user", "tool"]
    assert events[0]["gen_ai.output.messages"][0]["parts"][0]["content"] == "hello"
    assert "policy.decision" not in events[0]
    assert [e["timestamp"][-9:] for e in events] == ["12:01:00Z", "12:01:30Z"]
    assert scenarios.duration(scenario.cases[0]) == 90


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({}, "'cases' list"),
        ({"cases": []}, "non-empty list"),
        ({"cases": ["x"]}, "expected a mapping"),
        ({"cases": [case(extra=1)]}, "unknown key"),
        ({"cases": [case(name="")]}, "'name' is required"),
        ({"cases": [case(expect="maybe")]}, "alert or silent"),
        ({"cases": [case(alerts=2)]}, "consistent with 'expect'"),
        ({"cases": [case(events=[])]}, "non-empty list"),
        ({"cases": [case(events=["x"])]}, "must be a mapping"),
        ({"cases": [case(events=[{"sett": {}}])]}, "unknown key"),
        ({"cases": [case(events=[{"set": {"user.name": "x"}}])]}, "not an audit-schema field"),
        (
            {"cases": [case(events=[{"prompt": "a", "messages": []}])]},
            "either 'prompt' or 'messages'",
        ),
        ({"cases": [case(events=[{"messages": [{"role": "user"}]}])]}, "list of {role, text}"),
        ({"cases": [case(events=[{"prompt": ""}])]}, "non-empty string"),
        ({"cases": [case(events=[{"unset": "user.id"}])]}, "list of field names"),
        ({"cases": [case(events=[{"repeat": 0}])]}, "positive integer"),
        ({"cases": [case(events=[{"interval": "soon"}])]}, "is not a duration"),
        ({"cases": [case(), case()]}, "must be unique"),
        ({"cases": [case(events=[{"set": {"event.outcome": "maybe"}}])]}, "is not one of"),
        ({"cases": [case(events=[{"prompt": "run os.system('id') now"}])]}, "exploit payload"),
    ],
)
def test_invalid_scenarios_are_rejected(
    tmp_path: Path, pack: list[rules.Rule], document: Any, message: str
) -> None:
    root = write_scenario(tmp_path, pack[0], document)
    with pytest.raises(ScenarioError, match=message):
        load_scenario(pack[0], root)


def test_unparseable_and_missing_scenarios(tmp_path: Path, pack: list[rules.Rule]) -> None:
    with pytest.raises(ScenarioError, match="no scenario file"):
        load_scenario(pack[0], tmp_path)
    root = write_scenario(tmp_path, pack[0], None, raw="cases: [unclosed\n")
    with pytest.raises(ScenarioError, match="expected"):
        load_scenario(pack[0], root)


def test_orphan_scenario_files_are_rejected(tmp_path: Path, pack: list[rules.Rule]) -> None:
    for rule in pack:
        source = ROOT / "scenarios" / rule.relpath
        target = tmp_path / rule.relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source.read_text())
    (tmp_path / "extra.yml").write_text("cases: []\n")
    with pytest.raises(ScenarioError, match=r"without a rule: extra\.yml"):
        load_scenarios(pack, tmp_path)
