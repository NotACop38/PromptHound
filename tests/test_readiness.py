from __future__ import annotations

from typing import Any

from prompthound import generator, rules
from prompthound.readiness import assess, satisfiable
from tests.conftest import RuleWriter
from tests.helpers import load_one, selection_document


def _strip(dataset: generator.Dataset, *names: str) -> list[dict[str, Any]]:
    return [{k: v for k, v in e.items() if k not in names} for e in dataset.events]


def test_complete_telemetry_makes_every_rule_ready(
    pack: list[rules.Rule], dataset: generator.Dataset
) -> None:
    report = assess(pack, dataset.events)
    assert {r.status for r in report.rules} == {"ready"}
    assert all(f.present > 0 for f in report.fields)
    assert {f.name for f in report.fields} == {n for r in pack for n in r.fields}


def test_an_alternative_branch_keeps_a_rule_partially_ready(
    by_stem: dict[str, rules.Rule], dataset: generator.Dataset
) -> None:
    rule = by_stem["pii_secret_exfiltration_in_output"]
    partial = assess([rule], _strip(dataset, "content.output.pii.types")).rules[0]
    assert (partial.status, partial.missing) == ("partial", ("content.output.pii.types",))
    blocked = assess(
        [rule], _strip(dataset, "content.output.pii.types", "content.output.secret.types")
    ).rules[0]
    assert blocked.status == "blocked"


def test_missing_group_by_fields_block_correlations(
    by_stem: dict[str, rules.Rule], dataset: generator.Dataset
) -> None:
    report = assess([by_stem["denied_tool_retry_loop"]], _strip(dataset, "user.tenant.id"))
    assert report.rules[0].status == "blocked"


def test_negations_and_null_checks_do_not_require_fields(by_stem: dict[str, rules.Rule]) -> None:
    rule = by_stem["direct_injection_marker_count"]
    assert not satisfiable(rule, set())
    assert satisfiable(rule, {"content.input.injection_markers"})


def test_report_serializes(pack: list[rules.Rule]) -> None:
    report = assess(pack, [])
    document = report.to_dict()
    assert {r["status"] for r in document["rules"]} == {"blocked"}
    assert all(f["events"] == 0 and f["present"] == 0 for f in document["fields"])
    assert report.fields[0].share == 0.0


def test_negated_fields_are_not_required(write_rule: RuleWriter) -> None:
    detection = {
        "a": {"user.id": "u"},
        "b": {"policy.decision": "block"},
        "condition": "a and not b",
    }
    rule = load_one(write_rule(selection_document(detection)))
    assert satisfiable(rule, {"user.id"})
    assert not satisfiable(rule, {"policy.decision"})
