"""The offline evaluator against the declared semantics in tests/conformance.yml.

scripts/verify_siem.py runs the same cases in Splunk and the Kusto engine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from prompthound.convert import convert
from scripts.verify_siem import Conformance, conformance


@pytest.fixture(scope="module")
def suite(tmp_path_factory: pytest.TempPathFactory) -> Conformance:
    return conformance(tmp_path_factory.mktemp("conformance"))


def test_offline_results_match_the_declared_semantics(suite: Conformance) -> None:
    wrong = {
        case.name: sorted(matched)
        for case in suite.cases
        if (matched := {e["event.id"] for e in suite.events if case.rule.matches(e)})
        != case.matches
    }
    assert wrong == {}


def test_cases_are_distinct_and_convert(suite: Conformance) -> None:
    names = [case.name for case in suite.cases]
    assert len(names) == len(set(names))
    for case in suite.cases:
        queries = convert(case.rule)
        assert queries.spl
        assert queries.kql


def test_every_event_is_matched_and_missed_by_some_case(suite: Conformance) -> None:
    ids = {e["event.id"] for e in suite.events}
    matched = set().union(*(case.matches for case in suite.cases))
    missed = set().union(*(ids - case.matches for case in suite.cases))
    assert matched == ids == missed


def test_invalid_events_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "conformance.yml"
    source.write_text("events:\n  bad: {event.outcome: maybe}\ncases: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="conformance event 'bad'"):
        conformance(tmp_path, source)
