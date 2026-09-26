from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from prompthound import generator, rules, scenarios
from prompthound.evaluate import evaluate
from prompthound.scenarios import Case, EventGroup, Scenario
from prompthound.schema import parse_timestamp


def test_dataset_is_deterministic(scenario_set: list[Scenario], dataset: generator.Dataset) -> None:
    assert generator.build_dataset(scenario_set, seed=0).events == dataset.events
    other = generator.build_dataset(scenario_set, seed=1)
    assert other.events != dataset.events
    scenario_ids = {k for k, v in dataset.labels.items() if v.source == "scenario"}
    assert scenario_ids == {k for k, v in other.labels.items() if v.source == "scenario"}


def test_dataset_is_ordered_and_fully_labeled(dataset: generator.Dataset) -> None:
    times = [(e["timestamp"], e["event.id"]) for e in dataset.events]
    assert times == sorted(times)
    assert set(dataset.labels) == {e["event.id"] for e in dataset.events}
    assert len(dataset.labels) == len(dataset.events)


def test_background_traffic_raises_no_alerts(
    pack: list[rules.Rule], dataset: generator.Dataset
) -> None:
    background = [e for e in dataset.events if dataset.labels[e["event.id"]].source == "background"]
    assert len(background) == generator.DEFAULT_BACKGROUND
    assert evaluate(pack, background) == []


def test_background_includes_large_events(dataset: generator.Dataset) -> None:
    sizes = [
        len(json.dumps(e))
        for e in dataset.events
        if dataset.labels[e["event.id"]].source == "background"
    ]
    assert max(sizes) > generator.LARGE_EVENT_CHARACTERS


def test_each_case_occupies_its_own_slot(
    scenario_set: list[Scenario], dataset: generator.Dataset
) -> None:
    slot = generator.slot_seconds(scenario_set)
    slots: dict[tuple[str | None, str | None], set[int]] = {}
    for event in dataset.events:
        label = dataset.labels[event["event.id"]]
        if label.source == "scenario":
            moment = parse_timestamp(event["timestamp"]) - generator.DATASET_START
            slots.setdefault((label.rule, label.case), set()).add(
                int(moment.total_seconds()) // slot
            )
    assert all(len(used) == 1 for used in slots.values())
    assert len({next(iter(used)) for used in slots.values()}) == len(slots)


def test_cases_keep_their_outcome_in_the_combined_dataset(
    scenario_set: list[Scenario], dataset: generator.Dataset
) -> None:
    for scenario in scenario_set:
        for case in scenario.cases:
            events = [
                e
                for e in dataset.events
                if (label := dataset.labels[e["event.id"]]).rule == scenario.rule.relpath
                and label.case == case.name
            ]
            alerts = scenarios.count_alerts(scenario.rule, events)
            assert (alerts > 0) == (case.expect == "alert"), (scenario.rule.stem, case.name)


def test_padded_copies_are_large_and_behave_like_the_originals(
    scenario_set: list[Scenario],
) -> None:
    padded = generator.build_dataset(scenario_set, padded_copies=True)
    copies = [e for e in padded.events if padded.labels[e["event.id"]].padded]
    assert copies
    assert all(len(json.dumps(e)) > generator.LARGE_EVENT_CHARACTERS for e in copies)
    by_rule = {s.rule.relpath: s for s in scenario_set}
    for label_rule in {padded.labels[e["event.id"]].rule for e in copies}:
        assert label_rule is not None
        assert by_rule[label_rule].rule.requires_content
    for scenario in scenario_set:
        for case in scenario.cases:
            events = [
                e
                for e in copies
                if padded.labels[e["event.id"]].rule == scenario.rule.relpath
                and padded.labels[e["event.id"]].case == case.name
            ]
            if events:
                alerts = scenarios.count_alerts(scenario.rule, events)
                assert (alerts > 0) == (case.expect == "alert"), (scenario.rule.stem, case.name)


def test_slot_length(scenario_set: list[Scenario]) -> None:
    assert generator.slot_seconds(scenario_set) == 3600
    assert generator.slot_seconds([]) == 3600


def test_invalid_arguments(scenario_set: list[Scenario]) -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        generator.build_dataset(scenario_set, background=-1)
    long_case = Case("too long", "silent", (EventGroup({}, at=7200),))
    scenario = Scenario(scenario_set[0].rule, scenario_set[0].path, (long_case,))
    with pytest.raises(ValueError, match="does not fit in one slot"):
        generator.build_dataset([scenario], background=0)


def test_background_only_dataset() -> None:
    dataset = generator.build_dataset(
        [], background=3, start=dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    )
    assert len(dataset.events) == 3
    empty = generator.build_dataset([], background=0)
    assert empty.events == ()


def test_write_jsonl_round_trips(tmp_path: Path, dataset: generator.Dataset) -> None:
    path = tmp_path / "nested" / "events.jsonl"
    assert generator.write_jsonl(path, dataset.events) == len(dataset.events)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == list(dataset.events)


def test_filler_is_benign_text_of_the_requested_length() -> None:
    text = generator.filler(500)
    assert len(text) >= 500
    assert "instructions" not in text.lower()
