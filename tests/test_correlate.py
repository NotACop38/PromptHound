from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from prompthound.correlate import Correlation, Window, evaluate, window_start

CHAT = Correlation(
    group_by=("user.tenant.id", "user.id"), timespan=300, operator="gte", threshold=3
)


def is_chat(event: Any) -> bool:
    return bool(event.get("gen_ai.operation.name") == "chat")


def event(clock: str, user: str = "u1", tenant: str = "t1", ident: str = "") -> dict[str, Any]:
    return {
        "timestamp": f"2026-06-01T{clock}Z",
        "event.id": ident or f"{user}-{clock}",
        "gen_ai.operation.name": "chat",
        "user.tenant.id": tenant,
        "user.id": user,
    }


def test_windows_are_fixed_and_aligned_to_the_epoch() -> None:
    moment = dt.datetime(2026, 6, 1, 12, 7, 31, tzinfo=dt.UTC)
    assert window_start(moment, 300) == dt.datetime(2026, 6, 1, 12, 5, tzinfo=dt.UTC)
    assert window_start(moment, 3600) == dt.datetime(2026, 6, 1, 12, 0, tzinfo=dt.UTC)


def test_threshold_is_counted_per_window() -> None:
    events = [event("12:00:00"), event("12:01:00"), event("12:04:59")]
    assert evaluate(CHAT, is_chat, events) == [
        Window(
            group=("t1", "u1"),
            start=dt.datetime(2026, 6, 1, 12, 0, tzinfo=dt.UTC),
            count=3,
            event_ids=("u1-12:00:00", "u1-12:01:00", "u1-12:04:59"),
        )
    ]


def test_a_burst_across_a_window_boundary_is_split() -> None:
    events = [event("12:04:00"), event("12:04:30"), event("12:05:00"), event("12:05:30")]
    assert evaluate(CHAT, is_chat, events) == []


def test_every_qualifying_window_is_reported() -> None:
    events = [event(f"12:0{m}:00") for m in (0, 1, 2)] + [event(f"12:1{m}:00") for m in (0, 1, 2)]
    windows = evaluate(CHAT, is_chat, events)
    assert [w.start.minute for w in windows] == [0, 10]


def test_groups_and_tenants_do_not_pool() -> None:
    events = [
        event("12:00:00", tenant="a"),
        event("12:00:10", tenant="a"),
        event("12:00:20", tenant="b"),
    ]
    assert evaluate(CHAT, is_chat, events) == []


@pytest.mark.parametrize("missing", [None, "", ["u1"], {"id": 1}])
def test_events_without_a_usable_group_value_are_not_counted(missing: Any) -> None:
    events = [event("12:00:00"), event("12:00:10"), {**event("12:00:20"), "user.id": missing}]
    assert evaluate(CHAT, is_chat, events) == []


def test_non_matching_events_are_not_counted() -> None:
    events = [
        event("12:00:00"),
        event("12:00:10"),
        {**event("12:00:20"), "gen_ai.operation.name": "embeddings"},
    ]
    assert evaluate(CHAT, is_chat, events) == []


@pytest.mark.parametrize(
    ("operator", "threshold", "count", "expected"),
    [("gte", 3, 3, True), ("gt", 3, 3, False), ("lte", 1, 1, True), ("lt", 2, 2, False)],
)
def test_operators(operator: str, threshold: int, count: int, expected: bool) -> None:
    correlation = Correlation(("user.id",), 300, operator, threshold)
    events = [event(f"12:00:0{i}") for i in range(count)]
    assert bool(evaluate(correlation, is_chat, events)) is expected


def test_results_are_ordered_by_window_then_group() -> None:
    events = (
        [event("12:10:00", user="b")] * 3
        + [event("12:10:00", user="a")] * 3
        + [event("12:00:00", user="z")] * 3
    )
    windows = evaluate(CHAT, is_chat, events)
    assert [(w.start.minute, w.group[1]) for w in windows] == [(0, "z"), (10, "a"), (10, "b")]


def test_correlation_properties() -> None:
    assert CHAT.symbol == ">="
    assert CHAT.satisfied_by(3)
    assert not CHAT.satisfied_by(2)
