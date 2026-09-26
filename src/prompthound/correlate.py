"""Offline evaluation of Sigma ``event_count`` correlations.

Events that match the base detection are grouped by the correlation's
``group-by`` fields and counted in fixed UTC windows of ``timespan`` seconds
(inclusive start, exclusive end, aligned to the Unix epoch). Every window whose
count satisfies the condition is reported — the same rows the generated SPL
(``bin _time span=...`` + ``stats``) and KQL (``summarize ... by bin(timestamp,
...)``) return. Events missing a group-by value are not counted.

Fixed windows can miss a burst that straddles a window boundary; see
``docs/deployment.md``.
"""

from __future__ import annotations

import datetime as dt
import operator
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from prompthound.matcher import Event, Predicate
from prompthound.schema import parse_timestamp

_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)

#: Supported condition operators: Sigma name -> (query symbol, comparison).
OPERATORS: dict[str, tuple[str, Callable[[int, int], bool]]] = {
    "gte": (">=", operator.ge),
    "gt": (">", operator.gt),
    "lte": ("<=", operator.le),
    "lt": ("<", operator.lt),
}


@dataclass(frozen=True)
class Correlation:
    """A validated ``event_count`` correlation."""

    group_by: tuple[str, ...]
    timespan: int
    operator: str
    threshold: int

    @property
    def symbol(self) -> str:
        return OPERATORS[self.operator][0]

    def satisfied_by(self, count: int) -> bool:
        return OPERATORS[self.operator][1](count, self.threshold)


@dataclass(frozen=True)
class Window:
    """One fixed window in which a correlation's condition held."""

    group: tuple[Any, ...]
    start: dt.datetime
    count: int
    event_ids: tuple[str, ...]


def window_start(timestamp: dt.datetime, timespan: int) -> dt.datetime:
    """Start of the fixed UTC window of ``timespan`` seconds containing ``timestamp``."""
    return _EPOCH + ((timestamp - _EPOCH) // dt.timedelta(seconds=timespan)) * dt.timedelta(
        seconds=timespan
    )


def evaluate(correlation: Correlation, base: Predicate, events: Iterable[Event]) -> list[Window]:
    """Every window in which ``correlation`` holds, ordered by start time then group."""
    buckets: dict[tuple[tuple[Any, ...], dt.datetime], list[str]] = defaultdict(list)
    for event in events:
        if not base(event):
            continue
        group = tuple(event.get(name) for name in correlation.group_by)
        if any(not _groupable(value) for value in group):
            continue
        start = window_start(parse_timestamp(str(event["timestamp"])), correlation.timespan)
        buckets[group, start].append(str(event.get("event.id", "")))
    windows = [
        Window(group=group, start=start, count=len(ids), event_ids=tuple(ids))
        for (group, start), ids in buckets.items()
        if correlation.satisfied_by(len(ids))
    ]
    return sorted(windows, key=lambda w: (w.start, [str(v) for v in w.group]))


def _groupable(value: Any) -> bool:
    return value is not None and value != "" and isinstance(value, str | int | float | bool)


__all__ = ["OPERATORS", "Correlation", "Window", "evaluate", "window_start"]
