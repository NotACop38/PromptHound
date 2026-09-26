"""Run rules over audit events and describe the alerts they raise.

A single-event rule raises one alert per matching event. A correlation rule
raises one alert per group and fixed window in which its condition holds —
exactly the rows the generated SPL and KQL return.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from prompthound import correlate
from prompthound.rules import Rule


@dataclass(frozen=True)
class Alert:
    rule: Rule
    time: str
    event_ids: tuple[str, ...]
    group: tuple[tuple[str, Any], ...] = ()
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "rule_id": self.rule.id,
            "rule": self.rule.relpath,
            "title": self.rule.title,
            "level": self.rule.level,
            "time": self.time,
            "event_ids": list(self.event_ids),
        }
        if self.rule.correlation is not None:
            record["group"] = dict(self.group)
            record["window_seconds"] = self.rule.correlation.timespan
            record["count"] = self.count
        return record


def alerts_for(rule: Rule, events: Sequence[Mapping[str, Any]]) -> list[Alert]:
    """Alerts one rule raises over ``events``."""
    if rule.correlation is None:
        return [
            Alert(rule, str(e.get("timestamp", "")), (str(e.get("event.id", "")),))
            for e in events
            if rule.matches(e)
        ]
    return [
        Alert(
            rule,
            w.start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            w.event_ids,
            tuple(zip(rule.correlation.group_by, w.group, strict=True)),
            w.count,
        )
        for w in correlate.evaluate(rule.correlation, rule.predicate, events)
    ]


def evaluate(rules: Sequence[Rule], events: Sequence[Mapping[str, Any]]) -> list[Alert]:
    """Alerts from every rule, ordered by time, then rule title."""
    alerts = [alert for rule in rules for alert in alerts_for(rule, events)]
    return sorted(alerts, key=lambda a: (a.time, a.rule.title, a.event_ids))


__all__ = ["Alert", "alerts_for", "evaluate"]
