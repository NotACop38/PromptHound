"""Offline evaluator for Sigma ``event_count`` correlation rules (PRD §12).

The single-event matcher (:mod:`prompthound.matcher`) cannot express a windowed
aggregation, so correlation rules get their own evaluator here: filter events
through the correlation's *base* detection with :func:`~prompthound.matcher.
rule_matches`, group the matches by the correlation's ``group-by`` fields, and
count fixed UTC ``timespan`` buckets until the threshold condition passes.
This is the one implementation shared by the per-rule fire/
silence tests, the demo, and the generator drift guard — the offline result is
defined in exactly one place.

Window semantics match the shipped SPL/KQL: fixed UTC buckets, with an inclusive
start and exclusive end. A burst split across two buckets can be missed. This
offline summary reports the first qualifying bucket per group, while a SIEM
query returns every qualifying bucket. Missing/empty group keys are excluded.

Supported is the subset of Sigma correlations the rule pack uses: a single
``event_count`` correlation over a single base rule, with ``gte``/``gt``/
``lte``/``lt`` conditions. Anything else raises ``NotImplementedError`` rather
than silently miscounting, mirroring the matcher's fail-loud contract.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NamedTuple

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationCondition, SigmaCorrelationRule
from sigma.rule import SigmaRule

from prompthound.matcher import Event, rule_matches
from prompthound.schema import load_schema, parse_timestamp

_CONDITION_OPS: dict[str, Callable[[int, int], bool]] = {
    "GTE": lambda count, threshold: count >= threshold,
    "GT": lambda count, threshold: count > threshold,
    "LTE": lambda count, threshold: count <= threshold,
    "LT": lambda count, threshold: count < threshold,
}


class CorrelationAlert(NamedTuple):
    """One correlation alert: the group-by key values and the firing window's count.

    A ``NamedTuple`` so existing expectations written as plain tuples — e.g.
    ``hits == [(("u-burst-9001",), 12)]`` — keep comparing equal. (The count
    field is named ``event_count`` after the Sigma correlation metric, also
    because ``tuple`` already reserves a ``count`` method.)
    """

    group: tuple[object, ...]
    event_count: int


def _split(path: str | Path, collection: SigmaCollection) -> tuple[SigmaRule, SigmaCorrelationRule]:
    """``(base rule, correlation)`` from a loaded correlation file.

    The rule pack's correlation files each hold exactly one base detection plus
    one correlation; anything else is an authoring error surfaced here.
    """
    bases = [r for r in collection.rules if not isinstance(r, SigmaCorrelationRule)]
    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    if len(bases) != 1 or len(correlations) != 1:
        raise ValueError(
            f"{path}: expected one base rule + one correlation, "
            f"got {len(bases)} base / {len(correlations)} correlation"
        )
    return bases[0], correlations[0]


def load_correlation_file(path: str | Path) -> tuple[SigmaRule, SigmaCorrelationRule]:
    """Load ``(base rule, correlation)`` from a correlation rule file."""
    return _split(path, SigmaCollection.load_ruleset([str(path)]))


def is_correlation_file(path: str | Path) -> bool:
    """True if the rule file contains a Sigma correlation rule."""
    collection = SigmaCollection.load_ruleset([str(path)])
    return any(isinstance(r, SigmaCorrelationRule) for r in collection.rules)


def validate_correlation(base: SigmaRule, correlation: SigmaCorrelationRule) -> None:
    """Reject shapes the offline evaluator and both query emitters cannot preserve."""
    if not isinstance(correlation.condition, SigmaCorrelationCondition):
        raise NotImplementedError("unsupported correlation condition shape")
    if str(correlation.type) != "event_count" or correlation.condition.fieldref is not None:
        raise NotImplementedError("only event_count correlations without fieldref are supported")
    if (
        not correlation.rules
        or len(correlation.rules) != 1
        or correlation.rules[0].rule is not base
    ):
        raise NotImplementedError("correlation must reference exactly its one base rule")
    if correlation.aliases:
        raise NotImplementedError("correlation aliases are not supported")
    properties = load_schema()["properties"]
    for field in correlation.group_by or []:
        field_type = properties.get(field, {}).get("type")
        # KQL cannot summarize by dynamic columns. Event time is already a
        # bucket key and must not also be emitted as an unbinned group column.
        if (
            not isinstance(field_type, str)
            or field_type not in {"string", "integer", "number", "boolean"}
            or field == "timestamp"
        ):
            raise NotImplementedError(
                "correlation group-by requires scalar schema fields other than timestamp"
            )
    span = correlation.timespan.seconds
    if span <= 0 or 86400 % span:
        raise NotImplementedError("timespan must be a positive divisor of one UTC day")
    if correlation.condition.op.name not in _CONDITION_OPS:
        raise NotImplementedError("unsupported correlation condition operator")


def correlation_alerts(
    base: SigmaRule,
    correlation: SigmaCorrelationRule,
    events: Sequence[Event],
) -> list[CorrelationAlert]:
    """Alerts for one correlation over ``events`` (at most one per group)."""
    validate_correlation(base, correlation)
    if str(correlation.type) != "event_count":
        raise NotImplementedError(
            f"unsupported correlation type: {correlation.type} (only event_count)"
        )
    condition = correlation.condition
    if not isinstance(condition, SigmaCorrelationCondition):
        raise NotImplementedError(f"unsupported correlation condition: {type(condition).__name__}")
    op_name = condition.op.name
    passes = _CONDITION_OPS.get(op_name)
    if passes is None:
        raise NotImplementedError(f"unsupported correlation condition operator: {op_name}")
    # No group-by means one global aggregation bucket (the empty key).
    group_by = correlation.group_by or []
    span = dt.timedelta(seconds=correlation.timespan.seconds)
    threshold = condition.count

    groups: dict[tuple[object, ...], dict[dt.datetime, int]] = defaultdict(dict)
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)
    for event in events:
        if not rule_matches(base, event):
            continue
        key = tuple(event.get(field) for field in group_by)
        if any(value is None or value == "" for value in key):
            continue
        if any(not isinstance(value, (str, int, float, bool)) for value in key):
            raise ValueError("correlation group keys must be scalar values")
        time = _parse_timestamp(event)
        bucket = epoch + ((time - epoch) // span) * span
        groups[key][bucket] = groups[key].get(bucket, 0) + 1

    alerts: list[CorrelationAlert] = []
    for key, buckets in groups.items():
        for _, count in sorted(buckets.items()):
            if passes(count, threshold):
                alerts.append(CorrelationAlert(key, count))
                break
    return alerts


def correlation_hits(path: str | Path, events: Sequence[Event]) -> list[CorrelationAlert]:
    """Alerts for a correlation rule *file* over ``events`` (load + evaluate)."""
    base, correlation = load_correlation_file(path)
    return correlation_alerts(base, correlation, events)


class FileEvaluation(NamedTuple):
    """Hit count for one rule file: matching events (selection) or alerts (correlation)."""

    hits: int
    is_correlation: bool


def evaluate_rule_file(path: str | Path, events: Sequence[Event]) -> FileEvaluation:
    """Evaluate any rule file — selection or correlation — over ``events``.

    A selection rule's hit count is the number of matching events; a correlation
    rule's is the number of alerting groups (each group alerts at most once).
    """
    collection = SigmaCollection.load_ruleset([str(path)])
    if any(isinstance(r, SigmaCorrelationRule) for r in collection.rules):
        base, correlation = _split(path, collection)
        return FileEvaluation(len(correlation_alerts(base, correlation, events)), True)
    if len(collection.rules) != 1 or not isinstance(collection.rules[0], SigmaRule):
        raise ValueError(f"{path}: expected exactly one plain detection rule")
    rule = collection.rules[0]
    return FileEvaluation(sum(1 for event in events if rule_matches(rule, event)), False)


def _parse_timestamp(event: Event) -> dt.datetime:
    raw = event.get("timestamp")
    if not isinstance(raw, str):
        raise ValueError(f"event is missing a string 'timestamp' field: {raw!r}")
    return parse_timestamp(raw)


__all__ = [
    "CorrelationAlert",
    "FileEvaluation",
    "correlation_alerts",
    "correlation_hits",
    "evaluate_rule_file",
    "is_correlation_file",
    "load_correlation_file",
]
