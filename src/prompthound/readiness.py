"""Which rules can a given body of telemetry support?

A rule can only alert on events that carry the fields its detection reads. The
readiness report counts, for every field the rules read, how many events carry
it, and classifies each rule:

* **ready** — every field the rule reads appears in at least one event;
* **partial** — some fields never appear, but the detection can still match
  through an alternative (for example, credential labels without personal-data
  labels);
* **blocked** — the detection cannot match without a field that never appears.

Presence is measured per field, so *ready* is a necessary condition for an
alert, not a promise that one will occur.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)

from prompthound import fields
from prompthound.rules import Rule

Status = Literal["ready", "partial", "blocked"]


@dataclass(frozen=True)
class FieldPresence:
    name: str
    present: int
    total: int

    @property
    def share(self) -> float:
        return self.present / self.total if self.total else 0.0


@dataclass(frozen=True)
class RuleReadiness:
    rule: Rule
    status: Status
    missing: tuple[str, ...]


@dataclass(frozen=True)
class Report:
    fields: tuple[FieldPresence, ...]
    rules: tuple[RuleReadiness, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": [
                {
                    "field": f.name,
                    "class": fields.get(f.name).data_class,
                    "present": f.present,
                    "events": f.total,
                }
                for f in self.fields
            ],
            "rules": [
                {
                    "rule_id": r.rule.id,
                    "rule": r.rule.relpath,
                    "title": r.rule.title,
                    "status": r.status,
                    "missing_fields": list(r.missing),
                }
                for r in self.rules
            ],
        }


def satisfiable(rule: Rule, present: set[str]) -> bool:
    """Whether ``rule`` can match given only the fields in ``present``."""
    if rule.correlation and not set(rule.correlation.group_by) <= present:
        return False

    def possible(node: object) -> bool:
        if isinstance(node, ConditionAND):
            return all(possible(arg) for arg in node.args)
        if isinstance(node, ConditionOR):
            return any(possible(arg) for arg in node.args)
        if isinstance(node, ConditionNOT):
            return True  # a negation can hold when its fields are absent
        if isinstance(node, ConditionFieldEqualsValueExpression):
            return node.field in present
        raise NotImplementedError(f"unsupported condition element: {type(node).__name__}")

    return any(possible(c.parse()) for c in rule.base.detection.parsed_condition)


def assess(rules: Sequence[Rule], events: Sequence[Mapping[str, Any]]) -> Report:
    """Field presence for every field the rules read, and each rule's status."""
    used = {name for rule in rules for name in rule.fields}
    ordered = [name for name in fields.registry() if name in used]
    counts = {name: sum(1 for e in events if e.get(name) is not None) for name in ordered}
    present = {name for name, count in counts.items() if count}
    readiness = []
    for rule in rules:
        missing = tuple(name for name in rule.fields if name not in present)
        status: Status = "ready"
        if missing:
            status = "partial" if satisfiable(rule, present) else "blocked"
        readiness.append(RuleReadiness(rule, status, missing))
    return Report(
        tuple(FieldPresence(name, counts[name], len(events)) for name in ordered),
        tuple(readiness),
    )


__all__ = ["FieldPresence", "Report", "RuleReadiness", "Status", "assess", "satisfiable"]
