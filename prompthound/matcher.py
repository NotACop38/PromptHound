"""Offline Sigma rule evaluator -- the backend-agnostic test harness (PRD §12).

PromptHound's test-harness approach (PRD §12) is to *evaluate the Sigma rule
logic directly against sample events* -- no running SIEM, no SPL/KQL execution.
Generated SPL/KQL is snapshot-tested separately (stable + non-empty).

**Mechanism (the decision recorded in CHECKLIST Phase 1a "offline test-harness
mechanism"):** we parse each rule with pySigma -- the same library that emits the
SPL/KQL -- and walk pySigma's *own* fully-resolved condition tree
(``rule.detection.parsed_condition[i].parse()``) against a plain ``dict`` event.
Using pySigma's parser (rather than re-implementing Sigma's condition grammar)
keeps the harness faithful to the source of truth and free of a live backend.

Supported here is the subset of Sigma used by the current rule pack: ``and`` /
``or`` / ``not`` over named detections, field/value expressions with the
``contains`` (wildcard) and ``gte``/``gt``/``lte``/``lt`` numeric-compare
modifiers, plain string/number equality, and null checks. Wildcard string
matching is case-insensitive, mirroring KQL ``contains`` / Splunk search
semantics. Unsupported node types raise ``NotImplementedError`` rather than
silently passing, so the harness fails loudly when a new rule outgrows it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCompareExpression,
    SigmaNull,
    SigmaNumber,
    SigmaString,
    SpecialChars,
)

Event = dict[str, object]

_COMPARE_OPS = {
    SigmaCompareExpression.CompareOperators.LT: lambda a, b: a < b,
    SigmaCompareExpression.CompareOperators.LTE: lambda a, b: a <= b,
    SigmaCompareExpression.CompareOperators.GT: lambda a, b: a > b,
    SigmaCompareExpression.CompareOperators.GTE: lambda a, b: a >= b,
    SigmaCompareExpression.CompareOperators.NEQ: lambda a, b: a != b,
}


def load_rule(path: str | Path) -> SigmaRule:
    """Load a single Sigma rule from a YAML file."""
    collection = SigmaCollection.load_ruleset([str(path)])
    if len(collection.rules) != 1:
        raise ValueError(f"expected exactly one rule in {path}, got {len(collection.rules)}")
    rule = collection.rules[0]
    if not isinstance(rule, SigmaRule):
        raise TypeError(f"{path} is not a plain detection rule: {type(rule).__name__}")
    return rule


def rule_matches(rule: SigmaRule, event: Event) -> bool:
    """Return True if ``rule``'s detection logic fires on ``event``.

    A Sigma rule may carry multiple ``condition`` entries (a YAML list); Sigma
    treats them as independent queries that are logically OR-ed, and pySigma
    exposes them as multiple ``parsed_condition`` entries. We evaluate every one
    so the offline result matches what the SIEM backends emit.
    """
    conditions = rule.detection.parsed_condition
    if not conditions:
        raise ValueError("rule has no parsed detection condition")
    return any(_eval(condition.parse(), event) for condition in conditions)


# --- condition tree evaluation -------------------------------------------------


def _eval(node: object, event: Event) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_field(node.field, node.value, event)
    if isinstance(node, ConditionValueExpression):
        # Keyword (fieldless) match: test the value against every field's value.
        return any(_match_value(node.value, cand) for cand in _all_candidates(event))
    raise NotImplementedError(f"unsupported condition node: {type(node).__name__}")


def _match_field(field: str, value: object, event: Event) -> bool:
    candidates = _field_candidates(event, field)
    if isinstance(value, SigmaNull):
        # Sigma ``field: null`` matches when the field is absent OR explicitly null.
        return field not in event or any(cand is None for cand in candidates)
    return any(_match_value(value, cand) for cand in candidates)


def _match_value(value: object, candidate: object) -> bool:
    if isinstance(value, SigmaBool):
        # ``field: true|false`` -- match only a real JSON boolean of the same
        # value. ``candidate is True/False`` (not ``==``) so the int 1/0 a
        # numeric field might carry never satisfies a boolean comparison.
        return isinstance(candidate, bool) and candidate is value.boolean
    if isinstance(value, SigmaString):
        return isinstance(candidate, str) and _match_string(value, candidate)
    if isinstance(value, SigmaNumber):
        return _as_number(candidate) == value.number
    if isinstance(value, SigmaCompareExpression):
        number = _as_number(candidate)
        if number is None:
            return False
        return _COMPARE_OPS[value.op](number, value.number.number)
    raise NotImplementedError(f"unsupported value type: {type(value).__name__}")


def _match_string(value: SigmaString, text: str) -> bool:
    return re.fullmatch(_sigma_string_to_regex(value), text, re.IGNORECASE | re.DOTALL) is not None


def _sigma_string_to_regex(value: SigmaString) -> str:
    parts: list[str] = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        else:
            raise NotImplementedError(f"unsupported SigmaString element: {part!r}")
    # Sigma adds the appropriate leading/trailing wildcards for contains,
    # startswith and endswith. Every pattern still matches the whole value.
    return "".join(parts)


# --- event field access --------------------------------------------------------


def _field_candidates(event: Event, field: str) -> list[object]:
    """Candidate scalar values for ``field``; list/dict values are expanded."""
    if field not in event:
        return []
    return _expand(event[field])


def _all_candidates(event: Event) -> list[object]:
    candidates: list[object] = []
    for raw in event.values():
        candidates.extend(_expand(raw))
    return candidates


def _expand(raw: object) -> list[object]:
    if isinstance(raw, list):
        return [item if _is_scalar(item) else json.dumps(item) for item in raw]
    if isinstance(raw, dict):
        return [json.dumps(raw)]
    return [raw]


def _is_scalar(value: object) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _as_number(value: object) -> float | int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None
