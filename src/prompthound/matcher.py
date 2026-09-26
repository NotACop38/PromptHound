"""Compile a Sigma detection into a predicate over audit events.

The rule is parsed by pySigma — the same library that emits the SPL and KQL —
and its resolved condition tree is compiled once into nested closures. Matching
semantics follow the generated queries:

* strings compare ignoring the case of ASCII letters (a non-ASCII letter only
  matches itself, as in Splunk); ``*`` matches any run of characters and every
  pattern must match the whole value (``contains`` adds the wildcards);
* string-array fields match when any element equals the value;
* content fields (``x-class: content``) match against their JSON text, exactly
  as they are stored in the SIEM copy produced by :mod:`prompthound.normalize`;
* numbers compare numerically, booleans only equal JSON booleans;
* a missing field never matches, so a negation of it always does.

The rule loader (:mod:`prompthound.rules`) rejects detection features outside
this subset before a rule is compiled, so a rule that loads is a rule whose
offline result can match the SIEM result.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCompareExpression,
    SigmaNumber,
    SigmaString,
    SigmaType,
    SpecialChars,
)

from prompthound import fields

Event = Mapping[str, Any]
Predicate = Callable[[Event], bool]
_ValueTest = Callable[[Any], bool]

_COMPARE: dict[str, Callable[[Any, Any], bool]] = {
    "LT": operator.lt,
    "LTE": operator.le,
    "GT": operator.gt,
    "GTE": operator.ge,
}


def compile_rule(rule: SigmaRule) -> Predicate:
    """Return a predicate that is true when ``rule``'s detection matches an event.

    A Sigma rule may declare several conditions; they are alternatives.
    """
    trees = [condition.parse() for condition in rule.detection.parsed_condition]
    if not trees:
        raise ValueError(f"rule {rule.title!r} has no detection condition")
    predicates = [_compile(tree) for tree in trees]
    if len(predicates) == 1:
        return predicates[0]
    return lambda event: any(predicate(event) for predicate in predicates)


def has_non_ascii_letter(text: str) -> bool:
    """Whether ``text`` holds a letter outside ASCII that has upper- and lower-case forms."""
    return any(not c.isascii() and c.lower() != c.upper() for c in text)


def string_pattern(value: SigmaString) -> re.Pattern[str]:
    """Regular expression equivalent of a Sigma string (wildcards, whole value)."""
    parts: list[str] = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        else:
            raise NotImplementedError(f"unsupported special character in {str(value)!r}")
    return re.compile("".join(parts), re.IGNORECASE | re.DOTALL | re.ASCII)


def _compile(node: object) -> Predicate:
    if isinstance(node, ConditionAND):
        children = [_compile(arg) for arg in node.args]
        return lambda event: all(child(event) for child in children)
    if isinstance(node, ConditionOR):
        children = [_compile(arg) for arg in node.args]
        return lambda event: any(child(event) for child in children)
    if isinstance(node, ConditionNOT):
        child = _compile(node.args[0])
        return lambda event: not child(event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _field_predicate(node.field, node.value)
    raise NotImplementedError(f"unsupported condition element: {type(node).__name__}")


def _field_predicate(name: str, value: SigmaType) -> Predicate:
    test = _value_test(value)
    field = fields.registry().get(name)
    if field is not None and field.is_content:

        def match_content(event: Event) -> bool:
            raw = event.get(name)
            return raw is not None and test(fields.content_text(raw))

        return match_content

    def match(event: Event) -> bool:
        return any(test(candidate) for candidate in _candidates(event.get(name)))

    return match


def _candidates(raw: Any) -> Iterable[Any]:
    if isinstance(raw, list):
        return raw
    return () if raw is None else (raw,)


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _value_test(value: SigmaType) -> _ValueTest:
    if isinstance(value, SigmaBool):
        expected = value.boolean
        return lambda candidate: isinstance(candidate, bool) and candidate is expected
    if isinstance(value, SigmaString):
        pattern = string_pattern(value)
        return lambda candidate: isinstance(candidate, str) and bool(pattern.fullmatch(candidate))
    if isinstance(value, SigmaNumber):
        number = value.number
        return lambda candidate: _is_number(candidate) and candidate == number
    if isinstance(value, SigmaCompareExpression):
        compare, threshold = _COMPARE[value.op.name], value.number.number
        return lambda candidate: _is_number(candidate) and compare(candidate, threshold)
    raise NotImplementedError(f"unsupported value type: {type(value).__name__}")


__all__ = ["Event", "Predicate", "compile_rule", "has_non_ascii_letter", "string_pattern"]
