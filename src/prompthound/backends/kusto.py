"""KQL conversion for Microsoft Sentinel and Azure Data Explorer.

``pysigma-backend-kusto`` renders the detection logic; this module supplies the
PromptHound column mapping and corrects four places where the pinned backend's
output does not fit the audit-event table or PromptHound's matching semantics:

* string-array columns are ``dynamic``; equality becomes membership that
  ignores the case of ASCII letters (``set_has_element``, or ``set_intersect``
  for a value list) instead of scalar comparison;
* the backend's list optimization rewrites ``foo*bar`` into two ``contains``
  terms and loses their order, so wildcard lists stay as ordered regexes;
* KQL's case-insensitive operators also fold non-ASCII letters, which Splunk
  does not, so a value with a non-ASCII letter becomes a regex in which only
  ASCII letters ignore case;
* the backend renders boolean equality as ``field =~ true``, which does not
  compile against a ``bool`` column; it becomes ``field == true``.

The table name is prepended to every query (default ``PromptHoundAuditLog_CL``).
"""

from __future__ import annotations

import json
import re
import string
from dataclasses import dataclass
from typing import Any

from sigma.backends.kusto.kusto import KustoBackend
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionOR
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaRule
from sigma.types import SigmaString, SpecialChars

from prompthound import fields
from prompthound.matcher import has_non_ascii_letter

_RE2_SPECIAL = frozenset("\\.+*?()|[]{}^$")
_UPPER = string.ascii_uppercase
_LOWER = string.ascii_lowercase


def _array_columns() -> frozenset[str]:
    return frozenset(f.column for f in fields.registry().values() if f.is_string_array)


def _ascii_folding_regex(value: SigmaString) -> str:
    """An RE2 pattern for the whole value in which only ASCII letters ignore case."""
    parts = ["(?s)\\A"]
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
            continue
        if not isinstance(part, str):
            raise NotImplementedError(f"unsupported special character in {str(value)!r}")
        for char in part:
            if char.isascii() and char.isalpha():
                parts.append(f"[{char.upper()}{char.lower()}]")
            elif char in _RE2_SPECIAL:
                parts.append("\\" + char)
            elif not char.isprintable():
                parts.append(f"\\x{{{ord(char):x}}}")
            else:
                parts.append(char)
    parts.append("\\z")
    return "".join(parts)


class PromptHoundKustoBackend(KustoBackend):
    """Kusto backend with membership semantics for the schema's string arrays."""

    in_expressions_allow_wildcards = False
    wildcard_match_expression = '{field} matches regex "(?is)\\\\A{regex}\\\\z"'

    def decide_convert_condition_as_in_expression(
        self, cond: ConditionOR | ConditionAND, state: ConversionState
    ) -> bool:
        if any(
            isinstance(arg, ConditionFieldEqualsValueExpression)
            and has_non_ascii_letter(str(arg.value))
            for arg in cond.args
        ):
            return False
        if any(getattr(arg, "field", None) in _array_columns() for arg in cond.args):
            # A value list on an array column is an intersection test; an
            # "all values" list stays a conjunction of membership tests.
            return isinstance(cond, ConditionOR) and bool(
                super().decide_convert_condition_as_in_expression(cond, state)
            )
        return bool(super().decide_convert_condition_as_in_expression(cond, state))

    def convert_condition_as_in_expression(
        self, cond: ConditionOR | ConditionAND, state: ConversionState
    ) -> str | DeferredQueryExpression:
        first = cond.args[0]
        if (
            isinstance(first, ConditionFieldEqualsValueExpression)
            and first.field in _array_columns()
        ):
            values = [
                str(arg.value).lower()
                for arg in cond.args
                if isinstance(arg, ConditionFieldEqualsValueExpression)
            ]
            return (
                f"array_length(set_intersect({self._array_expression(first.field)}, "
                f"dynamic({json.dumps(values)}))) > 0"
            )
        result: str | DeferredQueryExpression = super().convert_condition_as_in_expression(
            cond, state
        )
        return result

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        if cond.field in _array_columns() and isinstance(cond.value, SigmaString):
            if cond.value.contains_special():
                raise NotImplementedError("string-array fields support exact element matching only")
            literal = self.convert_value_str(SigmaString(str(cond.value).lower()), state)
            return f"set_has_element({self._array_expression(cond.field)}, {literal})"
        if isinstance(cond.value, SigmaString) and has_non_ascii_letter(str(cond.value)):
            regex = _ascii_folding_regex(cond.value).replace("\\", "\\\\").replace('"', '\\"')
            return f'{self.escape_and_quote_field(cond.field)} matches regex "{regex}"'
        result: str | DeferredQueryExpression = super().convert_condition_field_eq_val_str(
            cond, state
        )
        return result

    def _array_expression(self, column: str) -> str:
        """The column's elements with ASCII letters lower-cased, as a dynamic array.

        ``tolower`` would also fold non-ASCII letters (and map a few, such as the
        Kelvin sign, onto ASCII ones), which Splunk does not.
        """
        text = f"tostring({self.escape_and_quote_field(column)})"
        return f'parse_json(translate("{_UPPER}", "{_LOWER}", {text}))'


@dataclass
class _Finalize(QueryPostprocessingTransformation):
    """Fix boolean comparisons outside string literals and prepend the table."""

    table: str = fields.DEFAULT_SENTINEL_TABLE

    _LITERAL_OR_BOOL = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|(=~|!~) (true|false)\b')

    def apply(self, rule: SigmaRule | SigmaCorrelationRule, query: Any) -> Any:
        super().apply(rule, query)

        def fix(match: re.Match[str]) -> str:
            if match.group(1) is None:
                return match.group(0)
            return f"{'==' if match.group(1) == '=~' else '!='} {match.group(2)}"

        return f"{self.table}\n| where {self._LITERAL_OR_BOOL.sub(fix, str(query))}"


def kusto_pipeline(table: str = fields.DEFAULT_SENTINEL_TABLE) -> ProcessingPipeline:
    """Column mapping plus table prefix and boolean fix for the audit-event table."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
        raise ValueError(f"not a valid table name: {table!r}")
    mapping: dict[str | None, str | list[str]] = {
        name: field.column for name, field in fields.registry().items() if field.column != name
    }
    return ProcessingPipeline(
        name="PromptHound audit schema to Kusto",
        priority=20,
        items=[
            ProcessingItem(
                identifier="prompthound_kusto_fields",
                transformation=FieldMappingTransformation(mapping),
                rule_conditions=[LogsourceCondition(product="llm_gateway")],
            )
        ],
        postprocessing_items=[
            QueryPostprocessingItem(
                identifier="prompthound_kusto_finalize",
                transformation=_Finalize(table=table),
                rule_conditions=[LogsourceCondition(product="llm_gateway")],
            )
        ],
    )


def kusto_backend(table: str = fields.DEFAULT_SENTINEL_TABLE) -> KustoBackend:
    # pySigma's TextQueryBackend.__new__ annotates **kwargs as dict[str, Any], so a
    # type checker rejects every keyword argument; the pipeline is correct at run time.
    return PromptHoundKustoBackend(processing_pipeline=kusto_pipeline(table))  # type: ignore[arg-type]


__all__ = ["PromptHoundKustoBackend", "kusto_backend", "kusto_pipeline"]
