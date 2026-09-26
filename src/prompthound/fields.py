"""Field registry derived from the audit-event schema.

Every property in the schema becomes a :class:`Field` that knows its SIEM column
name, how Splunk's JSON extraction names it, and which Microsoft Sentinel column
type holds it. Rules, the normalizer, the converters and the generated
documentation all read this registry, so the schema is the only place a field
is defined.

Column naming: dots become underscores (``gen_ai.usage.input_tokens`` ->
``gen_ai_usage_input_tokens``). Content fields are shipped to SIEMs as compact
JSON text so that substring rules behave identically in Splunk, Sentinel and the
offline evaluator. String arrays stay arrays; Splunk's JSON extraction names
their values ``<column>{}``.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from prompthound.schema import load_schema

DataClass = Literal["metadata", "derived", "content"]
Origin = Literal["otel", "prompthound"]

#: Default Microsoft Sentinel / Log Analytics table for the audit events.
DEFAULT_SENTINEL_TABLE = "PromptHoundAuditLog_CL"

#: Default Splunk search macro that scopes every query to the audit data.
DEFAULT_SPLUNK_MACRO = "prompthound_audit"

_SCALAR_TYPES = frozenset({"string", "integer", "number", "boolean"})
_SENTINEL_SCALAR = {"string": "string", "integer": "long", "number": "real", "boolean": "bool"}


@dataclass(frozen=True)
class Field:
    """One audit-event field and its representation in each SIEM."""

    name: str
    types: tuple[str, ...]
    item_type: str | None
    origin: Origin
    data_class: DataClass
    description: str

    @property
    def column(self) -> str:
        """Column name in the normalized SIEM copy."""
        return column_name(self.name)

    @property
    def is_string_array(self) -> bool:
        return self.types == ("array",) and self.item_type == "string"

    @property
    def is_scalar(self) -> bool:
        return bool(self.types) and set(self.types) <= _SCALAR_TYPES

    @property
    def is_content(self) -> bool:
        return self.data_class == "content"

    @property
    def is_timestamp(self) -> bool:
        return self.name == "timestamp"

    @property
    def splunk_name(self) -> str:
        """Field name produced by Splunk's JSON extraction of the normalized event."""
        return f"{self.column}{{}}" if self.is_string_array else self.column

    @property
    def sentinel_type(self) -> str:
        """Column type in the Sentinel / Azure Data Explorer table."""
        if self.is_timestamp:
            return "datetime"
        if self.is_content:
            return "string"
        if self.is_string_array:
            return "dynamic"
        if self.is_scalar and len(self.types) == 1:
            return _SENTINEL_SCALAR[self.types[0]]
        return "dynamic"


def column_name(field: str) -> str:
    """SIEM column name for a dotted field name."""
    return field.replace(".", "_")


def canonical_json(value: Any) -> str:
    """Compact JSON text: the form content fields take in the SIEM copy."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def content_text(value: Any) -> str:
    """Text that content rules match against: strings as-is, anything else as JSON."""
    return value if isinstance(value, str) else canonical_json(value)


@functools.cache
def registry() -> Mapping[str, Field]:
    """All schema fields by dotted name, in schema order."""
    fields: dict[str, Field] = {}
    for name, spec in load_schema()["properties"].items():
        declared = spec.get("type", ())
        types = (declared,) if isinstance(declared, str) else tuple(declared)
        items = spec.get("items", {})
        fields[name] = Field(
            name=name,
            types=types,
            item_type=items.get("type") if isinstance(items, dict) else None,
            origin=spec["x-origin"],
            data_class=spec["x-class"],
            description=spec.get("description", ""),
        )
    return MappingProxyType(fields)


def get(name: str) -> Field:
    """Look up a schema field; raise ``KeyError`` with a helpful message if unknown."""
    try:
        return registry()[name]
    except KeyError:
        raise KeyError(f"{name!r} is not a field of the audit-event schema") from None


__all__ = [
    "DEFAULT_SENTINEL_TABLE",
    "DEFAULT_SPLUNK_MACRO",
    "DataClass",
    "Field",
    "Origin",
    "canonical_json",
    "column_name",
    "content_text",
    "get",
    "registry",
]
