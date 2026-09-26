"""Audit-event schema loading and validation.

The schema (``data/audit_log.schema.json``) uses a small subset of JSON Schema
2020-12: ``type`` (including unions), ``const``, ``enum``, ``required``,
``properties``, ``items``, ``minimum``, ``minLength``, ``additionalProperties``
(boolean) and ``format: date-time``. Keys starting with ``x-`` are annotations.
The validator below implements exactly that subset and refuses any other
keyword, so a schema change that needs more fails loudly instead of being
silently ignored.
"""

from __future__ import annotations

import datetime as dt
import functools
import json
import math
import re
from importlib import resources
from typing import Any

#: Keywords the validator implements (plus ``x-*`` annotations).
_SUPPORTED_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "$comment",
        "title",
        "description",
        "default",
        "examples",
        "type",
        "const",
        "enum",
        "required",
        "properties",
        "items",
        "minimum",
        "minLength",
        "additionalProperties",
        "format",
    }
)

# ``bool`` is a subclass of ``int`` in Python but not a number in JSON Schema;
# ``_matches_type`` handles that case before consulting this table.
_TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "boolean": (bool,),
    "integer": (int,),
    "number": (int, float),
    "null": (type(None),),
}

_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))"
)


@functools.cache
def load_schema() -> dict[str, Any]:
    """Return the bundled audit-event schema. Callers must not mutate it."""
    text = resources.files("prompthound").joinpath("data/audit_log.schema.json").read_text("utf-8")
    schema: dict[str, Any] = json.loads(text)
    return schema


def schema_version() -> str:
    """The ``schema_version`` value every conforming event declares."""
    return str(load_schema()["properties"]["schema_version"]["const"])


def parse_timestamp(value: str) -> dt.datetime:
    """Parse an RFC 3339 timestamp that carries a UTC offset; return it in UTC."""
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise ValueError(f"not an RFC 3339 timestamp with a UTC offset: {value!r}")
    hours, minutes = match.groups()
    if hours is not None and (int(hours) > 23 or int(minutes) > 59):
        raise ValueError(f"invalid UTC offset in timestamp: {value!r}")
    parsed = dt.datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    return parsed.astimezone(dt.UTC)


def validate_event(event: Any, schema: dict[str, Any] | None = None) -> list[str]:
    """Return every schema violation in ``event`` (an empty list means valid)."""
    errors: list[str] = []
    _validate(event, schema if schema is not None else load_schema(), "", errors)
    return errors


def _matches_type(value: Any, type_name: str) -> bool:
    accepted = _TYPES.get(type_name)
    if accepted is None:
        raise NotImplementedError(f"unsupported JSON Schema type: {type_name}")
    if isinstance(value, bool) and type_name in ("integer", "number"):
        return False
    if type_name == "integer" and isinstance(value, float):
        return math.isfinite(value) and value.is_integer()
    return isinstance(value, accepted)


def _validate(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    unsupported = {k for k in schema if not k.startswith("x-")} - _SUPPORTED_KEYWORDS
    if unsupported or isinstance(schema.get("additionalProperties"), dict):
        raise NotImplementedError(f"schema keyword(s) outside the supported subset: {unsupported}")
    label = path or "<event>"

    if "type" in schema:
        types = [schema["type"]] if isinstance(schema["type"], str) else schema["type"]
        if not any(_matches_type(value, name) for name in types):
            errors.append(f"{label}: expected {' or '.join(types)}, got {type(value).__name__}")
            return
    if isinstance(value, float) and not math.isfinite(value):
        errors.append(f"{label}: NaN and infinity are not JSON numbers")
        return
    if "const" in schema and value != schema["const"]:
        errors.append(f"{label}: must be {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{label}: {value!r} is not one of {schema['enum']}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{label}: shorter than {schema['minLength']} character(s)")
        if schema.get("format") == "date-time":
            try:
                parse_timestamp(value)
            except ValueError:
                errors.append(f"{label}: not an RFC 3339 timestamp with a UTC offset")
    if (
        "minimum" in schema
        and isinstance(value, int | float)
        and not isinstance(value, bool)
        and value < schema["minimum"]
    ):
        errors.append(f"{label}: {value} is below the minimum of {schema['minimum']}")
    if isinstance(value, dict):
        properties: dict[str, Any] = schema.get("properties", {})
        errors.extend(
            f"{label}: missing required field {name!r}"
            for name in schema.get("required", [])
            if name not in value
        )
        if schema.get("additionalProperties", True) is False:
            errors.extend(
                f"{label}: unexpected field {name!r}" for name in value if name not in properties
            )
        for name, subschema in properties.items():
            if name in value:
                _validate(value[name], subschema, f"{path}.{name}" if path else name, errors)
    if isinstance(value, list) and schema.get("items"):
        for index, item in enumerate(value):
            _validate(item, schema["items"], f"{label}[{index}]", errors)


__all__ = ["load_schema", "parse_timestamp", "schema_version", "validate_event"]
