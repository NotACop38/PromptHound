"""Audit-log schema loading + a lean, dependency-free validator (PRD §10, D1).

Why a hand-rolled validator instead of ``jsonschema``? PRD §13 mandates lean
dependencies and the local CI runner (``scripts/ci.py``) is standard-library
only. Our schema (``schema/llm_audit_log.schema.json``) uses a small, fixed
subset of JSON Schema 2020-12 -- ``type`` (including unions), ``enum``,
``required``, ``properties``, ``items``, ``minimum`` and ``additionalProperties``
-- so a compact subset validator covers it exactly without pulling in a runtime
dependency. ``format`` (e.g. ``date-time``) is treated as a non-asserting
annotation, which matches default JSON Schema behaviour.

If the schema ever grows constructs beyond this subset (``$ref``, ``oneOf``,
``pattern``, ...), swap this for ``jsonschema`` rather than extending the
hand-rolled validator past its comfort zone.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

#: Canonical location of the machine-readable schema (PRD §14).
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "llm_audit_log.schema.json"

# JSON Schema type name -> accepted Python types. ``bool`` is handled specially
# below: Python treats ``bool`` as an ``int`` subclass, but JSON Schema does not
# consider ``true``/``false`` to be integers or numbers.
_TYPE_MAP: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "boolean": (bool,),
    "integer": (int,),
    "number": (int, float),
    "null": (type(None),),
}


def load_schema(path: Path | None = None) -> dict[str, Any]:
    """Load and parse the audit-log JSON Schema document.

    The schema lives at the canonical top-level ``schema/`` directory (PRD §14),
    which is **not** bundled into the wheel -- ``pyproject.toml`` ships only the
    importable library, leaving operational dirs out. So this resolves against a
    source checkout. Wheel-install support would mean packaging the schema as
    package data, part of the deployable-packaging fast-follow of decision D8
    (PRD §9; the v1 release bundle ships generated queries, not the wheel).
    Until then, a missing file raises an actionable error rather than a bare
    ``FileNotFoundError``.
    """
    schema_path = path or SCHEMA_PATH
    if not schema_path.is_file():
        raise FileNotFoundError(
            f"Audit-log schema not found at {schema_path}. "
            "prompthound.schema currently resolves the schema from a source "
            "checkout (the canonical schema/ dir is not packaged into the wheel; "
            "see PRD §14 and the D8 packaging fast-follow). Run from a source tree, "
            "or pass an explicit path=."
        )
    with open(schema_path, encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
    return data


def _matches_type(value: Any, type_name: str) -> bool:
    accepted = _TYPE_MAP.get(type_name)
    if accepted is None:
        return True  # unknown/unsupported type keyword: don't assert
    if isinstance(value, bool) and type_name in ("integer", "number"):
        return False
    return isinstance(value, accepted)


def _label(path: str) -> str:
    return path or "<root>"


def _validate(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    """Recursively check ``value`` against ``schema``, appending error strings."""
    if "type" in schema:
        types = schema["type"]
        type_list = [types] if isinstance(types, str) else types
        if not any(_matches_type(value, name) for name in type_list):
            errors.append(
                f"{_label(path)}: expected type {schema['type']}, got {type(value).__name__}"
            )
            return  # remaining keyword checks assume the declared type matched

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{_label(path)}: {value!r} not in enum {schema['enum']}")

    if "minimum" in schema and isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema["minimum"]:
            errors.append(f"{_label(path)}: {value} below minimum {schema['minimum']}")

    if isinstance(value, dict):
        properties: dict[str, Any] = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                errors.append(f"{_label(path)}: missing required property '{required}'")
        if schema.get("additionalProperties", True) is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{_label(path)}: additional property '{key}' not allowed")
        for key, subschema in properties.items():
            if key in value:
                child = f"{path}.{key}" if path else key
                _validate(value[key], subschema, child, errors)

    if isinstance(value, list) and "items" in schema:
        item_schema = schema["items"]
        if item_schema:  # an empty schema ({}) accepts anything
            for index, item in enumerate(value):
                _validate(item, item_schema, f"{path}[{index}]", errors)


def validate_event(event: Any, schema: dict[str, Any] | None = None) -> list[str]:
    """Validate one audit-log event dict; return a list of errors ([] == valid)."""
    errors: list[str] = []
    _validate(event, schema or load_schema(), "", errors)
    return errors


def is_valid(event: Any, schema: dict[str, Any] | None = None) -> bool:
    """Convenience boolean wrapper around :func:`validate_event`."""
    return not validate_event(event, schema)
