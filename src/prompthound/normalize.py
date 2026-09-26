"""Produce the SIEM copy of audit events.

Normalization validates each event against the schema and rewrites it into the
column layout the generated queries expect:

* dotted field names become underscore columns (``user.tenant.id`` ->
  ``user_tenant_id``); two fields that would share a column are an error;
* content fields become compact JSON text, so substring rules see the same text
  in Splunk, Sentinel and the offline evaluator;
* ``timestamp`` becomes UTC with microsecond precision
  (``2026-06-01T12:00:00.000000Z``), a single format both SIEMs parse exactly;
* every other value is kept as-is, including string arrays and extension fields.

Files are written atomically — a failure on any line leaves the destination
untouched — and readable only by their owner, because audit events can carry
prompts and responses.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompthound import fields
from prompthound.schema import parse_timestamp, validate_event


class NormalizationError(ValueError):
    """An event that cannot be normalized."""


def normalize_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Validate ``event`` and return its SIEM-copy form."""
    problems = validate_event(event)
    if problems:
        raise NormalizationError("invalid audit event: " + "; ".join(problems))
    registry = fields.registry()
    normalized: dict[str, Any] = {}
    sources: dict[str, str] = {}
    for name, value in event.items():
        column = fields.column_name(name)
        if column in sources:
            raise NormalizationError(
                f"fields {sources[column]!r} and {name!r} share column {column!r}"
            )
        sources[column] = name
        field = registry.get(name)
        if field is not None and field.is_content:
            value = fields.content_text(value)
        elif field is not None and field.is_timestamp:
            value = parse_timestamp(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        normalized[column] = value
    # Timestamp first: Splunk's TIME_PREFIX then matches at the start of the line.
    return {"timestamp": normalized.pop("timestamp"), **normalized}


def parse_json_line(line: str) -> Any:
    """Parse one JSON Lines record, rejecting duplicate object keys at any depth."""
    return json.loads(line, object_pairs_hook=_unique_keys)


def normalize_file(source: Path, destination: Path) -> int:
    """Normalize a JSON Lines file; return the number of events written."""
    if source.resolve() == destination.resolve():
        raise NormalizationError("input and output must be different files")
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    handle, temporary = tempfile.mkstemp(dir=destination.parent, suffix=".partial")
    try:
        with (
            os.fdopen(handle, "w", encoding="utf-8") as writer,
            source.open(encoding="utf-8") as reader,
        ):
            for number, line in enumerate(reader, start=1):
                if not line.strip():
                    continue
                try:
                    record = normalize_event(parse_json_line(line))
                except (ValueError, TypeError) as exc:
                    raise NormalizationError(f"line {number}: {exc}") from exc
                writer.write(fields.canonical_json(record) + "\n")
                count += 1
        if count == 0:
            raise NormalizationError(f"{source} contains no events")
        Path(temporary).replace(destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return count


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


__all__ = ["NormalizationError", "normalize_event", "normalize_file", "parse_json_line"]
