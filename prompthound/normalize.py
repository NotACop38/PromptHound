"""Validate and map dotted audit events to the shipped SIEM query columns.

This is a file adapter, not a log collector or a derived-feature detector.
Values and unknown extension fields are preserved; ambiguous names fail.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from prompthound.fieldmap import FIELD_MAP
from prompthound.schema import load_schema, validate_event


def normalize_event(event: dict[str, Any], schema: dict | None = None) -> dict[str, Any]:
    """Map an event without changing values or silently overwriting a column."""
    errors = validate_event(event, schema)
    if errors:
        raise ValueError("invalid audit event: " + "; ".join(errors))
    mapped: dict[str, Any] = {}
    reserved = set(FIELD_MAP.values())
    for field, value in event.items():
        if field in reserved or ("." in field and field not in FIELD_MAP):
            raise ValueError(f"unmapped or conflicting audit field: {field}")
        column = FIELD_MAP.get(field, field)
        if column in mapped:
            raise ValueError(f"duplicate SIEM column: {column}")
        mapped[column] = value
    return mapped


def normalize_file(source: Path, destination: Path) -> int:
    """Write a complete validated JSONL file atomically; preserve files on errors."""
    if source.resolve() == destination.resolve():
        raise ValueError("input and output must be different files")
    schema = load_schema()
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    temporary: Path | None = None
    try:
        with (
            source.open(encoding="utf-8") as reader,
            tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=destination.parent, delete=False
            ) as writer,
        ):
            temporary = Path(writer.name)
            for lineno, line in enumerate(reader, 1):
                try:
                    event = normalize_event(json.loads(line), schema)
                    writer.write(json.dumps(event, allow_nan=False, separators=(",", ":")) + "\n")
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"line {lineno}: invalid or ambiguous audit event") from exc
                count += 1
            if not count:
                raise ValueError("input contains no audit events")
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        count = normalize_file(args.input, args.out)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f"wrote {count} normalized events to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
