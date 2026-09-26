"""Read audit events from JSON Lines files."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from prompthound.normalize import parse_json_line
from prompthound.schema import validate_event


@dataclass(frozen=True)
class InvalidEvent:
    line: int
    problems: tuple[str, ...]


@dataclass
class EventFile:
    """Valid events plus a record of every line that was rejected."""

    events: list[dict[str, Any]] = field(default_factory=list)
    invalid: list[InvalidEvent] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.events) + len(self.invalid)


def _lines(path: Path | str) -> Iterator[tuple[int, str]]:
    if str(path) == "-":
        yield from enumerate(_stdin(), start=1)
        return
    with Path(path).open(encoding="utf-8") as handle:
        yield from enumerate(handle, start=1)


def _stdin() -> TextIO:
    return sys.stdin


def read_events(path: Path | str) -> EventFile:
    """Parse and validate a JSON Lines file (``-`` reads standard input)."""
    result = EventFile()
    for number, line in _lines(path):
        if not line.strip():
            continue
        try:
            event = parse_json_line(line)
        except (json.JSONDecodeError, ValueError) as exc:
            result.invalid.append(InvalidEvent(number, (f"not valid JSON: {exc}",)))
            continue
        problems = validate_event(event)
        if problems:
            result.invalid.append(InvalidEvent(number, tuple(problems)))
        else:
            result.events.append(event)
    return result


__all__ = ["EventFile", "InvalidEvent", "read_events"]
