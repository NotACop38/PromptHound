"""Keep working exploit payloads out of rules, scenarios and synthetic data.

PromptHound's test data encodes attack *signatures* as they appear in logs —
recognizable intent phrases and derived features — never operational payloads
that could be copied and run. This guard scans content fields (``x-class:
content`` in the schema) for patterns that indicate an operational exploit:
encoded blobs, shell and code execution, SQL-injection mechanics and
real-looking credentials. Intent phrases such as "ignore previous
instructions" are deliberately not flagged: they are the signature.

The scenario loader and the dataset generator refuse content that trips the
guard, and the test suite scans every rule file.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any, NamedTuple

from prompthound import fields


class Finding(NamedTuple):
    field: str
    pattern: str
    excerpt: str


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("encoded-blob", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")),
    ("hex-escape-run", re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")),
    ("recursive-delete", re.compile(r"\brm\s+-rf\s+/", re.IGNORECASE)),
    ("pipe-to-shell", re.compile(r"\|\s*(?:ba|z)?sh\b", re.IGNORECASE)),
    (
        "reverse-shell",
        re.compile(r"/bin/(?:ba)?sh\s+-i|bash\s+-i\s*>&|\bnc(?:at)?\b[^\n]*\s-e\b", re.IGNORECASE),
    ),
    ("python-exec", re.compile(r"\b(?:os\.system|subprocess\.\w+|__import__)\s*\(", re.IGNORECASE)),
    ("eval-call", re.compile(r"\b(?:eval|exec)\s*\(\s*['\"]", re.IGNORECASE)),
    ("sql-drop", re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE)),
    ("sql-union-select", re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE)),
    ("sql-tautology", re.compile(r"['\"]?\s*OR\s+['\"]?1['\"]?\s*=\s*['\"]?1", re.IGNORECASE)),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("api-secret-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
)


def scan_text(text: str) -> list[str]:
    """Names of the payload patterns found in ``text`` (empty when clean)."""
    return [name for name, pattern in _PATTERNS if pattern.search(text)]


def scan_event(event: Mapping[str, Any]) -> list[Finding]:
    """Payload findings in an event's content fields."""
    findings: list[Finding] = []
    for name, field in fields.registry().items():
        if not field.is_content or name not in event:
            continue
        for text in _strings(event[name]):
            excerpt = text if len(text) <= 120 else text[:117] + "..."
            findings.extend(Finding(name, pattern, excerpt) for pattern in scan_text(text))
    return findings


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


__all__ = ["Finding", "scan_event", "scan_text"]
