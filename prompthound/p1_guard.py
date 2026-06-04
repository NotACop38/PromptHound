"""P1 enforcement -- scan content fields for disallowed working-exploit patterns.

PRD §8 P1 ("Signatures, not payloads") is a non-negotiable invariant: positive
samples encode attack *signatures as they appear in logs* -- representative
marker phrases, derived/Tier-1 features -- **not** a curated set of working
jailbreak/injection exploits an attacker could lift and run.

This module makes P1 enforceable *in code* rather than only in review. It scans
the content-bearing fields of an audit-log event (PRD §10.5/§10.7 -- the only
fields that carry free text) for patterns that signify an *operational* exploit
as opposed to a recognizable intent marker:

  * encoded payloads (long base64 blobs, hex-escape runs);
  * shell/code execution and reverse shells (``rm -rf /``, ``| bash``,
    ``os.system(`` , ``nc -e``);
  * SQL-injection mechanics (``UNION SELECT``, ``DROP TABLE``, ``' OR '1'='1``);
  * real-looking secrets/credentials (private-key headers, ``AKIA...`` /
    ``sk-...`` keys).

Crucially it does **not** flag marker phrases such as "ignore previous
instructions" or "print your system prompt" -- those *are* the log signature and
are P1-compliant. The generator runs this guard over its own output (see
``prompthound.generator.build_samples(enforce_p1=True)``) and the test-suite
runs it over both generated and on-disk samples, so a payload that slips into a
content field fails the build and CI rather than silently shipping.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any, NamedTuple

#: Content-bearing fields (PRD §10.5 [T2] args/results, §10.7 [T2] messages).
#: Only these carry free text; metadata/derived fields are out of scope so that
#: e.g. ``output.sink: "sql_exec"`` (a legitimate enum) is never mistaken for a
#: payload.
CONTENT_FIELDS: tuple[str, ...] = (
    "gen_ai.system_instructions",
    "gen_ai.input.messages",
    "gen_ai.output.messages",
    "tool.call.arguments",
    "tool.call.result",
)


class Violation(NamedTuple):
    """One disallowed-pattern hit located within a content field."""

    field: str
    pattern: str
    excerpt: str


# (name, compiled regex). Each pattern signifies a *working exploit*, not a
# generalizable intent marker. Kept deliberately conservative: the goal is to
# catch payloads an attacker could copy-paste-and-run, without flagging the
# marker phrases that are the whole point of a positive sample.
_DISALLOWED: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Encoded payloads.
    ("base64-blob", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")),
    ("hex-escape-run", re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")),
    # Shell / code execution and reverse shells.
    ("rm-rf-root", re.compile(r"\brm\s+-rf\s+/", re.IGNORECASE)),
    ("pipe-to-shell", re.compile(r"\|\s*(?:ba)?sh\b", re.IGNORECASE)),
    (
        "reverse-shell",
        re.compile(
            r"(?:/bin/(?:ba)?sh\s+-i|bash\s+-i\s*>&|\bnc(?:at)?\b[^\n]*\s-e\b)", re.IGNORECASE
        ),
    ),
    ("python-exec", re.compile(r"\b(?:os\.system|subprocess\.\w+|__import__)\s*\(", re.IGNORECASE)),
    ("eval-exec-call", re.compile(r"\b(?:eval|exec)\s*\(\s*['\"]", re.IGNORECASE)),
    # SQL-injection mechanics.
    ("sql-drop", re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE)),
    ("sql-union-select", re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE)),
    ("sql-tautology", re.compile(r"['\"]?\s*OR\s+['\"]?1['\"]?\s*=\s*['\"]?1", re.IGNORECASE)),
    # Real-looking secrets / credentials.
    ("private-key-header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("api-secret-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
)


def _iter_strings(value: Any) -> Iterator[str]:
    """Yield every string nested anywhere within ``value`` (lists/dicts/scalars)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def scan_text(text: str) -> list[str]:
    """Return the names of every disallowed pattern matching ``text`` ([] == clean)."""
    return [name for name, pattern in _DISALLOWED if pattern.search(text)]


def scan_event(event: dict[str, Any]) -> list[Violation]:
    """Scan an event's content fields; return a list of violations ([] == clean)."""
    violations: list[Violation] = []
    for field in CONTENT_FIELDS:
        if field not in event:
            continue
        for text in _iter_strings(event[field]):
            for name in scan_text(text):
                excerpt = text if len(text) <= 120 else text[:117] + "..."
                violations.append(Violation(field=field, pattern=name, excerpt=excerpt))
    return violations


def scan_events(events: list[dict[str, Any]]) -> list[Violation]:
    """Scan many events; return the flattened list of violations across all of them."""
    found: list[Violation] = []
    for event in events:
        found.extend(scan_event(event))
    return found
