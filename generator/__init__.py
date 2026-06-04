"""PromptHound synthetic telemetry generator (PRD §7, §12; principles P1-P2).

Placeholder package. The generator emits, per rule, a positive (should-alert)
and a negative (should-not-alert) sample event conforming to the audit-log
schema in PRD §10.

Defensive invariants (PRD §8):
  * P1 -- positive samples encode log *signatures* (marker phrases, PII/exfil
    patterns, token/cost/rate behaviours), never working exploits.
  * P2 -- the generator only writes files; it never sends traffic to a live
    model endpoint.
"""

from __future__ import annotations

__all__: list[str] = []
