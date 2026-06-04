"""Tests for the sensitive-data / PII exfiltration rule (PRD §11 #5, LLM02).

``pii_secret_exfiltration_in_output`` is a Sigma *correlation* rule: the base
detection flags a single response carrying PII or secret/credential classes in
its output (derived markers, PRD §10.8); the correlation fires when one
principal receives an abnormal *volume* of such responses in a window — bulk
exfiltration through the model's outputs.

The single-event matcher can't express a windowed aggregation, so fire/silence
reuses ``rule_matches`` for the base detection, then groups by the correlation's
``group-by`` over its ``timespan`` and applies the threshold (the same approach
as ``test_dos_cost_abuse.py``). Conversion is checked through the real
toolchain: the full ``event_count`` correlation converts to SPL; KQL covers the
base detection plus the documented ``// summarize`` workaround.

Run just these with ``pytest -k exfil -q``.
"""

from __future__ import annotations

import datetime as dt
import json
from collections import defaultdict
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from prompthound.convert import convert_rule
from prompthound.matcher import rule_matches

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_PATH = REPO_ROOT / "rules" / "data_exfiltration" / "pii_secret_exfiltration_in_output.yml"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"
STEM = "pii_secret_exfiltration_in_output"


def _base_and_correlation():
    collection = SigmaCollection.load_ruleset([str(RULE_PATH)])
    base = next(r for r in collection.rules if not isinstance(r, SigmaCorrelationRule))
    correlation = next(r for r in collection.rules if isinstance(r, SigmaCorrelationRule))
    return base, correlation


def _samples(group: str) -> list[dict]:
    return json.loads((SAMPLES_DIR / f"{STEM}.{group}.json").read_text())


def _correlation_hits(events: list[dict]) -> list[tuple]:
    base, correlation = _base_and_correlation()
    assert str(correlation.type) == "event_count", "evaluator only supports event_count"
    group_by = correlation.group_by
    span = dt.timedelta(seconds=correlation.timespan.seconds)
    threshold = correlation.condition.count

    groups: dict[tuple, list[dt.datetime]] = defaultdict(list)
    for event in events:
        if not rule_matches(base, event):
            continue
        key = tuple(event.get(g) for g in group_by)
        ts = dt.datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        groups[key].append(ts)

    hits = []
    for key, times in groups.items():
        times.sort()
        for start in times:  # window anchored at each matched event
            count = sum(1 for t in times if start <= t < start + span)
            if count >= threshold:
                hits.append((key, count))
                break
    return hits


def test_exfil_fires_on_volume_burst() -> None:
    hits = _correlation_hits(_samples("positive"))
    assert hits == [(("u-exfil-9001",), 6)]


def test_exfil_silent_under_threshold() -> None:
    hits = _correlation_hits(_samples("negative"))
    assert hits == [], f"a few PII responses should stay silent, got {hits}"


def test_exfil_base_keys_on_pii_or_secret_in_output() -> None:
    # The base building block must require a PII/secret class IN THE OUTPUT;
    # a completion with no sensitive output is not a building block.
    base, _ = _base_and_correlation()
    sensitive = _samples("positive")[0]
    assert rule_matches(base, sensitive)

    clean = dict(sensitive)
    clean.pop("content.output.pii.types", None)
    clean.pop("content.output.secret.types", None)
    assert not rule_matches(base, clean)


def test_exfil_base_fires_on_secret_class() -> None:
    # The OR arm: a secret/credential class (no PII) is still a building block.
    base, _ = _base_and_correlation()
    event = {
        "schema_version": "0.1",
        "timestamp": "2026-06-04T16:21:00Z",
        "event.id": "exfil-unit-secret",
        "event.action": "chat",
        "event.outcome": "success",
        "user.id": "u-exfil-9001",
        "content.output.secret.types": ["aws_access_key"],
    }
    assert rule_matches(base, event)


def test_exfil_metadata() -> None:
    _base, correlation = _base_and_correlation()
    tags = {str(t) for t in correlation.tags}
    assert "owasp-llm.llm02" in tags
    assert "attack.atlas.aml.t0024" in tags
    assert "attack.atlas.aml.t0025" in tags  # cross-ref (PRD §11 #5)
    assert {"prompthound.tier.t1", "prompthound.tier.t2"} <= tags
    assert correlation.references and correlation.falsepositives


def test_exfil_is_per_principal_volume() -> None:
    _base, correlation = _base_and_correlation()
    assert correlation.group_by == ["user.id"]
    assert correlation.condition.count == 5
    assert correlation.timespan.seconds == 600


def test_exfil_converts() -> None:
    result = convert_rule(RULE_PATH)
    assert result.is_correlation
    spl = "\n".join(result.spl)
    assert "bin _time span=10m" in spl
    assert "by _time user_id" in spl
    assert "event_count >= 5" in spl
    kql = "\n".join(result.kql)
    assert kql.strip() and "PromptHoundAuditLog_CL" in kql
    assert "// | summarize" in kql  # documented Kusto correlation workaround
