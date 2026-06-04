"""Tests for the jailbreak correlation rule (PRD §11 #4, LLM01 ×LLM06).

``persona_safety_bypass_loop`` is a Sigma *correlation* rule (ATLAS AML.T0054 LLM
Jailbreak): its base detection keys on persona / safety-bypass marker phrases in
the input AND a ``content_filter`` finish reason (the attempt was blocked), and
the correlation fires when such filtered attempts repeat within one conversation
over a short window -- the signature of an adversary iterating on a jailbreak.

The offline matcher evaluates the *base* detection per event; the windowed
per-conversation count the single-event matcher can't express is applied here
(the same approach as ``test_dos_cost_abuse.py``). Conversion is checked through
the real toolchain.

Run just these with ``pytest -k jailbreak -q``.
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
RULE_PATH = REPO_ROOT / "rules" / "jailbreak" / "persona_safety_bypass_loop.yml"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"
STEM = "persona_safety_bypass_loop"


def _samples(group: str) -> list[dict]:
    return json.loads((SAMPLES_DIR / f"{STEM}.{group}.json").read_text())


def _base_and_correlation():
    collection = SigmaCollection.load_ruleset([str(RULE_PATH)])
    base = next(r for r in collection.rules if not isinstance(r, SigmaCorrelationRule))
    correlation = next(r for r in collection.rules if isinstance(r, SigmaCorrelationRule))
    return base, correlation


def _correlation_hits(events: list[dict]) -> list[tuple]:
    """``(group_key, count)`` for each group/window crossing the threshold."""
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
        for start in times:
            count = sum(1 for t in times if start <= t < start + span)
            if count >= threshold:
                hits.append((key, count))
                break
    return hits


# --- fire / silence -----------------------------------------------------------


def test_jailbreak_fires_on_repeated_filtered_attempts() -> None:
    hits = _correlation_hits(_samples("positive"))
    assert hits == [(("conv-jb-5001",), 4)]


def test_jailbreak_silent_under_threshold() -> None:
    # Two filtered attempts + one benign turn -> below the >=3 threshold.
    hits = _correlation_hits(_samples("negative"))
    assert hits == [], f"a short run of jailbreak attempts should stay silent, got {hits}"


# --- base detection: persona marker AND a content_filter block ----------------


def test_jailbreak_base_requires_marker_and_filter() -> None:
    base, _ = _base_and_correlation()
    attempt = _samples("positive")[0]
    assert rule_matches(base, attempt)

    # Same persona marker, but the turn was NOT filtered -> not a loop building block.
    not_filtered = dict(attempt)
    not_filtered["gen_ai.response.finish_reasons"] = ["stop"]
    assert not rule_matches(base, not_filtered)

    # Filtered, but no persona/bypass marker -> a normal blocked turn, not a jailbreak.
    no_marker = dict(attempt)
    no_marker["gen_ai.input.messages"] = [
        {"role": "user", "parts": ["What are your business hours?"]}
    ]
    assert not rule_matches(base, no_marker)


# --- metadata (PRD §15) -------------------------------------------------------


def test_jailbreak_metadata() -> None:
    _base, correlation = _base_and_correlation()
    tags = {str(t) for t in correlation.tags}
    assert "owasp-llm.llm01" in tags
    assert "owasp-llm.llm06" in tags  # LLM01 ×LLM06 (PRD §11 #4)
    assert "attack.atlas.aml.t0054" in tags
    assert "prompthound.tier.t2" in tags
    assert correlation.references and correlation.falsepositives


# --- conversion (PRD §16) -----------------------------------------------------


def test_jailbreak_converts() -> None:
    result = convert_rule(RULE_PATH)
    assert result.is_correlation
    spl = "\n".join(result.spl)
    assert 'gen_ai_response_finish_reasons="content_filter"' in spl
    assert "bin _time span=10m" in spl
    assert "by _time gen_ai_conversation_id" in spl
    assert "event_count >= 3" in spl
    kql = "\n".join(result.kql)
    assert kql.strip() and "PromptHoundAuditLog_CL" in kql
    assert "// | summarize" in kql  # documented Kusto correlation workaround


def test_jailbreak_samples_have_positive_and_negative() -> None:
    for group in ("positive", "negative"):
        assert _samples(group), f"{STEM}.{group} is empty"
