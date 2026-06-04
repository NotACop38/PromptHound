"""Tests for the token/cost-spike-per-principal correlation rule (CHECKLIST 1b).

PromptHound's second vertical slice: the first Sigma *correlation* rule, used to
exercise windowed aggregation once before the rule pack scales (PRD §11 #7).

The single-event matcher (`prompthound/matcher.py`) can't express a windowed
aggregation, so fire/silence here reuses `rule_matches` to filter the rule's
*base* detection per event, then groups by the correlation's `group-by` field
over its `timespan` and applies the threshold. Conversion is checked through the
real toolchain (`prompthound/convert.py`): the full `event_count` correlation
converts to SPL; KQL covers the base detection plus the documented `summarize`
workaround (the Kusto backend emits no correlations — see docs/authoring.md).

Run just these with ``pytest -k token_cost -q``.
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
RULE_PATH = REPO_ROOT / "rules" / "dos_cost_abuse" / "token_cost_spike_per_principal.yml"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"
STEM = "token_cost_spike_per_principal"


def _load() -> tuple[object, SigmaCorrelationRule]:
    """Return (base detection rule, correlation rule) from the rule file."""
    collection = SigmaCollection.load_ruleset([str(RULE_PATH)])
    base = next(r for r in collection.rules if not isinstance(r, SigmaCorrelationRule))
    correlation = next(r for r in collection.rules if isinstance(r, SigmaCorrelationRule))
    return base, correlation


def _samples(group: str) -> list[dict]:
    return json.loads((SAMPLES_DIR / f"{STEM}.{group}.json").read_text())


def _correlation_hits(events: list[dict]) -> list[tuple]:
    """Return ``(group_key, count)`` for each group/window crossing the threshold.

    Reuses the offline matcher for the base detection, then does the windowed
    per-principal counting the matcher can't express.
    """
    base, correlation = _load()
    assert str(correlation.type) == "event_count", "evaluator only supports event_count"
    group_by = correlation.group_by
    span = dt.timedelta(seconds=correlation.timespan.seconds)
    threshold = correlation.condition.count
    op = correlation.condition.op.name
    passes = {
        "GTE": lambda c: c >= threshold,
        "GT": lambda c: c > threshold,
        "LTE": lambda c: c <= threshold,
        "LT": lambda c: c < threshold,
    }[op]

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
            if passes(sum(1 for t in times if start <= t < start + span)):
                hits.append((key, sum(1 for t in times if start <= t < start + span)))
                break
    return hits


# --- fire / silence -----------------------------------------------------------


def test_token_cost_spike_fires_on_burst() -> None:
    hits = _correlation_hits(_samples("positive"))
    assert hits == [(("u-burst-9001",), 12)], (
        "correlation should fire on a single principal's high-token burst"
    )


def test_token_cost_spike_silent_on_normal_usage() -> None:
    hits = _correlation_hits(_samples("negative"))
    assert hits == [], f"correlation should stay silent on normal usage, got {hits}"


# --- samples ------------------------------------------------------------------


def test_token_cost_spike_samples_are_arrays() -> None:
    # A correlation positive is a burst, so samples are arrays of events; the
    # schema-validity of each event is asserted in test_schema.py.
    assert isinstance(_samples("positive"), list) and len(_samples("positive")) >= 10
    assert isinstance(_samples("negative"), list) and _samples("negative")


# --- metadata (PRD §15) -------------------------------------------------------


def test_token_cost_spike_has_required_metadata() -> None:
    _base, correlation = _load()
    tags = {str(t) for t in correlation.tags}
    assert "owasp-llm.llm10" in tags
    assert {"attack.atlas.aml.t0034", "attack.atlas.aml.t0029"} <= tags
    assert "prompthound.tier.t1" in tags


# --- conversion (PRD §16) -----------------------------------------------------

EXPECTED_SPL = """event_action IN ("chat", "text_completion") gen_ai_usage_total_tokens>=8000

| bin _time span=5m
| stats count as event_count by _time user_id

| search event_count >= 10"""


def test_token_cost_spike_converts_to_spl() -> None:
    result = convert_rule(RULE_PATH)
    assert result.is_correlation
    assert len(result.spl) == 1
    assert result.spl[0].strip() == EXPECTED_SPL


def test_token_cost_spike_kql_is_base_plus_workaround() -> None:
    # Kusto can't emit correlations: KQL is the base detection + a documented
    # `// summarize` workaround comment (docs/authoring.md). It must be non-empty
    # so the out/ snapshot stays complete.
    result = convert_rule(RULE_PATH)
    kql = "\n".join(result.kql)
    assert kql.strip(), "KQL must be non-empty"
    assert "PromptHoundAuditLog_CL" in kql
    assert "gen_ai_usage_total_tokens >= 8000" in kql  # base detection
    assert "// | summarize event_count = count() by user_id, bin(timestamp, 5m)" in kql
    assert "// | where event_count >= 10" in kql
