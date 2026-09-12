"""Tests for the token/cost-spike-per-principal correlation rule (CHECKLIST 1b).

PromptHound's second vertical slice: the first Sigma *correlation* rule, used to
exercise windowed aggregation once before the rule pack scales (PRD §11 #7).

Fire/silence reuses the shared windowed correlation evaluator
(``prompthound.correlate``), which filters the rule's *base* detection per
event with the offline matcher, then applies the correlation's group-by /
timespan / threshold. Conversion is checked through the real toolchain
(`prompthound/convert.py`): the full `event_count` correlation converts to SPL;
KQL covers the base detection plus the documented `summarize` workaround (the
Kusto backend emits no correlations — see docs/authoring.md).

Run just these with ``pytest -k token_cost -q``.
"""

from __future__ import annotations

import json
from pathlib import Path

from sigma.correlations import SigmaCorrelationRule

from prompthound.convert import convert_rule
from prompthound.correlate import correlation_hits, load_correlation_file

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_PATH = REPO_ROOT / "rules" / "dos_cost_abuse" / "token_cost_spike_per_principal.yml"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"
STEM = "token_cost_spike_per_principal"


def _load() -> tuple[object, SigmaCorrelationRule]:
    """Return (base detection rule, correlation rule) from the rule file."""
    return load_correlation_file(RULE_PATH)


def _samples(group: str) -> list[dict]:
    return json.loads((SAMPLES_DIR / f"{STEM}.{group}.json").read_text())


def _correlation_hits(events: list[dict]) -> list[tuple]:
    """Return ``(group_key, count)`` for each group/window crossing the threshold."""
    return list(correlation_hits(RULE_PATH, events))


# --- fire / silence -----------------------------------------------------------


def test_token_cost_spike_fires_on_burst() -> None:
    hits = _correlation_hits(_samples("positive"))
    assert hits == [
        (
            (
                "tenant-demo",
                "u-burst-9001",
            ),
            12,
        )
    ], "correlation should fire on a single principal's high-token burst"


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
| stats count as event_count by _time user_tenant_id user_id

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
    assert (
        "| summarize event_count = count() by user_tenant_id, user_id, bin(timestamp, 300s)" in kql
    )
    assert "| where event_count >= 10" in kql
