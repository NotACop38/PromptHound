"""Tests for the Tier-1 DoS / cost-abuse rules (PRD §11 #7, LLM10).

Step 7 expands ``dos_cost_abuse`` beyond the token/cost-spike slice (covered in
``test_token_cost_spike.py``) with three more operational, content-free signals:

  * ``oversized_max_tokens`` -- a single selection rule on the request budget;
  * ``request_rate_burst_per_principal`` -- a per-principal request-frequency
    correlation;
  * ``repeated_length_finish_loops`` -- a per-conversation correlation on
    repeated ``length`` truncations.

Selection rules reuse the offline matcher directly (``prompthound.matcher``);
correlations reuse the shared windowed evaluator (``prompthound.correlate``).
Conversion is checked through the real toolchain.

Run just these with ``pytest -k dos -q``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompthound.convert import convert_rule
from prompthound.correlate import correlation_hits as _correlation_hits
from prompthound.correlate import load_correlation_file as _base_and_correlation
from prompthound.matcher import load_rule, rule_matches

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "dos_cost_abuse"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"


def _samples(stem: str, group: str) -> list[dict] | dict:
    return json.loads((SAMPLES_DIR / f"{stem}.{group}.json").read_text())


# --- oversized_max_tokens (single selection rule) -----------------------------

OVERSIZED = "oversized_max_tokens"


def test_oversized_max_tokens_fires_on_positive() -> None:
    rule = load_rule(RULES_DIR / f"{OVERSIZED}.yml")
    assert rule_matches(rule, _samples(OVERSIZED, "positive"))


def test_oversized_max_tokens_silent_on_negative() -> None:
    rule = load_rule(RULES_DIR / f"{OVERSIZED}.yml")
    assert not rule_matches(rule, _samples(OVERSIZED, "negative"))


def test_oversized_max_tokens_metadata() -> None:
    rule = load_rule(RULES_DIR / f"{OVERSIZED}.yml")
    tags = {str(t) for t in rule.tags}
    assert "owasp-llm.llm10" in tags
    assert {"attack.atlas.aml.t0029", "attack.atlas.aml.t0034"} <= tags
    assert "prompthound.tier.t1" in tags
    assert rule.references and rule.falsepositives
    assert rule.logsource.product == "llm_gateway"


def test_oversized_max_tokens_converts() -> None:
    result = convert_rule(RULES_DIR / f"{OVERSIZED}.yml")
    assert not result.is_correlation
    assert result.spl and all(q.strip() for q in result.spl)
    assert "gen_ai_request_max_tokens>=100000" in result.spl[0]
    assert result.kql and all(q.strip() for q in result.kql)
    assert result.savedsearches.strip()


# --- request_rate_burst_per_principal (correlation) ---------------------------

RATE = "request_rate_burst_per_principal"


def test_request_rate_burst_fires_on_burst() -> None:
    hits = _correlation_hits(RULES_DIR / f"{RATE}.yml", _samples(RATE, "positive"))
    assert hits == [
        (
            (
                "tenant-demo",
                "u-rate-7001",
            ),
            20,
        )
    ]


def test_request_rate_burst_silent_on_normal_rate() -> None:
    hits = _correlation_hits(RULES_DIR / f"{RATE}.yml", _samples(RATE, "negative"))
    assert hits == [], f"normal request rate should stay silent, got {hits}"


def test_request_rate_burst_metadata() -> None:
    _base, correlation = _base_and_correlation(RULES_DIR / f"{RATE}.yml")
    tags = {str(t) for t in correlation.tags}
    assert "owasp-llm.llm10" in tags
    assert {"attack.atlas.aml.t0029", "attack.atlas.aml.t0034"} <= tags
    assert "prompthound.tier.t1" in tags


def test_request_rate_burst_converts() -> None:
    result = convert_rule(RULES_DIR / f"{RATE}.yml")
    assert result.is_correlation
    spl = "\n".join(result.spl)
    assert "bin _time span=1m" in spl
    assert "by _time user_tenant_id user_id" in spl
    assert "event_count >= 20" in spl
    kql = "\n".join(result.kql)
    assert kql.strip() and "PromptHoundAuditLog_CL" in kql
    assert "\n| summarize" in kql  # executable KQL correlation


# --- repeated_length_finish_loops (correlation) -------------------------------

LOOPS = "repeated_length_finish_loops"


def test_repeated_length_loops_fires_on_loop() -> None:
    hits = _correlation_hits(RULES_DIR / f"{LOOPS}.yml", _samples(LOOPS, "positive"))
    assert hits == [
        (
            (
                "tenant-demo",
                "conv-loop-3001",
            ),
            6,
        )
    ]


def test_repeated_length_loops_silent_under_threshold() -> None:
    hits = _correlation_hits(RULES_DIR / f"{LOOPS}.yml", _samples(LOOPS, "negative"))
    assert hits == [], f"a short run of truncations should stay silent, got {hits}"


def test_repeated_length_loops_base_keys_on_length_only() -> None:
    # The base detection must require the `length` finish reason, not just any
    # completion -- a normal `stop` turn is not a loop building block.
    base, _correlation = _base_and_correlation(RULES_DIR / f"{LOOPS}.yml")
    truncated = _samples(LOOPS, "positive")[0]
    normal = dict(truncated)
    normal["gen_ai.response.finish_reasons"] = ["stop"]
    assert rule_matches(base, truncated)
    assert not rule_matches(base, normal)


def test_repeated_length_loops_metadata() -> None:
    _base, correlation = _base_and_correlation(RULES_DIR / f"{LOOPS}.yml")
    tags = {str(t) for t in correlation.tags}
    assert "owasp-llm.llm10" in tags
    assert {"attack.atlas.aml.t0034", "attack.atlas.aml.t0029"} <= tags
    assert "prompthound.tier.t1" in tags


def test_repeated_length_loops_converts() -> None:
    result = convert_rule(RULES_DIR / f"{LOOPS}.yml")
    assert result.is_correlation
    spl = "\n".join(result.spl)
    assert 'gen_ai_response_finish_reasons="length"' in spl
    assert "bin _time span=5m" in spl
    assert "by _time user_tenant_id gen_ai_conversation_id" in spl
    assert "event_count >= 5" in spl


# --- shared invariants across the new dos rules -------------------------------

NEW_DOS_RULES = [OVERSIZED, RATE, LOOPS]


@pytest.mark.parametrize("stem", NEW_DOS_RULES)
def test_dos_samples_have_positive_and_negative(stem: str) -> None:
    for group in ("positive", "negative"):
        payload = _samples(stem, group)
        events = payload if isinstance(payload, list) else [payload]
        assert events, f"{stem}.{group} is empty"


@pytest.mark.parametrize("stem", NEW_DOS_RULES)
def test_dos_rules_are_tier1_only(stem: str) -> None:
    # Operational, content-free: the rule must not key on any Tier-2 content field.
    text = (RULES_DIR / f"{stem}.yml").read_text()
    for content_field in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.system_instructions",
        "tool.call.arguments",
        "tool.call.result",
    ):
        assert f"{content_field}|" not in text and f"{content_field}:" not in text
