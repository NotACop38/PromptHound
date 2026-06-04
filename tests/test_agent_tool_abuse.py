"""Tests for the Tier-1 agent tool-abuse rules (PRD §11 #6, LLM06 / AML.TA0015).

Step 10 adds the agent tool-abuse family — the newest, most complex category
(ATLAS v5.1.0, Nov 2025, added tactic AML.TA0015 Command and Control plus the
AI Agent Tools technique AML.T0085.001):

  * ``anomalous_tool_call_chain`` -- a single-event selection rule firing when one
    agent turn's ``tool.call.chain`` combines a sensitive-source read with an
    external egress sink (the read-then-exfiltrate adjacency);
  * ``denied_tool_retry_loop`` -- a per-conversation correlation on repeated
    ``denied`` tool calls (probing past a guardrail);
  * ``tool_call_amplification_loop`` -- a per-conversation correlation on
    tool-call *volume* (resource amplification, ties to LLM10; CurXecute
    CVE-2025-54135 / CVE-2025-54136 anchor).

Selection rules reuse the offline matcher directly (``prompthound.matcher``).
Correlations reuse it for the *base* detection, then apply the windowed group-by
count the single-event matcher can't express (same approach as
``test_dos_cost_abuse.py``). Conversion is checked through the real toolchain.

D6 (OWASP Agentic Top 10 secondary tag) is still ``[OPEN]`` in CHECKLIST, so no
``owasp-agentic`` tag is claimed here.

Run just these with ``pytest -k agent -q``.
"""

from __future__ import annotations

import datetime as dt
import json
from collections import defaultdict
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from prompthound.convert import convert_rule
from prompthound.matcher import load_rule, rule_matches

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "agent_tool_abuse"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"


def _samples(stem: str, group: str) -> list[dict] | dict:
    return json.loads((SAMPLES_DIR / f"{stem}.{group}.json").read_text())


def _base_and_correlation(path: Path):
    collection = SigmaCollection.load_ruleset([str(path)])
    base = next(r for r in collection.rules if not isinstance(r, SigmaCorrelationRule))
    correlation = next(r for r in collection.rules if isinstance(r, SigmaCorrelationRule))
    return base, correlation


def _correlation_hits(path: Path, events: list[dict]) -> list[tuple]:
    """``(group_key, count)`` for each group/window crossing the threshold."""
    base, correlation = _base_and_correlation(path)
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


# --- anomalous_tool_call_chain (single selection rule) ------------------------

CHAIN = "anomalous_tool_call_chain"


def test_chain_fires_on_read_then_exfil() -> None:
    rule = load_rule(RULES_DIR / f"{CHAIN}.yml")
    assert rule_matches(rule, _samples(CHAIN, "positive"))


def test_chain_silent_without_egress() -> None:
    # A sensitive read with no external-egress tool in the chain must not fire.
    rule = load_rule(RULES_DIR / f"{CHAIN}.yml")
    assert not rule_matches(rule, _samples(CHAIN, "negative"))


def test_chain_needs_both_a_source_and_a_sink() -> None:
    rule = load_rule(RULES_DIR / f"{CHAIN}.yml")
    positive = _samples(CHAIN, "positive")

    # Egress alone (no sensitive read) -> not the read-then-exfil adjacency.
    egress_only = dict(positive)
    egress_only["tool.call.chain"] = ["http.post"]
    assert not rule_matches(rule, egress_only)

    # Sensitive read alone -> not yet an exfil chain.
    read_only = dict(positive)
    read_only["tool.call.chain"] = ["secrets.get"]
    assert not rule_matches(rule, read_only)

    # Both present -> fires.
    both = dict(positive)
    both["tool.call.chain"] = ["secrets.get", "http.post"]
    assert rule_matches(rule, both)


def test_chain_metadata() -> None:
    rule = load_rule(RULES_DIR / f"{CHAIN}.yml")
    tags = {str(t) for t in rule.tags}
    assert "owasp-llm.llm06" in tags
    assert "attack.atlas.aml.ta0015" in tags  # ATLAS v5.1.0 Command and Control
    assert "attack.atlas.aml.t0085.001" in tags  # AI Agent Tools
    assert "prompthound.tier.t1" in tags
    assert rule.references and rule.falsepositives
    assert rule.logsource.product == "llm_gateway"


def test_chain_converts() -> None:
    result = convert_rule(RULES_DIR / f"{CHAIN}.yml")
    assert not result.is_correlation
    spl = "\n".join(result.spl)
    assert "tool_call_chain" in spl
    assert "event_action IN (" in spl
    kql = "\n".join(result.kql)
    assert kql.strip() and "PromptHoundAuditLog_CL" in kql
    assert result.savedsearches.strip()


# --- denied_tool_retry_loop (correlation) -------------------------------------

DENIED = "denied_tool_retry_loop"


def test_denied_retry_fires_on_loop() -> None:
    hits = _correlation_hits(RULES_DIR / f"{DENIED}.yml", _samples(DENIED, "positive"))
    assert hits == [(("conv-agent-6002",), 3)]


def test_denied_retry_silent_under_threshold() -> None:
    hits = _correlation_hits(RULES_DIR / f"{DENIED}.yml", _samples(DENIED, "negative"))
    assert hits == [], f"a short run of denials should stay silent, got {hits}"


def test_denied_retry_base_requires_denied_outcome() -> None:
    base, _correlation = _base_and_correlation(RULES_DIR / f"{DENIED}.yml")
    denied = _samples(DENIED, "positive")[0]
    assert rule_matches(base, denied)

    # Same tool call, but it succeeded -> not a loop building block.
    allowed = dict(denied)
    allowed["tool.call.outcome"] = "success"
    allowed["event.outcome"] = "success"
    assert not rule_matches(base, allowed)


def test_denied_retry_metadata() -> None:
    _base, correlation = _base_and_correlation(RULES_DIR / f"{DENIED}.yml")
    tags = {str(t) for t in correlation.tags}
    assert "owasp-llm.llm06" in tags
    assert "attack.atlas.aml.ta0015" in tags
    assert "attack.atlas.aml.t0085.001" in tags
    assert "prompthound.tier.t1" in tags
    assert correlation.references and correlation.falsepositives


def test_denied_retry_converts() -> None:
    result = convert_rule(RULES_DIR / f"{DENIED}.yml")
    assert result.is_correlation
    spl = "\n".join(result.spl)
    assert 'tool_call_outcome="denied"' in spl
    assert "bin _time span=5m" in spl
    assert "by _time gen_ai_conversation_id" in spl
    assert "event_count >= 3" in spl
    kql = "\n".join(result.kql)
    assert kql.strip() and "PromptHoundAuditLog_CL" in kql
    assert "// | summarize" in kql  # documented Kusto correlation workaround


# --- tool_call_amplification_loop (correlation, ties to LLM10) -----------------

AMP = "tool_call_amplification_loop"


def test_amplification_fires_on_fanout() -> None:
    hits = _correlation_hits(RULES_DIR / f"{AMP}.yml", _samples(AMP, "positive"))
    assert hits == [(("conv-agent-6004",), 15)]


def test_amplification_silent_on_normal_volume() -> None:
    hits = _correlation_hits(RULES_DIR / f"{AMP}.yml", _samples(AMP, "negative"))
    assert hits == [], f"a handful of tool calls should stay silent, got {hits}"


def test_amplification_metadata() -> None:
    _base, correlation = _base_and_correlation(RULES_DIR / f"{AMP}.yml")
    tags = {str(t) for t in correlation.tags}
    assert "owasp-llm.llm10" in tags  # resource amplification primary
    assert "owasp-llm.llm06" in tags  # agent tool-abuse cross-ref
    assert "attack.atlas.aml.ta0015" in tags
    assert {"attack.atlas.aml.t0034", "attack.atlas.aml.t0029"} <= tags
    assert "prompthound.tier.t1" in tags
    assert correlation.references and correlation.falsepositives


def test_amplification_converts() -> None:
    result = convert_rule(RULES_DIR / f"{AMP}.yml")
    assert result.is_correlation
    spl = "\n".join(result.spl)
    assert "bin _time span=2m" in spl
    assert "by _time gen_ai_conversation_id" in spl
    assert "event_count >= 15" in spl
    kql = "\n".join(result.kql)
    assert kql.strip() and "PromptHoundAuditLog_CL" in kql
    assert "// | summarize" in kql


# --- shared invariants across the agent tool-abuse rules ----------------------

AGENT_RULES = [CHAIN, DENIED, AMP]


@pytest.mark.parametrize("stem", AGENT_RULES)
def test_agent_samples_have_positive_and_negative(stem: str) -> None:
    for group in ("positive", "negative"):
        payload = _samples(stem, group)
        events = payload if isinstance(payload, list) else [payload]
        assert events, f"{stem}.{group} is empty"


@pytest.mark.parametrize("stem", AGENT_RULES)
def test_agent_rules_are_tier1_only(stem: str) -> None:
    # Prefer Tier-1 tool-call metadata (PRD §15): no Tier-2 content/args field.
    text = (RULES_DIR / f"{stem}.yml").read_text()
    for content_field in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.system_instructions",
        "tool.call.arguments",
        "tool.call.result",
    ):
        assert f"{content_field}|" not in text and f"{content_field}:" not in text


@pytest.mark.parametrize("stem", AGENT_RULES)
def test_agent_rules_have_no_agentic_tag_until_d6(stem: str) -> None:
    # D6 (OWASP Agentic Top 10 secondary tag) is still [OPEN]; do not claim it.
    text = (RULES_DIR / f"{stem}.yml").read_text()
    assert "owasp-agentic" not in text
