"""Tests for the prompt-injection content-marker rules (PRD §11 #1, #2, LLM01).

Step 8 adds the direct/indirect prompt-injection family:

  * ``direct_injection_markers`` -- Tier-2 (+derived): instruction-override
    marker phrases in input AND a non-zero derived injection-marker counter
    (ATLAS AML.T0051.000);
  * ``direct_injection_marker_count`` -- the Tier-1 derived-only sibling that
    runs the same intent on ``content.input.injection_markers`` alone (PRD D4
    bridge), so it deploys without Tier-2 content logging;
  * ``indirect_injection_from_untrusted_source`` -- Tier-2 + retrieval: markers
    arriving via content retrieved from an *untrusted* ``rag.source.types`` entry
    (ATLAS AML.T0051.001; EchoLeak / CVE-2025-32711).

All three are single selection-match rules, so they reuse the offline matcher
(``prompthound.matcher``) directly. Conversion is checked through the real
toolchain.

Run just these with ``pytest -k injection -q``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompthound.convert import convert_rule
from prompthound.matcher import load_rule, rule_matches

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "prompt_injection"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"

DIRECT = "direct_injection_markers"
DIRECT_COUNT = "direct_injection_marker_count"
INDIRECT = "indirect_injection_from_untrusted_source"

CONTENT_FIELDS = (
    "gen_ai.input.messages",
    "gen_ai.output.messages",
    "gen_ai.system_instructions",
    "tool.call.arguments",
    "tool.call.result",
)


def _rule(stem: str):
    return load_rule(RULES_DIR / f"{stem}.yml")


def _sample(stem: str, group: str) -> dict:
    return json.loads((SAMPLES_DIR / f"{stem}.{group}.json").read_text())


# --- direct_injection_markers (Tier-2 + derived) ------------------------------


def test_direct_injection_fires_on_positive() -> None:
    assert rule_matches(_rule(DIRECT), _sample(DIRECT, "positive"))


def test_direct_injection_silent_on_negative() -> None:
    assert not rule_matches(_rule(DIRECT), _sample(DIRECT, "negative"))


def test_direct_injection_needs_both_content_and_derived_marker() -> None:
    # The derived counter is a required gate: a marker phrase with a zero
    # injection_markers score (e.g. heuristic missed it) must NOT fire on its own.
    rule = _rule(DIRECT)
    phrase_only = _sample(DIRECT, "positive") | {"content.input.injection_markers": 0}
    assert not rule_matches(rule, phrase_only)
    # ...and the derived counter without an override phrase must not fire either.
    counter_only = _sample(DIRECT, "positive") | {
        "gen_ai.input.messages": [{"role": "user", "parts": ["Please summarize this article."]}]
    }
    assert not rule_matches(rule, counter_only)


def test_direct_injection_metadata() -> None:
    rule = _rule(DIRECT)
    tags = {str(t) for t in rule.tags}
    assert "owasp-llm.llm01" in tags
    assert "attack.atlas.aml.t0051.000" in tags
    assert "prompthound.tier.t2" in tags
    assert rule.references and rule.falsepositives
    assert rule.logsource.product == "llm_gateway"


def test_direct_injection_converts() -> None:
    result = convert_rule(RULES_DIR / f"{DIRECT}.yml")
    assert not result.is_correlation
    assert result.spl and all(q.strip() for q in result.spl)
    assert "content_input_injection_markers>=1" in result.spl[0]
    assert result.kql and all(q.strip() for q in result.kql)
    assert "PromptHoundAuditLog_CL" in "\n".join(result.kql)
    assert result.savedsearches.strip()


# --- direct_injection_marker_count (Tier-1 derived variant) -------------------


def test_direct_marker_count_fires_on_positive() -> None:
    assert rule_matches(_rule(DIRECT_COUNT), _sample(DIRECT_COUNT, "positive"))


def test_direct_marker_count_silent_below_threshold() -> None:
    # The negative scores a single marker (1) -- below the >=2 standalone gate.
    assert not rule_matches(_rule(DIRECT_COUNT), _sample(DIRECT_COUNT, "negative"))


def test_direct_marker_count_threshold_is_two() -> None:
    rule = _rule(DIRECT_COUNT)
    base = _sample(DIRECT_COUNT, "positive")
    assert not rule_matches(rule, base | {"content.input.injection_markers": 1})
    assert rule_matches(rule, base | {"content.input.injection_markers": 2})


def test_direct_marker_count_is_tier1_derived_only() -> None:
    # The privacy-preserving sibling must not reference any Tier-2 content field.
    rule = _rule(DIRECT_COUNT)
    tags = {str(t) for t in rule.tags}
    assert "prompthound.tier.t1" in tags
    assert "attack.atlas.aml.t0051.000" in tags
    text = (RULES_DIR / f"{DIRECT_COUNT}.yml").read_text()
    detection = text.split("detection:", 1)[1].split("falsepositives:", 1)[0]
    for field in CONTENT_FIELDS:
        assert field not in detection


def test_direct_marker_count_converts() -> None:
    result = convert_rule(RULES_DIR / f"{DIRECT_COUNT}.yml")
    assert not result.is_correlation
    assert result.spl and "content_input_injection_markers>=2" in result.spl[0]
    assert result.kql and all(q.strip() for q in result.kql)


# --- indirect_injection_from_untrusted_source (Tier-2 + retrieval) ------------


def test_indirect_injection_fires_on_positive() -> None:
    assert rule_matches(_rule(INDIRECT), _sample(INDIRECT, "positive"))


def test_indirect_injection_silent_on_negative() -> None:
    assert not rule_matches(_rule(INDIRECT), _sample(INDIRECT, "negative"))


def test_indirect_injection_requires_untrusted_source() -> None:
    # Same markers, but retrieved from a trusted internal source -> must not fire.
    rule = _rule(INDIRECT)
    trusted = _sample(INDIRECT, "positive") | {"rag.source.types": ["db"]}
    assert not rule_matches(rule, trusted)


def test_indirect_injection_requires_markers() -> None:
    # Untrusted source + injected phrase, but the derived counter is zero -> silent.
    rule = _rule(INDIRECT)
    no_markers = _sample(INDIRECT, "positive") | {"content.input.injection_markers": 0}
    assert not rule_matches(rule, no_markers)


@pytest.mark.parametrize("source", ["web", "email", "file", "ticket"])
def test_indirect_injection_fires_on_each_untrusted_source(source: str) -> None:
    rule = _rule(INDIRECT)
    event = _sample(INDIRECT, "positive") | {"rag.source.types": [source]}
    assert rule_matches(rule, event), f"should fire on injection from untrusted {source}"


def test_indirect_injection_metadata() -> None:
    rule = _rule(INDIRECT)
    tags = {str(t) for t in rule.tags}
    assert "owasp-llm.llm01" in tags
    assert "attack.atlas.aml.t0051.001" in tags
    assert "prompthound.tier.t2" in tags
    # EchoLeak / CVE-2025-32711 is the documented real-world anchor (PRD §11).
    assert any("CVE-2025-32711" in str(r) for r in rule.references)
    assert rule.falsepositives
    assert rule.logsource.product == "llm_gateway"


def test_indirect_injection_converts() -> None:
    result = convert_rule(RULES_DIR / f"{INDIRECT}.yml")
    assert not result.is_correlation
    assert result.spl and all(q.strip() for q in result.spl)
    assert result.kql and all(q.strip() for q in result.kql)
    assert "PromptHoundAuditLog_CL" in "\n".join(result.kql)


# --- shared invariants --------------------------------------------------------

ALL_PI_RULES = [DIRECT, DIRECT_COUNT, INDIRECT]


@pytest.mark.parametrize("stem", ALL_PI_RULES)
def test_pi_samples_have_positive_and_negative(stem: str) -> None:
    for group in ("positive", "negative"):
        payload = _sample(stem, group)
        events = payload if isinstance(payload, list) else [payload]
        assert events, f"{stem}.{group} is empty"
