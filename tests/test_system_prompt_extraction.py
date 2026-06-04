"""Tests for the system-prompt extraction SUCCESS variant (PRD §11 #3, LLM07).

The sibling slice (``test_rules.py``) covers ``extract_system_prompt_markers``,
which fires on the extraction *attempt* in the input. This module covers
``system_prompt_leaked_in_output`` — the *success*: the model's OUTPUT echoes its
hidden system instructions. It keys on the derived Tier-1 boolean
``content.output.contains_system_prompt`` OR a Tier-2 output-content echo
signature (PRD §10.8 bridge), so the rule degrades gracefully to Tier-1.

Run just these with ``pytest -k extraction -q``.
"""

from __future__ import annotations

import json
from pathlib import Path

from prompthound.convert import convert_rule
from prompthound.matcher import load_rule, rule_matches

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_PATH = REPO_ROOT / "rules" / "system_prompt_extraction" / "system_prompt_leaked_in_output.yml"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"
STEM = "system_prompt_leaked_in_output"


def _sample(group: str) -> dict:
    return json.loads((SAMPLES_DIR / f"{STEM}.{group}.json").read_text())


def test_extraction_success_fires_on_positive() -> None:
    rule = load_rule(RULE_PATH)
    assert rule_matches(rule, _sample("positive")), "must fire when output leaks the system prompt"


def test_extraction_success_silent_on_negative() -> None:
    rule = load_rule(RULE_PATH)
    assert not rule_matches(rule, _sample("negative")), "must stay silent on a benign response"


def test_extraction_success_fires_on_derived_marker_alone() -> None:
    # Tier-1 bridge: with no output content stored, the derived boolean alone
    # must still fire (graceful degradation, PRD §10.8 / D4).
    rule = load_rule(RULE_PATH)
    event = _sample("positive")
    event.pop("gen_ai.output.messages", None)
    assert event["content.output.contains_system_prompt"] is True
    assert rule_matches(rule, event)


def test_extraction_success_fires_on_output_text_alone() -> None:
    # Tier-2 path: even if the derived marker is false/absent, a recognizable
    # system-prompt echo in the output content fires the rule.
    rule = load_rule(RULE_PATH)
    event = _sample("positive")
    event["content.output.contains_system_prompt"] = False
    assert rule_matches(rule, event)


def test_extraction_success_metadata() -> None:
    rule = load_rule(RULE_PATH)
    tags = {str(t) for t in rule.tags}
    assert "owasp-llm.llm07" in tags
    assert "attack.atlas.aml.t0056" in tags
    assert {"prompthound.tier.t1", "prompthound.tier.t2"} <= tags
    assert rule.references and rule.falsepositives
    assert rule.logsource.product == "llm_gateway"


def test_extraction_success_converts() -> None:
    result = convert_rule(RULE_PATH)
    assert not result.is_correlation
    assert result.spl and all(q.strip() for q in result.spl)
    assert result.kql and all(q.strip() for q in result.kql)
    assert result.savedsearches.strip()
