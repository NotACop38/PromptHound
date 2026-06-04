"""Tests for the Tier-1 insecure-output-handling rule (PRD §11 #8, LLM05).

``unsanitized_output_to_sink`` fires when the gateway records LLM output reaching
a code/command/markup execution sink (sql_exec / shell_exec / html_render /
code_eval) without sanitization -- the OWASP LLM05:2025 primitive. It is a single
selection match on always-on output-handling metadata (PRD §10.6), so it reuses
the offline matcher directly.

Mapping note (PRD §11): LLM05 has no native MITRE ATLAS technique; the rule
cross-references ATT&CK T1059 (Command and Scripting Interpreter) instead, so the
metadata test deliberately asserts an ``attack.t1059`` tag and the *absence* of
an ATLAS tag.

Run just these with ``pytest -k insecure_output -q``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompthound.convert import convert_rule
from prompthound.matcher import load_rule, rule_matches

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_PATH = REPO_ROOT / "rules" / "insecure_output" / "unsanitized_output_to_sink.yml"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"
STEM = "unsanitized_output_to_sink"

DANGEROUS_SINKS = ["sql_exec", "shell_exec", "html_render", "code_eval"]
SAFE_SINKS = ["markdown", "downstream_api", "none"]


def _sample(group: str) -> dict:
    return json.loads((SAMPLES_DIR / f"{STEM}.{group}.json").read_text())


# --- fire / silence -----------------------------------------------------------


def test_insecure_output_fires_on_positive() -> None:
    rule = load_rule(RULE_PATH)
    assert rule_matches(rule, _sample("positive"))


def test_insecure_output_silent_on_negative() -> None:
    rule = load_rule(RULE_PATH)
    assert not rule_matches(rule, _sample("negative"))


@pytest.mark.parametrize("sink", DANGEROUS_SINKS)
def test_insecure_output_fires_on_each_dangerous_sink(sink: str) -> None:
    rule = load_rule(RULE_PATH)
    event = _sample("positive") | {"output.sink": sink, "output.rendered_unsanitized": True}
    assert rule_matches(rule, event), f"should fire on unsanitized output into {sink}"


@pytest.mark.parametrize("sink", SAFE_SINKS)
def test_insecure_output_silent_on_safe_sinks(sink: str) -> None:
    rule = load_rule(RULE_PATH)
    event = _sample("positive") | {"output.sink": sink, "output.rendered_unsanitized": True}
    assert not rule_matches(rule, event), f"{sink} is not a dangerous sink"


def test_insecure_output_silent_when_sanitized() -> None:
    # A dangerous sink that was sanitized must NOT fire -- the boolean is the gate.
    rule = load_rule(RULE_PATH)
    event = _sample("positive") | {"output.sink": "sql_exec", "output.rendered_unsanitized": False}
    assert not rule_matches(rule, event)


# --- metadata (PRD §15) -------------------------------------------------------


def test_insecure_output_metadata() -> None:
    rule = load_rule(RULE_PATH)
    tags = {str(t) for t in rule.tags}
    assert "owasp-llm.llm05" in tags
    assert "prompthound.tier.t1" in tags
    # Genuine ATT&CK cross-ref for the command/code execution sinks (PRD §11)...
    assert "attack.t1059" in tags
    # ...and no native ATLAS technique exists for LLM05, so none is claimed.
    assert not any(t.startswith("attack.atlas.aml.t") for t in tags)
    assert rule.references and rule.falsepositives
    assert rule.logsource.product == "llm_gateway"


def test_insecure_output_is_tier1_only() -> None:
    # No Tier-2 content field is referenced by the detection.
    text = RULE_PATH.read_text()
    detection = text.split("detection:", 1)[1].split("falsepositives:", 1)[0]
    for content_field in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.system_instructions",
        "tool.call.arguments",
        "tool.call.result",
    ):
        assert content_field not in detection


# --- conversion (PRD §16) -----------------------------------------------------


def test_insecure_output_converts() -> None:
    result = convert_rule(RULE_PATH)
    assert not result.is_correlation
    assert result.spl and all(q.strip() for q in result.spl)
    spl = result.spl[0]
    assert "output_rendered_unsanitized=true" in spl
    assert "output_sink IN (" in spl
    assert result.kql and all(q.strip() for q in result.kql)
    assert "PromptHoundAuditLog_CL" in "\n".join(result.kql)
    assert result.savedsearches.strip()
