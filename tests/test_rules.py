"""Rule-pack tests (PRD §16).

Phase 0 invariants (rule tree exists; an empty pack is fine) plus the Phase 1
vertical slice for ``system_prompt_extraction`` (PRD §11): fire, silence,
schema-validity, conversion snapshot, and metadata. The slice tests are
parametrized over a small registry so adding a rule means adding one entry.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompthound.matcher import load_rule, rule_matches

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"
SNAPSHOT_DIR = Path(__file__).resolve().parent / "snapshots"
SCHEMA_PATH = REPO_ROOT / "schema" / "llm_audit_log.schema.json"

# PRD §11 / §14 rule categories.
RULE_CATEGORIES = [
    "prompt_injection",
    "system_prompt_extraction",
    "jailbreak",
    "data_exfiltration",
    "agent_tool_abuse",
    "dos_cost_abuse",
    "insecure_output",
]


# --- Phase 0: structure --------------------------------------------------------


def test_rules_dir_exists() -> None:
    assert RULES_DIR.is_dir()


def test_rule_categories_present() -> None:
    for category in RULE_CATEGORIES:
        assert (RULES_DIR / category).is_dir(), f"missing rule category: {category}/"


def test_zero_or_more_rules_is_fine() -> None:
    rules = sorted(RULES_DIR.glob("*/*.yml")) + sorted(RULES_DIR.glob("*/*.yaml"))
    assert isinstance(rules, list)


# --- Phase 1: vertical-slice registry -----------------------------------------

# One entry per fully-implemented rule. Each test below is parametrized over it.
SLICE_RULES = [
    pytest.param(
        "system_prompt_extraction/extract_system_prompt_markers.yml",
        "extract_system_prompt_markers",
        id="extract_system_prompt_markers",
    ),
]


def _rule_path(rel: str) -> Path:
    return RULES_DIR / rel


@pytest.mark.parametrize(("rule_rel", "stem"), SLICE_RULES)
def test_rule_fires_on_positive_sample(rule_rel: str, stem: str) -> None:
    rule = load_rule(_rule_path(rule_rel))
    sample = json.loads((SAMPLES_DIR / f"{stem}.positive.json").read_text())
    assert rule_matches(rule, sample), "rule must fire on its positive sample"


@pytest.mark.parametrize(("rule_rel", "stem"), SLICE_RULES)
def test_rule_silent_on_negative_sample(rule_rel: str, stem: str) -> None:
    rule = load_rule(_rule_path(rule_rel))
    sample = json.loads((SAMPLES_DIR / f"{stem}.negative.json").read_text())
    assert not rule_matches(rule, sample), "rule must stay silent on its negative sample"


@pytest.mark.parametrize(("rule_rel", "stem"), SLICE_RULES)
def test_samples_validate_against_schema(rule_rel: str, stem: str) -> None:
    import jsonschema

    schema = json.loads(SCHEMA_PATH.read_text())
    for kind in ("positive", "negative"):
        sample = json.loads((SAMPLES_DIR / f"{stem}.{kind}.json").read_text())
        jsonschema.validate(instance=sample, schema=schema)


@pytest.mark.parametrize(("rule_rel", "stem"), SLICE_RULES)
def test_rule_has_required_metadata(rule_rel: str, stem: str) -> None:
    rule = load_rule(_rule_path(rule_rel))
    tags = {str(t) for t in rule.tags}
    assert any(t.startswith("owasp-llm.llm") for t in tags), f"missing OWASP tag: {tags}"
    assert any(t.startswith("attack.atlas.aml.t") for t in tags), f"missing ATLAS tag: {tags}"
    assert any(t.startswith("prompthound.tier.t") for t in tags), f"missing tier tag: {tags}"
    assert rule.references, "rule must cite references (PRD §15)"
    assert rule.falsepositives, "rule must document false positives (PRD §15)"
    assert rule.logsource.product == "llm_gateway", "logsource must be product: llm_gateway"


@pytest.mark.parametrize(("rule_rel", "stem"), SLICE_RULES)
def test_conversion_snapshot_splunk(rule_rel: str, stem: str) -> None:
    from pipelines.convert import convert_splunk

    queries = convert_splunk([_rule_path(rule_rel)])
    assert len(queries) == 1 and queries[0].strip(), "SPL must be non-empty"
    expected = (SNAPSHOT_DIR / f"{stem}.splunk.spl").read_text().strip()
    assert queries[0].strip() == expected, "SPL drifted from snapshot; review and re-bless"


@pytest.mark.parametrize(("rule_rel", "stem"), SLICE_RULES)
def test_conversion_snapshot_kusto(rule_rel: str, stem: str) -> None:
    from pipelines.convert import convert_kusto

    queries = convert_kusto([_rule_path(rule_rel)])
    assert len(queries) == 1 and queries[0].strip(), "KQL must be non-empty"
    expected = (SNAPSHOT_DIR / f"{stem}.kusto.kql").read_text().strip()
    assert queries[0].strip() == expected, "KQL drifted from snapshot; review and re-bless"
