"""Rule-pack tests -- currently green with zero rules (CHECKLIST Phase 0).

As rules are added under ``rules/<category>/*.yml`` (Phase 1+), this module grows
per-rule fire/silence and metadata assertions (PRD §16). For now it asserts only
that the rule tree exists and that an empty pack does not fail the suite.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"

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


def test_rules_dir_exists() -> None:
    assert RULES_DIR.is_dir()


def test_rule_categories_present() -> None:
    for category in RULE_CATEGORIES:
        assert (RULES_DIR / category).is_dir(), f"missing rule category: {category}/"


def test_zero_or_more_rules_is_fine() -> None:
    # Phase 0 exit criterion: pytest is green with zero rules. Per-rule
    # fire/silence and metadata tests are added in Phase 1+.
    rules = sorted(RULES_DIR.glob("*/*.yml")) + sorted(RULES_DIR.glob("*/*.yaml"))
    assert isinstance(rules, list)
