"""Shared SPL/KQL regeneration used by the CI snapshot check and the release step.

``scripts/ci.py`` *verifies* the committed ``out/`` snapshot (read-only, fails on
drift) and ``scripts/release.py`` *writes* it (PRD §12 local CD). Both call
:func:`build_artifacts` here so the generated content is defined in exactly one
place. Standard library only; the conversion itself comes from
``prompthound.convert`` (pySigma + the pinned backends, PRD §13).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# Make ``prompthound`` / ``pipelines`` importable when run as a script.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OUT_DIR = REPO_ROOT / "out"
RULES_DIR = REPO_ROOT / "rules"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

# out/ subtrees this toolchain owns end-to-end: every file under them is generated
# from a rule, so anything here without a current source is stale (PRD §12).
MANAGED_OUT_DIRS = (OUT_DIR / "splunk", OUT_DIR / "kusto")


def discover_rule_files() -> tuple[list[Path], Path, str]:
    """Return (rule files, base dir for out/ mirroring, human label).

    Prefers authored rules under ``rules/``; falls back to the toolchain smoke
    fixture so the pipeline is still exercised before any real rule exists.
    """
    rules = sorted(RULES_DIR.glob("**/*.yml")) + sorted(RULES_DIR.glob("**/*.yaml"))
    if rules:
        return rules, RULES_DIR, "rules/"
    fixtures = sorted(FIXTURES_DIR.glob("*.yml")) + sorted(FIXTURES_DIR.glob("*.yaml"))
    return fixtures, FIXTURES_DIR, "tests/fixtures/ (no rules authored yet)"


def _normalize(text: str) -> str:
    return text if text.endswith("\n") else text + "\n"


def build_artifacts() -> tuple[dict[Path, str], list[str]]:
    """Convert all discovered rules to the out/ artifact set, without touching disk.

    Returns ``(artifacts, errors)`` where ``artifacts`` maps each output path to
    its content and ``errors`` lists any empty SPL/KQL/savedsearches output or
    non-byte-stable conversion. A rule that errors contributes to ``errors`` and
    is omitted from ``artifacts``.
    """
    from prompthound.convert import convert_rule

    rule_files, base_dir, _label = discover_rule_files()
    artifacts: dict[Path, str] = {}
    errors: list[str] = []
    if not rule_files:
        errors.append("no rule or fixture files found to convert")
        return artifacts, errors

    for rule_file in rule_files:
        rel = rule_file.relative_to(base_dir).with_suffix("")
        try:
            result = convert_rule(rule_file)
            again = convert_rule(rule_file)  # determinism guard
        except Exception as exc:  # conversion error => recorded, with context
            errors.append(f"{rel}: {type(exc).__name__}: {exc}")
            continue

        spl_text = "\n".join(result.spl)
        kql_text = "\n".join(result.kql)
        saved_text = result.savedsearches

        # Every generated format must be non-empty -- including savedsearches.conf,
        # which ships as part of the toolchain (D5) and is easy to miss otherwise.
        # Each skip path records its error first, so a rule can never silently
        # drop out of the artifact set.
        empty = [
            label
            for label, text in (
                ("SPL", spl_text),
                ("KQL", kql_text),
                ("savedsearches.conf", saved_text),
            )
            if not text.strip()
        ]
        for label in empty:
            errors.append(f"{rel}: empty {label}")
        if (result.spl, result.kql, result.savedsearches) != (
            again.spl,
            again.kql,
            again.savedsearches,
        ):
            errors.append(f"{rel}: conversion is not byte-stable across runs")
            continue
        if empty:
            continue

        # Mirror the source layout under out/ so nested categories never collide.
        artifacts[OUT_DIR / "splunk" / rel.with_suffix(".spl")] = _normalize(spl_text)
        artifacts[OUT_DIR / "splunk" / rel.parent / (rel.name + ".savedsearches.conf")] = (
            _normalize(saved_text)
        )
        artifacts[OUT_DIR / "kusto" / rel.with_suffix(".kql")] = _normalize(kql_text)

    return artifacts, errors


def committed_outputs() -> set[Path]:
    """Every file currently committed under the managed out/ subtrees."""
    found: set[Path] = set()
    for directory in MANAGED_OUT_DIRS:
        if directory.is_dir():
            found.update(p for p in directory.rglob("*") if p.is_file())
    return found


__all__ = [
    "MANAGED_OUT_DIRS",
    "OUT_DIR",
    "build_artifacts",
    "committed_outputs",
    "discover_rule_files",
]
