"""Smoke tests -- keep pytest green on the bare scaffold (CHECKLIST Phase 0)."""

from __future__ import annotations

from pathlib import Path

import prompthound

REPO_ROOT = Path(__file__).resolve().parent.parent

# PRD §14 top-level directories that the scaffold must provide.
SCAFFOLD_DIRS = [
    "docs",
    "schema",
    "rules",
    "pipelines",
    "generator",
    "tests",
    "coverage",
    "demo",
    "scripts",
    "out",
]


def test_package_imports_and_versions() -> None:
    assert prompthound.__version__ == "0.1.0"
    assert prompthound.SCHEMA_VERSION == "0.1"


def test_scaffold_dirs_present() -> None:
    for name in SCAFFOLD_DIRS:
        assert (REPO_ROOT / name).is_dir(), f"missing scaffold dir: {name}/"


def test_source_of_truth_docs_present() -> None:
    assert (REPO_ROOT / "docs" / "PRD.md").is_file()
    assert (REPO_ROOT / "docs" / "CHECKLIST.md").is_file()
