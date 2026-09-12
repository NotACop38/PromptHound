"""Smoke tests for the one-command demo (PRD §1/§7; CHECKLIST Phase 5).

The demo is the project's front door, so a regression in it must fail CI: it
has to exit 0, write a schema-valid telemetry file, fire EVERY shipped rule on
its own generated dataset (the demo-level half of the generator drift guard),
and be byte-reproducible for a given seed.

Run just these with ``pytest -k demo -q``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from demo import run_demo
from prompthound import coverage
from prompthound.schema import load_schema, validate_event

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"


@pytest.fixture(autouse=True)
def isolate_demo_outputs(tmp_path, monkeypatch):
    # A demo test must not regenerate committed snapshots before CI checks them.
    monkeypatch.setattr(run_demo, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(run_demo, "TELEMETRY_PATH", tmp_path / "telemetry.jsonl")
    monkeypatch.setattr(coverage, "OUT_DIR", tmp_path / "coverage")


def _rule_count() -> int:
    return sum(len(list(RULES_DIR.glob(pattern))) for pattern in ("**/*.yml", "**/*.yaml"))


def test_demo_runs_and_fires_every_rule(capsys) -> None:
    rc = run_demo.main(["--seed", "0"])
    out = capsys.readouterr().out
    assert rc == 0
    n = _rule_count()
    assert f"{n}/{n} rules fired" in out, "the demo must fire every shipped rule"


def test_demo_writes_schema_valid_telemetry(capsys) -> None:
    assert run_demo.main(["--seed", "0"]) == 0
    capsys.readouterr()  # drain
    lines = run_demo.TELEMETRY_PATH.read_text(encoding="utf-8").splitlines()
    assert lines, "demo wrote no telemetry"
    schema = load_schema()
    for i, line in enumerate(lines):
        event = json.loads(line)
        assert validate_event(event, schema) == [], f"event {i} failed schema validation"


def test_demo_is_reproducible_per_seed(capsys) -> None:
    assert run_demo.main(["--seed", "7"]) == 0
    first = run_demo.TELEMETRY_PATH.read_bytes()
    assert run_demo.main(["--seed", "7"]) == 0
    capsys.readouterr()  # drain
    assert run_demo.TELEMETRY_PATH.read_bytes() == first
