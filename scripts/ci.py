"""PromptHound local CI runner (PRD §16, CHECKLIST Phase 2).

The runner itself is standard-library only; the ``convert`` stage additionally
imports ``prompthound.convert`` (pySigma + the pinned backends, PRD §13) to
regenerate SPL/KQL — install the lockfile before running it.

There is no hosted CI. Run the full check sequence on demand:

    python scripts/ci.py        # or: make ci

It runs an ordered list of stages, prints a PASS/FAIL banner for each, and exits
non-zero if any non-placeholder stage fails. Stage order follows PRD §16
(lint -> schema-validate -> convert -> test -> coverage build), with a final
security stage for the P1-P4 defensive-posture checks.

Stages marked ``[placeholder]`` are wired into the sequence but not yet
implemented; they pass without doing work so the runner stays green on the
current scaffold while keeping the remaining gaps visible.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "out"
RULES_DIR = REPO_ROOT / "rules"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
SAMPLES_DIR = REPO_ROOT / "generator" / "samples"
BAR = "=" * 72


def banner(text: str) -> None:
    print(f"\n{BAR}\n>> {text}\n{BAR}", flush=True)


def run_command(cmd: list[str]) -> bool:
    """Run a subprocess from the repo root; return True on exit code 0."""
    exe = cmd[0]
    if shutil.which(exe) is None:
        print(f"  tool not found on PATH: {exe}")
        return False
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=REPO_ROOT, check=False).returncode == 0


def tool(name: str, *args: str) -> Callable[[], bool]:
    """Build a stage that runs an external dev tool by name (resolved on PATH)."""
    return lambda: run_command([name, *args])


def schema_validate() -> bool:
    """Validate every generator/samples/*.json event against the audit-log schema.

    Both §10.9 example events ship as sample files; the malicious one is a P1
    marker phrase, not a working exploit (PRD §8). Conformance is the gate here,
    not detection -- whether a rule *fires* on a sample is the rule fire/silence
    stage's job.
    """
    sys.path.insert(0, str(REPO_ROOT))
    from prompthound.schema import load_schema, validate_event

    schema = load_schema()
    samples = sorted(SAMPLES_DIR.glob("*.json"))
    if not samples:
        print(f"  no sample events found under {SAMPLES_DIR.relative_to(REPO_ROOT)}/")
        return False

    ok = True
    for path in samples:
        event = json.loads(path.read_text(encoding="utf-8"))
        errors = validate_event(event, schema)
        rel = path.relative_to(REPO_ROOT)
        if errors:
            ok = False
            print(f"  INVALID  {rel}")
            for error in errors:
                print(f"      - {error}")
        else:
            print(f"  ok       {rel}")
    return ok


def placeholder(note: str) -> Callable[[], bool]:
    """Build a stage that does nothing yet but reports why (and passes)."""

    def _run() -> bool:
        print(f"  PLACEHOLDER -- {note}")
        return True

    return _run


# --- convert stage (PRD §16 "convert (snapshot)", §12, decision D5) -----------
#
# Real conversion: every rule is run through both pySigma backends and the SPL +
# KQL is regenerated into out/. The stage asserts each output is non-empty and
# byte-stable (a second pass produces identical text), which is the snapshot
# guarantee PRD §12 asks for. Until real rules exist under rules/ it falls back
# to the toolchain smoke fixture so the pipeline is still proven on every run.


def _discover_rule_files() -> tuple[list[Path], Path, str]:
    """Return (rule files, base dir for out/ mirroring, human label)."""
    rules = sorted(RULES_DIR.glob("**/*.yml")) + sorted(RULES_DIR.glob("**/*.yaml"))
    if rules:
        return rules, RULES_DIR, "rules/"
    fixtures = sorted(FIXTURES_DIR.glob("*.yml")) + sorted(FIXTURES_DIR.glob("*.yaml"))
    return fixtures, FIXTURES_DIR, "tests/fixtures/ (no rules authored yet)"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


def convert_stage() -> bool:
    """Regenerate SPL + KQL into out/; fail on empty or non-deterministic output."""
    from prompthound.convert import convert_rule

    rule_files, base_dir, label = _discover_rule_files()
    if not rule_files:
        print("  no rule or fixture files found to convert")
        return False
    print(f"  converting {len(rule_files)} file(s) from {label}")

    ok = True
    for rule_file in rule_files:
        rel = rule_file.relative_to(base_dir).with_suffix("")
        try:
            result = convert_rule(rule_file)
            # Stability/snapshot: a second pass must be byte-identical.
            again = convert_rule(rule_file)
        except Exception as exc:  # conversion error => stage fails, with context
            print(f"  [FAIL] {rel}: {type(exc).__name__}: {exc}")
            ok = False
            continue

        spl_text = "\n".join(result.spl)
        kql_text = "\n".join(result.kql)
        stable = (
            result.spl == again.spl
            and result.kql == again.kql
            and result.savedsearches == again.savedsearches
        )
        if not spl_text.strip():
            print(f"  [FAIL] {rel}: empty SPL")
            ok = False
        if not kql_text.strip():
            print(f"  [FAIL] {rel}: empty KQL")
            ok = False
        if not stable:
            print(f"  [FAIL] {rel}: conversion is not byte-stable across runs")
            ok = False
        if not (spl_text.strip() and kql_text.strip() and stable):
            continue

        # Mirror the source layout under out/ so nested categories never collide.
        _write_text(OUT_DIR / "splunk" / rel.with_suffix(".spl"), spl_text)
        _write_text(
            OUT_DIR / "splunk" / rel.parent / (rel.name + ".savedsearches.conf"),
            result.savedsearches,
        )
        _write_text(OUT_DIR / "kusto" / rel.with_suffix(".kql"), kql_text)
        print(f"  [ ok ] {rel}: SPL={len(result.spl)} KQL={len(result.kql)} -> out/")

    return ok


@dataclass(frozen=True)
class Stage:
    name: str
    run: Callable[[], bool]
    is_placeholder: bool = False


# Ordered per PRD §16: lint -> schema-validate -> convert -> test -> coverage.
STAGES: list[Stage] = [
    Stage("ruff format --check", tool("ruff", "format", "--check", ".")),
    Stage("ruff check", tool("ruff", "check", ".")),
    Stage("mypy prompthound", tool("mypy", "prompthound")),
    Stage("schema-validate", schema_validate),
    Stage("convert (SPL + KQL snapshot)", convert_stage),
    Stage("pytest", tool("pytest", "-q")),
    Stage(
        "coverage-build",
        placeholder("regenerate OWASP x ATLAS coverage map -- Phase 4 (PRD §16)."),
        is_placeholder=True,
    ),
    Stage(
        "security",
        placeholder("defensive-posture / P1 signature checks -- Phase 6 (PRD §8)."),
        is_placeholder=True,
    ),
]


def main() -> int:
    banner("PromptHound local CI runner")
    print(f"  repo:   {REPO_ROOT}")
    print(f"  python: {sys.version.split()[0]}")

    results: list[tuple[str, bool]] = []
    total = len(STAGES)
    for index, stage in enumerate(STAGES, start=1):
        suffix = "  [placeholder]" if stage.is_placeholder else ""
        banner(f"STAGE {index}/{total}: {stage.name}{suffix}")
        ok = stage.run()
        print(f"{'[ PASS ]' if ok else '[ FAIL ]'} {stage.name}", flush=True)
        results.append((stage.name, ok))

    banner("SUMMARY")
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    failed = [name for name, ok in results if not ok]
    if failed:
        print(f"\n[ FAIL ] CI failed -- {len(failed)} stage(s): {', '.join(failed)}")
        return 1
    print("\n[ PASS ] CI passed -- all stages green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
