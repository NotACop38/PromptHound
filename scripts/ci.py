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
# Importable when run as `python scripts/ci.py` (so `scripts.*`/`prompthound.*` resolve).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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
        payload = json.loads(path.read_text(encoding="utf-8"))
        # A sample file holds either a single event (selection-match rules) or a
        # JSON array of events (correlation rules, whose positive is a burst).
        events = payload if isinstance(payload, list) else [payload]
        errors = [
            f"[{i}] {error}"
            for i, event in enumerate(events)
            for error in validate_event(event, schema)
        ]
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
# Snapshot *check*, not a writer: every rule is run through both pySigma backends
# and the regenerated SPL/KQL is compared against the committed out/ snapshot.
# The stage fails if any output is empty (SPL, KQL, or savedsearches.conf),
# non-byte-stable, missing from out/, drifted from out/, or if out/ holds a stale
# generated file with no current source. Run `python scripts/release.py` to
# (re)write out/. This keeps an ephemeral CI run honest -- it never silently
# rewrites the artifacts it is supposed to be guarding.


def convert_stage() -> bool:
    """Verify the committed out/ SPL+KQL snapshot is current, non-empty, and stable."""
    from scripts.conversion import OUT_DIR as ARTIFACT_OUT_DIR
    from scripts.conversion import build_artifacts, committed_outputs

    artifacts, errors = build_artifacts()
    ok = True
    for error in errors:
        print(f"  [FAIL] {error}")
        ok = False
    if not artifacts:
        return False

    print(f"  checking {len(artifacts)} generated artifact(s) against out/")
    for path, content in sorted(artifacts.items()):
        rel = path.relative_to(ARTIFACT_OUT_DIR)
        if not path.is_file():
            print(f"  [FAIL] out/{rel}: missing snapshot (run scripts/release.py)")
            ok = False
        elif path.read_text(encoding="utf-8") != content:
            print(f"  [FAIL] out/{rel}: snapshot drift (run scripts/release.py)")
            ok = False
        else:
            print(f"  [ ok ] out/{rel}")

    # Orphans: committed artifacts whose source rule/fixture no longer exists.
    for path in sorted(committed_outputs() - set(artifacts)):
        print(f"  [FAIL] out/{path.relative_to(ARTIFACT_OUT_DIR)}: stale (run scripts/release.py)")
        ok = False

    return ok


# --- coverage-build stage (PRD §16, CHECKLIST Phase 4) ------------------------
#
# Unlike the read-only convert snapshot check, this stage *regenerates* the
# OWASP x ATLAS coverage map into out/coverage/ from rule metadata only. It fails
# on any build error -- a missing required tag (OWASP + tier + technique mapping)
# or an unknown/un-catalogued tag -- so the map can never silently go stale.


def coverage_build_stage() -> bool:
    """Regenerate the coverage map into out/coverage/; fail on missing/unknown tags."""
    from coverage.build_coverage import OUT_DIR as COVERAGE_OUT_DIR
    from coverage.build_coverage import generate_artifacts, write_artifacts

    artifacts, errors = generate_artifacts()
    if errors:
        for error in errors:
            print(f"  [FAIL] {error}")
        return False
    write_artifacts(artifacts)
    for path in sorted(artifacts):
        print(f"  [ ok ] out/{path.relative_to(COVERAGE_OUT_DIR.parent)}")
    return True


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
    Stage("coverage-build", coverage_build_stage),
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
