"""PromptHound local CI runner (PRD §16, CHECKLIST Phase 2). Standard library only.

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

import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
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


def placeholder(note: str) -> Callable[[], bool]:
    """Build a stage that does nothing yet but reports why (and passes)."""

    def _run() -> bool:
        print(f"  PLACEHOLDER -- {note}")
        return True

    return _run


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
    Stage(
        "schema-validate",
        placeholder("validate generator samples against schema/ -- Phase 1 (PRD §16)."),
        is_placeholder=True,
    ),
    Stage(
        "convert (SPL + KQL snapshot)",
        placeholder("pySigma conversion + snapshot test -- Phase 1/2 (PRD §16, D5)."),
        is_placeholder=True,
    ),
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
