"""The CI gate: every check a change must pass, in order.

    python scripts/ci.py                 # all stages
    python scripts/ci.py --only pytest   # stages whose name contains "pytest"

GitHub Actions runs the same script. Query verification in real SIEM engines
needs Docker and runs separately (``make verify-siem``).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess  # Fixed arguments, never a shell.  # nosec B404
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Stage:
    name: str
    argv: tuple[str, ...]


STAGES = (
    Stage("ruff format", ("ruff", "format", "--check", ".")),
    Stage("ruff check", ("ruff", "check", ".")),
    Stage("mypy", ("mypy",)),
    Stage("pytest", ("pytest", "--cov", "--cov-report=term-missing:skip-covered")),
    Stage("generated artifacts", (sys.executable, "scripts/generate.py", "--check")),
    Stage("security", (sys.executable, "scripts/security.py")),
)


def run(stage: Stage) -> bool:
    executable = shutil.which(stage.argv[0])
    if executable is None:
        print(f"{stage.argv[0]} is not installed (install requirements-dev.lock)")
        return False
    return (
        # The command line comes from STAGES.
        subprocess.run(  # noqa: S603  # nosec B603
            [executable, *stage.argv[1:]], cwd=REPO_ROOT, check=False
        ).returncode
        == 0
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", metavar="TEXT", help="run stages whose name contains TEXT")
    args = parser.parse_args(argv)
    stages = [s for s in STAGES if not args.only or args.only.lower() in s.name]
    if not stages:
        parser.error(f"no stage matches {args.only!r}; stages: {', '.join(s.name for s in STAGES)}")

    results: list[tuple[str, bool, float]] = []
    for stage in stages:
        print(f"\n=== {stage.name}: {' '.join(stage.argv)}", flush=True)
        started = time.monotonic()
        results.append((stage.name, run(stage), time.monotonic() - started))

    print("\n=== summary")
    for name, passed, seconds in results:
        print(f"{'pass' if passed else 'FAIL'}  {name} ({seconds:.1f}s)")
    failed = [name for name, passed, _ in results if not passed]
    print(f"\n{'CI failed: ' + ', '.join(failed) if failed else 'CI passed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
