"""PromptHound local CD (PRD §12, CHECKLIST Phase 2).

Regenerates every rule's SPL + KQL (and ``savedsearches.conf``) into ``out/`` so
the generated content can be published as artifacts (PRD §7 item 2). This is the
*writer*; ``scripts/ci.py``'s convert stage is the read-only snapshot check that
fails if ``out/`` drifts from what this would produce. Run it after changing a
rule, pipeline, or backend pin, and commit the resulting ``out/`` diff.

    python scripts/release.py   # or: make release

The coverage map (PRD §14) is a separate, still-pending artifact (Phase 4).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> int:
    from scripts.conversion import (
        OUT_DIR,
        build_artifacts,
        committed_outputs,
    )

    artifacts, errors = build_artifacts()
    if errors:
        for error in errors:
            print(f"  ERROR  {error}")
        print("\nrelease aborted: fix the conversion errors above.")
        return 1

    # Prune stale generated files (e.g. a rule was renamed or removed) so out/
    # mirrors the current rule set exactly, then write the fresh artifacts.
    for path in sorted(committed_outputs() - set(artifacts)):
        path.unlink()
        print(f"  removed  out/{path.relative_to(OUT_DIR)}")

    for path, content in sorted(artifacts.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"  wrote    out/{path.relative_to(OUT_DIR)}")

    print(f"\nregenerated {len(artifacts)} artifact(s) into {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
