"""PromptHound local CD (PRD §12, CHECKLIST Phase 2). Standard library only.

Placeholder. The finished release step will regenerate every rule's SPL + KQL
and the OWASP x ATLAS coverage map into ``out/`` so the generated content can be
published as artifacts (PRD §7 item 2). Deployable packaging is decision D8,
still open (PRD §9).

    python scripts/release.py   # or: make release
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "out"


def main() -> int:
    OUT_DIR.mkdir(exist_ok=True)
    print(f"scripts/release.py: placeholder -- would regenerate artifacts into {OUT_DIR}")
    print("  (SPL + KQL per rule, plus the coverage map) -- lands in Phase 2+ (PRD §12).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
