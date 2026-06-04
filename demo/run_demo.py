"""PromptHound one-command demo (PRD §7 item 6; CHECKLIST Phase 5).

Placeholder. The finished demo runs entirely offline and, in one command:
generates synthetic telemetry -> runs the rule pack against it -> prints the hits
-> renders the OWASP x ATLAS coverage map. No live LLM is ever contacted
(principles P1-P2, PRD §8).

    python demo/run_demo.py     # or: make demo
"""

from __future__ import annotations

import sys


def main() -> int:
    print("demo/run_demo.py: placeholder -- the one-command demo lands in Phase 5 (PRD §18).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
