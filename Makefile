# PromptHound — developer entrypoints (PRD §12). No hosted CI; run locally.
.PHONY: ci release fmt test demo

# Full local CI runner: ordered stages, non-zero exit on failure (PRD §16).
ci:
	python scripts/ci.py

# One-command offline demo (PRD §1/§7, CHECKLIST Phase 5): generate telemetry →
# run the rule pack → print hits → build the OWASP × ATLAS coverage map.
demo:
	python demo/run_demo.py --seed 0

# Local CD: regenerate SPL/KQL/coverage artifacts into out/ (PRD §12).
release:
	python scripts/release.py

# Auto-format and auto-fix lint where safe.
fmt:
	ruff format .
	ruff check --fix .

# Run the test suite.
test:
	pytest -q
