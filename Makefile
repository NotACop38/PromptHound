# PromptHound — developer entrypoints (PRD §12). No hosted CI; run locally.
.PHONY: ci release fmt test

# Full local CI runner: ordered stages, non-zero exit on failure (PRD §16).
ci:
	python scripts/ci.py

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
