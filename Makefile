# PromptHound — developer entrypoints (PRD §12). No hosted CI; run locally.
.PHONY: setup ci release fmt test demo

# Install the pinned runtime deps + dev/CI toolchain + the package, into the
# current environment (use a venv). requirements-dev.lock pins ruff/mypy/pytest/
# pip-audit/bandit so the green pass is reproducible (CHECKLIST Phase 6).
setup:
	python -m pip install -r requirements.lock -r requirements-dev.lock -e .

# Full local CI runner: ordered stages, non-zero exit on failure (PRD §16).
ci:
	python scripts/ci.py

# One-command offline demo (PRD §1/§7, CHECKLIST Phase 5): generate telemetry →
# run the rule pack → print hits → build the OWASP × ATLAS coverage map.
demo:
	python demo/run_demo.py --seed 0

# Local CD: regenerate SPL/KQL/coverage artifacts into out/, then stamp a
# versioned, reproducible release bundle under out/dist/ (PRD §12, D8).
release:
	python scripts/release.py

# Auto-format and auto-fix lint where safe.
fmt:
	ruff format .
	ruff check --fix .

# Run the test suite.
test:
	pytest -q
