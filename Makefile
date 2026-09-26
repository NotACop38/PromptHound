# Development tasks for PromptHound. See CONTRIBUTING.md.
PYTHON ?= python3
UV_COMPILE = uv pip compile pyproject.toml --universal --python-version 3.11 \
	--generate-hashes --custom-compile-command "make lock"

.PHONY: setup lock fmt test ci generate demo verify-siem release clean

## setup: install the locked development dependencies (hash-checked) and the package, editable
setup:
	$(PYTHON) -m pip install --require-hashes -r requirements-dev.lock
	$(PYTHON) -m pip install --no-deps -e .

## lock: re-resolve both lockfiles from pyproject.toml (needs uv)
lock:
	$(UV_COMPILE) --upgrade -o requirements.lock
	$(UV_COMPILE) --upgrade --group dev -c requirements.lock -o requirements-dev.lock

## fmt: format the code and apply safe lint fixes
fmt:
	ruff format .
	ruff check --fix .

## test: run the test suite
test:
	$(PYTHON) -m pytest

## ci: run every check CI runs
ci:
	$(PYTHON) scripts/ci.py

## generate: regenerate the SIEM content, the rule catalog and the generated documentation tables
generate:
	$(PYTHON) scripts/generate.py

## demo: evaluate the rule pack on synthetic telemetry
demo:
	$(PYTHON) -m prompthound demo

## verify-siem: run the generated queries in Splunk and the Kusto engine (needs Docker)
verify-siem:
	$(PYTHON) scripts/verify_siem.py --containers

## release: build the versioned release archives under dist/
release:
	$(PYTHON) scripts/release.py

## clean: remove build outputs and caches
clean:
	rm -rf build dist .coverage htmlcov .pytest_cache .mypy_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
