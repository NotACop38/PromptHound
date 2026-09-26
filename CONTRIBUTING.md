# Contributing

Contributions of rules, scenario cases, fixes and documentation are welcome.
This page covers the development setup and what a change needs before it is
merged. [docs/authoring.md](docs/authoring.md) explains how to write rules and
scenarios.

## Development setup

PromptHound needs Python 3.11 or later.

```bash
git clone https://github.com/NotACop38/PromptHound.git
cd PromptHound
python3 -m venv .venv
source .venv/bin/activate
make setup
```

`make setup` installs the pinned development dependencies from
`requirements-dev.lock`, with every package verified against its hash, and then
the package itself in editable mode.

## Checks

| Command | Runs |
|---|---|
| `make ci` | The full gate, exactly as CI runs it: formatting, lint, type checks, tests with coverage, generated-artifact drift, and security checks. |
| `make test` | The test suite. |
| `make fmt` | Formatting and safe lint fixes. |
| `prompthound test` | Every scenario case and the publication requirements. |
| `make generate` | Regenerates the SIEM content, the rule catalog and the generated documentation tables. |
| `make verify-siem` | Runs the generated queries in Splunk and the Kusto engine ([verification.md](docs/verification.md)); needs Docker. |

## What a change needs

- `make ci` passes.
- Behavior changes come with tests. A new or changed rule comes with scenario
  cases that alert, stay silent, and test its boundaries, and with an entry in
  `MUTATIONS` in `tests/test_scenarios.py`.
- Generated files are regenerated with `make generate` and committed; CI fails
  when they are out of date. Do not edit files under `siem/`, `docs/rules.md` or
  `docs/atlas-navigator-layer.json`, or the marked tables in `README.md` and
  `docs/schema.md`, by hand.
- A change to conversion code, a rule's detection logic or the pinned pySigma
  packages is also verified with `make verify-siem`. State in the pull request
  whether you ran it.
- Scenario text describes attacks as log signatures. Do not submit working
  payloads, operational jailbreaks or real credentials; the payload guard
  rejects the common forms, and review rejects the rest.
- User-visible changes get an entry under *Unreleased* in
  [CHANGELOG.md](CHANGELOG.md).

## Dependencies

Runtime dependencies are declared in `pyproject.toml` and locked, with hashes,
for every platform in `requirements.lock`; development tools are locked in
`requirements-dev.lock`. To change a dependency, edit `pyproject.toml` and run
`make lock`, which needs [uv](https://docs.astral.sh/uv/). An upgrade of pySigma
or a pySigma backend can change generated queries: regenerate, review the diff,
and run `make verify-siem`.

## Pull requests

Keep a pull request to one purpose and describe what changed and why. Use the
pull request template; for a new rule, use the rule template
(`?template=new_rule.md`).

## Licensing

By contributing, you agree that your contribution is licensed under the
repository's licenses: detection content (`rules/`, `siem/`) under the
[Detection Rule License 1.1](LICENSE-RULES), everything else under the
[Apache License 2.0](LICENSE).
