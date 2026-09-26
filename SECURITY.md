# Security policy

## Reporting a vulnerability

Report vulnerabilities in PromptHound privately through a
[GitHub security advisory](https://github.com/NotACop38/PromptHound/security/advisories/new).
Do not open a public issue.

Include what you found, where (file and line, or the command), how to reproduce
it, and the impact you expect. The maintainer aims to acknowledge reports within
seven days. PromptHound has no bug bounty; reporters who wish to be are credited
in the advisory.

## Scope

In scope:

- vulnerabilities in the `prompthound` package or the scripts under `scripts/`,
  such as unsafe parsing of rule, scenario or event files, or path handling;
- a generated query that matches different events than its rule, where the
  difference hides an attack from the SIEM;
- a working exploit payload or a real credential committed to the repository;
- a vulnerability in a dependency that PromptHound's use of the dependency
  reaches.

Out of scope:

- a rule that misses an attack or produces false positives; report it as an
  issue;
- vulnerabilities in Splunk, Microsoft Sentinel, or a gateway that emits the
  audit events.

[docs/threat-model.md](docs/threat-model.md) describes the assets, threats,
mitigations and accepted risks.

## Supported versions

Security fixes are made on the latest release.

## Supply chain

Dependencies are locked with hashes for every platform (`requirements.lock`,
`requirements-dev.lock`) and installed with `--require-hashes`. Every CI run
audits both lockfiles with pip-audit, scans first-party code with bandit, and
scans the repository for committed credentials (`python scripts/security.py`).
An advisory without a fixed release is accepted only with a written
justification in `scripts/security.py`.
