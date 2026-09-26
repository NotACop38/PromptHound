# Threat model

PromptHound is detection content and offline tooling: Sigma rules, scenario
files, a synthetic data generator, converters to SPL and KQL, and a command-line
tool. It runs on a workstation or a CI runner, reads files, and writes files. It
is not in the request path of any LLM application and contacts no model.

This page covers the risks to PromptHound's users that come from PromptHound
itself. Vulnerabilities in a user's gateway, SIEM or model provider are outside
it; so is the question of whether a rule detects a given attack, which is a
matter of detection engineering (see [verification.md](verification.md)).

## Assets

| Asset | Why it matters |
|---|---|
| Rules and generated SIEM content | Users deploy them. A query that silently differs from its rule is a detection gap nobody knows about. |
| Audit event schema | The contract between instrumentation and rules. |
| Scenario files and generated data | Public test data. They must describe attacks as log signatures, not supply working payloads. |
| Release bundles | Users install them without rebuilding. |
| Telemetry processed by the CLI | `validate`, `normalize`, `evaluate` and `readiness` read production audit events, which can contain prompts, responses and personal data. |

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| A generated query matches different events than its rule. | The loader accepts only constructs with verified cross-engine semantics; conformance cases and scenario datasets run in Splunk and the Kusto engine and must match the offline evaluator exactly; `scripts/generate.py --check` fails CI when committed SIEM content drifts from its source. |
| The repository becomes a source of working exploits. | `prompthound.payload_guard` rejects encoded blobs, shell and code execution, SQL-injection mechanics and credential-shaped strings in scenario content and generated data; the test suite scans every rule file. |
| Malicious input files. | YAML is parsed with safe loaders only; events are parsed as JSON, objects with duplicate keys are rejected, and every event is validated against the schema before use. Nothing in an input file is executed. |
| Exposure of telemetry. | The CLI makes no network connections. `normalize` writes its output atomically with owner-only permissions (`0600`). The schema separates content fields from derived fields so that rules can run without retaining raw text. |
| Network access during checks. | pySigma's validators that download MITRE data are excluded from the policy check; a test asserts that no pySigma MITRE cache is ever opened. Only two development scripts use the network: `update_atlas.py` (HTTPS to GitHub) and `verify_siem.py` (the engine URLs it is given). |
| A committed credential. | `scripts/security.py` scans tracked and unignored new files for credential shapes on every CI run. |
| A vulnerable or substituted dependency. | Universal lockfiles with hashes for every artifact, installed with `--require-hashes`; pip-audit on both lockfiles on every CI run. |
| A tampered or irreproducible release. | Release bundles are byte-reproducible from their commit and carry a manifest with the SHA-256 of every file and the source commit; the release script refuses a dirty checkout or stale generated content. Bundles are not signed. |
| Unsafe first-party code. | bandit on `src/` and `scripts/`; every exception is a reviewed `# nosec` with its reason. Subprocesses run fixed argument lists, never a shell. |

## Assumptions

- The machine that runs PromptHound is trusted. An attacker with write access
  to the working tree, the Python environment or local caches is out of scope.
- Rules, scenarios and the vendored catalogs arrive through reviewed changes.
  Loading an untrusted rule file is safe, but review generated queries before
  deploying them, as with any detection content.

## Accepted risks

| Risk | Rationale |
|---|---|
| CVE-2025-69872 in `diskcache` (a pySigma dependency): unpickling of cache files. | No fixed release exists. PromptHound never opens a diskcache cache (asserted by `tests/test_security.py`), and exploitation requires write access to the local cache directory, which the assumptions exclude. Recorded in `ACCEPTED_ADVISORIES` in `scripts/security.py`; revisit when a fix ships. |
| KQL's `=~` and `in~` treat U+212A KELVIN SIGN as `k`. | The only known difference between the engines; documented in [authoring.md](authoring.md#not-supported) and [deployment.md](deployment.md#known-differences). |
| The OpenTelemetry GenAI conventions are still in development. | Field names can change upstream. The schema is versioned, and a change is a new schema version with a migration table. |

## Out of scope

- Runtime enforcement: PromptHound does not block or rewrite traffic.
- Offensive use: PromptHound contains no attack tooling and targets no live
  system.
- Detection efficacy: a missed attack or a false positive is a rule defect to
  report as an issue, not a security vulnerability.
