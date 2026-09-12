# Project review — 2026-09-12

## Product decision

Keep PromptHound as a small detection-content and telemetry-contract project.
Its useful contribution is editable cross-SIEM rules with runnable fixtures.
A pivot into a guardrail, collector or general AI-security platform would add
unvalidated scope without addressing the current reliability problems.

The previous presentation conflated fixture success with production readiness,
taxonomy tags with coverage, derived features with built-in detection, and
static thresholds with anomalies. Those distinctions now appear at the front
of the README and in deployment guidance. Community stars are not a useful
primary success criterion; reproducible deployment and actionable alerts are.

## Findings and decisions

| Area | Finding | Disposition |
|---|---|---|
| Correlation conversion | KQL omitted executable aggregation and could alert on ordinary base events | Emit validated event-count aggregation and thresholds; reject unsupported shapes |
| Evaluator | Sliding-window tests disagreed with Splunk's fixed buckets | Align to fixed UTC buckets; test the boundary blind spot explicitly |
| Tenant isolation | Shared user/conversation IDs pooled events across tenants | Group every correlation by tenant; document identity namespacing and missing-key exclusion |
| KQL types | String-array columns used scalar equality/list comparisons | Emit case-insensitive array membership |
| Wildcards | Offline prefix/suffix patterns matched in the middle; KQL list optimization discarded wildcard order | Preserve full-value wildcard semantics and disable the lossy optimization |
| Input contract | Dotted event fields did not match underscore query columns; timestamps and nonfinite metrics passed validation | Add an atomic normalization adapter and validate usable event times, version and numeric values |
| Packaging | Installed generator could not locate its schema; `coverage` imports conflicted with coverage.py | Package the canonical schema and move internal coverage code into the project namespace |
| CI | Coverage regeneration repaired stale artifacts instead of rejecting them; demo tests also rewrote snapshots | Read-only snapshot check and isolated demo outputs |
| Release | Arbitrary files under output directories could enter bundles; provenance/version/manifest claims were incomplete | Restrict to expected current artifacts, require release inputs, validate versions, and hash all payloads |
| Secrets | Modern provider-token forms could be missed; discovered credentials were echoed into logs | Extend credential patterns, include new files, redact finding excerpts |
| Supply chain | Diskcache was incorrectly described as optional CLI-only | Correct the runtime dependency exception; remove unnecessary CLI packages from the base install; audit the fully pinned dev graph and update vulnerable pip/msgpack versions |
| Rule interpretation | Some titles implied confirmed exfiltration, extraction success or ordered tool use | Describe observable markers and co-occurrence; retain filenames and IDs for continuity |
| Taxonomy | The derived-only sensitive-output rule advertised a raw-content requirement; generic agent activity claimed command-and-control coverage | Correct that tier and unsupported tactic tags; label inventory as mappings |

## Validation boundaries

Regression tests cover the confirmed defects, existing per-rule fixtures,
normalization failure handling, release contamination and manifest contents.
The local CI gate checks formatting, lint, types, schema, deterministic query
and coverage snapshots, the full test suite, dependency advisories, SAST and
credential patterns. The demo and wheel installation are checked separately.

This is a code and product review, not proof of attack-detection completeness.
There is no representative independent corpus, measured production false-positive
rate, or live Splunk/Sentinel qualification. The next product milestone is an
observed deployment following `deployment.md`, with a benign-traffic baseline,
field-completeness measurements and per-rule query results. More rule count,
market claims or visual polish cannot substitute for that evidence.
