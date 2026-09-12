# Changelog

## 0.2.0 — 2026-09-12

- Emit executable Sentinel correlations; isolate tenants and align the offline
  evaluator with fixed UTC query buckets. Existing deployments must supply
  `user.tenant.id` and account for boundary misses.
- Correct KQL array equality, wildcard matching and cross-format state reuse.
- Add atomic telemetry normalization; package the schema and validate event
  times, schema versions, identities and finite metrics.
- Make coverage checks read-only and isolate demo tests from tracked artifacts.
- Harden release input selection, version validation, provenance and payload
  hashing; redact credential findings and scan unignored new files.
- Clarify experimental status, instrumentation requirements, signal limits and
  live SIEM qualification. Correct rule titles and metadata overclaims.


All notable changes to PromptHound are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version is stamped into each release bundle by `scripts/release.py` (it reads
`prompthound.__version__`). `scripts/ci.py` is the gate — run locally via `make ci`
and by GitHub Actions on every PR and push to main.

## [Unreleased]

### Added
- **Hosted CI** (`.github/workflows/ci.yml`): GitHub Actions now runs the same
  `scripts/ci.py` gate as `make ci` on every pull request and push to main
  (Python 3.11 + 3.12), so contributions are checked by exactly the sequence
  contributors run locally.
- **Shared correlation evaluator** (`prompthound/correlate.py`): the windowed
  `event_count` evaluation that was previously copy-pasted across six test files
  and the demo is now one library API (`correlation_hits`, `evaluate_rule_file`)
  with its own unit suite (`tests/test_correlate.py`).
- **Generator drift guard**: every shipped rule must now be targeted by a
  generator signature whose positive fires it and whose negative stays silent
  (`tests/test_generator.py`); a new rule cannot land without one.
- Generator signatures for the rules that previously had none —
  `denied_tool_retry_loop`, `tool_call_amplification_loop`, and
  `system_prompt_leaked_in_output` — and burst-shaped positives for
  `persona_safety_bypass_loop` and `pii_secret_exfiltration_in_output` (their
  correlation thresholds were unreachable with single-event samples). `make demo`
  now fires **15/15 rules** (previously 10/15).

### Fixed
- **Generated Sentinel KQL for boolean fields**: the pinned Kusto backend
  rendered Sigma boolean equality as `field =~ true` — KQL's `=~`/`!~` are
  string-only operators, so the queries for `unsanitized_output_to_sink` and
  `system_prompt_leaked_in_output` would not compile against a `bool` column.
  The Kusto pipeline now rewrites these to `==`/`!=` (with a regression test),
  and the committed `out/kusto/` artifacts are regenerated.
- Secrets scan: the `pragma: allowlist secret` marker is now honored on the line
  preceding a multiline private-key block, not only on its first line.

## [0.1.0] — 2026-06-04

First public cut: a forkable, contributable, releasable detection library.

### Added
- **Audit-log schema v0.1** (`schema/llm_audit_log.schema.json`, `docs/schema.md`)
  — vendor-neutral, OpenTelemetry-GenAI-aligned, with agent tool-call fields and
  Tier 1 / Tier 2 / derived-marker field classes (PRD §10, decisions D1/D4).
- **Rule pack — 15 Sigma rules across 7 categories**: prompt injection (direct +
  indirect), system-prompt extraction, jailbreak, data/PII exfiltration, agent
  tool-abuse, DoS / cost-abuse, and insecure output handling. Each rule is mapped
  to the OWASP LLM Top 10 (2025) and MITRE ATLAS, carries a detection tier, and
  ships positive + negative samples (PRD §11).
- **Author-once conversion** — pySigma pipelines emit Splunk SPL,
  `savedsearches.conf`, and Microsoft Sentinel KQL from one Sigma source, with a
  single schema→SIEM field map (`prompthound/`, `pipelines/`, decision D5).
- **Synthetic telemetry generator** + an offline, backend-agnostic test harness:
  `pytest` proves every rule fires on its malicious sample and stays silent on
  its benign one (`generator/`, `tests/`, PRD §12/§16).
- **Auto-generated coverage map** — OWASP × ATLAS, never hand-edited, built from
  rule metadata into an ATLAS Navigator layer + HTML/Markdown grids + an
  embeddable SVG; CI fails on a missing/unknown tag (`coverage/`, PRD §5/§17).
- **One-command offline demo** (`demo/run_demo.py`, `make demo`): generate
  telemetry → run the rule pack → print hits → build the coverage map.
- **Local CI runner** `scripts/ci.py` (PRD §16) with a defensive-posture +
  supply-chain **security stage** (pip-audit + bandit + a secrets scan), plus
  P1/P2 invariant tests.
- **Community readiness**: `CONTRIBUTING.md` (authoring standard + P1–P4),
  `docs/authoring.md` ("add a rule in 10 minutes"), GitHub issue forms (incl. a
  metadata-enforcing "New detection rule" form) and PR templates (incl. a
  "new rule" template), `SECURITY.md`, and `docs/THREAT-MODEL.md`.
- **Release builder** `scripts/release.py` (`make release`): regenerates all
  `out/` artifacts, stamps the version, and produces a byte-reproducible,
  versioned `out/dist/` bundle (SPL + KQL + coverage + `MANIFEST.json` with a
  per-file sha256 + licenses) — the "raw queries" v1 packaging of decision D8.
- **Pinned CI toolchain** (`requirements-dev.lock`) so the green pass is
  reproducible, not version-luck.

### Decisions ratified
- **D6 — OWASP Agentic Top 10:** agent rules (`rules/agent_tool_abuse/`) now carry
  a secondary `owasp-agentic.tNN` mapping (Tool Misuse / Privilege Compromise /
  Resource Overload). The metadata gate requires it for agent rules and the
  coverage map renders an Agentic section.
- **D7 — Licensing:** code and docs under **Apache-2.0** (`LICENSE`, `NOTICE`);
  detection content (rules + generated queries) under **DRL 1.1**
  (`LICENSE-RULES`).
- **D8 — Packaging:** raw-query bundle ships now via `scripts/release.py`;
  deployable per-SIEM packaging remains a documented fast-follow.

[Unreleased]: https://github.com/notacop38/prompthound/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/notacop38/prompthound/releases/tag/v0.1.0
