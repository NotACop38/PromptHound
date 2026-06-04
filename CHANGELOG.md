# Changelog

All notable changes to PromptHound are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version is stamped into each release bundle by `scripts/release.py` (it reads
`prompthound.__version__`). There is no hosted CI; `scripts/ci.py` is the gate.

## [Unreleased]

_Nothing yet._

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
