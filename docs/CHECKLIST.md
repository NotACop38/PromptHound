# PromptHound — Engineering Checklist

> Deployment qualification remains open. Historical phase checkmarks establish
> offline implementation only. The current evidence contract is in
> [deployment.md](deployment.md), with review decisions in [REVIEW.md](REVIEW.md).

> Companion to `PRD.md` (source of truth). Phases 0–6 shipped in v0.1.0 (see
> `CHANGELOG.md`); their checked items are the record. Open items live in
> "Post-0.1.0" and "Cross-cutting" below. 🤖 = offload to Claude Code; 🧠 =
> decide/design with the human.

Guiding principle: prove the whole pipeline on ONE rule (Phase 1) before building breadth (Phase 3).

## Phase 0 — Foundations
Goal: lock keystone decisions; stand up an empty-but-correct skeleton.
Exit: schema v0.1 validating; taxonomy agreed; skeleton builds; `pytest` runs with zero rules; deps pinned.
- [x] 🧠 Confirm D7 license, D9 name check.
- [x] 🧠 Finalize schema v0.1 (PRD §10).
- [x] 🤖 Write prompthound/llm_audit_log.schema.json.
- [x] 🤖 Write docs/schema.md (+ the two example events).
- [x] 🧠 Confirm taxonomy (PRD §11) and the vertical-slice rule.
- [x] 🤖 Scaffold repo layout (PRD §14).
- [x] 🤖 Pin deps in a lockfile.
- [x] ✅ Smoke-test: a throwaway rule converts to SPL + KQL.
- [x] 🤖 Bootstrap tests/ so pytest exits 0 with no rules.

## Phase 1 — Vertical slice
Goal: one rule fully end-to-end.
Exit: slice rule converts to SPL + KQL; positive + negative samples validate; pytest proves fire/silence; conversion snapshot-tested.
### 1a — selection-match rule
- [x] 🧠 Decide the offline test-harness mechanism (PRD §12): parse each rule with
  pySigma and evaluate its fully-resolved condition tree against plain `dict`
  events — no live SIEM, no SPL/KQL execution. See `prompthound/matcher.py`.
- [x] 🤖 Author rules/system_prompt_extraction/extract_system_prompt_markers.yml (OWASP llm07, ATLAS AML.T0056, tier t2).
- [x] 🤖 Build pySigma pipelines (splunk + kusto/sentinelasim) — shared toolchain
  from the Phase 0/1 conversion work (`pipelines/`, `prompthound/convert.py`).
- [x] 🤖 Generator: positive + negative samples.
- [x] 🤖 Wire conversion → SPL + KQL (`prompthound/convert.py`; `out/` snapshot via `scripts/release.py`).
- [x] 🤖 Tests: fire, silence (`test_rules.py`), schema-validity (`test_schema.py`), conversion snapshot (`out/` + `scripts/ci.py`).
- [x] 🧠 Hand-review generated SPL + KQL (committed under `out/`).
### 1b — correlation/threshold rule
- [x] 🤖 Author rules/dos_cost_abuse/token_cost_spike_per_principal.yml (tier t1; llm10; AML.T0034 + AML.T0029).
- [x] 🤖 Generator: burst vs normal usage.
- [x] ✅ Confirm correlation rule converts + passes fire/silence. (SPL: full event_count correlation; KQL: base detection + manual summarize — Kusto backend has no correlation support.)
- [x] 🧠 Capture lessons into docs/authoring.md.

## Phase 2 — Local CI runner
Goal: one command runs the full check sequence — locally and (post-0.1.0) in GitHub Actions.
Exit: `python scripts/ci.py` runs lint → schema-validate → convert → fire/silence → metadata gate and exits non-zero on failure.
- [x] 🤖 scripts/ci.py (stdlib): ordered stages with PASS/FAIL banners, non-zero exit on failure (PRD §16).
- [x] 🤖 Metadata gate (fail if any rule lacks OWASP + ATLAS + tier).
- [x] 🤖 Conversion-snapshot check.
- [x] 🤖 Regenerate SPL/KQL into out/.
- [x] ✅ Confirm a deliberately-broken rule makes the runner exit non-zero, then revert.

## Phase 3 — Rule pack breadth
Goal: fill the taxonomy, one category at a time, each rule with samples + tests.
Exit: ≥1 rule per category (PRD §11), all green, each with honest falsepositives.
- [x] 🤖 DoS + cost-abuse (LLM10).
- [x] 🤖 Insecure output handling (LLM05).
- [x] 🤖 System-prompt extraction success-variant (LLM07).
- [x] 🤖 Direct prompt injection (LLM01 / AML.T0051.000).
- [x] 🤖 Indirect prompt injection (LLM01 / AML.T0051.001) — EchoLeak / CVE-2025-32711.
- [x] 🤖 Jailbreaks (LLM01×LLM06 / AML.T0054).
- [x] 🤖 Data / PII exfiltration (LLM02 / AML.T0024).
- [x] 🤖 Agent tool-abuse (LLM06 / tool-use and resource signals) — CurXecute / CVE-2025-54135/6.
- [x] 🧠 Per category: review 1–2 rules for generalizability (P1) + FP honesty.
- [x] 🧠 D6 — OWASP Agentic Top 10 secondary tag: **yes**. Agent rules carry a
  secondary `owasp-agentic.tNN` (OWASP Agentic AI — Threats and Mitigations,
  T1–T15); the metadata gate requires it for agent rules and the coverage map
  renders an Agentic section.

## Phase 4 — Coverage map
Goal: auto-generated, generated OWASP × ATLAS coverage.
Exit: coverage/build_coverage.py emits the map from metadata; CI rebuilds it; not hand-editable.
- [x] 🧠 Choose output: ATLAS Navigator layer JSON + HTML/Markdown grid + embeddable SVG card (`docs/assets/coverage.svg`, generated; gated by the CI coverage stage).
- [x] 🤖 Build the generator (Jinja2).
- [x] 🤖 Render OWASP grid + ATLAS coverage + Tier breakdown.
- [x] 🤖 CI step regenerates and fails on error (`scripts/ci.py` coverage-build stage; unknown/missing tags fail).
- [x] ✅ Spot-check against the rule pack (`tests/test_coverage.py`).

## Phase 5 — Demo + README
Goal: the 10-second value hook and one-command wow.
Exit: demo/run_demo.py does generate → detect → hits + coverage map, from a clean clone.
- [x] 🤖 demo/run_demo.py + `make demo`.
- [x] ✅ Test on a clean clone / fresh venv.
- [x] 🧠 README: value prop above the fold; demo + coverage visuals; quickstart; honest comparison (PRD §6); OWASP + ATLAS badges; contribution pointer.
- [x] 🤖 Example generated SPL + KQL snippets in the README (system-prompt extraction, SPL + KQL side by side from `out/`).

## Phase 6 — Community readiness
Goal: forkable, contributable, trustworthy.
Exit: a stranger can understand the line, add a rule, and get it merged via CI.
- [x] 🧠 D7 — LICENSE: **Apache-2.0** (code & docs) + **DRL 1.1** (detection content under `rules/` + generated `out/`). See `LICENSE`, `LICENSE-RULES`, `NOTICE`.
- [x] 🤖 CONTRIBUTING.md (authoring standard §15 + P1–P4 + the merge gate).
- [x] 🤖 docs/authoring.md ("add a rule in 10 minutes" walkthrough + reference).
- [x] 🤖 Issue/PR templates: metadata-enforcing "New detection rule" issue form, bug-report form, default PR template + a "new rule" PR template.
- [x] 🤖 SECURITY.md + docs/THREAT-MODEL.md (non-goals).
- [x] 🤖 Security stage enforced locally: `scripts/ci.py` security stage (pip-audit + bandit + secrets scan), runnable alone via `--only security`; P1/P2 invariant tests (`tests/test_invariants.py`).
- [x] 🤖 Release builder `scripts/release.py`: regenerate all `out/` artifacts, stamp the version, build a reproducible bundle (`out/dist/`); `CHANGELOG.md` added.
- [x] 🧠 D8 — packaging: raw-query versioned bundle ships via `scripts/release.py`; deployable per-SIEM packaging is a documented fast-follow.
- [x] 🤖 Pinned local-CI toolchain (`requirements-dev.lock`) so the green pass is reproducible.

## Post-0.1.0
Goal: keep the gate honest as the pack and contributor base grow.
- [x] 🤖 Hosted CI: GitHub Actions runs `scripts/ci.py` on every PR and push to main (`.github/workflows/ci.yml`), Python 3.11 + 3.12.
- [x] 🤖 Shared correlation evaluator (`prompthound/correlate.py`) used by the demo and every correlation test; unit suite in `tests/test_correlate.py`.
- [x] 🤖 Generator drift guard: every shipped rule must have a generator signature that fires it (`tests/test_generator.py`); `make demo` proves 15/15 rules.
- [x] 🤖 Fix generated Sentinel KQL boolean comparisons (`=~ true` → `== true`; the Kusto backend's string operator does not compile against bool columns).
- [ ] 🧠 Pre-launch: name check (**D9**), repo description, topics. (Badges + branding in README done.)
- [ ] 🧠 Deployable per-SIEM packaging (Splunk app / Sentinel ARM template) — the documented D8 fast-follow.

## Cross-cutting
- [ ] Keep PRD.md and this checklist in sync; log decision changes in the PRD.
- [ ] Every new rule: positive + negative sample, OWASP + ATLAS + tier tags, honest FPs, P1 compliance.
- [ ] Treat any pySigma/backend version bump as a reviewed change with full SPL/KQL regeneration.
- [ ] Re-verify framework specifics (OWASP numbering, ATLAS IDs, OTel field names) at author time.
