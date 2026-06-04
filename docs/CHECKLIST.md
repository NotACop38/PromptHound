# PromptHound — Engineering Checklist

> Companion to `PRD.md` (source of truth). Work top-to-bottom; don't start a phase before the prior phase's exit criteria are met. 🤖 = offload to Claude Code; 🧠 = decide/design with the human.

Guiding principle: prove the whole pipeline on ONE rule (Phase 1) before building breadth (Phase 3).

## Phase 0 — Foundations
Goal: lock keystone decisions; stand up an empty-but-correct skeleton.
Exit: schema v0.1 validating; taxonomy agreed; skeleton builds; `pytest` runs with zero rules; deps pinned.
- [ ] 🧠 Confirm D7 license, D9 name check.
- [ ] 🧠 Finalize schema v0.1 (PRD §10).
- [ ] 🤖 Write schema/llm_audit_log.schema.json.
- [ ] 🤖 Write docs/schema.md (+ the two example events).
- [ ] 🧠 Confirm taxonomy (PRD §11) and the vertical-slice rule.
- [ ] 🤖 Scaffold repo layout (PRD §14).
- [ ] 🤖 Pin deps in a lockfile.
- [ ] ✅ Smoke-test: a throwaway rule converts to SPL + KQL.
- [ ] 🤖 Bootstrap tests/ so pytest exits 0 with no rules.

## Phase 1 — Vertical slice
Goal: one rule fully end-to-end.
Exit: slice rule converts to SPL + KQL; positive + negative samples validate; pytest proves fire/silence; conversion snapshot-tested.
### 1a — selection-match rule
- [ ] 🧠 Decide the offline test-harness mechanism (PRD §12).
- [ ] 🤖 Author rules/system_prompt_extraction/extract_system_prompt_markers.yml (OWASP llm07, ATLAS AML.T0056, tier t2).
- [ ] 🤖 Build pySigma pipelines (splunk + kusto/sentinelasim).
- [ ] 🤖 Generator: positive + negative samples.
- [ ] 🤖 Wire conversion → SPL + KQL.
- [ ] 🤖 Tests: fire, silence, schema-validity, conversion snapshot.
- [ ] 🧠 Hand-review generated SPL + KQL.
### 1b — correlation/threshold rule
- [ ] 🤖 Author rules/dos_cost_abuse/token_cost_spike_per_principal.yml (tier t1; llm10; AML.T0034 + AML.T0029).
- [ ] 🤖 Generator: burst vs normal usage.
- [ ] ✅ Confirm correlation rule converts + passes fire/silence.
- [ ] 🧠 Capture lessons into docs/authoring.md.

## Phase 2 — Local CI runner
Goal: one local command runs the full check sequence; no hosted CI.
Exit: `python scripts/ci.py` runs lint → schema-validate → convert → fire/silence → metadata gate and exits non-zero on failure.
- [ ] 🤖 scripts/ci.py (stdlib): ordered stages with PASS/FAIL banners, non-zero exit on failure (PRD §16).
- [ ] 🤖 Metadata gate (fail if any rule lacks OWASP + ATLAS + tier).
- [ ] 🤖 Conversion-snapshot check.
- [ ] 🤖 Regenerate SPL/KQL into out/.
- [ ] ✅ Confirm a deliberately-broken rule makes the runner exit non-zero, then revert.

## Phase 3 — Rule pack breadth
Goal: fill the taxonomy, one category at a time, each rule with samples + tests.
Exit: ≥1 rule per category (PRD §11), all green, each with honest falsepositives.
- [ ] 🤖 DoS + cost-abuse (LLM10).
- [ ] 🤖 Insecure output handling (LLM05).
- [ ] 🤖 System-prompt extraction success-variant (LLM07).
- [ ] 🤖 Direct prompt injection (LLM01 / AML.T0051.000).
- [ ] 🤖 Indirect prompt injection (LLM01 / AML.T0051.001) — EchoLeak / CVE-2025-32711.
- [ ] 🤖 Jailbreaks (LLM01×LLM06 / AML.T0054).
- [ ] 🤖 Data / PII exfiltration (LLM02 / AML.T0024).
- [ ] 🤖 Agent tool-abuse (LLM06 / AML.TA0015) — CurXecute / CVE-2025-54135/6.
- [ ] 🧠 Per category: review 1–2 rules for generalizability (P1) + FP honesty.
- [ ] 🧠 [OPEN] D6 — OWASP Agentic Top 10 secondary tag?

## Phase 4 — Coverage map
Goal: auto-generated, never-stale OWASP × ATLAS coverage.
Exit: coverage/build_coverage.py emits the map from metadata; CI rebuilds it; not hand-editable.
- [ ] 🧠 Choose output: ATLAS Navigator layer JSON + HTML/Markdown grid.
- [ ] 🤖 Build the generator (Jinja2).
- [ ] 🤖 Render OWASP grid + ATLAS coverage + Tier breakdown.
- [ ] 🤖 CI step regenerates and fails on error.
- [ ] ✅ Spot-check against the rule pack.

## Phase 5 — Demo + README
Goal: the 10-second value hook and one-command wow.
Exit: demo/run_demo.py does generate → detect → hits + coverage map, from a clean clone.
- [ ] 🤖 demo/run_demo.py + `make demo`.
- [ ] ✅ Test on a clean clone / fresh venv.
- [ ] 🧠 README: value prop above the fold; demo + coverage visuals; quickstart; honest comparison (PRD §6); OWASP + ATLAS badges; contribution pointer.
- [ ] 🤖 Example generated SPL + KQL snippets in the README.

## Phase 6 — Community readiness
Goal: forkable, contributable, trustworthy.
Exit: a stranger can understand the line, add a rule, and get it merged via CI.
- [ ] 🧠 [OPEN] D7 — LICENSE.
- [ ] 🤖 CONTRIBUTING.md (authoring standard + P1–P4).
- [ ] 🤖 docs/authoring.md ("add a rule in 10 minutes").
- [ ] 🤖 Issue/PR templates incl. a "new rule" template enforcing metadata + samples.
- [ ] 🤖 SECURITY.md + docs/THREAT-MODEL.md (non-goals).
- [ ] 🧠 [OPEN] D8 — deployable packaging fast-follow.
- [ ] 🧠 Pre-launch: name/branding, badges, repo description, topics.

## Cross-cutting
- [ ] Keep PRD.md and this checklist in sync; log decision changes in the PRD.
- [ ] Every new rule: positive + negative sample, OWASP + ATLAS + tier tags, honest FPs, P1 compliance.
- [ ] Treat any pySigma/backend version bump as a reviewed change with full SPL/KQL regeneration.
- [ ] Re-verify framework specifics (OWASP numbering, ATLAS IDs, OTel field names) at author time.
