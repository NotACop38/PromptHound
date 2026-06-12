<!--
New detection rule PR. Metadata (OWASP + ATLAS + tier) and a positive AND
negative sample are required — the metadata gate + fire/silence tests enforce
them, and a reviewer will check P1 (signature, not payload).
See docs/authoring.md ("add a rule in 10 minutes").
-->

## Rule

- **Title:**
- **File:** `rules/<category>/<name>.yml`
- **Behavior (one rule = one behavior):**

## Required metadata (the gate fails without these)

- **OWASP LLM (2025):** `owasp-llm.llmNN` →
- **MITRE ATLAS technique/tactic:** `attack.atlas.aml.…` →
- **Detection tier:** `prompthound.tier.tN` →  <!-- T1 operational / T2 content -->
- **OWASP Agentic (agent rules only, PRD D6):** `owasp-agentic.tNN` →  <!-- omit if not under agent_tool_abuse/ -->

## Samples

- [ ] **Positive** (should-alert): `generator/samples/<name>.positive.json` — a log **signature**, not a working exploit (P1).
- [ ] **Negative** (should-not-alert): `generator/samples/<name>.negative.json` — a near-miss benign event.
- [ ] **Generator signature**: a `SampleSpec` in `prompthound/generator.py` with `rules=` pointing at the rule (the drift guard in `tests/test_generator.py` enforces this).
- **Honest false positives:** <!-- where it misfires and how to scope/tune -->

## Checklist

- [ ] Standard Sigma fields present (`title`, `id` UUID, `status`, `description`, `author`, `date`, `logsource: {product: llm_gateway}`, `detection`, `falsepositives`, `level`).
- [ ] `references:` to OWASP / ATLAS / CVE where relevant.
- [ ] Positive test fires and negative test is silent (`pytest`).
- [ ] Converts cleanly to SPL + KQL; `make release` run and the `out/` diff committed.
- [ ] `make ci` green.
- [ ] **P1–P4 honored** — this is a signature, nothing targets a live endpoint, no offensive how-to, Tier-1/derived preferred where equivalent.
