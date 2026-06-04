# Add a rule in 10 minutes

> **Source of truth:** [`PRD.md` §15 (authoring standard)](./PRD.md#15-rule-authoring-standard)
> and the defensive posture in [§8 (P1–P4)](./PRD.md#8-defensive-posture-standing-principles).
> The bar: a stranger can write a rule, prove it, and get it merged via CI. This
> guide is the fast path; [`CONTRIBUTING.md`](../CONTRIBUTING.md) is the full standard.

A PromptHound rule is **one Sigma file + a positive and a negative sample**. The
local CI runner converts it to Splunk SPL and Sentinel KQL and proves it fires on
the malicious sample and stays quiet on the benign one. Here is the whole loop.

## Setup (once)

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.lock -r requirements-dev.lock -e .   # or: make setup
```

## The loop

### 1. Pick one behavior and a category

One rule = one behavior. Drop it under the matching `rules/<category>/`
(`prompt_injection`, `system_prompt_extraction`, `jailbreak`,
`data_exfiltration`, `agent_tool_abuse`, `dos_cost_abuse`, `insecure_output`).
Detect a **log signature**, not a working exploit (P1).

### 2. Write the Sigma rule

Reference schema fields by their **dotted** name (e.g.
`guardrail.input.categories`); the pipeline flattens them to SIEM columns. A
minimal selection rule:

```yaml
# rules/insecure_output/example_unsafe_html_render.yml
# Sample spec: generator/samples/example_unsafe_html_render.{positive,negative}.json
title: Unsanitized model output rendered to HTML
id: 00000000-0000-0000-0000-000000000000   # generate a fresh UUID
status: experimental
description: >
  Detects model output that reached an HTML sink without sanitization — the
  log signature of LLM05 Improper Output Handling.
references:
  - https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
author: Your Name
date: 2026-06-04
tags:
  - owasp-llm.llm05            # required: OWASP LLM Top 10 (2025)
  - attack.t1059               # required: >=1 ATLAS/ATT&CK technique mapping
  - prompthound.tier.t1        # required: detection tier (t1 operational / t2 content)
logsource:
  product: llm_gateway         # required: aligns to the audit-log schema (PRD §10)
detection:
  sink:
    output.sink: html_render
  unsanitized:
    output.rendered_unsanitized: true
  condition: sink and unsanitized
falsepositives:
  - Trusted templates rendered as HTML by design — scope by app.name.
level: medium
```

**Required metadata** (the gate fails the build without it): `owasp-llm.llmNN`,
at least one `attack.atlas.aml.*` (or `attack.tNNNN` where genuine),
`prompthound.tier.tN`. **Agent rules** (`rules/agent_tool_abuse/`) additionally
require a secondary `owasp-agentic.tNN` tag (PRD D6) — see
[agent rules](#agent-rules-the-owasp-agentic-secondary-tag) below.

### 3. Add a positive and a negative sample

Create `generator/samples/<stem>.positive.json` (should alert) and
`<stem>.negative.json` (a near-miss that should **not**), where `<stem>` matches
the rule filename. Each is one schema-valid event — or a JSON **array** of events
for a correlation rule (a burst vs. normal usage). Keep the positive a
*signature*, never a payload (P1).

### 4. Prove it (fire / silence)

```bash
pytest -q                      # or: make test
```

Add the rule to its category's test (e.g. `tests/test_insecure_output.py`) so
`pytest` asserts the positive fires and the negative is silent. The harness
evaluates the rule logic offline — no running SIEM (see below).

### 5. Convert + rebuild coverage

```bash
make release                   # rewrites out/ (SPL, KQL, savedsearches) + coverage map
```

Commit the resulting `out/` diff. (`make release` also stamps a versioned bundle
under the git-ignored `out/dist/`.)

### 6. Green CI, then PR

```bash
make ci                        # the merge gate — every stage must pass
```

Open a PR with the **new-rule template** (append `?template=new_rule.md` to the
PR URL). Done.

---

## Required fields (PRD §15)

- **Standard Sigma:** `title`, `id` (UUID), `status`, `description`, `author`,
  `date`, `logsource`, `detection`, `falsepositives`, `level`.
- **PromptHound tags:** `owasp-llm.llmNN`, `attack.atlas.aml.tNNNN` /
  `attack.tNNNN` (only when a technique genuinely maps), `prompthound.tier.tN`,
  and `owasp-agentic.tNN` for agent rules.
- **`logsource`** aligned to our schema (`product: llm_gateway`).
- **A reference to the sample spec** in `generator/samples/`.
- **`references:`** to OWASP / ATLAS / CVE where relevant.

**Conventions:** one rule = one behavior; prefer Tier-1 / derived fields where
equivalent (P4); document expected false positives honestly; never encode a
working exploit (P1).

## Agent rules: the OWASP Agentic secondary tag

Rules under `rules/agent_tool_abuse/` carry a **secondary** OWASP Agentic AI —
Threats and Mitigations mapping in addition to the OWASP LLM Top 10 (PRD D6). Add
exactly the threat(s) the behavior matches, zero-padded to mirror `llmNN`:

```yaml
tags:
  - owasp-llm.llm06            # primary taxonomy stays the OWASP LLM Top 10
  - owasp-agentic.t02          # secondary: T2 Tool Misuse (agent rules only)
  - attack.atlas.aml.ta0015
  - prompthound.tier.t1
```

The catalog of valid `owasp-agentic.tNN` ids (T1–T15) lives in
`coverage/build_coverage.py` (`OWASP_AGENTIC`); an un-catalogued id fails the
build wherever it appears. The metadata gate **requires** at least one agentic
tag for agent-category rules; non-agent rules don't need one (the secondary
mapping is for agent behaviors).

## Offline test harness (PRD §12)

Rules are proven **without a running SIEM**. The harness
(`prompthound/matcher.py`) parses each rule with pySigma — the same library that
emits the SPL/KQL — and walks pySigma's own fully-resolved condition trees
(every `rule.detection.parsed_condition[i].parse()`, OR-ed) against a plain
`dict` event. Using pySigma's parser instead of re-implementing Sigma's grammar
keeps the harness faithful to the conversion source of truth.

- **Fire/silence** tests (`tests/test_rules.py` and the per-category modules) run
  the matcher against `generator/samples/<stem>.{positive,negative}.json`.
- **Conversion** is exercised separately: the byte-stable record is the committed
  `out/` snapshot, written by `scripts/release.py` and checked for drift by
  `scripts/ci.py`.
- The matcher supports the Sigma subset the pack uses (`and`/`or`/`not`,
  `contains` wildcards, numeric `gte`/`gt`/`lte`/`lt`, equality, null — where
  `field: null` matches an absent *or* explicitly-null field). It raises on
  unsupported nodes rather than passing silently, so it fails loudly when a new
  rule outgrows it.
- **Correlation rules** (e.g.
  `dos_cost_abuse/token_cost_spike_per_principal.yml`) add windowed aggregation
  the single-event matcher can't express. Their tests reuse `rule_matches` to
  filter the *base* rule per event, then group by the correlation's `group-by`
  over its `timespan` and apply the threshold (`tests/test_token_cost_spike.py`).
  Their samples are therefore JSON **arrays** of events.

## Sigma → SPL + KQL conversion (toolchain)

Author once in Sigma; the local CI runner emits Splunk SPL and Sentinel KQL via
pySigma (PRD §9 **D5**, §12). The pieces:

- **`prompthound/convert.py`** — `convert_rule(path)` returns a `ConversionResult`
  with `.spl`, `.savedsearches` (a `savedsearches.conf` document), and `.kql`.
- **`pipelines/prompthound_splunk.py`** — Splunk backend, target `splunk`. Emits
  the `default` plain-SPL format and the `savedsearches` (`savedsearches.conf`)
  format.
- **`pipelines/prompthound_kusto.py`** — Kusto backend, target `kusto`. Uses the
  **`sentinelasim`** pipeline by default with **`azure_monitor`** as a documented
  fallback (PRD §17). There is **no** `pysigma-backend-sentinel` — it does not
  exist (D5).

pySigma 1.0.0's **factory-pattern** pipelines apply: each pipeline is a function
returning a fresh `ProcessingPipeline`. Everything is pinned in
`requirements.lock`; a pySigma/backend bump is a reviewed change with full
regeneration (PRD §13, §17).

### Field-mapping decisions

The audit-log schema (PRD §10) uses OpenTelemetry-style **dotted** field names
(`gen_ai.usage.input_tokens`). The canonical schema → SIEM mapping lives in one
place — **`prompthound/fieldmap.py`** — and both backends import it, so a rename
changes Splunk and Sentinel together.

- **Rule:** dots become underscores — `a.b.c` → `a_b_c`.
- **Why map at all:** KQL column references cannot contain dots, so the mapping
  is *mandatory* for Kusto; we apply the **same** map to Splunk so a schema field
  resolves to the **identical column** in both SIEMs.
- **Target tables/sources:** SPL assumes a flattened PromptHound audit
  index/source (no table prefix). KQL is prepended with a Sentinel custom-log
  table, default **`PromptHoundAuditLog_CL`** (override via
  `convert_rule(..., query_table=...)`).
- **`logsource`:** every rule uses `product: llm_gateway`; the field mapping only
  fires for that logsource.

### Correlation rules and the KQL aggregation gap

Sigma **correlation** rules (per-principal counts over a window) convert unevenly
across backends, so `convert_rule` treats them specially:

- **SPL** — the Splunk backend emits the full `event_count` correlation. Author
  cost/token-spike rules as an `event_count` over a base rule rather than a literal
  token sum (the Splunk backend has no `value_sum`).
- **KQL** — the Kusto backend (1.0.x) emits **no** correlations. For a correlation
  rule the generated `.kql` is the **base rule's** `where` clause plus the windowed
  aggregation appended as a `// summarize …` comment the analyst un-comments.

### Regenerating and snapshotting `out/`

- **`python scripts/release.py`** (`make release`) *writes* `out/` — regenerates
  SPL, KQL, and `savedsearches.conf` for every rule, rebuilds the coverage map +
  ATLAS Navigator layer + README SVG, prunes any stale generated file, then
  stamps a versioned bundle under `out/dist/` (git-ignored). **Commit the `out/`
  diff.**
- **`scripts/ci.py`'s `convert` + `coverage-build` stages** are read-only
  *checks*. They reconvert/rebuild and fail on any empty output, non-byte-stable
  conversion, snapshot drift, or stale artifact — so an ephemeral CI run can't
  hide an uncommitted regeneration.

Both share `scripts/conversion.py` so the generated content is defined once.

## Lessons (Phase 1b, correlation slice)

- The Splunk and Kusto backends are **not** at parity for correlations — design
  for SPL-complete + KQL-best-effort and document the gap in the rule.
- Keep aggregation rules as `event_count` over a base detection; it's the subset
  both the harness and the Splunk backend handle cleanly.
- Samples for correlation rules are **arrays** — a burst that crosses the
  threshold (positive) and steady traffic that doesn't (negative).
