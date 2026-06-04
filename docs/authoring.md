# Authoring a PromptHound rule

> **Source of truth:** [`PRD.md` §15 (Rule authoring standard)](./PRD.md#15-rule-authoring-standard) and the defensive posture in [§8 (P1–P4)](./PRD.md#8-defensive-posture-standing-principles).
> This is a stub; it grows into an "add a rule in 10 minutes" guide once the vertical slice lands (CHECKLIST Phase 1b → Phase 6).

## Every rule must include

- **Standard Sigma fields:** `title`, `id` (UUID), `status`, `description`, `author`, `date`, `logsource`, `detection`, `falsepositives`, `level`.
- **PromptHound tags:** `owasp-llm.llmNN`, `attack.atlas.aml.tNNNN`, `attack.tNNNN` (only when a technique genuinely maps), `prompthound.tier.tN`.
- **`logsource`** aligned to our schema (`product: llm_gateway`).
- **A reference to its sample spec** in `generator/samples/`.
- **`references:`** to OWASP / ATLAS / CVE where relevant.

## Conventions

- One rule = one behavior.
- Prefer Tier-1 / derived fields where they are equivalent to content inspection (privacy by design, PRD §8 P4).
- Document expected false positives **honestly**.
- **Never encode a working exploit (P1).** Positive samples are log *signatures* — marker phrases and behavioural patterns — not payloads an attacker can lift and run.

## Checklist for a new rule (mirrors CHECKLIST "Cross-cutting")

- [ ] Positive (should-alert) **and** negative (should-not-alert) sample.
- [ ] OWASP + ATLAS + tier tags present (the metadata gate fails the build otherwise).
- [ ] Honest `falsepositives`.
- [ ] P1 compliance (signature, not payload).
- [ ] Converts cleanly to SPL + KQL via the local CI runner.

## Sigma → SPL + KQL conversion (toolchain)

Author once in Sigma; the local CI runner emits Splunk SPL and Sentinel KQL via
pySigma (PRD §9 **D5**, §12). The pieces:

- **`prompthound/convert.py`** — `convert_rule(path)` returns a `ConversionResult`
  with `.spl`, `.savedsearches` (a `savedsearches.conf` document), and `.kql`.
  This is the seam tests and `scripts/ci.py` use.
- **`pipelines/prompthound_splunk.py`** — Splunk backend, target `splunk`. Emits
  the `default` plain-SPL format and the `savedsearches` (`savedsearches.conf`)
  format.
- **`pipelines/prompthound_kusto.py`** — Kusto backend, target `kusto`. Uses the
  **`sentinelasim`** pipeline by default with **`azure_monitor`** as a documented
  fallback for non-ASIM Log Analytics deployments (PRD §17). There is **no**
  `pysigma-backend-sentinel` — it does not exist (D5).

pySigma 1.0.0's **factory-pattern** pipelines apply: each pipeline is a function
returning a fresh `ProcessingPipeline`, not a shared singleton. Everything is
pinned in `requirements.lock`; a pySigma/backend bump is a reviewed change with
full regeneration (PRD §13, §17).

### Field-mapping decisions

The audit-log schema (PRD §10) uses OpenTelemetry-style **dotted** field names
(`gen_ai.usage.input_tokens`). The canonical schema → SIEM mapping lives in one
place — **`prompthound/fieldmap.py`** — and both backends import it, so a rename
changes Splunk and Sentinel together.

- **Rule:** dots become underscores — `a.b.c` → `a_b_c`. Mechanical and
  reversible, so the SIEM column is recoverable from the schema field.
- **Why map at all:** KQL column references cannot contain dots, so the mapping
  is *mandatory* for Kusto. We apply the **same** map to Splunk so a given schema
  field resolves to the **identical column** in both SIEMs (lock-step parity),
  even though SPL could technically quote dotted names.
- **Target tables/sources:** SPL queries assume a flattened PromptHound audit
  index/source (no table prefix is emitted). KQL queries are prepended with a
  Sentinel custom-log table, default **`PromptHoundAuditLog_CL`** (override via
  `convert_rule(..., query_table=...)`). Neither bundled Kusto pipeline knows our
  `llm_gateway` logsource, so we set the table explicitly.
- **`logsource`:** every rule uses `product: llm_gateway`; the field mapping only
  fires for that logsource, leaving other rulesets untouched.
- **Coverage:** the map is an explicit list of PRD §10 fields (grouped to match
  the schema sections), not an inferred transform — update it when §10 changes.

When you reference a schema field in a rule's `detection:`, use the **dotted
schema name** (e.g. `guardrail.input.categories`); the pipeline handles the
flattening.

### Regenerating and snapshotting `out/`

The generated artifacts live in `out/` and are split across two scripts:

- **`python scripts/release.py`** *writes* `out/` — regenerates SPL, KQL, and
  `savedsearches.conf` for every rule and prunes any stale generated file whose
  source rule was renamed or removed. Run it after changing a rule, pipeline, or
  backend pin, and **commit the `out/` diff**.
- **`scripts/ci.py`'s `convert` stage** is a read-only *check*. It reconverts
  every rule and fails the build if any output is empty (SPL, KQL, **or**
  savedsearches), non-byte-stable, missing from `out/`, drifted from `out/`, or
  if `out/` holds a stale artifact with no current source (the snapshot
  guarantee, PRD §12). It never rewrites `out/`, so an ephemeral CI run can't
  hide an uncommitted regeneration.

Both share `scripts/conversion.py` so the generated content is defined once.
