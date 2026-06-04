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

## Offline test harness (PRD §12)

Rules are proven **without a running SIEM**. The harness
(`prompthound/matcher.py`) parses each rule with pySigma — the same library that
emits the SPL/KQL — and walks pySigma's own fully-resolved condition tree
(`rule.detection.parsed_condition[0].parse()`) against a plain `dict` event.
Using pySigma's parser instead of re-implementing Sigma's grammar keeps the
harness faithful to the conversion source of truth.

- **Fire/silence** tests run the matcher against the rule's positive/negative
  samples in `generator/samples/<stem>.{positive,negative}.json`.
- **Conversion** is exercised separately: `pipelines/convert.py` emits SPL + KQL,
  snapshot-tested (non-empty + stable) against `tests/snapshots/`. If a rule or
  pipeline legitimately changes the output, re-bless the snapshot and review it.
- The matcher supports the Sigma subset the pack currently uses (`and`/`or`/`not`,
  `contains` wildcards, numeric `gte`/`gt`/`lte`/`lt`, equality, null). It raises
  on unsupported nodes rather than passing silently, so it fails loudly when a
  new rule outgrows it.

## Checklist for a new rule (mirrors CHECKLIST "Cross-cutting")

- [ ] Positive (should-alert) **and** negative (should-not-alert) sample.
- [ ] OWASP + ATLAS + tier tags present (the metadata gate fails the build otherwise).
- [ ] Honest `falsepositives`.
- [ ] P1 compliance (signature, not payload).
- [ ] Converts cleanly to SPL + KQL via the local CI runner.
