# PromptHound — Threat Model

> **Status:** Draft v0.1 · Companion to [`PRD.md`](PRD.md) §3 (non-goals), §8
> (defensive posture) and §17 (risks). [`SECURITY.md`](../SECURITY.md) covers how
> to report issues; this document scopes *what PromptHound defends, what it does
> not, and the risks it accepts*.

PromptHound is detection **content and test data** — Sigma rules, a synthetic
telemetry generator, conversion to SPL/KQL, and a coverage map. It is a library
that produces artifacts and runs offline. It is **not** a runtime system, a
service, or an attack tool. The threat model follows from that.

## 1. What PromptHound is (assets)

| Asset | Why it matters |
|---|---|
| **The rule pack** (`rules/*.yml`) | The detection IP. Must stay correct, portable, and *defensive* (signatures, not payloads). |
| **The audit-log schema** (`schema/`) | The contract detections and telemetry share. Drift breaks both. |
| **The synthetic generator** (`prompthound/generator.py`, `generator/`) | Proves rules offline with zero live LLM. Must remain offline and P1-safe. |
| **Generated artifacts** (`out/`) | SPL/KQL/coverage a user drops into their SIEM. Must be reproducible from source. |
| **The repository's reputation** | A *defensive* repo. Its value collapses if it doubles as an attack cookbook. |

## 2. Who and what we defend against

PromptHound is consumed by detection engineers, SOC analysts, and platform
teams who clone the repo, run the demo, and lift rules into their SIEM. The
threats we take seriously are about **the repo staying trustworthy and the
content staying correct and defensive**:

- **T1 — The repo drifts into an attack cookbook.** A contributor adds a working
  jailbreak/injection exploit, a real reverse shell, or a live payload to a rule
  or sample. *Mitigation:* **P1** enforced in code — `prompthound.p1_guard` plus
  `tests/test_invariants.py` scan every rule, sample, and generated event for
  working-exploit patterns and fail the build. This is the primary threat.
- **T2 — The "offline" generator/demo quietly gains a live capability.** Code on
  the generator/demo path starts importing a networking stack or a model SDK and
  could send traffic to a real endpoint. *Mitigation:* **P2** enforced — an
  invariant test asserts no networking / provider-SDK imports exist on those
  paths; the generator only builds dicts and writes files.
- **T3 — A committed secret.** An API key, token, or private key lands in the
  history. *Mitigation:* the security stage's secrets scan over every tracked
  file; the schema itself only ever carries a *hashed/opaque* `api_key.id`
  (PRD §10.1), never a secret.
- **T4 — A vulnerable or malicious dependency.** A pinned dependency carries a
  known CVE, or a bump pulls in something unreviewed. *Mitigation:* a pinned
  `requirements.lock`, `pip-audit` in CI, and "a bump is a reviewed change with
  full regeneration" (PRD §17).
- **T5 — Silent content rot.** A rule loses its OWASP/ATLAS/tier metadata, a
  sample stops validating, or the coverage map goes stale. *Mitigation:* the
  metadata gate, schema-validate stage, snapshot conversion check, and
  generated-only coverage map (PRD §16) — correctness, enforced.
- **T6 — Tampered generated output.** `out/` is hand-edited so the SPL/KQL no
  longer matches the rules. *Mitigation:* the convert stage is a read-only
  snapshot check that fails on any drift from what `scripts/release.py` produces.

## 3. Non-goals (explicitly **not** in scope)

These restate PRD §3 and bound the threat model. PromptHound does **not** try to
defend, and will not accept changes that assume it does:

- **Not a runtime guardrail, WAF, or inline prompt firewall.** We do not sit in
  the request path or block anything in production. Runtime-enforcement features
  are rejected.
- **Not a red-team / attack tool.** We never attack live systems and ship no
  curated payload library. "Make the generator hit a real endpoint" is out of
  scope by construction (P2).
- **Not a model-hosting or inference product.** No model is run, hosted, or
  called. There is no inference attack surface here to defend.
- **Not a SIEM.** We emit content *for* Splunk and Sentinel. Vulnerabilities in
  those platforms, or in a user's gateway, are their vendors' threat model.
- **Not responsible for the security of a deployment that adopts our schema.**
  Whether a user's gateway authenticates callers, encrypts logs, or scopes
  access is outside this repo. We document a schema; we do not operate it.
- **Not a guarantee of detection.** Rules are best-effort, behavioral, and
  documented with honest false positives. Evasion of a specific rule is a
  detection-engineering issue (file a PR), not a vulnerability in this model.

## 4. Trust boundaries & assumptions

- **Single-user, local, offline execution.** The runner, generator, demo, and
  tests are assumed to run on a developer's or CI machine they control. We do
  **not** defend against an attacker who already has local write access to the
  working tree, the Python environment, or on-disk caches — that is a
  compromised host, outside our model.
- **Inputs are first-party.** Rules, samples, and the schema are authored in-repo
  and reviewed. The generator consumes its own declarative specs, not untrusted
  external input. (Telemetry a *user* later feeds to their SIEM is their data
  under their controls — see non-goals.)
- **The dependency set is pinned and reviewed.** We trust pinned versions of
  pySigma and its backends; an unreviewed bump is the threat (T4), not the
  steady state.

## 5. Accepted risks

Risks we acknowledge and consciously do not mitigate further, with rationale:

- **`pip-audit` ignore-list.** Advisories accepted in
  `scripts/security.py` (`IGNORED_VULNS`) are those with **no fixed release**
  whose exploitation requires a precondition outside the trust boundary above.
  - *CVE-2025-69872 (diskcache pickle deserialization → RCE).* Reached only via
    the **optional** `sigma-cli` extra; no fixed version exists (the advisory is
    "through 5.6.3", the latest release). Exploitation requires an attacker who
    already has **write access to the local cache directory** — i.e. a
    compromised host, which §4 already places out of scope. Re-evaluate when a
    fixed diskcache ships.
- **Best-effort detection.** Rules can be evaded or can misfire; this is inherent
  to signature/behavioral detection and is managed as detection engineering, not
  as a vulnerability.
- **Schema is experimental-adjacent.** Field names track the still-experimental
  OTel GenAI conventions (PRD §9 D1). We pin our own versioned schema and treat
  drift as a content risk (T5), not a security one.

## 6. How the model is enforced

Every threat above maps to an automated gate, so the posture cannot quietly
regress:

```bash
pip install -e .[security]
python scripts/ci.py --only security      # T3, T4 (+ supply-chain hygiene)
pytest -k "invariant or security" -q      # T1 (P1), T2 (P2), scanner units
python scripts/ci.py                       # full sequence incl. T5, T6
```
