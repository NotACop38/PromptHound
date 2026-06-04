# Security Policy

PromptHound is a **defensive** detection library: Sigma rules, a synthetic
telemetry generator, and tests for spotting attacks *against* LLM applications
and AI agents. It is deliberately **not** an attack tool (PRD §3 non-goals). The
security posture below is enforced in code and CI, not just in review.

## Reporting a vulnerability

If you find a security issue in PromptHound itself — a bug in the generator,
matcher, conversion pipeline, or CI tooling, a committed secret, or a way the
repo could be used to cause harm that the defensive posture is supposed to
prevent — please report it privately:

- **Preferred:** open a [GitHub Security Advisory](https://github.com/notacop38/prompthound/security/advisories/new)
  (private disclosure) on this repository.
- Do **not** open a public issue for a sensitive report.

Please include: what you found, where (file/line or command), how to reproduce,
and the impact you believe it has. We aim to acknowledge reports within a few
days. There is no paid bounty — this is a community project — but we will credit
reporters who want it.

### What is *in* scope

- Code-execution, path-traversal, or injection bugs in first-party Python
  (`prompthound/`, `scripts/`, `pipelines/`, `coverage/`, `demo/`, `generator/`).
- A **working exploit / live payload** that slipped into a rule or sample,
  violating **P1** (see below). These are treated as security bugs, not content
  bugs.
- A committed credential or secret in the repository history.
- A dependency vulnerability that is reachable in how we actually use the
  dependency (see the supply-chain section).

### What is *out* of scope

- The detection efficacy of a rule (false positives / false negatives). File a
  normal issue or PR — that is detection engineering, not a vulnerability.
- Vulnerabilities in a downstream SIEM (Splunk, Sentinel) or in your own
  gateway. PromptHound emits content *for* those systems; it does not run them.
- Anything in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) marked as a
  non-goal or an accepted risk.

## Defensive posture (enforced)

These are the PRD §8 invariants. They are not aspirational — each is checked by
the security stage of the local CI runner and by the invariant test suite:

| # | Principle | Enforcement |
|---|---|---|
| **P1** | **Signatures, not payloads.** Samples encode attack *signatures as they appear in logs* — marker phrases, derived/Tier-1 features — never working jailbreak/injection exploits. | `prompthound.p1_guard` scans content fields; `tests/test_invariants.py` scans every rule, on-disk sample, and generated event; the generator refuses to emit a dataset that smuggles an exploit. |
| **P2** | **No live targeting.** Nothing here sends traffic to a real model endpoint. The generator writes files; it does not attack. | `tests/test_invariants.py` asserts no networking / model-provider-SDK imports exist on the generator/demo paths. |
| **P3** | **Detection over exploitation.** We document *what to detect and why*, citing public references (OWASP, ATLAS, CVEs) — not step-by-step offensive how-tos. | Authoring standard (PRD §15); review. |
| **P4** | **Privacy-aware by design.** Content-bearing fields (prompts/responses) are treated as sensitive; derived markers let high-signal detections run without storing raw user content. | Schema tiering (PRD §10, Tier 1 / Tier 2 / derived); secrets scan over tracked files. |

## Supply chain

- Runtime dependencies are pinned in [`requirements.lock`](requirements.lock).
  A version bump is a reviewed change with full SPL/KQL regeneration (PRD §17).
- `python scripts/ci.py --only security` runs, each failing on findings:
  - **`pip-audit`** against the lockfile. Advisories with **no fixed release**
    that fall outside the threat model are accepted with a written justification
    in `scripts/security.py` (`IGNORED_VULNS`) and documented in the threat
    model — never silently suppressed.
  - **`bandit`** static analysis over the first-party Python. Security-reviewed
    lines carry an inline `# nosec <ID>` with a reason.
  - **a secrets scan** over every git-tracked file (AWS keys, private-key
    blocks, provider/API tokens). Deliberate example values carry an inline
    `# pragma: allowlist secret` marker.

Install the tooling with `pip install -e .[security]`.

## Running the checks locally

```bash
pip install -e .[security]
python scripts/ci.py --only security          # supply chain + SAST + secrets
pytest -k "invariant or security" -q          # P1/P2 invariants + scanner units
```
