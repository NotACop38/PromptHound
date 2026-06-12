# Contributing to PromptHound

Thanks for helping build open, portable, **defensive** detection content for
attacks against LLM apps and AI agents. The bar we hold:

> **A stranger can understand the line, add a rule, and get it merged via CI.**

Most contributions are a **new detection rule**. That is one Sigma file plus a
positive **and** negative sample, with OWASP + ATLAS + tier metadata. The local
CI runner enforces everything else. If you want to add a rule, jump to
**[docs/authoring.md](docs/authoring.md) — "add a rule in 10 minutes."** This
document is the standard those rules are held to.

`docs/PRD.md` and `docs/CHECKLIST.md` are the source of truth; when a decision
changes, update them in the same PR.

---

## 1. The line we hold (P1–P4) — non-negotiable

PromptHound is a **blue-team detection** project: it encodes what attacks look
like *in your logs*, not how to run them. These four invariants (PRD
[§8](docs/PRD.md#8-defensive-posture-standing-principles)) are non-negotiable; a
PR that violates one is rejected, no matter how good the detection is.

- **P1 — Signatures, not payloads.** Positive samples encode attack *log
  signatures* — representative marker phrases, PII/exfil patterns, token-spike
  and request-rate behaviors — **not** a curated set of working jailbreak /
  injection exploits. Rules should catch generalizable patterns, not strings an
  attacker mutates in seconds.
- **P2 — No live targeting.** Nothing here sends traffic to a real model
  endpoint as part of an attack. The generator writes files; it does not attack.
- **P3 — Detection over exploitation.** Document *what to detect and why*, citing
  public references (OWASP, ATLAS, CVEs). No step-by-step offensive how-tos.
- **P4 — Privacy-aware by design.** Treat content-bearing fields
  (prompts/responses) as sensitive. Prefer **derived / Tier-1** features so
  high-signal detections can run without storing raw user content.

Security issues and the broader threat model live in
[`SECURITY.md`](SECURITY.md) and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
Read them before your first PR.

---

## 2. Rule authoring standard (PRD §15)

Every Sigma rule **must** include:

- **Standard Sigma fields:** `title`, `id` (a fresh UUID), `status`,
  `description`, `author`, `date`, `logsource`, `detection`, `falsepositives`,
  `level`.
- **PromptHound metadata tags** (the metadata gate fails the build without them):
  - `owasp-llm.llmNN` — OWASP LLM Top 10 (2025), the user-facing taxonomy. **Required.**
  - `attack.atlas.aml.tNNNN[.NNN]` and/or `attack.atlas.aml.taNNNN` — the MITRE
    ATLAS technique/tactic mapping. **At least one technique mapping is required**
    (ATLAS, or `attack.tNNNN` ATT&CK only where a technique genuinely maps).
  - `prompthound.tier.tN` — detection tier `t1` (operational/always-on) or `t2`
    (content inspection/opt-in). **Required.**
  - `owasp-agentic.tNN` — **agent rules only** (anything under
    `rules/agent_tool_abuse/`): the secondary OWASP Agentic AI — Threats and
    Mitigations mapping (PRD D6). **Required for agent rules**, omit elsewhere.
- **`logsource`** aligned to our schema: `product: llm_gateway`.
- A **reference to its sample spec** in `generator/samples/` (see the rule's
  leading comment for the convention).
- **`references:`** to OWASP / ATLAS / CVE where relevant.

**Conventions:** one rule = one behavior; prefer Tier-1 / derived fields where
they are equivalent to content inspection (P4); document expected false positives
**honestly**; never encode a working exploit (P1). Reference a schema field in
`detection:` by its **dotted** name (e.g. `guardrail.input.categories`) — the
pipeline handles the flattening to SIEM columns.

**Each new rule ships with** (CHECKLIST "Cross-cutting"):

- [ ] A positive (should-alert) **and** negative (should-not-alert) sample.
- [ ] A `SampleSpec` in `prompthound/generator.py` (`SPECS`) with `rules=` pointing
      at the rule — the drift guard fails the build without one, and it is what
      makes `make demo` fire the whole pack.
- [ ] OWASP + ATLAS + tier tags (agent rules: + an `owasp-agentic` tag).
- [ ] Honest `falsepositives`.
- [ ] P1 compliance — a signature, not a payload.
- [ ] Clean conversion to SPL + KQL via the local CI runner.

---

## 3. Setup

PromptHound is Python 3.11+ with a pinned toolchain. Install the runtime deps,
the dev/CI toolchain, and the package into one environment:

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.lock -r requirements-dev.lock -e .
```

- `requirements.lock` — pinned runtime deps (pySigma + the Splunk/Kusto
  backends), audited by the CI security stage.
- `requirements-dev.lock` — pinned `ruff` / `mypy` / `pytest` / `pip-audit` /
  `bandit`, so the green pass is reproducible rather than version-luck.

`make setup` runs the install line above.

---

## 4. The merge gate: `make ci`

The gate is one runner, `scripts/ci.py`: GitHub Actions executes it on every
push and pull request, and the same command runs locally. Run it before opening
a PR; every stage must pass:

```bash
make ci          # python scripts/ci.py
```

Stage order (PRD §16): `ruff format --check` → `ruff check` → `mypy` →
`schema-validate` → `convert (SPL+KQL snapshot)` → `pytest` → `coverage-build` →
`security`. A single stage runs in isolation with, e.g.,
`python scripts/ci.py --only security`.

If you changed a **rule, pipeline, or backend pin**, regenerate the committed
artifacts and commit the diff — CI's `convert`/`coverage-build` stages are
read-only snapshot checks that fail on drift:

```bash
make release     # python scripts/release.py — rewrites out/ (and builds a bundle)
make demo        # offline generate → detect → coverage map (the 10-second wow)
```

---

## 5. Pull requests

1. Branch from `main`.
2. Make the change; add/adjust tests and samples.
3. `make ci` green locally; `make release` and commit the `out/` diff if you
   touched generated content.
4. Open the PR. For a new rule, the **"new rule" PR template** walks through the
   metadata + sample + P1–P4 checklist; the **"New detection rule" issue form**
   collects the same up front if you want to propose before implementing.
5. Keep `docs/PRD.md` / `docs/CHECKLIST.md` in sync when a decision changes.

Be your own first reviewer: would a stranger reading only the rule and its
samples agree it's a signature (P1), not a payload? If yes, you're in good shape.
