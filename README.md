# PromptHound 🐶🔍

**Open-source, SIEM-ready *detection* content for attacks _against_ LLM apps and AI agents.**

> *"You shipped an LLM app. Do you know what an attack on it looks like in Splunk or Sentinel? PromptHound is the detection content and the test data."*

Rules are authored once in [Sigma](https://sigmahq.io/) and converted to **Splunk SPL** and **Microsoft Sentinel KQL**. A bundled **synthetic telemetry generator** lets you test the rules entirely offline: generate logs → run rules → see hits and an OWASP × MITRE ATLAS coverage map. Every rule is mapped to the **OWASP Top 10 for LLM Applications (2025)** and **MITRE ATLAS**, and proven by `pytest` to fire on its malicious sample and stay quiet on its benign one.

> ⚠️ **Status: early scaffold (Phase 0).** The repository structure, schema, and local CI runner are in place; the rule pack, conversion pipelines, generator, and demo are being built out. See [`docs/CHECKLIST.md`](docs/CHECKLIST.md) for exactly where we are.

---

## Why this exists

The AI-security ecosystem is saturated with **offensive** tooling and nearly empty on the **defensive** side. Teams shipping LLM apps have almost no off-the-shelf way to answer *"what does malicious activity look like in our logs, and how do we alert on it?"* PromptHound closes three gaps at once:

- **Portable** — Sigma → SPL **and** KQL, not one vendor.
- **Testable** — a synthetic generator + `pytest`, so you can evaluate offline with **zero live LLM and zero risk**.
- **Legible** — every rule mapped to OWASP LLM Top 10 **and** ATLAS, rendered as a coverage map.

## Strictly defensive (the line we hold)

PromptHound is **not** a red-team tool, payload zoo, runtime guardrail, or WAF. Our standing invariants (see [`docs/PRD.md` §8](docs/PRD.md#8-defensive-posture-standing-principles)):

- **P1 — Signatures, not payloads.** Positive samples encode attack *log signatures*, not working exploits.
- **P2 — No live targeting.** The generator writes files; it never attacks a real endpoint.
- **P3 — Detection over exploitation.** We describe *what to detect and why*, citing public references.
- **P4 — Privacy-aware by design.** Content fields are sensitive; prefer derived/Tier-1 features.

## Prior art (we're not first, and that's fine)

Inspired by and complementary to Splunkbase's *MITRE ATLAS AI Threat Detection for Splunk* (the Tier 1 / Tier 2 model is theirs, and credited) and the OWASP GenAI Security Project. PromptHound's wedge is being **multi-SIEM, open source, and shipping its own test data**. Full comparison in [`docs/PRD.md` §6](docs/PRD.md#6-competitive-landscape--prior-art).

## Quickstart

```bash
# Python 3.11+
python -m pip install -r requirements.lock   # pinned runtime deps (PRD §13)

make demo    # the one-command wow (python demo/run_demo.py --seed 0)
make ci      # run the full local check sequence (python scripts/ci.py)
make test    # just the tests
make fmt     # auto-format + lint-fix
```

There is **no hosted CI** — the local runner (`scripts/ci.py`) is the gate, run on demand.

## See it in action

`make demo` is the 10-second hook. Entirely offline, it **generates** synthetic telemetry (benign traffic + a should-alert / should-not-alert signature per rule), **evaluates** the whole Sigma rule pack against it with the backend-agnostic offline matcher, prints a hits table (rule · OWASP · ATLAS · tier · #hits), and **builds** the OWASP × ATLAS coverage map — then tells you where to open it. No live LLM is ever contacted (PRD §8, P1–P2), and a given `--seed` is byte-reproducible.

![PromptHound demo output](docs/assets/demo.svg)

> Full captured output: [`docs/assets/demo_output.txt`](docs/assets/demo_output.txt). The visual coverage map lands at `out/coverage/coverage.html` (plus a Markdown grid and an [ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/) layer).

## Layout

See [`docs/PRD.md` §14](docs/PRD.md#14-repository-layout) for the full tree. In short: `schema/` (audit-log JSON Schema), `rules/` (Sigma, by category), `pipelines/` (pySigma → Splunk/Kusto), `generator/` (synthetic telemetry), `tests/`, `coverage/` (map generator), `demo/`, `scripts/` (`ci.py` / `release.py`).

## Documentation

- **[`docs/PRD.md`](docs/PRD.md)** — product requirements (source of truth).
- **[`docs/CHECKLIST.md`](docs/CHECKLIST.md)** — engineering checklist & phase status.
- **[`docs/schema.md`](docs/schema.md)** — the audit-log schema, with examples.
- **[`docs/authoring.md`](docs/authoring.md)** — how to author a rule.

## License

Licensing is an open decision (PRD §9, **D7**) — recommended direction is **Apache-2.0** for code and **DRL 1.1** for detection content, but it is **not yet ratified**. See [`LICENSE`](LICENSE).
