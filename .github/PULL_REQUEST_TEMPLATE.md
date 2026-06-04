<!--
Adding a NEW RULE? Use the new-rule PR template instead — append
?template=new_rule.md to the PR URL, or see .github/PULL_REQUEST_TEMPLATE/new_rule.md
-->

## What & why

<!-- What does this change and why? Link any related issue. -->

## Checklist

- [ ] `make ci` is green locally (lint → schema → convert → tests → coverage → security).
- [ ] If I changed a rule, pipeline, or backend pin, I ran `make release` and committed the `out/` diff (CI's convert/coverage stages are read-only snapshot checks).
- [ ] Tests added/updated for the change.
- [ ] Docs updated where relevant; `docs/PRD.md` / `docs/CHECKLIST.md` kept in sync if a decision changed.
- [ ] This change honors the defensive posture **P1–P4** (signatures not payloads; no live targeting; detection over exploitation; privacy-aware). See [SECURITY.md](../SECURITY.md).
