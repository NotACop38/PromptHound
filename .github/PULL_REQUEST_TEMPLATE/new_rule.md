<!-- See docs/authoring.md for the rule format, the supported Sigma subset and scenario files. -->

## Rule

- **File:** `rules/<category>/<name>.yml`
- **Behavior:** <!-- the one behavior the rule detects, and why it matters -->
- **Telemetry:** <!-- metadata only, a content detector's output, or raw content -->

## Mappings

- **OWASP LLM Top 10 2025:** <!-- e.g. LLM01 -->
- **OWASP Agentic Top 10 2026:** <!-- required for agent_tool_abuse rules, e.g. ASI02 -->
- **MITRE ATLAS / ATT&CK:** <!-- e.g. AML.T0051.000 -->

## Scenario cases

<!-- The cases that alert, the near misses that stay silent, and the boundaries tested. -->

## False positives

<!-- Where the rule fires on benign activity, and how to scope or tune it. -->

## Checklist

- [ ] `prompthound test` passes: every case behaves as declared and the rule meets the publication requirements.
- [ ] `MUTATIONS` in `tests/test_scenarios.py` has an entry for the rule.
- [ ] Generated files are regenerated (`make generate`) and committed.
- [ ] `make verify-siem` passes.
- [ ] Scenario text is a log signature, not a working payload.
- [ ] `make ci` passes.
