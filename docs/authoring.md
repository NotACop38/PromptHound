# Writing rules and scenarios

A PromptHound rule is a Sigma file under `rules/<category>/<name>.yml` with a
scenario file of the same name under `scenarios/<category>/`. The scenario file
states which event sequences must raise an alert and which must not. Everything
downstream — the Splunk and Microsoft Sentinel queries, the Splunk app, the rule
catalog — is generated from these two files.

A rule is accepted when:

1. it loads, which means every detection feature it uses is in the
   [supported subset](#supported-sigma-subset);
2. it meets the [publication requirements](#publication-requirements);
3. every scenario case behaves as declared;
4. the generated artifacts are regenerated and committed.

## Workflow

```bash
make setup                                   # once: pinned dependencies and the package
$EDITOR rules/<category>/<name>.yml
$EDITOR scenarios/<category>/<name>.yml
prompthound test                             # scenarios and publication requirements
python scripts/generate.py                   # SPL, KQL, Splunk app, catalog, README table
make ci                                      # the full gate, as CI runs it
make verify-siem                             # optional: run the queries in Splunk and Kusto (Docker)
```

Add the rule to `MUTATIONS` in `tests/test_scenarios.py`: a one-line change that
weakens the rule (a lower threshold, a dropped condition) and that at least one
of its cases must catch. The test suite fails for a rule without one.

## Rule files

### A single-event rule

```yaml
title: Unsanitized LLM Output Reached an Interpreter or Renderer
id: 3bc7ddec-e008-450b-950c-263f73f90440     # a new random UUID
status: experimental
description: |
    Detects model output that reached a SQL, shell, code-evaluation or HTML sink
    without sanitization, as reported by the application's output handling.
references:
    - https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
author: PromptHound contributors
date: 2026-06-04
modified: 2026-09-26
license: DRL-1.1
tags:
    - attack.execution
    - attack.t1059
logsource:
    product: llm_gateway
detection:
    unsanitized:
        output.rendered_unsanitized: true
    dangerous_sink:
        output.sink:
            - 'sql_exec'
            - 'shell_exec'
            - 'code_eval'
            - 'html_render'
    condition: unsanitized and dangerous_sink
falsepositives:
    - Consumers that sanitize output after the point where it is recorded.
level: high
prompthound:
    owasp_llm: [LLM05]
    owasp_agentic: [ASI05]
```

Detections name fields by their schema names (`output.sink`), never by SIEM
column names; the converters apply the column mapping. `logsource.product` is
always `llm_gateway`. Indent with four spaces.

### A correlation rule

A correlation counts the events matched by a base detection in the same file.
The base detection carries a `name` and no framework mappings; the correlation
carries the alert metadata.

```yaml
title: Denied Agent Tool Call
name: denied_tool_call
id: 9c1a7e60-4d2b-4f8a-bb53-1e6c0a9d3f44
status: experimental
description: Building block for the correlation below.
author: PromptHound contributors
date: 2026-06-04
logsource:
    product: llm_gateway
detection:
    selection:
        gen_ai.operation.name: ['execute_tool', 'invoke_agent']
        tool.call.outcome: 'denied'
    condition: selection
---
title: Repeated Denied Tool Calls in One Conversation
id: 4b7d2f81-3a59-46c0-9e1d-8f5b2c7a0e63
# ... status, description, references, author, date, license
correlation:
    type: event_count
    rules:
        - denied_tool_call
    group-by:
        - user.tenant.id
        - gen_ai.conversation.id
    timespan: 5m
    condition:
        gte: 3
falsepositives:
    - Authorized agent-evaluation suites that probe tool boundaries.
level: medium
prompthound:
    owasp_llm: [LLM06]
    owasp_agentic: [ASI03]
    atlas: [AML.T0053]
```

Windows are fixed and aligned to UTC (00:00–00:05, 00:05–00:10, …), as in the
generated SPL (`bin _time`) and KQL (`bin(timestamp, 5m)`). A burst that
straddles a boundary is split between two windows and can stay below the
threshold; the scenario files test this on purpose.

### Framework mappings

Sigma restricts `tags` to a few standard namespaces, so mappings to OWASP and
MITRE ATLAS live in a `prompthound:` block that other Sigma tools ignore:

| Key | Values | Catalog |
|---|---|---|
| `owasp_llm` | `LLM01` … `LLM10` | OWASP Top 10 for LLM Applications 2025 |
| `owasp_agentic` | `ASI01` … `ASI10` | OWASP Top 10 for Agentic Applications 2026 |
| `atlas` | technique IDs such as `AML.T0051.000` | MITRE ATLAS, vendored in `src/prompthound/data/atlas.json` |

MITRE ATT&CK mappings use standard Sigma tags (`attack.t1059`,
`attack.execution`) and are checked against the ATT&CK entries PromptHound
knows. Every identifier must exist in its catalog; `scripts/update_atlas.py`
refreshes the ATLAS catalog, after which a renamed or retired technique fails the
tests. A mapping says which risk a rule relates to. It is not a claim that the
rule covers the risk.

### Publication requirements

`prompthound test` and the test suite enforce these for the shipped pack:

- `title`, `description`, `author`, `status` (`experimental`, `test` or
  `stable`), `level`, `date`, and `modified` no earlier than `date`;
- an `id` (a UUID) on every document, and unique ids and titles across the pack;
- at least one reference and at least one documented false positive;
- an OWASP LLM mapping and at least one ATLAS or ATT&CK technique; rules in
  `agent_tool_abuse/` also map to the OWASP Agentic Top 10;
- correlations group by `user.tenant.id` and by `user.id` or
  `gen_ai.conversation.id`, so that tenants never pool;
- pySigma's own validators pass (all except the two that download MITRE data).

Choose the level for the alert, not for the technique: `high` when a match is
likely an incident on its own, `medium` when it needs triage with known benign
causes, `low` for weak signals meant for hunting or context. Describe the benign
causes in `falsepositives` so that the analyst who receives the alert can rule
them out.

## Supported Sigma subset

PromptHound evaluates every rule offline and converts it to SPL and KQL. The
loader rejects any construct whose result would differ between the three, so a
rule that loads matches the same events everywhere. The semantics below are
pinned by the conformance cases in [`tests/conformance.yml`](../tests/conformance.yml),
which run offline in the test suite and in Splunk and the Kusto engine in
[`make verify-siem`](verification.md).

### Matching

| Value | Matches |
|---|---|
| String | The whole value, ignoring the case of ASCII letters. A non-ASCII letter matches only itself (`É` does not match `é`). `*` matches any run of characters, including line breaks. |
| String with `contains`, `startswith`, `endswith` | The value anywhere, at the start, or at the end, with the same case rules. |
| String list | Any of the values. With `all` (together with `contains`, `startswith` or `endswith`), every value. |
| Number | Numerically: `5` matches `5` and `5.0`. `gt`, `gte`, `lt`, `lte` compare. |
| `true` / `false` | JSON booleans only. |
| String-array field (`tool.call.chain`, `user.roles`, …) | Any element that equals the value exactly, ignoring ASCII case. With `all`, every listed value must be an element. |
| Content field (`gen_ai.input.messages`, `gen_ai.tool.call.arguments`, …) | The field's compact JSON text, which is how the SIEM stores it. Quotes, backslashes and line breaks inside message text are escaped: match a literal `"` as `\"`. A plain string value is matched as it is. |

An event that lacks a field never matches a condition on that field, so
`not selection` matches it.

### Not supported

| Construct | Why |
|---|---|
| Keyword (field-less) detections | No field to map; full-text search differs by engine. |
| Modifiers other than `contains`, `startswith`, `endswith`, `all`, `gt`, `gte`, `lt`, `lte` | Regular expressions, CIDR, encodings and field references have no common semantics in all three. |
| `?` wildcards | Splunk search has no single-character wildcard. |
| Values made only of `*`, and empty values | KQL stores a missing string as `""`, which such a value matches. |
| `null` values | Splunk counts an empty string as a value and an empty array as none; KQL cannot tell a missing string from an empty one. `prompthound readiness` reports missing fields instead. |
| `not` over numeric or string-array conditions | Splunk (`NOT n>=3`) and KQL (`not(n >= 3)`) both drop events without the field; KQL also drops them from a negated array test. Use the opposite comparison. |
| Wildcards, substring modifiers or non-ASCII letters in string-array values | Elements match exactly; KQL and Splunk fold non-ASCII case differently. |
| `all` on a scalar field without `contains`, `startswith` or `endswith` | KQL renders it as a term search (`has_all`). |
| `timestamp` in a detection | Time scoping belongs to the SIEM search window. |
| Correlation types other than `event_count`; more than one base rule; aliases; `generate: true`; conditions other than `gt`, `gte`, `lt` and `lte`; grouping by arrays, content or `timestamp`; timespans that do not divide 24 hours | A count per group in fixed UTC windows is the correlation shape all three evaluate identically. |

One difference remains that the loader cannot prevent: KQL's `=~` and `in~`
treat U+212A KELVIN SIGN as the letter `k`, so a telemetry value containing that
character can match an ASCII `k` in Sentinel but not in Splunk or offline.

## Scenario files

A scenario file lists cases. Each case builds a short event sequence from a
benign base event and states whether the rule must alert.

```yaml
x-denied-call: &denied-call          # keys starting with x- are ignored: use them for anchors
  gen_ai.operation.name: execute_tool
  event.outcome: blocked
  tool.call.chain: [secrets.get]
  tool.call.outcome: denied

cases:
  - name: Three denied calls in one conversation
    expect: alert
    alerts: 1                        # optional: the exact number of alerts
    events:
      - set: *denied-call
        repeat: 3
        interval: 60s

  - name: Denials split across two five-minute windows
    expect: silent
    events:
      - at: 4m
        set: *denied-call
        repeat: 3
        interval: 30s
```

| Key | Meaning |
|---|---|
| `set` | Field overrides, by schema name. |
| `unset` | Fields to remove from the base event. |
| `prompt` | Shorthand for one user message in `gen_ai.input.messages`. |
| `messages` | A list of `{role, text}` input messages. |
| `response` | Shorthand for one assistant message in `gen_ai.output.messages`. |
| `repeat` | Number of events in the group (default 1). |
| `interval` | Spacing between the group's events, such as `10s` or `2m` (default `10s`). |
| `at` | Offset of the group's first event from the start of the case. |

Each case runs on its own, starting at 2026-06-01T12:00:00Z, with a principal
and conversation of its own in tenant `tenant-example`. Operations named
`execute_tool` or `invoke_agent` get tool-call fields in the base event; other
operations get a prompt, a response and token usage. When a case overrides token
counts, `usage.total_tokens` and `cost.usd` follow unless the case sets them.
Every event must validate against the schema.

Good scenario files cover:

- the behavior the rule targets, and its variants (other operations, casing);
- the nearest benign behavior, which must stay silent;
- boundaries: one below the threshold, exactly at it, a burst split across two
  windows, two tenants sharing a conversation ID, missing identity fields.

Scenario text must be a log signature, not a working payload. The loader and the
dataset generator refuse content fields that contain encoded blobs, shell or
code execution, SQL-injection mechanics or credential-shaped strings
(`prompthound.payload_guard`). An instruction-override phrase is a signature and
is allowed.
