# Deployment contract and qualification

PromptHound ships experimental query templates and synthetic test data. The
Python demo evaluates Sigma logic; it does not execute SPL or KQL. A passing
fixture test or taxonomy mapping does not establish detection accuracy, attack
success, or production coverage.

## Instrumentation required

Emit one JSON object per operation using the bundled
[`llm_audit_log.schema.json`](../prompthound/llm_audit_log.schema.json).
Use RFC3339 timestamps with an offset, stable event IDs, and schema version
`0.1`. Deduplicate replayed operations by event ID before alert evaluation.

Every correlation requires a nonempty `user.tenant.id` and its principal or
conversation key. Assign a stable tenant identifier even in a single-tenant
installation. Principal and conversation IDs must be unique within that tenant
across applications; namespace application-local IDs before ingestion. Missing
keys exclude events from correlations; missing detector fields cannot be
interpreted as a clean verdict. Monitor field completeness separately.

The gateway must supply derived features such as injection-marker counts,
sensitive-output classes, system-prompt similarity, and sink-sanitization status.
PromptHound does not compute those features. Their upstream precision and recall
limit the rules that consume them. Tier 1 means the rule can use metadata or
precomputed markers without storing raw text; computing markers may still
require sensitive content processing. Tier 2 rules consume raw message text.

## Normalize the event fields

The query columns use a registered mapping (`user.id` → `user_id`). Keep the
original audit events and produce an ingestion copy:

```bash
python -m prompthound.generator --out out/telemetry.jsonl --seed 0
python -m prompthound.normalize --input out/telemetry.jsonl --out out/siem.jsonl
```

The adapter validates events, retains types and values, and rejects unmapped
dotted fields and column collisions. It replaces the output only after every
line succeeds. It neither uploads logs nor installs SIEM resources. Non-dotted
extension fields are retained; provide their own ingestion mapping if needed.

| JSON value | Sentinel column | Splunk field |
|---|---|---|
| `timestamp` string | `datetime` | Parse as event time `_time` |
| Other strings | `string` | String |
| Integers / metrics | `long` / `real` | Numeric extraction |
| Booleans | `bool` | Boolean text recognized by search |
| String arrays | `dynamic` array | Multivalue field |
| Message arrays / objects | `dynamic` | JSON text for content searches |

In Sentinel, create `PromptHoundAuditLog_CL` with these column types, map the
source timestamp to both `timestamp` and `TimeGenerated`, and provision **all
columns referenced by the selected queries**, including optional content fields.
Missing values may be null, but an absent column can prevent compilation.
Configure your data collection rule and ingestion transform for the normalized
JSON. The pipeline name `sentinelasim` does not make this an ASIM schema. Both
pipeline flavours still require this custom table and field contract.

String-array equality uses case-insensitive membership in KQL. Current content
and tool-chain substring rules inspect serialized values; these are marker
searches and do not infer semantic intent, causal links, or tool-call ordering.

In Splunk, scope every raw `.spl` or saved-search stanza to your audit index and
sourcetype. Configure timestamp parsing from `timestamp`, JSON field extraction,
and multivalue arrays. Use UTC for the saved-search owner and validate `_time`
against source event time. The supplied saved searches are templates: scheduling,
lookback, alert actions, permissions, and throttling are deployment decisions.

## Correlation windows

Both outputs contain executable `event_count` aggregation and threshold filters.
The supported shape is one base detection and one correlation, no aliases, with
`gt`, `gte`, `lt`, or `lte`, and a positive timespan that divides one UTC day.
Unsupported shapes fail conversion. The shipped rules all use upper thresholds.

Windows are fixed UTC buckets with inclusive starts and exclusive ends. For a
five-minute rule, 12:04:00 and 12:04:30 fall in a different bucket from 12:05:00.
A burst straddling that boundary can be missed; this is a known limitation of
this conversion, also described in the [Sigma correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html#compatibility).
The offline summary reports the first qualifying bucket per group; the SIEM
queries return every qualifying bucket. Empty buckets are not generated.

Use a lookback covering complete buckets plus expected ingestion delay. Repeated
runs can return the same bucket, so configure deduplication by rule, tenant,
principal/conversation and bucket timestamp. Test scheduling across bucket
boundaries and late arrivals before enabling alert actions.

## Evidence required before enabling alerts

1. Load positive, negative, mixed-case, missing-field, duplicate, cross-tenant,
   and bucket-boundary fixtures into an isolated SIEM test dataset.
2. Execute each selected query and inspect returned event/group identities,
   timestamps and counts. Verify array types, source scoping and time extraction.
3. Replay representative benign traffic. Measure false positives, query cost,
   latency and data completeness; tune thresholds for that deployment.
4. Confirm the investigation workflow, ownership, suppression and rollback.

No live Splunk or Sentinel execution, independent attack corpus evaluation, or
production false-positive rate is established by this repository's offline CI.
The framework grid counts tagged rules. It is an inventory, not a percentage of
attacks prevented or detected.
