# Deploying to Splunk and Microsoft Sentinel

PromptHound ships generated SIEM content under [`siem/`](../siem):

| Path | Contents |
|---|---|
| `siem/splunk/app/prompthound/` | A Splunk app: sourcetype settings (`props.conf`), the search macro (`macros.conf`), one saved search per rule (`savedsearches.conf`), and the permissions that export them (`metadata/default.meta`). |
| `siem/splunk/<category>/<rule>.spl` | Each rule's search, for use outside the app. |
| `siem/sentinel/table.json` | Column definitions for the Log Analytics custom table. |
| `siem/sentinel/<category>/<rule>.kql` | Each rule's query. |

The rules are experimental. Every query is verified to return exactly what the
offline evaluator returns ([verification.md](verification.md)), but whether a
rule is useful depends on your telemetry and traffic. Work through
[qualification](#qualify-before-alerting) before enabling alerts.

## 1. Instrument

Emit one [schema 0.2](schema.md) event per LLM call, tool call and agent
invocation, then check a sample:

```bash
prompthound validate sample.jsonl       # every event matches the schema
prompthound readiness sample.jsonl      # which rules the telemetry supports, and what is missing
```

Set `user.tenant.id` on every event, keep `user.id` and
`gen_ai.conversation.id` unique within a tenant, and deduplicate replayed events
by `event.id`. Rules that read derived fields depend on the detector that
produces them; their accuracy is bounded by that detector's.

## 2. Convert to the SIEM layout

The queries read events in the SIEM column layout described in
[schema.md](schema.md#siem-column-layout): dotted names become underscored
columns, content fields become JSON text, and timestamps become UTC. Apply the
same conversion in your log pipeline. `prompthound normalize` is the reference
implementation and converts files, for example to backfill or to test:

```bash
prompthound normalize events.jsonl -o siem.jsonl
```

## 3. Splunk

### Install

1. Create an index for the events. The macro assumes `prompthound`.
2. Install the app on the search heads and on the tier that parses the events
   (indexers or heavy forwarders). `make release` builds
   `dist/prompthound-<version>-splunk-app.tgz` for *Install app from file*; you
   can also copy `siem/splunk/app/prompthound` to `$SPLUNK_HOME/etc/apps/`.
3. Point the macro at your index by overriding it in the app's `local/macros.conf`:

   ```ini
   [prompthound_audit]
   definition = index=<your index> sourcetype="prompthound:audit"
   ```

4. Send the converted events with sourcetype `prompthound:audit`, from a
   monitored file, a forwarder or the HTTP Event Collector's raw endpoint. The
   sourcetype's settings take each line as one event, read its time from
   `timestamp`, and never truncate it.

### Keep the app's permissions

`metadata/default.meta` exports the app's settings to every app
(`export = system`). Without the export, the JSON extraction settings apply only
inside the PromptHound app; a search elsewhere falls back to automatic key-value
extraction, which in Splunk 10.4.3 stopped at the first 10,240 characters of an
event, so content rules missed phrases later in long prompts. With the export,
events up to 1.5 MB were extracted completely under Splunk's default limits.

### Searches

Every search starts with the macro `` `prompthound_audit` ``. The app defines
one saved search per rule, named `PromptHound - <rule title>`, unscheduled and
without actions, with a default time range of the last 24 hours. To alert on
one:

- schedule it, with a time range that covers whole correlation windows plus your
  ingestion delay;
- trigger when it returns results;
- throttle on the fields that identify a finding: `event_id` for single-event
  rules; for correlations, the group fields and `_time` (the window start).

Array fields are multivalue fields named with braces, such as
`tool_call_chain{}`; the searches quote them. To use another macro name, generate
the searches with `prompthound convert --target splunk --splunk-macro <name> -o <dir>`.

## 4. Microsoft Sentinel

### Table and ingestion

1. Create a custom table named `PromptHoundAuditLog_CL` with the Analytics
   plan and the columns in `siem/sentinel/table.json`, and a data collection
   rule whose stream declares the same columns.
2. Set `TimeGenerated` from `timestamp` in the rule's transformation:

   ```kusto
   source
   | extend TimeGenerated = todatetime(timestamp)
   ```

3. Send the converted events with the Logs Ingestion API.

The Logs Ingestion API truncates field values longer than 64 KB, so a content
rule cannot match text beyond that point of a message field. Column names stay
within Log Analytics' limit of 45 characters.

### Queries

Every query starts with the table name. To use another table, generate the
queries with `prompthound convert --target sentinel --sentinel-table <name> -o <dir>`.
Create a scheduled analytics rule per query, with a lookback that covers whole
correlation windows plus ingestion delay, and group or suppress alerts on the
same fields as in Splunk: `event_id`, or the group columns and `timestamp`,
which after aggregation holds the window start.

The queries are verified in the Kusto emulator, which runs the Azure Data
Explorer engine. Azure Monitor uses the same query language and documents where
it differs. The queries use only the `where` and `summarize` operators, `bin`,
the comparison operators (`==`, `=~`, `in~`, `contains`, `startswith`,
`endswith`, `matches regex` and numeric comparisons), and the functions
`set_has_element`, `set_intersect`, `array_length`, `parse_json`, `translate`,
`tostring` and `isnotempty`. This project has not run them in a Log Analytics
workspace.

## 5. Correlation windows

Correlations count matching events per group in fixed windows aligned to UTC
midnight: a 5-minute rule counts 12:00–12:05, 12:05–12:10, and so on. The offline
evaluator, the SPL (`bin _time span=5m`) and the KQL (`bin(timestamp, 5m)`)
agree on this, and every qualifying window is a result.

- A burst that straddles a window boundary is split and can stay below the
  threshold. The
  [Sigma correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
  notes the same limitation for backends that bucket time.
- Events that lack a group field are not counted.
- A scheduled search whose time range ends inside a window sees part of it and
  finds the whole window on a later run; deduplicate on the group and window
  start so that one window raises one alert.

## Qualify before alerting

1. Run `prompthound readiness` on production telemetry and resolve missing
   fields for the rules you plan to enable.
2. Optionally run `scripts/verify_siem.py` against your own test instances
   (never production: it creates an index and a table and loads synthetic data).
   See [verification.md](verification.md).
3. Replay representative benign traffic and measure each rule's alert volume.
   Tune thresholds, and replace the tool-name lists in the agent rules with your
   own tool inventory, including namespaces.
4. Decide ownership, triage steps, suppression and rollback for every rule you
   enable.

## Known differences

- KQL's `=~` and `in~` treat U+212A KELVIN SIGN as the letter `k`; Splunk and
  the offline evaluator do not.
- Content longer than 64 KB per field is truncated in Sentinel, not in Splunk.
