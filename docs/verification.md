# Verification

PromptHound makes one central claim: a rule that loads matches the same events
offline, in Splunk and in KQL. This page describes how that claim and the rest
of the pack's behavior are checked, what the last run found, and what is not
covered.

## What is checked

| Check | What it establishes | Where |
|---|---|---|
| Rule loader | Every detection uses only the [supported Sigma subset](authoring.md#supported-sigma-subset), and every framework mapping exists in its catalog. | `src/prompthound/rules.py` |
| Scenario cases | Each rule alerts on the behavior it targets and stays silent on nearby benign behavior and at its boundaries: thresholds, window edges, tenant isolation, casing. 83 cases across 16 rules. | `scenarios/`, `prompthound test` |
| Mutation tests | Weakening any rule — a lower threshold, a dropped condition, a missing group field — breaks at least one of its cases, so the cases constrain the logic. | `tests/test_scenarios.py` |
| Conformance cases | The matching semantics of the subset, including the edge cases where engines commonly differ: case folding, non-ASCII letters, escaped quotes in JSON text, line breaks, integer and decimal equality, missing fields under negation. 39 cases over 7 events. | `tests/conformance.yml` |
| Engine verification | The generated SPL and KQL return exactly what the offline evaluator returns, in Splunk Enterprise and in the Kusto engine. | `scripts/verify_siem.py`, `make verify-siem` |
| Generated artifacts | The committed SIEM content, rule catalog, ATLAS layer and documentation tables match their sources. | `scripts/generate.py --check` |
| Background traffic | 48 benign events, including events over 12,000 characters, raise no alert. | `tests/test_generator.py` |
| Static checks | Formatting and lint (ruff), strict typing of the package, scripts and tests (mypy), and branch coverage of at least 95%. | `make ci` |
| Supply chain | Known vulnerabilities in both lockfiles (pip-audit, hashes required), unsafe patterns in first-party code (bandit), committed credentials, and exploit payloads in rules, scenarios and generated data. | `scripts/security.py`, `prompthound.payload_guard` |

`make ci` runs everything except the engine verification, which needs Docker.

## Engine verification

`scripts/verify_siem.py`:

1. builds the scenario dataset (background traffic, every scenario case, and
   copies of the content cases padded past 12,000 characters) and the
   conformance events;
2. converts them to the SIEM layout and loads them into a Splunk index and a
   Kusto table;
3. runs every rule as shipped — each saved search from the generated Splunk app,
   through its macro and sourcetype, and each generated KQL file — and every
   conformance case as an ad-hoc search and query;
4. compares each result with the offline evaluator: the same event IDs for
   single-event rules, and the same groups, window starts and counts for
   correlations. Any difference fails the run.

### Last run

2026-09-26, Splunk Enterprise 10.4.3 (`splunk/splunk:latest`) and the Kusto
emulator build 1.0.9763.20628 (`mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`),
463 events, the largest 37,567 bytes. All 16 rules and all 39 conformance cases
agreed.

<details>
<summary>Output</summary>

```text
rule (saved search / KQL file)                                 offline  splunk  kusto
agent_tool_abuse/anomalous_tool_call_chain.yml                       3   ok     ok
agent_tool_abuse/denied_tool_retry_loop.yml                          2   ok     ok
agent_tool_abuse/tool_call_amplification_loop.yml                    2   ok     ok
data_exfiltration/pii_secret_exfiltration_in_output.yml              2   ok     ok
dos_cost_abuse/oversized_max_tokens.yml                              2   ok     ok
dos_cost_abuse/repeated_length_finish_loops.yml                      3   ok     ok
dos_cost_abuse/request_rate_burst_per_principal.yml                  3   ok     ok
dos_cost_abuse/token_cost_spike_per_principal.yml                    2   ok     ok
insecure_output/unsanitized_output_to_sink.yml                       3   ok     ok
jailbreak/persona_safety_bypass_loop.yml                             4   ok     ok
prompt_injection/direct_injection_marker_count.yml                  44   ok     ok
prompt_injection/direct_injection_markers.yml                       16   ok     ok
prompt_injection/indirect_injection_from_untrusted_source.yml        6   ok     ok
system_prompt_extraction/extract_system_prompt_markers.yml           5   ok     ok
system_prompt_extraction/system_prompt_disclosure_phrases.yml        4   ok     ok
system_prompt_extraction/system_prompt_leaked_in_output.yml          1   ok     ok

conformance case (ad-hoc query)                                offline  splunk  kusto
equality ignores case                                                2   ok     ok
a value list matches any value                                       3   ok     ok
contains                                                             2   ok     ok
startswith                                                           4   ok     ok
endswith                                                             4   ok     ok
a wildcard matches any run of characters                             4   ok     ok
a dot is literal                                                     1   ok     ok
wildcard lists keep the order within each value                     25   ok     ok
contains all in content                                              4   ok     ok
a wildcard spans an escaped line break                               2   ok     ok
quotes are escaped in the JSON text                                  0   ok     ok
an escaped quote matches                                             1   ok     ok
a non-ASCII letter does not fold                                     0   ok     ok
ASCII letters beside a non-ASCII letter fold                         1   ok     ok
a non-ASCII letter in an exact value                                 1   ok     ok
a non-ASCII letter in the other case                                 0   ok     ok
a value list with a non-ASCII letter                                 2   ok     ok
array elements fold ASCII letters only                               0   ok     ok
string content                                                       1   ok     ok
structured content                                                   1   ok     ok
gte                                                                 42   ok     ok
gt                                                                  41   ok     ok
lt                                                                   1   ok     ok
lte                                                                  2   ok     ok
integer equality                                                     1   ok     ok
decimal comparison                                                   2   ok     ok
decimal equality                                                     1   ok     ok
zero equals zero point zero                                          2   ok     ok
equals true                                                          9   ok     ok
equals false                                                         7   ok     ok
an element matches                                                   8   ok     ok
any listed element matches                                           5   ok     ok
all listed elements                                                  3   ok     ok
negated string                                                     461   ok     ok
negated boolean                                                    454   ok     ok
negated content                                                    433   ok     ok
negated group                                                      453   ok     ok
one of                                                              10   ok     ok
all of                                                               1   ok     ok

all engines agree with the offline evaluator
```

</details>

The *offline* column is the number of result rows: matching events for
single-event rules and conformance cases, qualifying windows for correlations.

### Run it

```bash
make verify-siem
```

This starts both engines in throwaway Docker containers bound to localhost,
installs the generated Splunk app, runs the comparison and removes the
containers. It needs Docker, about 12 GB of disk for the two images, and ports
8080 and 8089, and takes several minutes. Starting the containers accepts the
[Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html)
and the Kusto emulator's license on your behalf; read them first.

To use instances you manage instead (test instances only: the harness creates
an index and a table and loads synthetic data):

```bash
python scripts/verify_siem.py --kusto-url http://localhost:8080 \
    --splunk-url http://localhost:8089 --splunk-password '<admin password>'
```

The Splunk instance must have `siem/splunk/app/prompthound` installed.

On GitHub, the *Verify SIEM queries* workflow runs the same comparison when
started manually from the Actions tab.

## Not covered

- **Detection quality.** Scenarios are synthetic. They show that each rule's
  logic does what it states, not how often real attacks produce these signals or
  how often benign traffic does. Measure that on your own traffic.
- **Log Analytics.** The KQL runs in the Azure Data Explorer engine, not in a
  Log Analytics workspace; see [deployment.md](deployment.md#queries).
- **Other versions and ingestion paths.** Splunk receives events through its
  simple receiver endpoint and Kusto through inline ingestion. Other Splunk
  versions, forwarders, the HTTP Event Collector and data collection rules are
  not exercised.
- **Scheduling and alerting.** Saved-search schedules, analytics-rule settings,
  throttling and alert actions are deployment decisions and are not tested.
- **The one known difference.** KQL's `=~` and `in~` treat U+212A KELVIN SIGN as
  `k`; no conformance case exercises it.
