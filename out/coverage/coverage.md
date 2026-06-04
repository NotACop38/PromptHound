# PromptHound coverage map

> Auto-generated from rule metadata by `coverage/build_coverage.py`. Do not hand-edit.

**15 rules** · OWASP LLM Top 10 covered: **6/10**

## OWASP LLM Top 10 (2025)

| OWASP | Category | Covered | Rules | Rule files |
|---|---|:---:|:---:|---|
| LLM01 | Prompt Injection | ✅ | 4 | `jailbreak/persona_safety_bypass_loop.yml`<br>`prompt_injection/direct_injection_marker_count.yml`<br>`prompt_injection/direct_injection_markers.yml`<br>`prompt_injection/indirect_injection_from_untrusted_source.yml` |
| LLM02 | Sensitive Information Disclosure | ✅ | 1 | `data_exfiltration/pii_secret_exfiltration_in_output.yml` |
| LLM03 | Supply Chain | — | 0 |  |
| LLM04 | Data and Model Poisoning | — | 0 |  |
| LLM05 | Improper Output Handling | ✅ | 1 | `insecure_output/unsanitized_output_to_sink.yml` |
| LLM06 | Excessive Agency | ✅ | 4 | `agent_tool_abuse/anomalous_tool_call_chain.yml`<br>`agent_tool_abuse/denied_tool_retry_loop.yml`<br>`agent_tool_abuse/tool_call_amplification_loop.yml`<br>`jailbreak/persona_safety_bypass_loop.yml` |
| LLM07 | System Prompt Leakage | ✅ | 2 | `system_prompt_extraction/extract_system_prompt_markers.yml`<br>`system_prompt_extraction/system_prompt_leaked_in_output.yml` |
| LLM08 | Vector and Embedding Weaknesses | — | 0 |  |
| LLM09 | Misinformation | — | 0 |  |
| LLM10 | Unbounded Consumption | ✅ | 5 | `agent_tool_abuse/tool_call_amplification_loop.yml`<br>`dos_cost_abuse/oversized_max_tokens.yml`<br>`dos_cost_abuse/repeated_length_finish_loops.yml`<br>`dos_cost_abuse/request_rate_burst_per_principal.yml`<br>`dos_cost_abuse/token_cost_spike_per_principal.yml` |

## MITRE ATLAS

| ATLAS ID | Name | Kind | Rules | Rule files |
|---|---|---|:---:|---|
| AML.T0024 | Exfiltration via ML Inference API | technique | 1 | `data_exfiltration/pii_secret_exfiltration_in_output.yml` |
| AML.T0025 | Exfiltration via Cyber Means | technique | 1 | `data_exfiltration/pii_secret_exfiltration_in_output.yml` |
| AML.T0029 | Denial of ML Service | technique | 5 | `agent_tool_abuse/tool_call_amplification_loop.yml`<br>`dos_cost_abuse/oversized_max_tokens.yml`<br>`dos_cost_abuse/repeated_length_finish_loops.yml`<br>`dos_cost_abuse/request_rate_burst_per_principal.yml`<br>`dos_cost_abuse/token_cost_spike_per_principal.yml` |
| AML.T0034 | Cost Harvesting | technique | 5 | `agent_tool_abuse/tool_call_amplification_loop.yml`<br>`dos_cost_abuse/oversized_max_tokens.yml`<br>`dos_cost_abuse/repeated_length_finish_loops.yml`<br>`dos_cost_abuse/request_rate_burst_per_principal.yml`<br>`dos_cost_abuse/token_cost_spike_per_principal.yml` |
| AML.T0051.000 | LLM Prompt Injection: Direct | technique | 2 | `prompt_injection/direct_injection_marker_count.yml`<br>`prompt_injection/direct_injection_markers.yml` |
| AML.T0051.001 | LLM Prompt Injection: Indirect | technique | 1 | `prompt_injection/indirect_injection_from_untrusted_source.yml` |
| AML.T0054 | LLM Jailbreak | technique | 1 | `jailbreak/persona_safety_bypass_loop.yml` |
| AML.T0056 | LLM Meta Prompt Extraction | technique | 2 | `system_prompt_extraction/extract_system_prompt_markers.yml`<br>`system_prompt_extraction/system_prompt_leaked_in_output.yml` |
| AML.T0085.001 | AI Agent Tools | technique | 2 | `agent_tool_abuse/anomalous_tool_call_chain.yml`<br>`agent_tool_abuse/denied_tool_retry_loop.yml` |
| AML.TA0015 | Command and Control | tactic | 3 | `agent_tool_abuse/anomalous_tool_call_chain.yml`<br>`agent_tool_abuse/denied_tool_retry_loop.yml`<br>`agent_tool_abuse/tool_call_amplification_loop.yml` |

## MITRE ATT&CK (cross-reference)

| ATT&CK ID | Name | Rules | Rule files |
|---|---|:---:|---|
| T1059 | Command and Scripting Interpreter | 1 | `insecure_output/unsanitized_output_to_sink.yml` |

## Tier breakdown

| Tier | Description | Rules |
|---|---|:---:|
| T1 | Operational / metadata (always-on) | 11 |
| T2 | Content inspection (opt-in) | 6 |
