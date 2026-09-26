# Audit event schema

PromptHound's rules read one JSON object per LLM or agent operation: a model
call, a tool call or a sub-agent invocation, as recorded by the gateway or
application that brokers it. The schema is
[`src/prompthound/data/audit_log.schema.json`](../src/prompthound/data/audit_log.schema.json)
(JSON Schema 2020-12), version **0.2**. Check a file of events with:

```bash
prompthound validate events.jsonl
```

## Conventions

- **Names.** Fields marked *OpenTelemetry* use the attribute names of the
  [OpenTelemetry semantic conventions for generative AI](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
  and the general conventions (`service.name`, `user.id`, `client.address`).
  The GenAI conventions are still in development; `schema_version` records which
  names an event uses. Fields marked *PromptHound* have no OpenTelemetry
  equivalent: identity and gateway context, tool-chain state, cost, and the
  outputs of content detectors.
- **Required fields.** `schema_version` (`"0.2"`), `timestamp`, `event.id`,
  `event.outcome` and `gen_ai.operation.name`. Every other field is optional,
  and an event may carry fields the schema does not define.
- **Timestamps** are RFC 3339 with a UTC offset (`2026-06-01T12:00:00Z` or
  `2026-06-01T14:00:00+02:00`).
- **Identity.** `user.id` and `gen_ai.conversation.id` must be unique within a
  tenant, and `user.tenant.id` must be set even in a single-tenant deployment:
  every correlation groups by it, and an event without it is not counted.
- **Operations.** Completion operations (`chat`, `text_completion`,
  `generate_content`) carry model, usage and message fields. Tool operations
  (`execute_tool`, `invoke_agent`) carry `gen_ai.tool.*` and `tool.call.*`
  fields.
- **Event IDs** identify an operation. Deduplicate replayed events by
  `event.id` before they reach the SIEM, or correlations count them twice.

## Data classes

Each field has a class, which decides what an organization must collect and
retain for a rule to work:

| Class | Content | Collected by |
|---|---|---|
| **Metadata** | Identities, operation, model, token usage, cost, tool-chain state, policy decisions. | The gateway, without analyzing prompts or responses. |
| **Derived** | Counts, flags and class labels a content detector produces: injection markers, detected personal-data and credential classes, system-prompt leakage, guardrail verdicts. | A detector that reads the content. Only its verdict is stored. |
| **Content** | Prompts, responses, system instructions and tool payloads. | The gateway, when content logging is enabled. |

Content fields hold personal and confidential data. Rules that read derived
fields detect the same behavior without retaining raw text; the
[rule catalog](rules.md) lists which class each rule needs, and
`prompthound readiness events.jsonl` reports which rules a body of telemetry
supports.

## Example

```json
{
  "schema_version": "0.2",
  "timestamp": "2026-06-01T12:00:00Z",
  "event.id": "0f7c2e0a-5b1d-4f59-9a51-3c1d2e4f6a7b",
  "event.outcome": "success",
  "gen_ai.operation.name": "chat",
  "service.name": "support-assistant",
  "deployment.environment.name": "production",
  "user.tenant.id": "tenant-example",
  "user.id": "user-7f3a9c21d4",
  "gen_ai.conversation.id": "conv-7f3a9c21d4",
  "policy.decision": "allow",
  "gen_ai.provider.name": "openai",
  "gen_ai.request.model": "gpt-4.1",
  "gen_ai.response.model": "gpt-4.1",
  "gen_ai.usage.input_tokens": 320,
  "gen_ai.usage.output_tokens": 180,
  "usage.total_tokens": 500,
  "cost.usd": 0.00208,
  "gen_ai.response.finish_reasons": ["stop"],
  "content.input.injection_markers": 0,
  "content.output.contains_system_prompt": false,
  "gen_ai.input.messages": [
    {"role": "user", "parts": [{"type": "text", "content": "Can you summarize the open support tickets for my account?"}]}
  ],
  "gen_ai.output.messages": [
    {"role": "assistant", "parts": [{"type": "text", "content": "You have two open tickets, both awaiting a reply."}], "finish_reason": "stop"}
  ]
}
```

## SIEM column layout

`prompthound normalize` converts events to the layout the generated queries
read. The audit events stay as they are; the SIEM receives the converted copy.

- Dotted names become column names with underscores: `user.tenant.id` becomes
  `user_tenant_id`. A field outside the schema is renamed the same way, and a
  name that would collide with another column is rejected.
- Content fields become their compact JSON text (a plain string stays as it is),
  which is what content rules match against.
- `timestamp` is converted to UTC with microseconds
  (`2026-06-01T12:00:00.000000Z`) and written first.
- Every event is validated, and a JSON object with a duplicate key is rejected
  rather than silently collapsed. The output file is replaced only when every
  line converts.

String arrays stay arrays: Splunk extracts them as multivalue fields named
`column{}` (for example `tool_call_chain{}`), and Sentinel stores them as
`dynamic` columns. The table below lists each field's column; the Splunk name
differs only for arrays. [deployment.md](deployment.md) covers ingestion.

## Field reference

<!-- fields:start -->
### Metadata fields

| Field | Type | Origin | SIEM column | Description |
|---|---|---|---|---|
| `schema_version` | string | PromptHound | `schema_version` | Schema version of this event. |
| `timestamp` | string | PromptHound | `timestamp` | Operation time as an RFC 3339 timestamp with a UTC offset. |
| `event.id` | string | PromptHound | `event_id` | Unique event identifier; used to deduplicate replayed events. |
| `event.outcome` | string | PromptHound | `event_outcome` | Operation outcome. blocked means a policy stopped the operation. |
| `gen_ai.operation.name` | string | OpenTelemetry | `gen_ai_operation_name` | Operation name. Well-known values include chat, generate_content, text_completion, embeddings, retrieval, execute_tool, invoke_agent, create_agent and invoke_workflow. |
| `gen_ai.conversation.id` | string | OpenTelemetry | `gen_ai_conversation_id` | Conversation or session identifier, unique within the tenant. |
| `gen_ai.provider.name` | string | OpenTelemetry | `gen_ai_provider_name` | Model provider, for example openai, anthropic or aws.bedrock. |
| `gen_ai.request.model` | string | OpenTelemetry | `gen_ai_request_model` | Requested model name. |
| `gen_ai.response.model` | string | OpenTelemetry | `gen_ai_response_model` | Model that produced the response. |
| `service.name` | string | OpenTelemetry | `service_name` | Name of the LLM application or gateway. |
| `deployment.environment.name` | string | OpenTelemetry | `deployment_environment_name` | Deployment environment, for example production or staging. |
| `user.id` | string | OpenTelemetry | `user_id` | Pseudonymous principal identifier, unique within the tenant. |
| `user.roles` | string array | OpenTelemetry | `user_roles` (Splunk `user_roles{}`) | Roles or authorization groups of the principal. |
| `user.tenant.id` | string | PromptHound | `user_tenant_id` | Tenant or organization identifier. Every correlation groups by it. |
| `api_key.id` | string | PromptHound | `api_key_id` | Opaque or hashed API key identifier. Never the key itself. |
| `client.address` | string | OpenTelemetry | `client_address` | Address of the client that called the gateway. |
| `user_agent.original` | string | OpenTelemetry | `user_agent_original` | Client user agent. |
| `http.request.id` | string | PromptHound | `http_request_id` | Request identifier for correlation with upstream HTTP logs. |
| `gen_ai.usage.input_tokens` | integer | OpenTelemetry | `gen_ai_usage_input_tokens` | Input tokens consumed. |
| `gen_ai.usage.output_tokens` | integer | OpenTelemetry | `gen_ai_usage_output_tokens` | Output tokens produced. |
| `gen_ai.usage.reasoning.output_tokens` | integer | OpenTelemetry | `gen_ai_usage_reasoning_output_tokens` | Reasoning tokens, when the provider reports them. |
| `usage.total_tokens` | integer | PromptHound | `usage_total_tokens` | Input plus output tokens. |
| `gen_ai.request.temperature` | number | OpenTelemetry | `gen_ai_request_temperature` | Requested sampling temperature. |
| `gen_ai.request.top_p` | number | OpenTelemetry | `gen_ai_request_top_p` | Requested nucleus-sampling probability. |
| `gen_ai.request.max_tokens` | integer | OpenTelemetry | `gen_ai_request_max_tokens` | Requested maximum output tokens. |
| `gen_ai.request.choice.count` | integer | OpenTelemetry | `gen_ai_request_choice_count` | Requested number of candidate completions. |
| `gen_ai.response.finish_reasons` | string array | OpenTelemetry | `gen_ai_response_finish_reasons` (Splunk `gen_ai_response_finish_reasons{}`) | Finish reason per choice, for example stop, length, tool_calls or content_filter. |
| `cost.usd` | number | PromptHound | `cost_usd` | Gateway-computed cost of the operation in US dollars. |
| `error.type` | string | OpenTelemetry | `error_type` | Low-cardinality error class when the operation failed. |
| `policy.decision` | string | PromptHound | `policy_decision` | Gateway policy decision for the operation. |
| `gen_ai.data_source.id` | string | OpenTelemetry | `gen_ai_data_source_id` | Identifier of the data source used for retrieval. |
| `rag.retrieved.count` | integer | PromptHound | `rag_retrieved_count` | Number of retrieved chunks added to the model context. |
| `rag.source.types` | string array | PromptHound | `rag_source_types` (Splunk `rag_source_types{}`) | Types of the retrieved sources, for example web, email, file, ticket or db. |
| `gen_ai.agent.id` | string | OpenTelemetry | `gen_ai_agent_id` | Agent identifier. |
| `gen_ai.agent.name` | string | OpenTelemetry | `gen_ai_agent_name` | Agent name. |
| `gen_ai.tool.name` | string | OpenTelemetry | `gen_ai_tool_name` | Name of the invoked tool. |
| `gen_ai.tool.call.id` | string | OpenTelemetry | `gen_ai_tool_call_id` | Tool call identifier. |
| `gen_ai.tool.type` | string | OpenTelemetry | `gen_ai_tool_type` | Tool type, for example function, extension or datastore. |
| `tool.call.depth` | integer | PromptHound | `tool_call_depth` | Position of this call in the current tool chain. |
| `tool.call.chain` | string array | PromptHound | `tool_call_chain` (Splunk `tool_call_chain{}`) | Names of the tools invoked so far in this turn, in order. |
| `tool.call.outcome` | string | PromptHound | `tool_call_outcome` | Outcome of the tool call. denied means an authorization policy refused it. |
| `output.sink` | string | PromptHound | `output_sink` | Downstream consumer that received the model output. |
| `output.rendered_unsanitized` | boolean | PromptHound | `output_rendered_unsanitized` | The output reached its sink without sanitization or escaping. |

### Derived fields (produced by a content detector)

| Field | Type | Origin | SIEM column | Description |
|---|---|---|---|---|
| `guardrail.input.flagged` | boolean | PromptHound | `guardrail_input_flagged` | An input guardrail flagged the request. |
| `guardrail.input.categories` | string array | PromptHound | `guardrail_input_categories` (Splunk `guardrail_input_categories{}`) | Input guardrail categories, for example injection or pii. |
| `guardrail.output.flagged` | boolean | PromptHound | `guardrail_output_flagged` | An output guardrail flagged the response. |
| `guardrail.output.categories` | string array | PromptHound | `guardrail_output_categories` (Splunk `guardrail_output_categories{}`) | Output guardrail categories. |
| `content.input.injection_markers` | integer | PromptHound | `content_input_injection_markers` | Number of prompt-injection or instruction-extraction markers a detector found in the input. |
| `content.output.contains_system_prompt` | boolean | PromptHound | `content_output_contains_system_prompt` | A detector found system-instruction content in the output. |
| `content.output.pii.types` | string array | PromptHound | `content_output_pii_types` (Splunk `content_output_pii_types{}`) | Personal-data classes a detector found in the output, for example email, phone or ssn. |
| `content.output.secret.types` | string array | PromptHound | `content_output_secret_types` (Splunk `content_output_secret_types{}`) | Credential classes a detector found in the output, for example api_key or private_key. |

### Content fields

| Field | Type | Origin | SIEM column | Description |
|---|---|---|---|---|
| `gen_ai.tool.call.arguments` | any | OpenTelemetry | `gen_ai_tool_call_arguments` | Arguments passed to the tool. |
| `gen_ai.tool.call.result` | any | OpenTelemetry | `gen_ai_tool_call_result` | Result returned by the tool. |
| `gen_ai.system_instructions` | string or array | OpenTelemetry | `gen_ai_system_instructions` | System instructions supplied to the model. |
| `gen_ai.input.messages` | array | OpenTelemetry | `gen_ai_input_messages` | Input messages in the OpenTelemetry message format: {role, parts}. |
| `gen_ai.output.messages` | array | OpenTelemetry | `gen_ai_output_messages` | Output messages in the OpenTelemetry message format: {role, parts, finish_reason}. |
<!-- fields:end -->

## Changes from 0.1

Schema 0.2 aligns field names with the OpenTelemetry conventions. Events that
declare `schema_version: "0.1"` are rejected.

| 0.1 | 0.2 |
|---|---|
| `event.action` (required; fixed list) | `gen_ai.operation.name` (required; any operation name) |
| `app.name` | `service.name` |
| `app.env` (`prod`, `staging`, `dev`) | `deployment.environment.name` (any value) |
| `source.ip` | `client.address` |
| `gen_ai.usage.total_tokens` | `usage.total_tokens` |
| `tool.call.arguments`, `tool.call.result` | `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` (any JSON value) |
| `gen_ai.data_source.id` (array) | `gen_ai.data_source.id` (string) |
| `gen_ai.tool.type` (`function`, `extension`, `mcp`) | `gen_ai.tool.type` (any value) |
| `gen_ai.system_instructions` (string) | `gen_ai.system_instructions` (string, or an array of parts) |
| `client.geo.country`, `gen_ai.client.operation.duration` | Removed |
| `guardrail.*` (metadata) | `guardrail.*` (derived) |
