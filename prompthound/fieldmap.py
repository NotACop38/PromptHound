"""Canonical PromptHound schema → SIEM field mapping (PRD §10, D5).

This is the single source of truth shared by both pySigma processing pipelines
(``pipelines/prompthound_splunk.py`` and ``pipelines/prompthound_kusto.py``) so
Splunk SPL and Sentinel KQL stay in lock-step: a field renamed here changes both
backends at once.

Why map at all? The audit-log schema (PRD §10) uses OpenTelemetry-style dotted
field names (``gen_ai.usage.input_tokens``). KQL column references cannot contain
dots, so a mapping is mandatory for the Kusto backend; we apply the *same* map to
Splunk so a given schema field resolves to the identical column in both SIEMs.

Mapping rule: dots become underscores (``a.b.c`` → ``a_b_c``). This is mechanical
and lossless — the SIEM column name is recoverable from the schema field and vice
versa — which keeps generated queries legible against a flattened audit table.

The rationale is documented for rule authors in ``docs/authoring.md``.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

#: Default Sentinel/Log Analytics custom-log table the KQL queries run against.
#: Custom logs land in a ``*_CL`` table; rules target a flattened PromptHound
#: audit table. Override per-conversion if your deployment uses another name.
DEFAULT_QUERY_TABLE = "PromptHoundAuditLog_CL"

# Canonical audit-log field names, grouped exactly as in PRD §10. Every dotted
# field a rule may key on is listed so the mapping is explicit and reviewable
# (not silently inferred). Update this list when the schema (PRD §10) changes.
_SCHEMA_FIELDS: tuple[str, ...] = (
    # 10.1 Envelope, identity, network
    "schema_version",
    "timestamp",
    "event.id",
    "event.action",
    "event.outcome",
    "gen_ai.conversation.id",
    "gen_ai.provider.name",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "app.name",
    "app.env",
    "user.id",
    "user.tenant.id",
    "user.roles",
    "api_key.id",
    "source.ip",
    "user_agent.original",
    "client.geo.country",
    "http.request.id",
    # 10.2 Operational metrics
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
    "gen_ai.usage.reasoning.output_tokens",
    "gen_ai.usage.total_tokens",
    "gen_ai.request.temperature",
    "gen_ai.request.top_p",
    "gen_ai.request.max_tokens",
    "gen_ai.request.choice.count",
    "gen_ai.response.finish_reasons",
    "gen_ai.client.operation.duration",
    "cost.usd",
    "error.type",
    # 10.3 Gateway / guardrail verdicts
    "guardrail.input.flagged",
    "guardrail.input.categories",
    "guardrail.output.flagged",
    "guardrail.output.categories",
    "policy.decision",
    # 10.4 Retrieval / RAG
    "gen_ai.data_source.id",
    "rag.retrieved.count",
    "rag.source.types",
    # 10.5 Agent / tool-call
    "gen_ai.agent.id",
    "gen_ai.agent.name",
    "gen_ai.tool.name",
    "gen_ai.tool.call.id",
    "gen_ai.tool.type",
    "tool.call.depth",
    "tool.call.chain",
    "tool.call.outcome",
    "tool.call.arguments",
    "tool.call.result",
    # 10.6 Insecure output handling
    "output.sink",
    "output.rendered_unsanitized",
    # 10.7 Content (Tier 2)
    "gen_ai.system_instructions",
    "gen_ai.input.messages",
    "gen_ai.output.messages",
    # 10.8 Derived markers
    "content.input.injection_markers",
    "content.output.contains_system_prompt",
    "content.output.pii.types",
    "content.output.secret.types",
)


def _to_column(field: str) -> str:
    """Flatten a dotted schema field to its SIEM column name (``a.b`` → ``a_b``)."""
    return field.replace(".", "_")


#: Schema field → SIEM column. Read-only so neither pipeline can mutate the shared
#: mapping at import time. Only fields that actually contain a dot are remapped;
#: already-flat fields (``timestamp``) are intentionally omitted (no-op).
FIELD_MAP: Mapping[str, str] = MappingProxyType(
    {field: _to_column(field) for field in _SCHEMA_FIELDS if "." in field}
)

__all__ = ["DEFAULT_QUERY_TABLE", "FIELD_MAP"]
