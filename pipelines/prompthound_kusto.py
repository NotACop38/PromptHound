"""PromptHound -> Kusto/Sentinel pySigma processing pipeline (PRD §12, decision D5).

Maps the PromptHound audit-log schema (PRD §10, ``logsource: product:
llm_gateway``) onto a Sentinel custom table and emits KQL via
``pysigma-backend-kusto`` (target ``kusto``).

There is deliberately NO ``pysigma-backend-sentinel`` -- it does not exist (D5);
Sentinel KQL comes from the Kusto backend.

ASIM has no native table for LLM gateway audit logs, so we target a custom
Log Analytics table. Custom tables in Azure Monitor Logs always carry the
``_CL`` suffix, hence ``PromptHoundAuditLog_CL``. Log Analytics column names
cannot contain dots, so the dotted OTel-style schema fields are mapped to
PascalCase columns here.

Column naming: DCR-based custom tables (the current Logs-ingestion path) accept
arbitrary column names, so the unsuffixed PascalCase columns below are valid as
written. The legacy HTTP Data Collector API instead appends *type* suffixes
(``_s`` string, ``_d`` double, ``_b`` bool, ...); a site ingesting via that path
would add those suffixes to the values below -- this map is the single place to
do so. (``azure_monitor`` is the documented fallback if a site ingests these
events into a different table -- only the table/mappings below change.)
"""

from __future__ import annotations

from sigma.pipelines.kusto_common.postprocessing import create_prepend_query_table_item
from sigma.pipelines.kusto_common.transformations import SetQueryTableStateTransformation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

# Custom Log Analytics / Sentinel table the gateway audit log is ingested into.
# Azure Monitor custom tables always carry the ``_CL`` suffix.
GATEWAY_TABLE = "PromptHoundAuditLog_CL"

# Schema (PRD §10, dotted OTel-style) -> Sentinel custom-log column names.
# Extend this map as new schema fields are referenced by rules.
FIELD_MAPPINGS = {
    "content.input.injection_markers": "InjectionMarkers",
    "content.output.contains_system_prompt": "ContainsSystemPrompt",
    "gen_ai.input.messages": "InputMessages",
    "gen_ai.output.messages": "OutputMessages",
    "gen_ai.system_instructions": "SystemInstructions",
    "guardrail.input.flagged": "GuardrailInputFlagged",
    "guardrail.input.categories": "GuardrailInputCategories",
    "policy.decision": "PolicyDecision",
}


def build_pipeline() -> ProcessingPipeline:
    """Return the PromptHound->Kusto/Sentinel processing pipeline."""
    return ProcessingPipeline(
        name="PromptHound LLM gateway -> Kusto/Sentinel",
        priority=20,
        items=[
            ProcessingItem(
                identifier="prompthound_kusto_set_table",
                transformation=SetQueryTableStateTransformation(GATEWAY_TABLE),
            ),
            ProcessingItem(
                identifier="prompthound_kusto_field_mapping",
                transformation=FieldMappingTransformation(FIELD_MAPPINGS),
            ),
        ],
        # Prepend "<table>\n| where" once the table is set in pipeline state.
        postprocessing_items=[create_prepend_query_table_item()],
    )
