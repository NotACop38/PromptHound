"""PromptHound → Kusto/Sentinel pySigma processing pipeline (PRD §12, decision D5).

Maps the PromptHound audit-log schema (PRD §10, ``logsource: product:
llm_gateway``) onto flattened Kusto column names and a Sentinel custom-log table,
then lets ``pysigma-backend-kusto`` (target ``kusto``) emit KQL.

There is deliberately **no** ``pysigma-backend-sentinel`` — it does not exist
(D5). Sentinel KQL comes from the Kusto backend driven by one of its bundled
pipelines:

* ``sentinelasim`` — the default, aligning to Sentinel's ASIM normalized schema.
* ``azure_monitor`` — a documented fallback for plain Log Analytics
  deployments without ASIM (PRD §17: "Sentinel ASIM table mismatch → fall back
  to ``azure_monitor``").

Neither bundled pipeline knows our ``llm_gateway`` logsource, so they would not
assign a query table. We therefore (a) flatten our schema fields ourselves and
(b) pass an explicit ``query_table`` so the Kusto backend prepends the audit
table to every query. pySigma 1.0.0's factory pattern (PRD §13) lets us compose
``our_field_map + bundled_pipeline`` with the ``+`` operator.
"""

from __future__ import annotations

from typing import Literal

from sigma.backends.kusto import KustoBackend
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from prompthound.fieldmap import DEFAULT_QUERY_TABLE, FIELD_MAP

#: Kusto pipeline flavours we support. ``sentinelasim`` is the default; switch to
#: ``azure_monitor`` for non-ASIM Log Analytics deployments (PRD §17).
KustoFlavour = Literal["sentinelasim", "azure_monitor"]

# Lower priority => our field flattening runs before the bundled pipeline.
_PIPELINE_PRIORITY = 20


def _prompthound_field_pipeline() -> ProcessingPipeline:
    """The PromptHound-specific half: flatten schema fields for ``llm_gateway`` rules."""
    return ProcessingPipeline(
        name="PromptHound LLM Gateway field mapping (Kusto)",
        priority=_PIPELINE_PRIORITY,
        items=[
            ProcessingItem(
                identifier="prompthound_kusto_field_mapping",
                transformation=FieldMappingTransformation(dict(FIELD_MAP)),
                rule_conditions=[LogsourceCondition(product="llm_gateway")],
            ),
        ],
    )


def prompthound_kusto_pipeline(
    query_table: str = DEFAULT_QUERY_TABLE,
    flavour: KustoFlavour = "sentinelasim",
) -> ProcessingPipeline:
    """Return a fresh PromptHound → Kusto/Sentinel pipeline (factory pattern).

    Args:
        query_table: Sentinel/Log Analytics table the KQL runs against. Passed to
            the bundled pipeline so the backend prepends it to each query.
        flavour: ``"sentinelasim"`` (default) or ``"azure_monitor"`` fallback.
    """
    if flavour == "sentinelasim":
        bundled = sentinel_asim_pipeline(query_table=query_table)
    elif flavour == "azure_monitor":
        bundled = azure_monitor_pipeline(query_table=query_table)
    else:  # pragma: no cover - guarded by the Literal type
        raise ValueError(f"unknown Kusto flavour: {flavour!r}")
    return _prompthound_field_pipeline() + bundled


def kusto_backend(
    query_table: str = DEFAULT_QUERY_TABLE,
    flavour: KustoFlavour = "sentinelasim",
) -> KustoBackend:
    """Return a Kusto backend (target ``kusto``) wired to the PromptHound pipeline."""
    return KustoBackend(processing_pipeline=prompthound_kusto_pipeline(query_table, flavour))


__all__ = [
    "KustoFlavour",
    "kusto_backend",
    "prompthound_kusto_pipeline",
]
