"""PromptHound -> Kusto/Sentinel pySigma processing pipeline (PRD §12, decision D5).

Placeholder. Phase 1 will implement a ``ProcessingPipeline`` that maps the
PromptHound audit-log schema (PRD §10, ``logsource: product: llm_gateway``) onto
Sentinel/ASIM and emits KQL via ``pysigma-backend-kusto`` (target ``kusto``,
``sentinelasim`` pipeline, with ``azure_monitor`` as a documented fallback).

There is deliberately NO ``pysigma-backend-sentinel`` -- it does not exist (D5).
Kept import-free for now so the scaffold needs no pySigma installed.
"""

from __future__ import annotations


def build_pipeline() -> object:
    """Return the PromptHound->Kusto/Sentinel processing pipeline (not yet implemented)."""
    raise NotImplementedError("Kusto/Sentinel pipeline lands in Phase 1 (PRD §12, D5).")
