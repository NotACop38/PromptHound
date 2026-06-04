"""PromptHound -> Splunk pySigma processing pipeline (PRD §12, decision D5).

Placeholder. Phase 1 will implement a ``ProcessingPipeline`` that maps the
PromptHound audit-log schema (PRD §10, ``logsource: product: llm_gateway``) onto
Splunk field names and emits SPL via ``pysigma-backend-splunk`` (target
``splunk``). Kept import-free for now so the scaffold needs no pySigma installed.
"""

from __future__ import annotations


def build_pipeline() -> object:
    """Return the PromptHound->Splunk processing pipeline (not yet implemented)."""
    raise NotImplementedError("Splunk pipeline lands in Phase 1 (PRD §12, D5).")
