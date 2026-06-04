"""PromptHound -> Splunk pySigma processing pipeline (PRD §12, decision D5).

Maps the PromptHound audit-log schema (PRD §10, ``logsource: product:
llm_gateway``) onto Splunk and emits SPL via ``pysigma-backend-splunk`` (target
``splunk``).

Splunk's JSON sourcetypes auto-extract dotted field names (e.g.
``content.input.injection_markers``), so the schema field names are already
valid SPL fields and need no renaming. The pipeline therefore only scopes the
search to the gateway sourcetype, which is what a deployable saved search wants.
"""

from __future__ import annotations

from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation

# Splunk sourcetype the LLM gateway audit log is expected to land on.
GATEWAY_SOURCETYPE = "llm:gateway:audit"


def build_pipeline() -> ProcessingPipeline:
    """Return the PromptHound->Splunk processing pipeline."""
    return ProcessingPipeline(
        name="PromptHound LLM gateway -> Splunk",
        priority=20,
        items=[
            ProcessingItem(
                identifier="prompthound_splunk_sourcetype",
                transformation=AddConditionTransformation({"sourcetype": GATEWAY_SOURCETYPE}),
            ),
        ],
    )
