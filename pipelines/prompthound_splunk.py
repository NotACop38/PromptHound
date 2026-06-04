"""PromptHound → Splunk pySigma processing pipeline (PRD §12, decision D5).

Maps the PromptHound audit-log schema (PRD §10, ``logsource: product:
llm_gateway``) onto flattened Splunk field names and lets ``pysigma-backend-
splunk`` (target ``splunk``) emit SPL.

Two output formats are supported by the Splunk backend (PRD §12, D5):

* ``default`` — plain SPL search strings.
* ``savedsearches`` — the same SPL wrapped in a ``savedsearches.conf`` stanza.

pySigma 1.0.0 moved pipelines to the *factory pattern*: a pipeline is a function
returning a fresh :class:`ProcessingPipeline` rather than a module-level
singleton (PRD §13, version discipline). ``prompthound_splunk_pipeline`` is that
factory; ``splunk_backend`` wires it into a configured backend.
"""

from __future__ import annotations

from sigma.backends.splunk import SplunkBackend
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from prompthound.fieldmap import FIELD_MAP

#: Output formats exposed by the Splunk backend that we support (PRD D5).
SUPPORTED_FORMATS = ("default", "savedsearches")

# Lower priority => runs before vendor/content pipelines, so downstream items see
# already-flattened column names.
_PIPELINE_PRIORITY = 20


def prompthound_splunk_pipeline() -> ProcessingPipeline:
    """Return a fresh PromptHound → Splunk processing pipeline (factory pattern)."""
    return ProcessingPipeline(
        name="PromptHound LLM Gateway to Splunk",
        priority=_PIPELINE_PRIORITY,
        items=[
            ProcessingItem(
                identifier="prompthound_splunk_field_mapping",
                transformation=FieldMappingTransformation(dict(FIELD_MAP)),
                rule_conditions=[LogsourceCondition(product="llm_gateway")],
            ),
        ],
    )


def splunk_backend() -> SplunkBackend:
    """Return a Splunk backend (target ``splunk``) wired to the PromptHound pipeline."""
    return SplunkBackend(processing_pipeline=prompthound_splunk_pipeline())


__all__ = ["SUPPORTED_FORMATS", "prompthound_splunk_pipeline", "splunk_backend"]
