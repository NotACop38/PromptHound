"""Splunk SPL conversion for rules over the PromptHound audit schema.

Fields are renamed to the names Splunk's JSON extraction gives the normalized
events: ``user.tenant.id`` becomes ``user_tenant_id`` and string arrays such as
``tool.call.chain`` become ``tool_call_chain{}``, which pySigma quotes in the
generated search.
"""

from __future__ import annotations

from sigma.backends.splunk.splunk import SplunkBackend
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from prompthound import fields


def splunk_pipeline() -> ProcessingPipeline:
    """Field mapping from audit-schema names to Splunk field names."""
    mapping: dict[str | None, str | list[str]] = {
        name: field.splunk_name
        for name, field in fields.registry().items()
        if field.splunk_name != name
    }
    return ProcessingPipeline(
        name="PromptHound audit schema to Splunk",
        priority=20,
        items=[
            ProcessingItem(
                identifier="prompthound_splunk_fields",
                transformation=FieldMappingTransformation(mapping),
                rule_conditions=[LogsourceCondition(product="llm_gateway")],
            )
        ],
    )


def splunk_backend() -> SplunkBackend:
    return SplunkBackend(processing_pipeline=splunk_pipeline())


__all__ = ["splunk_backend", "splunk_pipeline"]
