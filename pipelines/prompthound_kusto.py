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

import re
from dataclasses import dataclass
from typing import Literal

from sigma.backends.kusto import KustoBackend
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import (
    ProcessingItem,
    ProcessingPipeline,
    QueryPostprocessingItem,
)
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.processing.transformations import FieldMappingTransformation

from prompthound.fieldmap import DEFAULT_QUERY_TABLE, FIELD_MAP

#: Kusto pipeline flavours we support. ``sentinelasim`` is the default; switch to
#: ``azure_monitor`` for non-ASIM Log Analytics deployments (PRD §17).
KustoFlavour = Literal["sentinelasim", "azure_monitor"]

# Ordering guarantee: ``prompthound_kusto_pipeline`` composes our pipeline as
# ``field_pipeline + bundled`` and pySigma applies items in list order (it does
# NOT re-sort by priority on apply), so our dotted->underscore mapping always runs
# before the bundled ASIM/Azure-Monitor transformations. We additionally set a
# priority below the bundled pipelines' 10 so the order is also correct if these
# pipelines are ever merged via the plugin resolver (which does sort by priority).
_PIPELINE_PRIORITY = 9


@dataclass
class _BooleanCompareFixTransformation(QueryPostprocessingTransformation):
    """Rewrite the backend's boolean comparisons to valid KQL — outside literals.

    The pinned Kusto backend (1.0.x) renders Sigma boolean equality with the
    case-insensitive *string* operators: ``field =~ true`` / ``field !~ false``.
    KQL's ``=~``/``!~`` are string-only, so those queries fail to compile against
    a real ``bool`` column; they must be ``==``/``!=``.

    The rewrite walks the query skipping quoted string literals, so a detection
    marker whose *text* happens to contain ``=~ true`` (inside a ``contains``
    value, say) is never altered — only genuine operator-position comparisons
    against a bare ``true``/``false`` are touched.
    """

    #: One alternation: a single- or double-quoted KQL string literal (group 0
    #: only, passed through untouched) OR a boolean comparison (groups 1+2).
    _LITERAL_OR_BOOL = re.compile(
        r'"(?:\\.|[^"\\])*"'
        r"|'(?:\\.|[^'\\])*'"
        r"|(=~|!~) (true|false)\b"
    )

    def apply(self, rule: object, query: str) -> str:
        super().apply(rule, query)  # type: ignore[arg-type]

        def fix(match: re.Match[str]) -> str:
            operator = match.group(1)
            if operator is None:
                return match.group(0)  # a string literal: leave verbatim
            return f"{'==' if operator == '=~' else '!='} {match.group(2)}"

        return self._LITERAL_OR_BOOL.sub(fix, query)


def _prompthound_field_pipeline() -> ProcessingPipeline:
    """The PromptHound-specific half: flatten schema fields for ``llm_gateway`` rules."""
    # Typed to FieldMappingTransformation's parameter (dict is invariant, so a
    # plain dict[str, str] won't satisfy dict[str | None, str | list[str]]).
    mapping: dict[str | None, str | list[str]] = {k: v for k, v in FIELD_MAP.items()}
    return ProcessingPipeline(
        name="PromptHound LLM Gateway field mapping (Kusto)",
        priority=_PIPELINE_PRIORITY,
        items=[
            ProcessingItem(
                identifier="prompthound_kusto_field_mapping",
                transformation=FieldMappingTransformation(mapping),
                rule_conditions=[LogsourceCondition(product="llm_gateway")],
            ),
        ],
        # See _BooleanCompareFixTransformation: the backend's `=~ true` boolean
        # comparisons are invalid KQL and are rewritten to `== true` — skipping
        # string literals so marker text can never be altered.
        postprocessing_items=[
            QueryPostprocessingItem(
                identifier="prompthound_kusto_bool_compare",
                transformation=_BooleanCompareFixTransformation(),
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
    pipeline = prompthound_kusto_pipeline(query_table, flavour)
    # KustoBackend accepts a ProcessingPipeline at runtime (its __init__ first arg),
    # but the pinned pysigma-backend-kusto stub mistypes the keyword as a dict.
    return KustoBackend(processing_pipeline=pipeline)  # type: ignore[arg-type]


__all__ = [
    "KustoFlavour",
    "kusto_backend",
    "prompthound_kusto_pipeline",
]
