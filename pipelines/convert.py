"""Sigma -> SPL / KQL conversion helpers (PRD §12, decision D5).

One place that wires a ruleset path to each backend with its PromptHound
processing pipeline. Used by the conversion-snapshot tests, ``scripts/ci.py``,
and ``scripts/release.py`` so the conversion is defined exactly once.

A fresh ``SigmaCollection`` is loaded per backend on purpose: pySigma pipelines
mutate the parsed rule objects in place, so sharing one collection across
backends would leak (e.g.) the Splunk sourcetype condition into the KQL output.
"""

from __future__ import annotations

from pathlib import Path

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

from pipelines.prompthound_kusto import build_pipeline as build_kusto_pipeline
from pipelines.prompthound_splunk import build_pipeline as build_splunk_pipeline


def _load(paths: list[str | Path]) -> SigmaCollection:
    return SigmaCollection.load_ruleset([str(p) for p in paths])


def convert_splunk(paths: list[str | Path]) -> list[str]:
    """Convert the rules at ``paths`` to Splunk SPL queries."""
    backend = SplunkBackend(processing_pipeline=build_splunk_pipeline())
    return backend.convert(_load(paths))


def convert_kusto(paths: list[str | Path]) -> list[str]:
    """Convert the rules at ``paths`` to Microsoft Sentinel KQL queries."""
    backend = KustoBackend(processing_pipeline=build_kusto_pipeline())
    return backend.convert(_load(paths))
