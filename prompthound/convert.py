"""Convert a PromptHound Sigma rule to Splunk SPL + Sentinel KQL (PRD §12, D5).

This is the toolchain seam the rest of the project builds on: give it a rule
file, get back both backends' output. It deliberately holds *no* detection logic
— it only wires the two pySigma pipelines (``pipelines/prompthound_splunk.py``,
``pipelines/prompthound_kusto.py``) to their backends so the conversion is
proven before any real rule is written.

Backends and pipelines are imported lazily so that merely importing
``prompthound`` (e.g. for ``__version__``) does not require pySigma to be
installed; the cost is paid only when a conversion is actually requested.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

# ``pipelines`` is packaged in the wheel (see pyproject), so it imports cleanly
# when PromptHound is installed. When run from a checkout, add the repo root so
# ``import pipelines.*`` also resolves from a test, a script, or the REPL.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class ConversionResult:
    """The SPL + KQL produced for a single rule file.

    Each backend returns a list of query strings (one per rule in the file; a
    Sigma file may hold several). ``spl`` is plain SPL; ``savedsearches`` is the
    same content as a ``savedsearches.conf`` document; ``kql`` is Sentinel KQL.

    Correlation output is executable in both backends. PromptHound implements
    the supported single-base event_count subset with fixed UTC time buckets;
    unsupported shapes fail conversion. These are query templates requiring
    the ingestion contract in docs/deployment.md, not installed alerts.
    """

    rule_path: Path
    spl: list[str]
    savedsearches: str
    kql: list[str]
    is_correlation: bool = False


# KQL comparison operators for executable aggregation, keyed by the
# pySigma correlation-condition operator name.
_KQL_COMPARE = {"GT": ">", "GTE": ">=", "LT": "<", "LTE": "<=", "EQ": "==", "NEQ": "!="}


def convert_rule(
    rule_path: str | Path,
    *,
    query_table: str | None = None,
    kusto_flavour: str = "sentinelasim",
) -> ConversionResult:
    """Convert one Sigma rule file to SPL + KQL.

    Args:
        rule_path: Path to a Sigma ``.yml``/``.yaml`` rule file.
        query_table: Sentinel table for the KQL output; defaults to the schema's
            ``DEFAULT_QUERY_TABLE`` when ``None``.
        kusto_flavour: ``"sentinelasim"`` (default) or ``"azure_monitor"``.

    Returns:
        A :class:`ConversionResult` with non-empty SPL and KQL for a valid rule.
    """
    # Lazy imports (see module docstring): keep ``import prompthound`` pySigma-free.
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule

    from pipelines.prompthound_kusto import kusto_backend
    from pipelines.prompthound_splunk import splunk_backend
    from prompthound.correlate import validate_correlation
    from prompthound.fieldmap import DEFAULT_QUERY_TABLE

    path = Path(rule_path)
    collection = SigmaCollection.load_ruleset([str(path)])

    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    base_dicts = []
    if correlations:
        bases = [r for r in collection.rules if not isinstance(r, SigmaCorrelationRule)]
        if len(bases) != 1 or len(correlations) != 1:
            raise NotImplementedError("expected one base rule and one event_count correlation")
        validate_correlation(bases[0], correlations[0])
        base_dicts = [bases[0].to_dict()]

    # pySigma pipelines mutate rule objects. Each format gets a fresh parse so
    # field mappings and conversion state cannot leak into the next backend.
    spl = list(splunk_backend().convert(SigmaCollection.load_ruleset([str(path)])))
    savedsearches = splunk_backend().convert(
        SigmaCollection.load_ruleset([str(path)]), output_format="savedsearches"
    )

    table = query_table or DEFAULT_QUERY_TABLE
    kusto = kusto_backend(query_table=table, flavour=kusto_flavour)  # type: ignore[arg-type]

    if correlations:
        kql = _correlation_kql(base_dicts, correlations, kusto)
    else:
        kql = list(kusto.convert(collection))

    return ConversionResult(
        rule_path=path,
        spl=spl,
        savedsearches=str(savedsearches),
        kql=kql,
        is_correlation=bool(correlations),
    )


def _correlation_kql(base_dicts: list[dict], correlations: list, kusto: object) -> list[str]:
    """Emit the validated event_count subset using executable fixed UTC buckets."""
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule

    from prompthound.fieldmap import FIELD_MAP

    standalone = SigmaCollection([SigmaRule.from_dict(d) for d in base_dicts])
    queries = list(kusto.convert(standalone))  # type: ignore[attr-defined]
    if len(queries) != 1:
        raise NotImplementedError("correlation base must produce exactly one KQL query")
    correlation = correlations[0]
    fields = [FIELD_MAP.get(f, f) for f in (correlation.group_by or [])]
    # Group fields are schema columns; reject expressions or unknown spellings.
    from prompthound.fieldmap import SCHEMA_FIELDS

    if any(f not in SCHEMA_FIELDS for f in (correlation.group_by or [])):
        raise ValueError("correlation group-by must use known schema fields")
    span = correlation.timespan.seconds
    op = _KQL_COMPARE[correlation.condition.op.name]
    query = queries[0]
    if fields:
        query += "\n| where " + " and ".join(f"isnotempty({f})" for f in fields)
    grouping = ", ".join([*fields, f"bin(timestamp, {span}s)"])
    query += (
        "\n// Fixed UTC buckets; bursts crossing a bucket boundary can be missed."
        f"\n| summarize event_count = count() by {grouping}"
        f"\n| where event_count {op} {correlation.condition.count}"
    )
    return [query]


__all__ = ["ConversionResult", "convert_rule"]
