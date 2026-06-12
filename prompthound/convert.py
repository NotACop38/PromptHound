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
from collections.abc import Mapping
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

    ``is_correlation`` flags a file containing a Sigma correlation rule. The
    Splunk backend emits the full correlation as SPL, but the Kusto backend
    (1.0.x) emits no correlations at all (PRD §11 #7, docs/authoring.md). For
    those, ``kql`` is the *base* rule's query plus the windowed aggregation as a
    ``// summarize`` comment the analyst un-comments -- so SPL is always
    complete while KQL aggregation is best-effort + documented.
    """

    rule_path: Path
    spl: list[str]
    savedsearches: str
    kql: list[str]
    is_correlation: bool = False


# KQL comparison operators for the aggregation-workaround comment, keyed by the
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
    from prompthound.fieldmap import DEFAULT_QUERY_TABLE

    path = Path(rule_path)
    collection = SigmaCollection.load_ruleset([str(path)])

    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    # Snapshot the base rules' plain dicts BEFORE conversion: each backend's
    # pipeline mutates the shared rule objects in place (field mapping), after
    # which `to_dict()` can no longer reproduce the original detection.
    base_dicts = (
        [r.to_dict() for r in collection.rules if not isinstance(r, SigmaCorrelationRule)]
        if correlations
        else []
    )

    splunk = splunk_backend()
    spl = list(splunk.convert(collection))
    savedsearches = splunk.convert(collection, output_format="savedsearches")

    table = query_table or DEFAULT_QUERY_TABLE
    kusto = kusto_backend(query_table=table, flavour=kusto_flavour)  # type: ignore[arg-type]

    if correlations:
        # The Kusto backend can't emit correlations: emit the base detection's KQL
        # and append the windowed aggregation as a documented `// summarize` comment.
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
    """KQL for a correlation rule: base detection + a `// summarize` workaround.

    The base rule(s) convert to KQL normally; the per-principal windowed
    aggregation the Kusto backend can't express is appended as a commented
    one-liner derived from the correlation's own group-by/timespan/threshold
    (docs/authoring.md).

    Base rules are re-parsed from their plain dict so they convert as standalone
    detections: a base rule still linked to its correlation is suppressed by the
    backend (correlations own their output), which would yield empty KQL.
    """
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule

    from prompthound.fieldmap import FIELD_MAP

    standalone = SigmaCollection([SigmaRule.from_dict(d) for d in base_dicts])
    base_kql = list(kusto.convert(standalone))  # type: ignore[attr-defined]
    if not base_kql:  # pragma: no cover - a correlation file always ships its base rule
        return []

    workaround = "\n".join(_summarize_comment(c, FIELD_MAP) for c in correlations)
    # Attach the workaround to the (single) base query; tolerate the multi-query case.
    base_kql[-1] = f"{base_kql[-1]}\n{workaround}"
    return base_kql


def _summarize_comment(correlation: object, field_map: Mapping[str, str]) -> str:
    """A commented KQL ``summarize`` line realizing the correlation's aggregation."""
    group_by = ", ".join(field_map.get(f, f) for f in correlation.group_by)  # type: ignore[attr-defined]
    ts = field_map.get("timestamp", "timestamp")
    span = correlation.timespan.spec  # type: ignore[attr-defined]
    cond = correlation.condition  # type: ignore[attr-defined]
    op = _KQL_COMPARE.get(cond.op.name)
    if op is None:
        raise ValueError(f"unsupported correlation condition operator: {cond.op.name}")
    ctype = str(correlation.type)  # type: ignore[attr-defined]
    fieldref = field_map.get(cond.fieldref, cond.fieldref) if cond.fieldref else None
    agg = {
        "event_count": "count()",
        "value_count": f"dcount({fieldref})",
        "value_sum": f"sum({fieldref})",
        "value_avg": f"avg({fieldref})",
    }.get(ctype, "count()")
    metric = ctype  # e.g. event_count
    return (
        "// PromptHound: the Kusto backend cannot emit Sigma correlations. To complete\n"
        "// the per-principal windowed aggregation, append the following to the query:\n"
        f"// | summarize {metric} = {agg} by {group_by}, bin({ts}, {span})\n"
        f"// | where {metric} {op} {cond.count}"
    )


__all__ = ["ConversionResult", "convert_rule"]
