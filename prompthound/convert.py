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
    """

    rule_path: Path
    spl: list[str]
    savedsearches: str
    kql: list[str]


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

    from pipelines.prompthound_kusto import kusto_backend
    from pipelines.prompthound_splunk import splunk_backend
    from prompthound.fieldmap import DEFAULT_QUERY_TABLE

    path = Path(rule_path)
    collection = SigmaCollection.load_ruleset([str(path)])

    splunk = splunk_backend()
    spl = list(splunk.convert(collection))
    savedsearches = splunk.convert(collection, output_format="savedsearches")

    table = query_table or DEFAULT_QUERY_TABLE
    kusto = kusto_backend(query_table=table, flavour=kusto_flavour)  # type: ignore[arg-type]
    kql = list(kusto.convert(collection))

    return ConversionResult(
        rule_path=path,
        spl=spl,
        savedsearches=str(savedsearches),
        kql=kql,
    )


__all__ = ["ConversionResult", "convert_rule"]
