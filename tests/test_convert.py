"""Toolchain proof: Sigma → SPL + KQL (PRD §12, §16 conversion snapshot; D5).

These tests prove the conversion *toolchain* works before any real rule is
authored. They assert the smoke fixture produces non-empty SPL **and** non-empty
KQL through both pySigma backends, exercising the Splunk default + savedsearches
formats and the Kusto ``sentinelasim`` default with the ``azure_monitor``
fallback. Run just these with ``pytest -k convert -q``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from prompthound.convert import convert_rule

REPO_ROOT = Path(__file__).resolve().parent.parent
SMOKE_RULE = REPO_ROOT / "tests" / "fixtures" / "smoke_system_prompt_extraction.yml"


def test_smoke_fixture_exists() -> None:
    assert SMOKE_RULE.is_file(), "missing toolchain smoke fixture"


def test_convert_emits_nonempty_spl_and_kql() -> None:
    result = convert_rule(SMOKE_RULE)

    # Non-empty SPL.
    assert result.spl, "expected at least one SPL query"
    assert all(query.strip() for query in result.spl), "SPL query is blank"

    # Non-empty KQL.
    assert result.kql, "expected at least one KQL query"
    assert all(query.strip() for query in result.kql), "KQL query is blank"


def test_savedsearches_conf_is_nonempty() -> None:
    result = convert_rule(SMOKE_RULE)
    assert result.savedsearches.strip(), "expected non-empty savedsearches.conf output"
    # savedsearches.conf wraps the SPL in a stanza named after the rule title.
    assert "search = " in result.savedsearches


def test_kql_targets_the_audit_table() -> None:
    result = convert_rule(SMOKE_RULE)
    # The Kusto backend prepends our query table because neither bundled
    # pipeline knows the llm_gateway logsource (see prompthound_kusto.py).
    assert all("PromptHoundAuditLog_CL" in query for query in result.kql)


@pytest.mark.parametrize("flavour", ["sentinelasim", "azure_monitor"])
def test_kusto_flavours_both_convert(flavour: str) -> None:
    result = convert_rule(SMOKE_RULE, kusto_flavour=flavour)
    assert result.kql and all(query.strip() for query in result.kql)
