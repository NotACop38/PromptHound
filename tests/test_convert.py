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


@pytest.mark.parametrize("flavour", ["sentinelasim", "azure_monitor"])
def test_kql_boolean_equality_uses_double_equals(flavour: str) -> None:
    # Regression: the pinned Kusto backend renders Sigma `field: true` with the
    # string-only `=~` operator, which does not compile against a bool column.
    # The pipeline's postprocessing must rewrite it to `==` (prompthound_kusto.py).
    rule = REPO_ROOT / "rules" / "insecure_output" / "unsanitized_output_to_sink.yml"
    kql = "\n".join(convert_rule(rule, kusto_flavour=flavour).kql)
    assert "output_rendered_unsanitized == true" in kql
    assert "=~ true" not in kql and "=~ false" not in kql


LITERAL_PROBE_RULE = """\
title: Boolean rewrite literal probe
id: 9d2f4c1e-7b3a-4e60-9c15-2a8d0f6b3e72
status: experimental
description: pipeline test fixture - a marker whose text contains an operator-like sequence
author: PromptHound tests
date: 2026-06-12
logsource:
  product: llm_gateway
detection:
  flag:
    output.rendered_unsanitized: true
  marker:
    gen_ai.output.messages|contains: 'flag =~ true'
  condition: flag and marker
falsepositives:
  - none
level: low
"""


def test_kql_boolean_rewrite_spares_string_literals(tmp_path: Path) -> None:
    # The rewrite must touch only operator-position boolean comparisons: a
    # detection marker whose *text* contains "=~ true" lives inside a quoted
    # KQL string literal and has to come through verbatim.
    rule = tmp_path / "literal_probe.yml"
    rule.write_text(LITERAL_PROBE_RULE, encoding="utf-8")
    kql = "\n".join(convert_rule(rule).kql)
    assert 'contains "flag =~ true"' in kql, "marker text inside a literal was altered"
    assert "output_rendered_unsanitized == true" in kql, "real boolean compare not rewritten"
