from __future__ import annotations

from pathlib import Path

import pytest

from prompthound import demo
from tests.helpers import ROOT


@pytest.fixture(scope="module")
def result() -> demo.Result:
    return demo.run()


def test_the_demo_passes(result: demo.Result) -> None:
    assert result.ok
    assert result.cases_passed == result.cases_total > 0
    assert result.background_alerts == 0
    assert len(result.summaries) == 16
    assert all(summary.alerts > 0 for summary in result.summaries)


def test_render(result: demo.Result) -> None:
    text = demo.render(result)
    lines = text.splitlines()
    assert lines[0] == "PromptHound demo: synthetic telemetry, evaluated offline"
    assert lines[2].startswith(f"Dataset: {len(result.dataset.events)} events")
    assert lines[4].split() == ["Rule", "Level", "Cases", "Alerts"]
    assert f"{result.cases_total} of {result.cases_total} scenario cases behave as expected" in text
    assert all(len(line) == len(line.rstrip()) for line in lines)


def test_a_failing_case_fails_the_demo(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    source = ROOT / "rules"
    for path in source.rglob("*.yml"):
        target = rules_dir / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(path.read_text().replace("gte: 20", "gte: 19"))
    result = demo.run(rules_dir=rules_dir)
    assert not result.ok
    assert result.cases_passed < result.cases_total


def test_table_alignment() -> None:
    lines = demo.table(("Name", "Count"), [("a", "5"), ("longer", "10")], right=(1,))
    assert lines == ["Name    Count", "------  -----", "a           5", "longer     10"]
