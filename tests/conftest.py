from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from prompthound import generator, rules, scenarios

RuleWriter = Callable[..., Path]


@pytest.fixture(scope="session")
def pack() -> list[rules.Rule]:
    return rules.load_rules()


@pytest.fixture(scope="session")
def by_stem(pack: list[rules.Rule]) -> dict[str, rules.Rule]:
    return {rule.stem: rule for rule in pack}


@pytest.fixture(scope="session")
def scenario_set(pack: list[rules.Rule]) -> list[scenarios.Scenario]:
    return scenarios.load_scenarios(pack)


@pytest.fixture(scope="session")
def dataset(scenario_set: list[scenarios.Scenario]) -> generator.Dataset:
    return generator.build_dataset(scenario_set, seed=0)


@pytest.fixture
def write_rule(tmp_path: Path) -> RuleWriter:
    """Write rule documents to ``<tmp>/rules/<relpath>`` and return the rule-pack root."""

    def write(
        documents: dict[str, Any] | list[dict[str, Any]], relpath: str = "t/rule.yml"
    ) -> Path:
        root = tmp_path / "rules"
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        docs = documents if isinstance(documents, list) else [documents]
        path.write_text(yaml.safe_dump_all(docs, sort_keys=False), encoding="utf-8")
        return root

    return write
