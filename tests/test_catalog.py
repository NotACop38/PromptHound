from __future__ import annotations

import json
import re

import pytest

from prompthound import catalog, fields, rules, taxonomy
from prompthound.scenarios import Scenario


@pytest.mark.parametrize(
    ("seconds", "text"), [(300, "5-minute"), (3600, "1-hour"), (7200, "2-hour"), (90, "90-second")]
)
def test_window(seconds: int, text: str) -> None:
    assert catalog.window(seconds) == text


def test_readme_table_has_one_row_per_rule_linking_to_the_catalog(
    pack: list[rules.Rule], scenario_set: list[Scenario]
) -> None:
    table = catalog.readme_rule_table(pack).splitlines()
    assert table[0] == "| Rule | Level | Logic | Telemetry | OWASP | ATLAS |"
    rows = table[2:]
    assert len(rows) == len(pack)
    anchors = set(re.findall(r'<a id="([^"]+)"></a>', catalog.rule_catalog(pack, scenario_set)))
    links = [re.search(r"\(docs/rules\.md#([^)]+)\)", row) for row in rows]
    assert all(link is not None for link in links)
    assert {link.group(1) for link in links if link} == anchors


def test_catalog_describes_every_rule(pack: list[rules.Rule], scenario_set: list[Scenario]) -> None:
    text = catalog.rule_catalog(pack, scenario_set)
    assert text.startswith("# Rule catalog\n")
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    assert f"{len(pack)} rules." in text
    cases = {s.rule.relpath: len(s.cases) for s in scenario_set}
    for rule in pack:
        assert f"### {rule.title}\n" in text
        assert f"`{rule.id}`" in text
        assert f"({cases[rule.relpath]} cases)" in text
    for key in (taxonomy.OWASP_LLM, taxonomy.OWASP_AGENTIC, taxonomy.ATTACK):
        assert f"{key.name} {key.version}" in text
    assert f"{taxonomy.atlas().name} {taxonomy.atlas().version}" in text


def test_catalog_states_correlation_logic(
    by_stem: dict[str, rules.Rule], scenario_set: list[Scenario]
) -> None:
    text = catalog.rule_catalog(list(by_stem.values()), scenario_set)
    assert (
        "| Logic | >= 3 matching events per `user.tenant.id`, `gen_ai.conversation.id` "
        "in a fixed 5-minute UTC window |" in text
    )


def test_mapping_labels_link_atlas_and_skip_attack_tactics(
    by_stem: dict[str, rules.Rule], scenario_set: list[Scenario]
) -> None:
    rule = next(r for r in by_stem.values() if r.mappings and "T1059" in r.mappings.attack)
    text = catalog.rule_catalog([rule], [s for s in scenario_set if s.rule is rule])
    assert "[T1059](https://attack.mitre.org/techniques/T1059/)" in text
    assert "execution" not in text.split("| Mappings |")[1].split("\n")[0]
    for technique in rule.mappings.atlas if rule.mappings else ():
        assert f"[{technique}]({taxonomy.atlas_url(technique)})" in text


def test_schema_reference_lists_every_field_once() -> None:
    text = catalog.schema_reference()
    lines = text.splitlines()
    for name, field in fields.registry().items():
        assert sum(line.startswith(f"| `{name}` |") for line in lines) == 1, name
        if field.is_string_array:
            assert f"(Splunk `{field.splunk_name}`)" in text
    assert text.count("### ") == 3


def test_atlas_layer(pack: list[rules.Rule]) -> None:
    layer = json.loads(catalog.atlas_layer(pack))
    assert layer["domain"] == "atlas-atlas"
    assert layer["metadata"] == [{"name": "atlas_data_version", "value": taxonomy.atlas().version}]
    counts: dict[str, int] = {}
    for rule in pack:
        for technique in rule.mappings.atlas if rule.mappings else ():
            counts[technique] = counts.get(technique, 0) + 1
    assert {t["techniqueID"]: t["score"] for t in layer["techniques"]} == counts
    assert set(counts) <= set(taxonomy.atlas().entries)
    assert layer["gradient"]["maxValue"] == max(counts.values())


def test_atlas_layer_without_mappings() -> None:
    layer = json.loads(catalog.atlas_layer([]))
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1
