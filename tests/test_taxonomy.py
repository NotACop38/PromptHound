from __future__ import annotations

import importlib.util
from types import ModuleType

from prompthound import rules, taxonomy
from tests.helpers import ROOT


def _update_atlas() -> ModuleType:
    spec = importlib.util.spec_from_file_location("update_atlas", ROOT / "scripts/update_atlas.py")
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_atlas_catalog_is_pinned_to_a_release() -> None:
    atlas = taxonomy.atlas()
    assert atlas.version == "2026.09"
    assert len(atlas.entries) > 150
    assert atlas.entries["AML.T0051.000"] == "LLM Prompt Injection: Direct"
    assert atlas.entries["AML.T0056"] == "Extract LLM System Prompt"
    assert atlas.entries["AML.T0034.002"] == "Cost Harvesting: Agentic Resource Consumption"
    assert taxonomy.atlas_tactics()["AML.T0086"] == ("Exfiltration",)


def test_every_mapping_in_the_pack_resolves(pack: list[rules.Rule]) -> None:
    for rule in pack:
        assert rule.mappings is not None
        for technique in rule.mappings.atlas:
            assert taxonomy.atlas_tactics()[technique], technique
        for risk in rule.mappings.owasp_llm:
            assert risk in taxonomy.OWASP_LLM.entries
        for risk in rule.mappings.owasp_agentic:
            assert risk in taxonomy.OWASP_AGENTIC.entries


def test_labels_and_urls() -> None:
    assert taxonomy.OWASP_LLM.label("LLM01") == "LLM01 Prompt Injection"
    assert taxonomy.OWASP_AGENTIC.label("ASI02") == "ASI02 Tool Misuse and Exploitation"
    assert taxonomy.atlas_url("AML.T0054") == "https://atlas.mitre.org/techniques/AML.T0054"
    assert taxonomy.attack_url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"


def test_catalog_builder_names_subtechniques_and_resolves_tactics() -> None:
    release = {
        "collection": {"version": "2099.01"},
        "tactics": {"AML.TA0005": {"name": "Execution"}},
        "techniques": {
            "AML.T0051": {"name": "LLM Prompt Injection"},
            "AML.T0051.000": {"name": "Direct"},
        },
        "relationships": {
            "AML.T0051": {"achieves": [{"target": "AML.TA0005"}]},
            "AML.T0051.000": {
                "achieves": [{"target": "AML.TA0005"}],
                "specializes": [{"target": "AML.T0051"}],
            },
        },
    }
    catalog = _update_atlas().build_catalog(release)
    assert catalog["version"] == "2099.01"
    assert catalog["techniques"]["AML.T0051.000"] == {
        "name": "LLM Prompt Injection: Direct",
        "tactics": ["Execution"],
    }
