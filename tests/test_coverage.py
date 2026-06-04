"""Coverage-build tests (PRD §16 "Coverage build test"; CHECKLIST Phase 4).

The map is generated from rule metadata only, so it cannot go stale (PRD §17):
these assert it builds cleanly from the *current* rule pack, that every artifact
is well-formed, and that the metadata gate rejects missing / unknown tags.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from coverage.build_coverage import (
    AGENT_RULE_CATEGORIES,
    OWASP_AGENTIC,
    OWASP_LLM,
    ParsedTag,
    RuleMeta,
    build_model,
    coverage_html,
    coverage_markdown,
    coverage_svg,
    generate_artifacts,
    generate_presentation_assets,
    load_rule_meta,
    load_rules,
    parse_tag,
)

# --- the headline gate: coverage builds from the current rule set --------------


def test_coverage_builds_from_current_rule_set() -> None:
    artifacts, errors = generate_artifacts()
    assert errors == [], f"coverage build reported tag errors: {errors}"
    names = {p.name for p in artifacts}
    assert names == {"atlas_navigator_layer.json", "coverage.html", "coverage.md"}


def test_coverage_atlas_layer_is_valid_navigator_json() -> None:
    artifacts, errors = generate_artifacts()
    assert errors == []
    layer_path = next(p for p in artifacts if p.name == "atlas_navigator_layer.json")
    layer = json.loads(artifacts[layer_path])
    assert layer["domain"] == "mitre-atlas"
    assert layer["techniques"], "navigator layer has no scored techniques"
    for tech in layer["techniques"]:
        assert tech["techniqueID"].startswith("AML.T")
        assert tech["score"] >= 1


def test_coverage_svg_asset_builds_and_is_wellformed() -> None:
    # The README's coverage image is generated from the same metadata (so it
    # cannot drift) and must be well-formed SVG GitHub can render inline.
    assets, errors = generate_presentation_assets()
    assert errors == [], f"coverage svg build reported tag errors: {errors}"
    names = {p.name for p in assets}
    assert names == {"coverage.svg"}
    svg = next(iter(assets.values()))
    root = ET.fromstring(svg)  # raises on malformed XML
    assert root.tag.endswith("svg")
    assert "PromptHound" in svg and "OWASP LLM Top 10" in svg
    for oid in OWASP_LLM:
        assert oid in svg, f"{oid} missing from coverage.svg"


def test_coverage_markdown_and_html_non_empty() -> None:
    artifacts, errors = generate_artifacts()
    assert errors == []
    md = next(artifacts[p] for p in artifacts if p.name == "coverage.md")
    html = next(artifacts[p] for p in artifacts if p.name == "coverage.html")
    assert "OWASP LLM Top 10" in md
    assert md.strip().startswith("# PromptHound coverage map")
    assert html.startswith("<!doctype html>")
    assert "PromptHound coverage map" in html
    # Every OWASP id appears in both renderings (grid is complete, not just covered).
    for oid in OWASP_LLM:
        assert oid in md and oid in html


# --- metadata gate: every on-disk rule passes the OWASP + ATLAS + tier checks ---


def test_every_rule_meta_loads_without_error() -> None:
    errors: list[str] = []
    rules = load_rules(errors)
    assert errors == [], f"rule metadata errors: {errors}"
    assert rules, "no rules discovered"
    for rule in rules:
        assert rule.owasp, f"{rule.path}: no OWASP tag survived parsing"
        assert rule.tiers, f"{rule.path}: no tier tag survived parsing"
        assert rule.atlas_techniques or rule.atlas_tactics or rule.attack


def test_owasp_grid_marks_covered_only_when_rules_present() -> None:
    rules = load_rules([])
    model = build_model(rules)
    by_id = {e["id"]: e for e in model["owasp"]}
    assert len(by_id) == 10
    for entry in model["owasp"]:
        assert entry["covered"] == (entry["count"] > 0)
        assert entry["count"] == len(entry["rules"])


# --- tag parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "tag,expected",
    [
        ("owasp-llm.llm07", ParsedTag("owasp", "LLM07")),
        ("attack.atlas.aml.t0056", ParsedTag("atlas_technique", "AML.T0056")),
        ("attack.atlas.aml.t0051.000", ParsedTag("atlas_technique", "AML.T0051.000")),
        ("attack.atlas.aml.ta0015", ParsedTag("atlas_tactic", "AML.TA0015")),
        ("attack.t1059", ParsedTag("attack", "T1059")),
        ("prompthound.tier.t2", ParsedTag("tier", "T2")),
        # OWASP Agentic: authored zero-padded (t04) or bare (t4), canonical un-padded.
        ("owasp-agentic.t04", ParsedTag("owasp_agentic", "T4")),
        ("owasp-agentic.t2", ParsedTag("owasp_agentic", "T2")),
        ("owasp-agentic.t15", ParsedTag("owasp_agentic", "T15")),
        ("totally.bogus.tag", ParsedTag("unknown", "totally.bogus.tag")),
    ],
)
def test_parse_tag(tag: str, expected: ParsedTag) -> None:
    assert parse_tag(tag) == expected


def test_unknown_tag_fails_the_build(tmp_path, monkeypatch) -> None:
    # A rule referencing an un-catalogued ATLAS technique must be an error.
    f = tmp_path / "system_prompt_extraction"
    f.mkdir()
    rule = f / "bogus.yml"
    import yaml

    rule.write_text(
        yaml.safe_dump(
            {
                "title": "t",
                "tags": [
                    "owasp-llm.llm07",
                    "attack.atlas.aml.t9999",  # not in catalog
                    "prompthound.tier.t2",
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("coverage.build_coverage.RULES_DIR", tmp_path)
    errors: list[str] = []
    load_rules(errors)
    assert any("unknown atlas_technique" in e for e in errors), errors


def test_missing_required_tag_fails_the_build(tmp_path, monkeypatch) -> None:
    rule = tmp_path / "r.yml"
    import yaml

    # OWASP + tier but no technique mapping -> missing-technique error.
    rule.write_text(
        yaml.safe_dump({"title": "t", "tags": ["owasp-llm.llm07", "prompthound.tier.t2"]}),
        encoding="utf-8",
    )
    monkeypatch.setattr("coverage.build_coverage.RULES_DIR", tmp_path)
    errors: list[str] = []
    meta = load_rule_meta(rule, errors)
    assert isinstance(meta, RuleMeta)
    assert any("missing required technique mapping" in e for e in errors), errors


# --- D6: OWASP Agentic Top 10 secondary mapping for agent rules ----------------


def test_agent_rules_carry_secondary_agentic_mapping() -> None:
    # Every shipped agent rule must declare a catalogued OWASP Agentic threat.
    rules = load_rules([])
    agent_rules = [r for r in rules if r.category in AGENT_RULE_CATEGORIES]
    assert agent_rules, "no agent rules discovered"
    for rule in agent_rules:
        assert rule.owasp_agentic, f"{rule.path}: agent rule has no OWASP Agentic tag"
        for cid in rule.owasp_agentic:
            assert cid in OWASP_AGENTIC, f"{rule.path}: {cid} not in the Agentic catalog"


def test_agentic_section_present_in_all_renders() -> None:
    model = build_model(load_rules([]))
    assert model["agentic"], "agent rules should populate the agentic coverage section"
    assert model["agentic_total"] == len(OWASP_AGENTIC) == 15
    assert 0 < model["agentic_covered"] <= model["agentic_total"]
    # The secondary mapping surfaces in every rendering (md / html / svg).
    for text in (coverage_markdown(model), coverage_html(model), coverage_svg(model)):
        assert "OWASP Agentic AI" in text
    # Covered threat ids appear in the markdown grid.
    md = coverage_markdown(model)
    for entry in model["agentic"]:
        assert entry["id"] in md


def test_unknown_agentic_tag_fails_the_build(tmp_path, monkeypatch) -> None:
    f = tmp_path / "agent_tool_abuse"
    f.mkdir()
    rule = f / "bogus.yml"
    import yaml

    rule.write_text(
        yaml.safe_dump(
            {
                "title": "t",
                "tags": [
                    "owasp-llm.llm06",
                    "attack.atlas.aml.ta0015",
                    "owasp-agentic.t99",  # not in the 15-threat catalog
                    "prompthound.tier.t1",
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("coverage.build_coverage.RULES_DIR", tmp_path)
    errors: list[str] = []
    load_rules(errors)
    assert any("unknown owasp_agentic" in e for e in errors), errors


def test_agent_rule_missing_agentic_tag_fails_gate(tmp_path, monkeypatch) -> None:
    # A rule under an agent category without an Agentic tag must fail the gate,
    # even though it has the otherwise-complete OWASP + ATLAS + tier metadata.
    cat = tmp_path / "agent_tool_abuse"
    cat.mkdir()
    rule = cat / "r.yml"
    import yaml

    rule.write_text(
        yaml.safe_dump(
            {
                "title": "t",
                "tags": ["owasp-llm.llm06", "attack.atlas.aml.ta0015", "prompthound.tier.t1"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("coverage.build_coverage.RULES_DIR", tmp_path)
    errors: list[str] = []
    meta = load_rule_meta(rule, errors)
    assert isinstance(meta, RuleMeta)
    assert any("missing required OWASP Agentic tag" in e for e in errors), errors
