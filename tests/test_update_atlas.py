from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from prompthound import taxonomy
from scripts import update_atlas

RELEASE = {
    "collection": {"version": "2099.01"},
    "tactics": {
        "AML.TA0001": {"name": "Execution"},
        "AML.TA0002": {"name": "Initial Access"},
    },
    "techniques": {
        "AML.T0051": {"name": "LLM Prompt Injection"},
        "AML.T0051.000": {"name": "Direct"},
        "AML.T0099": {"name": "Unmapped"},
    },
    "relationships": {
        "AML.T0051": {
            "achieves": [
                {"target": "AML.TA0002"},
                {"target": "AML.TA0001"},
                {"target": "AML.TA9999"},
            ]
        },
        "AML.T0051.000": {
            "specializes": [{"target": "AML.T0051"}],
            "achieves": [{"target": "AML.TA0001"}],
        },
    },
}


def test_build_catalog() -> None:
    catalog = update_atlas.build_catalog(RELEASE)
    assert catalog["version"] == "2099.01"
    assert catalog["techniques"] == {
        "AML.T0051": {"name": "LLM Prompt Injection", "tactics": ["Execution", "Initial Access"]},
        "AML.T0051.000": {"name": "LLM Prompt Injection: Direct", "tactics": ["Execution"]},
        "AML.T0099": {"name": "Unmapped", "tactics": []},
    }


def test_main_writes_the_catalog_from_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "ATLAS.yaml"
    source.write_text(yaml.safe_dump(RELEASE), encoding="utf-8")
    output = tmp_path / "atlas.json"
    monkeypatch.setattr(update_atlas, "OUTPUT", output)
    assert update_atlas.main(["--file", str(source)]) == 0
    assert json.loads(output.read_text())["version"] == "2099.01"
    assert "ATLAS 2099.01, 3 techniques" in capsys.readouterr().out


def test_main_downloads_the_named_release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fetched: list[str] = []

    def fetch(url: str) -> str:
        fetched.append(url)
        return yaml.safe_dump(RELEASE)

    monkeypatch.setattr(update_atlas, "_fetch", fetch)
    monkeypatch.setattr(update_atlas, "OUTPUT", tmp_path / "atlas.json")
    assert update_atlas.main(["--release", "2099.01"]) == 0
    assert fetched == [update_atlas.BASE_URL + "ATLAS-2099.01.yaml"]


def test_only_https_is_fetched() -> None:
    with pytest.raises(ValueError, match="non-HTTPS"):
        update_atlas._fetch("http://example.org/ATLAS.yaml")


def test_the_vendored_catalog_is_complete() -> None:
    atlas = taxonomy.atlas()
    assert atlas.name == "MITRE ATLAS"
    assert len(atlas.entries) > 100
    assert atlas.entries["AML.T0051.000"] == "LLM Prompt Injection: Direct"
