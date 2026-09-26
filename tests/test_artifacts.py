"""The committed generated artifacts (scripts/generate.py)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts import generate
from tests.helpers import ROOT


def test_committed_artifacts_are_current() -> None:
    assert generate.check() == []


def test_every_artifact_is_listed(pack: list[object]) -> None:
    paths = {path.relative_to(ROOT).as_posix() for path in generate.artifacts()}
    assert len(paths) == 2 * len(pack) + 10
    assert "siem/splunk/app/prompthound/default/savedsearches.conf" in paths
    assert "siem/sentinel/table.json" in paths
    assert {"README.md", "docs/schema.md", "docs/rules.md"} <= paths


def test_splice_replaces_only_the_marked_block() -> None:
    text = "intro\n<!-- t:start -->\nold\n<!-- t:end -->\noutro\n"
    assert generate.splice(text, "t", "new\n") == (
        "intro\n<!-- t:start -->\nnew\n<!-- t:end -->\noutro\n"
    )


@pytest.mark.parametrize(
    "text", ["no markers\n", "<!-- t:start -->\n<!-- t:end -->\n<!-- t:start -->\n<!-- t:end -->\n"]
)
def test_splice_needs_exactly_one_marker_pair(text: str) -> None:
    with pytest.raises(ValueError, match="exactly one t:start/t:end marker pair"):
        generate.splice(text, "t", "x")


@pytest.fixture
def checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of the files generate.py reads, with ROOT pointing at it."""
    for name in ("README.md", "docs/schema.md"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, tmp_path / name)
    monkeypatch.setattr(generate, "ROOT", tmp_path)
    monkeypatch.setattr(generate, "SIEM", tmp_path / "siem")
    return tmp_path


def test_write_then_check_round_trips(checkout: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert generate.check()  # nothing generated yet
    stale = checkout / "siem" / "sentinel" / "retired_rule.kql"
    stale.parent.mkdir(parents=True)
    stale.write_text("old\n")
    assert generate.stale(generate.artifacts()) == [stale]

    assert generate.main([]) == 0
    assert not stale.exists()
    assert generate.check() == []
    assert generate.main(["--check"]) == 0
    output = capsys.readouterr().out
    assert "removed siem/sentinel/retired_rule.kql" in output
    assert "all generated artifacts are current" in output

    for relative in ("siem/splunk/app/prompthound/default/props.conf", "docs/rules.md"):
        committed = (ROOT / relative).read_text("utf-8")
        assert (checkout / relative).read_text("utf-8") == committed

    assert generate.main([]) == 0
    assert "0 of" in capsys.readouterr().out


def test_check_reports_drift(checkout: Path, capsys: pytest.CaptureFixture[str]) -> None:
    generate.write()
    edited = checkout / "siem" / "splunk" / "app" / "prompthound" / "default" / "macros.conf"
    edited.write_text("edited\n")
    orphan = checkout / "siem" / "orphan.txt"
    orphan.write_text("x\n")
    capsys.readouterr()
    assert generate.main(["--check"]) == 1
    output = capsys.readouterr().out
    assert "siem/splunk/app/prompthound/default/macros.conf is out of date" in output
    assert "siem/orphan.txt has no source" in output
