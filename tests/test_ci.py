from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import ci


def test_stages_are_named_and_ordered() -> None:
    names = [stage.name for stage in ci.STAGES]
    assert len(names) == len(set(names))
    assert names[0] == "ruff format"
    assert names[-1] == "security"
    pytest_stage = next(s for s in ci.STAGES if s.name == "pytest")
    assert "--cov" in pytest_stage.argv


def _stage_of(argv: list[str]) -> str:
    """The stage whose command line ``argv`` is (the executable resolved to a path)."""
    for stage in ci.STAGES:
        if Path(argv[0]).name == Path(stage.argv[0]).name and tuple(argv[1:]) == stage.argv[1:]:
            return stage.name
    raise AssertionError(f"unexpected command {argv}")


def _fake_run(failing: set[str], ran: list[str]) -> object:
    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        ran.append(_stage_of(argv))
        return subprocess.CompletedProcess(argv, 1 if ran[-1] in failing else 0)

    return run


@pytest.fixture
def tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda tool: f"/usr/bin/{Path(tool).name}")


@pytest.mark.usefixtures("tools")
def test_all_stages_run_and_the_summary_reports_failures(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ran: list[str] = []
    monkeypatch.setattr(subprocess, "run", _fake_run({"mypy"}, ran))
    assert ci.main([]) == 1
    assert ran == [stage.name for stage in ci.STAGES]
    out = capsys.readouterr().out
    assert "FAIL  mypy" in out
    assert out.rstrip().endswith("CI failed: mypy")


@pytest.mark.usefixtures("tools")
def test_only_selects_stages(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ran: list[str] = []
    monkeypatch.setattr(subprocess, "run", _fake_run(set(), ran))
    assert ci.main(["--only", "RUFF"]) == 0
    assert ran == ["ruff format", "ruff check"]
    assert capsys.readouterr().out.rstrip().endswith("CI passed")


def test_an_unknown_stage_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        ci.main(["--only", "lint"])
    assert exit_info.value.code == 2
    assert "no stage matches 'lint'" in capsys.readouterr().err


def test_a_missing_tool_fails_its_stage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert ci.run(ci.STAGES[0]) is False
    assert "ruff is not installed" in capsys.readouterr().out
