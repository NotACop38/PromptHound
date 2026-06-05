"""Release-bundle guardrails (PRD §12, §17)."""

from __future__ import annotations

from scripts import release


def test_release_dirty_blocker_limits_display(capsys) -> None:
    entries = [f" M file_{i}.txt" for i in range(25)]

    release._print_dirty_release_blocker(entries)

    out = capsys.readouterr().out
    assert "refusing to build release bundle from a dirty git checkout" in out
    assert " M file_0.txt" in out
    assert " M file_19.txt" in out
    assert " M file_20.txt" not in out
    assert "... and 5 more" in out
    assert "--allow-dirty" in out
