from __future__ import annotations

from pathlib import Path

import pytest

from prompthound import resources
from tests.helpers import ROOT


def test_a_checkout_uses_the_repository_directories() -> None:
    assert resources.content_root() == ROOT
    assert resources.rules_dir() == ROOT / "rules"
    assert resources.scenarios_dir() == ROOT / "scenarios"


def test_an_installed_package_prefers_its_bundled_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "site-packages" / "prompthound"
    (package / "_bundled" / "rules").mkdir(parents=True)
    monkeypatch.setattr(resources, "_PACKAGE", package)
    assert resources.content_root() == package / "_bundled"


def test_a_missing_pack_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resources, "_PACKAGE", tmp_path / "src" / "prompthound")
    with pytest.raises(FileNotFoundError, match="rule pack was not found"):
        resources.content_root()
