from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from prompthound import __version__
from scripts import release


def _members(path: Path) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(path) as archive:
        return {info.name: info for info in archive.getmembers()}


def _read(path: Path, name: str) -> bytes:
    with tarfile.open(path) as archive:
        member = archive.extractfile(name)
        assert member is not None
        return member.read()


def test_version_comes_from_the_package() -> None:
    assert release.package_version() == __version__


def test_collect_maps_sources_to_bundle_paths() -> None:
    members = release.collect()
    assert list(members) == sorted(members)
    assert "schema/audit_log.schema.json" in members
    assert "siem/splunk/app/prompthound/default/savedsearches.conf" in members
    assert any(name.startswith("rules/prompt_injection/") for name in members)
    assert not any("__pycache__" in name for name in members)


def test_collect_rejects_missing_inputs_and_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(release, "REPO_ROOT", tmp_path)
    (tmp_path / "real.txt").write_text("x")
    (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    (tmp_path / "tree").mkdir()
    (tmp_path / "tree" / "inner.txt").symlink_to(tmp_path / "real.txt")
    assert release.collect({"real.txt": "r.txt"}) == {"r.txt": b"x"}
    with pytest.raises(ValueError, match="release input is missing"):
        release.collect({"no/such/file": "x"})
    with pytest.raises(ValueError, match="symbolic link"):
        release.collect({"link.txt": "x"})
    with pytest.raises(ValueError, match="symbolic link"):
        release.collect({"tree": "t"})


def test_archives_are_reproducible(tmp_path: Path) -> None:
    members = {"b.txt": b"b", "a/x.txt": b"x"}
    first, second = tmp_path / "1.tar.gz", tmp_path / "2.tar.gz"
    release.write_archive(first, "root", members)
    release.write_archive(second, "root", dict(reversed(members.items())))
    assert first.read_bytes() == second.read_bytes()
    infos = _members(first)
    assert list(infos) == ["root/a/x.txt", "root/b.txt"]
    for info in infos.values():
        assert (info.mtime, info.uid, info.gid, info.mode) == (0, 0, 0, 0o644)
        assert (info.uname, info.gname) == ("", "")


@pytest.fixture
def dist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(release, "DIST", tmp_path / "dist")
    return tmp_path / "dist"


def test_build_writes_a_verifiable_bundle_and_the_splunk_app(dist: Path) -> None:
    bundle, app = release.build("9.9.9", "0" * 40, dirty=False)
    assert bundle.name == "prompthound-detections-9.9.9.tar.gz"
    assert app.name == "prompthound-9.9.9-splunk-app.tgz"

    manifest = json.loads(_read(bundle, "prompthound-detections-9.9.9/MANIFEST.json"))
    assert (manifest["version"], manifest["source_commit"], manifest["source_dirty"]) == (
        "9.9.9",
        "0" * 40,
        False,
    )
    names = set(_members(bundle))
    listed = {f"prompthound-detections-9.9.9/{f['path']}" for f in manifest["files"]}
    assert names == listed | {"prompthound-detections-9.9.9/MANIFEST.json"}
    for entry in manifest["files"]:
        data = _read(bundle, f"prompthound-detections-9.9.9/{entry['path']}")
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        assert len(data) == entry["bytes"]

    app_names = set(_members(app))
    assert "prompthound/default/savedsearches.conf" in app_names
    assert "prompthound/metadata/default.meta" in app_names

    again = release.build("9.9.9", "0" * 40, dirty=False)
    assert [p.read_bytes() for p in again] == [bundle.read_bytes(), app.read_bytes()]


class Git:
    def __init__(self, status: str) -> None:
        self.status = status

    def __call__(self, *args: str) -> str:
        return self.status if args[0] == "status" else "f" * 40 + "\n"


def _generate_check(returncode: int) -> object:
    def run(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], returncode)

    return run


def test_main_refuses_a_dirty_checkout(
    dist: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(release, "_git", Git(" M README.md\n"))
    monkeypatch.setattr(subprocess, "run", _generate_check(0))
    assert release.main([]) == 1
    assert "uncommitted changes" in capsys.readouterr().out
    assert not dist.exists()

    assert release.main(["--allow-dirty"]) == 0
    bundle = dist / f"prompthound-detections-{__version__}.tar.gz"
    manifest = _read(bundle, f"prompthound-detections-{__version__}/MANIFEST.json")
    assert json.load(io.BytesIO(manifest))["source_dirty"] is True


def test_main_requires_current_artifacts(
    dist: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(release, "_git", Git(""))
    monkeypatch.setattr(subprocess, "run", _generate_check(1))
    assert release.main([]) == 1
    monkeypatch.setattr(subprocess, "run", _generate_check(0))
    assert release.main([]) == 0
    assert "sha256" in capsys.readouterr().out


def test_an_unreadable_version_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = tmp_path / "src" / "prompthound"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "latest"\n')
    monkeypatch.setattr(release, "REPO_ROOT", tmp_path)
    with pytest.raises(ValueError, match="semantic version"):
        release.package_version()
