"""Release-bundle guardrails (PRD §12, §17).

The bundle's headline claims — byte-reproducibility and a per-file sha256
manifest — are asserted here against real builds into a temp directory, so a
silently introduced non-determinism or a wrong hash cannot ship.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import pytest

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


def _build_into(monkeypatch: pytest.MonkeyPatch, dist_dir: Path) -> Path:
    monkeypatch.setattr(release, "DIST_DIR", dist_dir)
    bundle = release.build_bundle("0.0.0-test")
    assert bundle is not None, "bundle build failed against the committed out/ artifacts"
    return bundle


def test_release_bundle_is_byte_reproducible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    # The same tree must yield an identical archive (sorted members, zeroed
    # mtimes/uids, fixed gzip timestamp) — the D8 reproducibility claim.
    first = _build_into(monkeypatch, tmp_path / "a")
    second = _build_into(monkeypatch, tmp_path / "b")
    assert first.read_bytes() == second.read_bytes()


def test_release_manifest_hashes_match_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    bundle = _build_into(monkeypatch, tmp_path / "dist")
    manifest = json.loads((tmp_path / "dist" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["name"] == "prompthound-detections"
    assert manifest["version"] == "0.0.0-test"
    assert manifest["file_count"] == len(manifest["files"]) > 0
    with tarfile.open(bundle, mode="r:gz") as archive:
        root = "prompthound-detections-0.0.0-test/"
        expected_names = {root + entry["path"] for entry in manifest["files"]}
        assert set(archive.getnames()) == expected_names | {root + "MANIFEST.json"}
        for entry in manifest["files"]:
            member = archive.extractfile(root + entry["path"])
            assert member is not None
            data = member.read()
            assert hashlib.sha256(data).hexdigest() == entry["sha256"]
            assert len(data) == entry["bytes"]


def test_release_bundle_carries_stamp_and_licenses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    bundle = _build_into(monkeypatch, tmp_path / "dist")
    with tarfile.open(bundle, mode="r:gz") as tar:
        names = {Path(n).name for n in tar.getnames()}
    for required in ("VERSION", "MANIFEST.json", "README.txt", *release.LICENSE_FILES):
        assert required in names, f"bundle is missing {required}"


@pytest.mark.parametrize("version", ["../../escape", "0.2.0/extra", "\n0.2.0", "", "0.2.0\\file"])
def test_release_rejects_unsafe_versions(version):
    with pytest.raises(ValueError, match="version"):
        release._resolve_version(version)


def test_release_excludes_stray_output_file(tmp_path, monkeypatch):
    from prompthound import coverage
    from scripts import conversion

    out = tmp_path / "out"
    (out / "coverage").mkdir(parents=True)
    (out / "coverage" / "private-note.txt").write_text("unintended payload")
    monkeypatch.setattr(conversion, "OUT_DIR", out)
    monkeypatch.setattr(conversion, "build_artifacts", lambda: ({}, []))
    monkeypatch.setattr(coverage, "generate_artifacts", lambda: ({}, []))
    with pytest.raises(ValueError, match="unexpected"):
        release._collect_bundle_files()
