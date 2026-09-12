from prompthound import coverage
from scripts import ci


def test_coverage_stage_rejects_stale_output_without_rewriting(tmp_path, monkeypatch):
    snapshot = tmp_path / "coverage.md"
    snapshot.write_text("stale content\n")
    monkeypatch.setattr(coverage, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(coverage, "generate_artifacts", lambda: ({snapshot: "current\n"}, []))
    monkeypatch.setattr(coverage, "generate_presentation_assets", lambda: ({}, []))
    assert not ci.coverage_build_stage()
    assert snapshot.read_text() == "stale content\n"


def test_schema_stage_rejects_empty_sample_array(tmp_path, monkeypatch):
    (tmp_path / "empty.json").write_text("[]\n")
    monkeypatch.setattr(ci, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(ci, "SAMPLES_DIR", tmp_path)
    assert not ci.schema_validate()
