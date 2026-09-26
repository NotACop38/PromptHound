from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest

from prompthound.normalize import NormalizationError, normalize_event, normalize_file
from prompthound.scenarios import base_event


@pytest.fixture
def event() -> dict[str, Any]:
    return {
        **base_event("norm"),
        "timestamp": "2026-06-01T14:00:00+02:00",
        "event.id": "e-1",
        "tool.call.chain": ["search_kb"],
    }


def test_fields_become_columns_and_timestamp_comes_first(event: dict[str, Any]) -> None:
    normalized = normalize_event(event)
    assert next(iter(normalized)) == "timestamp"
    assert normalized["timestamp"] == "2026-06-01T12:00:00.000000Z"
    assert normalized["user_tenant_id"] == "tenant-example"
    assert normalized["tool_call_chain"] == ["search_kb"]
    assert "user.tenant.id" not in normalized
    assert len(normalized) == len(event)


def test_content_becomes_compact_json_text(event: dict[str, Any]) -> None:
    normalized = normalize_event(event)
    assert isinstance(normalized["gen_ai_input_messages"], str)
    assert json.loads(normalized["gen_ai_input_messages"]) == event["gen_ai.input.messages"]
    assert ", " not in normalized["gen_ai_input_messages"]
    plain = normalize_event({**event, "gen_ai.system_instructions": "Be brief."})
    assert plain["gen_ai_system_instructions"] == "Be brief."


def test_extension_fields_are_kept(event: dict[str, Any]) -> None:
    normalized = normalize_event({**event, "gateway.region": "eu", "flat": {"a": 1}})
    assert normalized["gateway_region"] == "eu"
    assert normalized["flat"] == {"a": 1}


def test_column_collisions_are_rejected(event: dict[str, Any]) -> None:
    with pytest.raises(NormalizationError, match="share column 'user_id'"):
        normalize_event({**event, "user_id": "shadow"})


def test_invalid_events_are_rejected(event: dict[str, Any]) -> None:
    with pytest.raises(NormalizationError, match="invalid audit event"):
        normalize_event({**event, "event.outcome": "maybe"})


def _write(path: Path, *events: Any) -> Path:
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return path


def test_files_are_written_atomically_and_privately(tmp_path: Path, event: dict[str, Any]) -> None:
    source = _write(tmp_path / "in.jsonl", event, event)
    destination = tmp_path / "out" / "siem.jsonl"
    assert normalize_file(source, destination) == 2
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert [json.loads(line)["event_id"] for line in destination.read_text().splitlines()] == [
        "e-1",
        "e-1",
    ]


def test_a_bad_line_leaves_the_destination_untouched(tmp_path: Path, event: dict[str, Any]) -> None:
    source = tmp_path / "in.jsonl"
    source.write_text(json.dumps(event) + "\n\n" + "{not json\n", encoding="utf-8")
    destination = tmp_path / "siem.jsonl"
    destination.write_text("previous\n")
    with pytest.raises(NormalizationError, match="line 3"):
        normalize_file(source, destination)
    assert destination.read_text() == "previous\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in.jsonl", "siem.jsonl"]


@pytest.mark.parametrize(
    "duplicate",
    ['"user.id":"a","user.id":"b"', '"extension":{"k":1,"k":2}'],
)
def test_duplicate_keys_are_rejected_at_any_depth(
    tmp_path: Path, event: dict[str, Any], duplicate: str
) -> None:
    line = json.dumps(event)[:-1] + "," + duplicate + "}"
    source = tmp_path / "in.jsonl"
    source.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(NormalizationError, match="duplicate JSON key"):
        normalize_file(source, tmp_path / "out.jsonl")


def test_empty_input_and_same_file_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "in.jsonl"
    source.write_text("\n", encoding="utf-8")
    with pytest.raises(NormalizationError, match="contains no events"):
        normalize_file(source, tmp_path / "out.jsonl")
    with pytest.raises(NormalizationError, match="different files"):
        normalize_file(source, source)
