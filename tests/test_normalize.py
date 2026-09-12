import json

import pytest

from prompthound.generator import build_samples, iter_events
from prompthound.normalize import normalize_event, normalize_file
from prompthound.schema import validate_event


@pytest.fixture
def event():
    return next(iter_events(build_samples(n_benign=1)))


def test_normalization_preserves_values_and_arrays(event):
    mapped = normalize_event(event)
    assert len(mapped) == len(event)
    assert mapped["gen_ai_response_finish_reasons"] == ["stop"]
    assert mapped["user_tenant_id"] == "tenant-demo"
    assert mapped["gen_ai_input_messages"] == event["gen_ai.input.messages"]
    assert mapped["timestamp"] == event["timestamp"]


@pytest.mark.parametrize("field", ["user_id", "extension.unknown"])
def test_normalization_rejects_collisions_and_unmapped_dotted_fields(event, field):
    event[field] = "ambiguous"
    with pytest.raises(ValueError, match="conflicting"):
        normalize_event(event)


@pytest.mark.parametrize(
    "timestamp", ["nonsense", "2026-06-11", "2026-06-11T12:00:00", "2026-06-11T12:00:00+00:99"]
)
def test_schema_rejects_unusable_event_times(event, timestamp):
    event["timestamp"] = timestamp
    assert validate_event(event)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_schema_rejects_nonfinite_metrics(event, value):
    event["cost.usd"] = value
    assert validate_event(event)


def test_schema_rejects_unknown_version(event):
    event["schema_version"] = "unknown"
    assert validate_event(event)


def test_validator_rejects_unsupported_constraints():
    with pytest.raises(NotImplementedError, match="subset"):
        validate_event(
            {"cost": 100},
            {"type": "object", "properties": {"cost": {"type": "number", "maximum": 1}}},
        )


def test_invalid_later_line_preserves_existing_output(tmp_path, event):
    source, output = tmp_path / "events.jsonl", tmp_path / "normalized.jsonl"
    source.write_text(json.dumps(event) + "\nnull\n")
    output.write_text("previous complete output\n")
    with pytest.raises(ValueError, match="line 2"):
        normalize_file(source, output)
    assert output.read_text() == "previous complete output\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["events.jsonl", "normalized.jsonl"]


def test_normalization_cannot_overwrite_source(tmp_path, event):
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(event) + "\n")
    with pytest.raises(ValueError, match="different files"):
        normalize_file(source, source)
