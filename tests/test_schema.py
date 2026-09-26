from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from prompthound import fields
from prompthound.scenarios import base_event
from prompthound.schema import load_schema, parse_timestamp, schema_version, validate_event
from tests.helpers import ROOT


@pytest.fixture
def event() -> dict[str, Any]:
    return {**base_event("schema"), "timestamp": "2026-06-01T12:00:00Z", "event.id": "e-1"}


def test_schema_version_comes_from_the_schema() -> None:
    assert schema_version() == load_schema()["properties"]["schema_version"]["const"] == "0.2"


def test_every_field_declares_its_origin_and_data_class() -> None:
    for name, spec in load_schema()["properties"].items():
        assert spec["x-origin"] in {"otel", "prompthound"}, name
        assert spec["x-class"] in {"metadata", "derived", "content"}, name
        assert spec.get("description"), name


def test_otel_fields_are_real_opentelemetry_attributes() -> None:
    lines = (ROOT / "tests" / "data" / "otel_attributes.txt").read_text().splitlines()
    otel = {line for line in lines if line and not line.startswith("#")}
    for field in fields.registry().values():
        if field.origin == "otel":
            assert field.name in otel, f"{field.name} is not an OpenTelemetry attribute"
        # Extensions must not squat in the OpenTelemetry GenAI namespace.
        if field.name.startswith("gen_ai."):
            assert field.origin == "otel", field.name


def test_base_event_is_valid(event: dict[str, Any]) -> None:
    assert validate_event(event) == []


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"schema_version": "0.1"}, "must be '0.2'"),
        ({"event.outcome": "maybe"}, "is not one of"),
        ({"event.id": ""}, "shorter than 1"),
        ({"gen_ai.usage.input_tokens": -1}, "below the minimum"),
        ({"gen_ai.usage.input_tokens": 1.5}, "expected integer"),
        ({"gen_ai.usage.input_tokens": True}, "expected integer"),
        ({"cost.usd": float("nan")}, "NaN and infinity"),
        ({"cost.usd": float("inf")}, "NaN and infinity"),
        ({"tool.call.chain": ["ok", 3]}, "tool.call.chain[1]: expected string"),
        ({"gen_ai.input.messages": [{"role": 1}]}, "gen_ai.input.messages[0].role"),
        ({"timestamp": "2026-06-01"}, "RFC 3339"),
    ],
)
def test_invalid_values_are_reported(
    event: dict[str, Any], changes: dict[str, Any], message: str
) -> None:
    problems = validate_event({**event, **changes})
    assert any(message in p for p in problems), problems


def test_missing_required_fields_are_reported(event: dict[str, Any]) -> None:
    del event["gen_ai.operation.name"]
    assert validate_event(event) == ["<event>: missing required field 'gen_ai.operation.name'"]


def test_integral_floats_are_integers(event: dict[str, Any]) -> None:
    assert validate_event({**event, "gen_ai.usage.input_tokens": 12.0}) == []


def test_non_objects_are_rejected() -> None:
    assert validate_event([]) == ["<event>: expected object, got list"]


def test_extension_fields_are_allowed(event: dict[str, Any]) -> None:
    assert validate_event({**event, "custom.gateway.region": "eu-west-1"}) == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-06-01T12:00:00Z", "2026-06-01T12:00:00+00:00"),
        ("2026-06-01t12:00:00z", "2026-06-01T12:00:00+00:00"),
        ("2026-06-01T14:30:00.25+02:30", "2026-06-01T12:00:00.250000+00:00"),
        ("2026-06-01T07:00:00-05:00", "2026-06-01T12:00:00+00:00"),
    ],
)
def test_timestamps_are_converted_to_utc(value: str, expected: str) -> None:
    parsed = parse_timestamp(value)
    assert parsed.tzinfo == dt.UTC
    assert parsed.isoformat() == expected


@pytest.mark.parametrize(
    "value",
    ["2026-06-01", "2026-06-01T12:00:00", "2026-06-01 12:00:00Z", "2026-06-01T12:00:00+00:99", "x"],
)
def test_timestamps_without_a_valid_offset_are_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="timestamp"):
        parse_timestamp(value)


def test_validator_refuses_keywords_outside_its_subset() -> None:
    with pytest.raises(NotImplementedError, match="supported subset"):
        validate_event({"a": 1}, {"type": "object", "properties": {"a": {"maximum": 3}}})
    with pytest.raises(NotImplementedError, match="supported subset"):
        validate_event({}, {"type": "object", "additionalProperties": {"type": "string"}})
    with pytest.raises(NotImplementedError, match="unsupported JSON Schema type"):
        validate_event(1, {"type": "decimal"})


def test_closed_objects_reject_unknown_fields() -> None:
    schema = {"type": "object", "properties": {"a": {}}, "additionalProperties": False}
    assert validate_event({"a": 1, "b": 2}, schema) == ["<event>: unexpected field 'b'"]
