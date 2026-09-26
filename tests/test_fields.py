from __future__ import annotations

from collections import Counter

import pytest

from prompthound import fields
from prompthound.schema import load_schema


def test_registry_covers_the_schema_in_order() -> None:
    assert list(fields.registry()) == list(load_schema()["properties"])


def test_columns_are_unique() -> None:
    counts = Counter(f.column for f in fields.registry().values())
    assert [column for column, n in counts.items() if n > 1] == []


def test_columns_fit_log_analytics_limits() -> None:
    # Azure Monitor: at most 45 characters per column name and 500 columns per table.
    columns = [f.column for f in fields.registry().values()]
    assert max(len(column) for column in columns) <= 45
    assert len(columns) + 1 <= 500  # plus TimeGenerated


@pytest.mark.parametrize(
    ("name", "column", "splunk", "sentinel"),
    [
        ("timestamp", "timestamp", "timestamp", "datetime"),
        ("user.tenant.id", "user_tenant_id", "user_tenant_id", "string"),
        ("tool.call.chain", "tool_call_chain", "tool_call_chain{}", "dynamic"),
        (
            "gen_ai.usage.input_tokens",
            "gen_ai_usage_input_tokens",
            "gen_ai_usage_input_tokens",
            "long",
        ),
        ("cost.usd", "cost_usd", "cost_usd", "real"),
        (
            "output.rendered_unsanitized",
            "output_rendered_unsanitized",
            "output_rendered_unsanitized",
            "bool",
        ),
        ("gen_ai.input.messages", "gen_ai_input_messages", "gen_ai_input_messages", "string"),
        (
            "gen_ai.tool.call.arguments",
            "gen_ai_tool_call_arguments",
            "gen_ai_tool_call_arguments",
            "string",
        ),
    ],
)
def test_field_representations(name: str, column: str, splunk: str, sentinel: str) -> None:
    field = fields.get(name)
    assert (field.column, field.splunk_name, field.sentinel_type) == (column, splunk, sentinel)


def test_data_classes() -> None:
    assert fields.get("gen_ai.input.messages").is_content
    assert fields.get("content.input.injection_markers").data_class == "derived"
    assert fields.get("user.id").data_class == "metadata"
    assert fields.get("tool.call.chain").is_string_array
    assert not fields.get("gen_ai.input.messages").is_string_array
    assert fields.get("gen_ai.request.max_tokens").is_scalar
    assert not fields.get("gen_ai.tool.call.result").is_scalar


def test_unknown_fields_are_reported_by_name() -> None:
    with pytest.raises(KeyError, match=r"'user\.name' is not a field"):
        fields.get("user.name")


def test_canonical_json_is_compact_and_keeps_unicode() -> None:
    assert fields.canonical_json({"a": ["é", 1]}) == '{"a":["é",1]}'
    with pytest.raises(ValueError, match="JSON compliant"):
        fields.canonical_json(float("nan"))


def test_content_text() -> None:
    assert fields.content_text("plain text") == "plain text"
    assert fields.content_text([{"role": "user"}]) == '[{"role":"user"}]'
