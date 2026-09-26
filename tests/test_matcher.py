from __future__ import annotations

from typing import Any

import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.types import SigmaString

from prompthound.matcher import compile_rule, string_pattern


def rule(detection: dict[str, Any]) -> SigmaRule:
    return SigmaRule.from_dict(
        {"title": "t", "logsource": {"product": "llm_gateway"}, "detection": detection}
    )


def matches(detection: dict[str, Any], event: dict[str, Any]) -> bool:
    return compile_rule(rule(detection))(event)


@pytest.mark.parametrize(
    ("key", "value", "text", "expected"),
    [
        ("user.id|contains", "mark", "a MARKER b", True),
        ("user.id|contains", "mark", "no", False),
        ("user.id|startswith", "mark", "marker", True),
        ("user.id|startswith", "mark", "a marker", False),
        ("user.id|endswith", "ker", "marker", True),
        ("user.id|endswith", "ker", "markers", False),
        ("user.id", "mar*er", "MARKER", True),
        ("user.id", "mar*er", "a marker", False),
        ("user.id", "marker", "marker\n", False),
        ("user.id|contains", "line two", "line one\nline two", True),
        ("user.id", "a.b", "axb", False),
    ],
)
def test_string_matching(key: str, value: str, text: str, expected: bool) -> None:
    assert matches({"s": {key: value}, "condition": "s"}, {"user.id": text}) is expected


@pytest.mark.parametrize("candidate", [None, 7, True])
def test_strings_only_match_strings(candidate: Any) -> None:
    assert not matches({"s": {"user.id": "*"}, "condition": "s"}, {"user.id": candidate})


def test_string_arrays_match_any_element_case_insensitively() -> None:
    detection = {"s": {"tool.call.chain": ["read_file", "db.query"]}, "condition": "s"}
    assert matches(detection, {"tool.call.chain": ["search", "DB.Query"]})
    assert not matches(detection, {"tool.call.chain": ["db.query_meta"]})
    assert not matches(detection, {"tool.call.chain": []})
    assert not matches(detection, {})


def test_all_modifier_requires_every_element() -> None:
    detection = {"s": {"tool.call.chain|all": ["read_file", "send_email"]}, "condition": "s"}
    assert matches(detection, {"tool.call.chain": ["send_email", "read_file"]})
    assert not matches(detection, {"tool.call.chain": ["read_file"]})


def test_content_fields_match_their_json_text() -> None:
    detection = {"s": {"gen_ai.input.messages|contains": "ignore this"}, "condition": "s"}
    messages = [{"role": "user", "parts": [{"type": "text", "content": "Please IGNORE THIS."}]}]
    assert matches(detection, {"gen_ai.input.messages": messages})
    assert matches(detection, {"gen_ai.input.messages": "a plain string: ignore this"})
    assert not matches(detection, {"gen_ai.input.messages": None})
    # Matching runs over the JSON text, so structure can match too (as in a SIEM).
    structure = {"s": {"gen_ai.input.messages|contains": '"role":"user"'}, "condition": "s"}
    assert matches(structure, {"gen_ai.input.messages": messages})


@pytest.mark.parametrize(
    ("key", "value", "candidate", "expected"),
    [
        ("gen_ai.usage.input_tokens", 5, 5, True),
        ("gen_ai.usage.input_tokens", 5, 5.0, True),
        ("gen_ai.usage.input_tokens", 5, "5", False),
        ("gen_ai.usage.input_tokens|gte", 5, 5, True),
        ("gen_ai.usage.input_tokens|gt", 5, 5, False),
        ("gen_ai.usage.input_tokens|lte", 5, 5, True),
        ("gen_ai.usage.input_tokens|lt", 5, 4, True),
        ("gen_ai.usage.input_tokens|gte", 1, True, False),
    ],
)
def test_numbers(key: str, value: int, candidate: Any, expected: bool) -> None:
    event = {"gen_ai.usage.input_tokens": candidate}
    assert matches({"s": {key: value}, "condition": "s"}, event) is expected


def test_booleans_only_match_json_booleans() -> None:
    detection = {"s": {"output.rendered_unsanitized": True}, "condition": "s"}
    assert matches(detection, {"output.rendered_unsanitized": True})
    assert not matches(detection, {"output.rendered_unsanitized": 1})
    assert not matches(detection, {"output.rendered_unsanitized": "true"})


def test_boolean_conditions() -> None:
    detection = {
        "a": {"user.id": "a"},
        "b": {"gen_ai.conversation.id": "b"},
        "condition": "a and not b",
    }
    assert matches(detection, {"user.id": "a", "gen_ai.conversation.id": "c"})
    assert not matches(detection, {"user.id": "a", "gen_ai.conversation.id": "b"})
    # A missing field never matches, so its negation does (as in Splunk and KQL).
    assert matches(detection, {"user.id": "a"})
    either = {"a": {"user.id": "a"}, "b": {"user.id": "b"}, "condition": "a or b"}
    assert matches(either, {"user.id": "b"})


def test_multiple_conditions_are_alternatives() -> None:
    detection = {"a": {"user.id": "a"}, "b": {"user.id": "b"}, "condition": ["a", "b"]}
    predicate = compile_rule(rule(detection))
    assert predicate({"user.id": "a"})
    assert predicate({"user.id": "b"})
    assert not predicate({"user.id": "c"})


def test_keyword_detections_are_not_compiled() -> None:
    with pytest.raises(NotImplementedError, match="unsupported condition element"):
        compile_rule(rule({"k": ["keyword"], "condition": "k"}))


@pytest.mark.parametrize("value", [None, {"re": "a.*"}])
def test_null_checks_and_regular_expressions_are_not_compiled(value: Any) -> None:
    key, value = ("user.id|re", value["re"]) if isinstance(value, dict) else ("user.id", value)
    with pytest.raises(NotImplementedError, match="unsupported value type"):
        compile_rule(rule({"s": {key: value}, "condition": "s"}))


def test_single_character_wildcards_are_not_compiled() -> None:
    with pytest.raises(NotImplementedError, match="special character"):
        string_pattern(SigmaString("a?b"))


def test_rules_without_a_condition_are_rejected() -> None:
    parsed = SigmaCollection.from_dicts(
        [
            {
                "title": "t",
                "logsource": {"product": "x"},
                "detection": {"s": {"a": 1}, "condition": "s"},
            }
        ]
    ).rules[0]
    assert isinstance(parsed, SigmaRule)
    parsed.detection.parsed_condition = []
    with pytest.raises(ValueError, match="no detection condition"):
        compile_rule(parsed)
