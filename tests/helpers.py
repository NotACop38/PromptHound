"""Builders for rule documents used across the test suite."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from prompthound import rules

ROOT = Path(__file__).resolve().parent.parent


def selection_document(detection: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """A minimal, valid selection rule document around ``detection``."""
    return {
        "title": extra.pop("title", "Test rule"),
        "id": extra.pop("id", "0e5b0d6c-2f3a-4b61-9c7d-1a2b3c4d5e60"),
        "status": "experimental",
        "description": "A rule written by the test suite.",
        "references": ["https://example.org/reference"],
        "author": "tests",
        "date": "2026-09-26",
        "logsource": {"product": "llm_gateway"},
        "detection": detection,
        "falsepositives": ["None known."],
        "level": "low",
        "prompthound": {"owasp_llm": ["LLM01"], "atlas": ["AML.T0051.000"]},
        **extra,
    }


def correlation_documents(
    base_detection: dict[str, Any], correlation: dict[str, Any], **extra: Any
) -> list[dict[str, Any]]:
    """A base detection plus an event_count correlation that references it."""
    base = {
        "title": "Test building block",
        "name": "test_block",
        "id": "0e5b0d6c-2f3a-4b61-9c7d-1a2b3c4d5e61",
        "status": "experimental",
        "logsource": {"product": "llm_gateway"},
        "detection": base_detection,
    }
    alerting = selection_document({}, title="Test correlation", **extra)
    del alerting["detection"], alerting["logsource"]
    alerting["id"] = extra.get("id", "0e5b0d6c-2f3a-4b61-9c7d-1a2b3c4d5e62")
    alerting["correlation"] = {
        "type": "event_count",
        "rules": ["test_block"],
        "group-by": ["user.tenant.id", "user.id"],
        "timespan": "5m",
        "condition": {"gte": 3},
        **correlation,
    }
    return [base, alerting]


def load_one(root: Path, relpath: str = "t/rule.yml") -> rules.Rule:
    return rules.load_rule(root / relpath, root)
