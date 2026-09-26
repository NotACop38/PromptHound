"""Unit tests for the SIEM verification harness.

The engines themselves run in `make verify-siem`.
"""

from __future__ import annotations

import json
import shutil
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest

from prompthound import generator, rules
from prompthound.convert import Queries
from prompthound.convert import convert as convert_rule
from prompthound.normalize import normalize_event
from scripts import verify_siem
from scripts.verify_siem import Row


def test_expected_rows(by_stem: dict[str, rules.Rule], dataset: generator.Dataset) -> None:
    events = list(dataset.events)
    selection = verify_siem.expected_rows(by_stem["oversized_max_tokens"], events)
    assert len(selection) == 2
    assert all(len(row) == 1 for row in selection)
    windows = verify_siem.expected_rows(by_stem["denied_tool_retry_loop"], events)
    assert {row[-1] for row in windows} == {3}
    assert all(isinstance(row[2], int) and row[2] % 300 == 0 for row in windows)


def test_epoch() -> None:
    assert verify_siem._epoch("1970-01-01T00:01:00Z") == 60
    assert verify_siem._epoch("2026-06-01T00:00:00.000000Z") == 1780272000


def test_only_http_urls_are_requested() -> None:
    with pytest.raises(ValueError, match="unsupported URL scheme"):
        verify_siem._request("file:///etc/passwd")


def test_kusto_rows(by_stem: dict[str, rules.Rule], monkeypatch: pytest.MonkeyPatch) -> None:
    kusto = verify_siem.Kusto("http://kusto.invalid")
    queries: list[str] = []

    def call(kind: str, csl: str) -> list[list[Any]]:
        queries.append(csl)
        if csl.endswith("| project event_id"):
            return [["e-1"], ["e-2"]]
        return [["tenant", "conversation", "2026-06-01T00:05:00Z", 3]]

    monkeypatch.setattr(kusto, "_call", call)
    assert kusto.rows(by_stem["oversized_max_tokens"], "Q") == {("e-1",), ("e-2",)}
    rows = kusto.rows(by_stem["denied_tool_retry_loop"], "Q")
    assert rows == {("tenant", "conversation", 1780272300, 3)}
    assert queries[-1].endswith(
        "| project user_tenant_id, gen_ai_conversation_id, timestamp, event_count"
    )


def test_kusto_load_checks_the_row_count(monkeypatch: pytest.MonkeyPatch) -> None:
    kusto = verify_siem.Kusto("http://kusto.invalid")
    statements: list[str] = []

    def call(kind: str, csl: str) -> list[list[Any]]:
        statements.append(csl)
        return [[1]]

    monkeypatch.setattr(kusto, "_call", call)
    event = {"timestamp": "2026-06-01T00:00:00.000000Z", "event_id": "e"}
    kusto.load([event])
    assert statements[1].startswith(".create table PromptHoundAuditLog_CL (TimeGenerated:datetime")
    with pytest.raises(RuntimeError, match="ingested 1 of 2 events"):
        kusto.load([event, event])


def test_splunk_rows(by_stem: dict[str, rules.Rule], monkeypatch: pytest.MonkeyPatch) -> None:
    splunk = verify_siem.Splunk("http://splunk.invalid", "admin", "pw")
    assert splunk.headers["Authorization"].startswith("Basic ")

    def dispatch(name: str, *field_names: str) -> list[dict[str, Any]]:
        if field_names == ("_raw",):
            return [{"_raw": json.dumps({"event_id": "e-9"})}]
        return [
            {
                "user_tenant_id": "t",
                "gen_ai_conversation_id": "c",
                "_time": "2026-06-01T00:05:00.000+00:00",
                "event_count": "4",
            }
        ]

    monkeypatch.setattr(splunk, "dispatch", dispatch)
    assert splunk.rows(by_stem["oversized_max_tokens"]) == {("e-9",)}
    assert splunk.rows(by_stem["denied_tool_retry_loop"]) == {("t", "c", 1780272300, 4)}
    searches: list[str] = []

    def search(spl: str) -> list[dict[str, Any]]:
        searches.append(spl)
        return [{"event_id": "e-1"}]

    monkeypatch.setattr(splunk, "search", search)
    assert splunk.search_rows("`m` x=1") == {("e-1",)}
    assert searches == ["search `m` x=1 | table event_id"]


def test_mismatch_lists_missing_and_unexpected_rows() -> None:
    expected = frozenset({("a",), ("b",), ("c",), ("d",)})
    text = verify_siem._mismatch(expected, frozenset({("a",), ("z",)}))
    assert text == "missing [('b',), ('c',), ('d',)], unexpected [('z',)]"
    many = verify_siem._mismatch(expected | {("e",)}, frozenset())
    assert many.startswith("missing [('a',), ('b',), ('c',)]...")


@dataclass
class FakeEngine:
    """Returns the offline rows, plus a spurious row for the rule titles in ``wrong``."""

    audit: list[dict[str, Any]]
    by_spl: dict[str, rules.Rule]
    wrong: set[str] = field(default_factory=set)
    loaded: list[dict[str, Any]] = field(default_factory=list)
    has_app: bool = True

    def version(self) -> str:
        return "test"

    def saved_searches(self) -> set[str]:
        return {f"PromptHound - {r.title}" for r in rules.load_rules()} if self.has_app else set()

    def load(self, events: Sequence[dict[str, Any]]) -> None:
        self.loaded = list(events)

    def rows(self, rule: rules.Rule, kql: str = "") -> frozenset[Row]:
        rows = verify_siem.expected_rows(rule, self.audit)
        return rows | {("extra",)} if rule.title in self.wrong else rows

    def search_rows(self, spl: str) -> frozenset[Row]:
        return self.rows(self.by_spl[spl])


@pytest.fixture
def engine(monkeypatch: pytest.MonkeyPatch) -> Callable[..., FakeEngine]:
    """Build fake engines that see the audit events verify() loads and the SPL it converts."""
    audit: list[dict[str, Any]] = []
    by_spl: dict[str, rules.Rule] = {}

    def normalize(event: dict[str, Any]) -> dict[str, Any]:
        audit.append(event)
        return normalize_event(event)

    def convert(rule: rules.Rule) -> Queries:
        queries = convert_rule(rule)
        by_spl[queries.spl] = rule
        return queries

    monkeypatch.setattr(verify_siem, "normalize_event", normalize)
    monkeypatch.setattr(verify_siem, "convert", convert)
    return lambda **options: FakeEngine(audit, by_spl, **options)


def test_verify_passes_when_every_engine_agrees(
    engine: Callable[..., FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    kusto, splunk = engine(), engine()
    assert verify_siem.verify(kusto, splunk, seed=0)  # type: ignore[arg-type]
    assert len(kusto.loaded) == len(splunk.loaded) > 0
    assert "event_id" in kusto.loaded[0]  # the SIEM column layout
    out = capsys.readouterr().out
    assert "FAIL" not in out
    assert out.rstrip().endswith("all engines agree with the offline evaluator")


def test_verify_reports_a_disagreement(
    engine: Callable[..., FakeEngine], capsys: pytest.CaptureFixture[str]
) -> None:
    kusto = engine(wrong={"Conformance: contains"})
    assert not verify_siem.verify(kusto, engine(), seed=0)  # type: ignore[arg-type]
    out = capsys.readouterr().out
    assert "  kusto contains: missing [], unexpected [('extra',)]" in out
    assert out.rstrip().endswith("MISMATCH")


def test_verify_requires_the_splunk_app(engine: Callable[..., FakeEngine]) -> None:
    with pytest.raises(RuntimeError, match="missing saved searches"):
        verify_siem.verify(engine(), engine(has_app=False), seed=0)  # type: ignore[arg-type]


def test_main_needs_a_password_without_containers(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        verify_siem.main([])
    assert exit_info.value.code == 2
    assert "--splunk-password is required" in capsys.readouterr().err


def test_containers_need_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    containers = verify_siem.Containers("pw")
    containers.stop()  # a no-op without docker
    with pytest.raises(RuntimeError, match="needs the docker CLI"):
        containers.start()


def test_wait_retries_until_the_condition_holds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _: None)
    outcomes: list[bool | Exception] = [OSError("connection refused"), False, True]

    def condition() -> bool:
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    verify_siem._wait(condition, "the engine")
    assert outcomes == []
    with pytest.raises(RuntimeError, match="timed out waiting for the engine"):
        verify_siem._wait(lambda: False, "the engine", timeout=0)
