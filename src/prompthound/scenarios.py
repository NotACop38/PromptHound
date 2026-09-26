"""Rule scenarios: labeled synthetic event sequences with an expected outcome.

Each rule ``rules/<category>/<name>.yml`` has a scenario file
``scenarios/<category>/<name>.yml`` listing cases. A case is a short sequence of
events built from overrides on a benign base event, plus whether the rule must
alert on it::

    cases:
      - name: Twenty requests in one minute
        expect: alert
        events:
          - repeat: 20
            interval: 2s
      - name: A burst split across two windows does not alert
        expect: silent
        events:
          - at: 50s
            repeat: 20
            interval: 1s

Event-group keys:

``set``       field overrides (dotted schema names)
``prompt``    shorthand for a single user message in ``gen_ai.input.messages``
``messages``  list of ``{role, text}`` input messages
``response``  shorthand for one assistant message in ``gen_ai.output.messages``
``unset``     fields to remove from the base event
``repeat``    number of events in the group (default 1)
``interval``  spacing between events, e.g. ``10s`` or ``2m`` (default 10s)
``at``        offset of the group's first event from the start of the case

Top-level keys starting with ``x-`` are ignored and can hold YAML anchors that
several cases share. Every case runs in isolation; the generator also lays all cases out, one per
time slot and with distinct identities, to build a dataset for the demo and the
SIEM verification harness.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from prompthound import fields, resources
from prompthound.evaluate import alerts_for
from prompthound.payload_guard import scan_event
from prompthound.rules import Rule
from prompthound.schema import schema_version, validate_event

Expectation = Literal["alert", "silent"]

#: Start of every case when it is evaluated on its own.
CASE_START = dt.datetime(2026, 6, 1, 12, 0, tzinfo=dt.UTC)

_DEFAULT_INTERVAL = 10
_NAMESPACE = uuid.UUID("5c0f6a4e-7a39-4f3e-9d0b-2f8f5f8b6a11")
_GROUP_KEYS = frozenset(
    {"set", "prompt", "messages", "response", "unset", "repeat", "interval", "at"}
)
_CASE_KEYS = frozenset({"name", "expect", "alerts", "events"})
_DURATION = re.compile(r"(\d+)([smh])")
_UNITS = {"s": 1, "m": 60, "h": 3600}

#: Token prices used to keep ``cost.usd`` consistent with token overrides.
INPUT_PRICE_PER_TOKEN = 0.000002
OUTPUT_PRICE_PER_TOKEN = 0.000008


class ScenarioError(ValueError):
    """A scenario file that is malformed or produces invalid events."""


@dataclass(frozen=True)
class EventGroup:
    overrides: Mapping[str, Any]
    unset: tuple[str, ...] = ()
    repeat: int = 1
    interval: int = _DEFAULT_INTERVAL
    at: int | None = None


@dataclass(frozen=True)
class Case:
    name: str
    expect: Expectation
    groups: tuple[EventGroup, ...]
    alerts: int | None = None


@dataclass(frozen=True)
class Scenario:
    """All cases for one rule."""

    rule: Rule
    path: Path
    cases: tuple[Case, ...]


@dataclass(frozen=True)
class CaseResult:
    scenario: Scenario
    case: Case
    alerts: int
    events: tuple[dict[str, Any], ...] = field(repr=False)

    @property
    def passed(self) -> bool:
        if self.case.alerts is not None:
            return self.alerts == self.case.alerts
        return (self.alerts > 0) == (self.case.expect == "alert")


def text_messages(role: str, text: str) -> dict[str, Any]:
    """One message in the OpenTelemetry GenAI message format."""
    return {"role": role, "parts": [{"type": "text", "content": text}]}


#: Operations whose events describe a tool call or sub-agent invocation.
TOOL_OPERATIONS = frozenset({"execute_tool", "invoke_agent"})


def base_event(identity: str, operation: str = "chat") -> dict[str, Any]:
    """A complete, benign event for one synthetic principal and conversation.

    Completion operations get prompt, response and token usage; tool operations
    get tool-call metadata instead, as an agent gateway would record them.
    """
    event: dict[str, Any] = {
        "schema_version": schema_version(),
        "gen_ai.operation.name": operation,
        "event.outcome": "success",
        "service.name": "support-assistant",
        "deployment.environment.name": "production",
        "user.tenant.id": "tenant-example",
        "user.id": f"user-{identity}",
        "gen_ai.conversation.id": f"conv-{identity}",
        "policy.decision": "allow",
    }
    if operation in TOOL_OPERATIONS:
        event.update(
            {
                "gen_ai.agent.id": "agent-support-1",
                "gen_ai.agent.name": "support-agent",
                "gen_ai.tool.name": "search_kb",
                "gen_ai.tool.type": "function",
                "tool.call.depth": 1,
                "tool.call.chain": ["search_kb"],
                "tool.call.outcome": "success",
            }
        )
        return event
    event.update(
        {
            "gen_ai.provider.name": "openai",
            "gen_ai.request.model": "gpt-4.1",
            "gen_ai.response.model": "gpt-4.1",
            "gen_ai.usage.input_tokens": 320,
            "gen_ai.usage.output_tokens": 180,
            "usage.total_tokens": 500,
            "cost.usd": round(320 * INPUT_PRICE_PER_TOKEN + 180 * OUTPUT_PRICE_PER_TOKEN, 6),
            "gen_ai.response.finish_reasons": ["stop"],
            "content.input.injection_markers": 0,
            "content.output.contains_system_prompt": False,
            "gen_ai.input.messages": [
                text_messages("user", "Can you summarize the open support tickets for my account?")
            ],
            "gen_ai.output.messages": [
                {
                    **text_messages(
                        "assistant", "You have two open tickets, both awaiting a reply."
                    ),
                    "finish_reason": "stop",
                }
            ],
        }
    )
    return event


def scenario_path(rule: Rule, directory: Path | None = None) -> Path:
    root = directory if directory is not None else resources.scenarios_dir()
    return root / rule.relpath


def load_scenario(rule: Rule, directory: Path | None = None) -> Scenario:
    """Load and validate the scenario file for ``rule``."""
    path = scenario_path(rule, directory)
    if not path.is_file():
        raise ScenarioError(f"{rule.relpath}: no scenario file at {path}")
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{path}: {exc}") from exc
    # Top-level keys starting with "x-" may hold YAML anchors shared by cases.
    if not isinstance(document, dict) or {
        key for key in document if not str(key).startswith("x-")
    } != {"cases"}:
        raise ScenarioError(f"{path}: expected a 'cases' list (and optional x- anchor keys)")
    raw_cases = document["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ScenarioError(f"{path}: 'cases' must be a non-empty list")
    cases = tuple(_case(path, index, raw) for index, raw in enumerate(raw_cases))
    names = [case.name for case in cases]
    if len(set(names)) != len(names):
        raise ScenarioError(f"{path}: case names must be unique")
    scenario = Scenario(rule=rule, path=path, cases=cases)
    for index, case in enumerate(cases):
        for event in materialize(scenario, index):
            problems = validate_event(event)
            if problems:
                raise ScenarioError(f"{path}: case {case.name!r}: {'; '.join(problems)}")
            if scan_event(event):
                raise ScenarioError(
                    f"{path}: case {case.name!r} carries an exploit payload, not a signature"
                )
    return scenario


def load_scenarios(rules: Sequence[Rule], directory: Path | None = None) -> list[Scenario]:
    """Scenarios for every rule; every scenario file must belong to a rule."""
    scenarios = [load_scenario(rule, directory) for rule in rules]
    root = directory if directory is not None else resources.scenarios_dir()
    known = {rule.relpath for rule in rules}
    orphans = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.yml")
        if path.relative_to(root).as_posix() not in known
    )
    if orphans:
        raise ScenarioError(f"scenario files without a rule: {', '.join(orphans)}")
    return scenarios


def case_identity(scenario: Scenario, index: int) -> str:
    """Short stable identifier used to make a case's principal and conversation unique."""
    return hashlib.sha256(f"{scenario.rule.relpath}#{index}".encode()).hexdigest()[:10]


def materialize(
    scenario: Scenario,
    index: int,
    *,
    start: dt.datetime = CASE_START,
    identity: str | None = None,
) -> list[dict[str, Any]]:
    """The events of case ``index``, starting at ``start``."""
    case = scenario.cases[index]
    ident = identity or case_identity(scenario, index)
    events: list[dict[str, Any]] = []
    cursor = 0
    for group in case.groups:
        if group.at is not None:
            cursor = group.at
        operation = str(group.overrides.get("gen_ai.operation.name", "chat"))
        for _ in range(group.repeat):
            event = base_event(ident, operation)
            for name in group.unset:
                event.pop(name, None)
            event.update(_deep_copy(group.overrides))
            _reconcile_usage(event, group.overrides)
            position = len(events)
            event["timestamp"] = _iso(start + dt.timedelta(seconds=cursor))
            event["event.id"] = str(
                uuid.uuid5(_NAMESPACE, f"{scenario.rule.relpath}#{index}#{ident}#{position}")
            )
            events.append(event)
            cursor += group.interval
    return events


def duration(case: Case) -> int:
    """Seconds from the start of the case to its last event."""
    cursor = last = 0
    for group in case.groups:
        if group.at is not None:
            cursor = group.at
        last = max(last, cursor + group.interval * (group.repeat - 1))
        cursor += group.interval * group.repeat
    return last


def count_alerts(rule: Rule, events: Sequence[Mapping[str, Any]]) -> int:
    """Alerts ``rule`` raises over ``events``: matching events, or qualifying windows."""
    return len(alerts_for(rule, events))


def run(scenario: Scenario) -> list[CaseResult]:
    """Evaluate every case of a scenario in isolation."""
    results = []
    for index, case in enumerate(scenario.cases):
        events = materialize(scenario, index)
        results.append(
            CaseResult(scenario, case, count_alerts(scenario.rule, events), tuple(events))
        )
    return results


def _case(path: Path, index: int, raw: Any) -> Case:
    where = f"{path}: case {index + 1}"
    if not isinstance(raw, dict):
        raise ScenarioError(f"{where}: expected a mapping")
    unknown = set(raw) - _CASE_KEYS
    if unknown:
        raise ScenarioError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    name = raw.get("name")
    expect = raw.get("expect")
    if not isinstance(name, str) or not name.strip():
        raise ScenarioError(f"{where}: 'name' is required")
    if expect not in ("alert", "silent"):
        raise ScenarioError(f"{where}: 'expect' must be alert or silent")
    alerts = raw.get("alerts")
    if alerts is not None and (
        not isinstance(alerts, int)
        or isinstance(alerts, bool)
        or (alerts > 0) != (expect == "alert")
    ):
        raise ScenarioError(f"{where}: 'alerts' must be a count consistent with 'expect'")
    groups = raw.get("events")
    if not isinstance(groups, list) or not groups:
        raise ScenarioError(f"{where}: 'events' must be a non-empty list")
    return Case(
        name=name.strip(),
        expect=expect,
        alerts=alerts,
        groups=tuple(_group(f"{where} ({name})", g) for g in groups),
    )


def _group(where: str, raw: Any) -> EventGroup:
    if not isinstance(raw, dict):
        raise ScenarioError(f"{where}: each event group must be a mapping")
    unknown = set(raw) - _GROUP_KEYS
    if unknown:
        raise ScenarioError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    overrides: dict[str, Any] = dict(raw.get("set") or {})
    if not all(isinstance(k, str) for k in overrides):
        raise ScenarioError(f"{where}: 'set' keys must be field names")
    if "prompt" in raw and "messages" in raw:
        raise ScenarioError(f"{where}: use either 'prompt' or 'messages'")
    if "prompt" in raw:
        overrides["gen_ai.input.messages"] = [text_messages("user", _text(where, raw["prompt"]))]
    if "messages" in raw:
        messages = raw["messages"]
        if not isinstance(messages, list) or not all(
            isinstance(m, dict) and set(m) == {"role", "text"} for m in messages
        ):
            raise ScenarioError(f"{where}: 'messages' must be a list of {{role, text}}")
        overrides["gen_ai.input.messages"] = [
            text_messages(str(m["role"]), _text(where, m["text"])) for m in messages
        ]
    if "response" in raw:
        overrides["gen_ai.output.messages"] = [
            {
                **text_messages("assistant", _text(where, raw["response"])),
                "finish_reason": "stop",
            }
        ]
    unset = raw.get("unset", [])
    if not isinstance(unset, list) or not all(isinstance(u, str) for u in unset):
        raise ScenarioError(f"{where}: 'unset' must be a list of field names")
    for name in [*overrides, *unset]:
        if name not in fields.registry():
            raise ScenarioError(f"{where}: {name!r} is not an audit-schema field")
    repeat = raw.get("repeat", 1)
    if not isinstance(repeat, int) or isinstance(repeat, bool) or repeat < 1:
        raise ScenarioError(f"{where}: 'repeat' must be a positive integer")
    return EventGroup(
        overrides=overrides,
        unset=tuple(unset),
        repeat=repeat,
        interval=_seconds(where, raw.get("interval", _DEFAULT_INTERVAL)),
        at=None if raw.get("at") is None else _seconds(where, raw["at"]),
    )


def _text(where: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{where}: message text must be a non-empty string")
    return value


def _seconds(where: str, value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    match = _DURATION.fullmatch(str(value))
    if match is None:
        raise ScenarioError(f"{where}: {value!r} is not a duration such as 30s, 5m or 1h")
    return int(match.group(1)) * _UNITS[match.group(2)]


def _reconcile_usage(event: dict[str, Any], overrides: Mapping[str, Any]) -> None:
    """Keep derived usage fields consistent when a case overrides token counts."""
    tokens_in = event.get("gen_ai.usage.input_tokens")
    tokens_out = event.get("gen_ai.usage.output_tokens")
    if not (isinstance(tokens_in, int) and isinstance(tokens_out, int)):
        return
    if "usage.total_tokens" not in overrides:
        event["usage.total_tokens"] = tokens_in + tokens_out
    if "cost.usd" not in overrides:
        event["cost.usd"] = round(
            tokens_in * INPUT_PRICE_PER_TOKEN + tokens_out * OUTPUT_PRICE_PER_TOKEN, 6
        )


def _deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    return value


def _iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "CASE_START",
    "Case",
    "CaseResult",
    "EventGroup",
    "Scenario",
    "ScenarioError",
    "base_event",
    "case_identity",
    "count_alerts",
    "duration",
    "load_scenario",
    "load_scenarios",
    "materialize",
    "run",
    "scenario_path",
    "text_messages",
]
