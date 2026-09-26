"""Build a synthetic audit-event dataset from the rule scenarios.

The dataset combines seeded, varied benign *background* traffic with every
scenario case. Each case gets its own time slot and its own principal and
conversation, so cases cannot influence each other's correlation windows, and
every event carries a label saying where it came from. The same seed always
produces the same bytes.

Background traffic is designed to raise no alerts; the test suite enforces it.
It includes a few events with long prompts so that SIEM verification exercises
large-event field extraction.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import random
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from prompthound.payload_guard import scan_event
from prompthound.scenarios import (
    INPUT_PRICE_PER_TOKEN,
    OUTPUT_PRICE_PER_TOKEN,
    Scenario,
    base_event,
    case_identity,
    duration,
    materialize,
    text_messages,
)
from prompthound.schema import validate_event

#: Start of generated datasets; slots follow at fixed intervals.
DATASET_START = dt.datetime(2026, 6, 1, 0, 0, tzinfo=dt.UTC)

#: Default number of background events.
DEFAULT_BACKGROUND = 48

#: Length of the benign filler used for large events.
LARGE_EVENT_CHARACTERS = 12_000

_NAMESPACE = "prompthound-background"
_TENANTS = ("tenant-acme", "tenant-globex")
_MODELS = (("openai", "gpt-4.1"), ("anthropic", "claude-sonnet-4-5"), ("aws.bedrock", "nova-pro"))
_PROMPTS = (
    "Can you summarize the open support tickets for my account?",
    "Draft a friendly reply thanking the customer for their feedback.",
    "What is the status of order 4471?",
    "Explain our refund policy in two sentences.",
    "Translate this paragraph into Spanish for the customer.",
    "List the steps to reset a password in the billing portal.",
)
_RESPONSES = (
    "Here is a short summary of the three open tickets.",
    "Thank you for taking the time to share your feedback with us.",
    "Order 4471 shipped yesterday and should arrive on Friday.",
    "Refunds are available within 30 days; they reach the original payment method.",
    "Aqui esta la traduccion solicitada para el cliente.",
    "Open the billing portal, choose Reset password and follow the emailed link.",
)
_RETRIEVED = (
    "[retrieved article] Refunds are processed within five business days.",
    "[retrieved page] Shipping to Canada takes three to seven days.",
    "[retrieved record] The account is on the Business plan.",
)
_TOOL_CHAINS = (
    ["search_kb"],
    ["search_kb", "summarize"],
    ["calendar.list"],
    ["read_file"],
    ["send_email"],
)
_FILLER_SENTENCES = (
    "The quarterly review covers ticket volume, response times and customer satisfaction.",
    "Average first-response time improved in every region compared with the previous quarter.",
    "The billing team resolved most payment questions within one business day.",
    "Customers asked most often about shipping estimates, invoices and plan upgrades.",
    "The next review will add trends for the new self-service help center.",
)

Source = Literal["background", "scenario"]


@dataclass(frozen=True)
class Label:
    """Where a generated event came from."""

    source: Source
    rule: str | None = None
    case: str | None = None
    expect: str | None = None
    padded: bool = False


@dataclass(frozen=True)
class Dataset:
    events: tuple[dict[str, Any], ...]
    labels: Mapping[str, Label]


def slot_seconds(scenarios: Sequence[Scenario]) -> int:
    """Slot length: a whole number of hours that every correlation window divides."""
    spans = [s.rule.correlation.timespan for s in scenarios if s.rule.correlation]
    return math.lcm(3600, *spans)


def build_dataset(
    scenarios: Sequence[Scenario],
    *,
    seed: int = 0,
    background: int = DEFAULT_BACKGROUND,
    padded_copies: bool = False,
    start: dt.datetime = DATASET_START,
) -> Dataset:
    """Background traffic followed by every scenario case, one case per slot.

    With ``padded_copies``, every case of a rule that reads content fields is
    repeated with long benign filler in front of each message, which verifies
    that queries still match when a SIEM has to extract large events.
    """
    if background < 0:
        raise ValueError("background must not be negative")
    slot = dt.timedelta(seconds=slot_seconds(scenarios))
    events: list[dict[str, Any]] = []
    labels: dict[str, Label] = {}

    background_events = _background(random.Random(seed), background, start)  # noqa: S311  # nosec B311
    for event in background_events:
        labels[event["event.id"]] = Label("background")
    events.extend(background_events)

    last = max((e["timestamp"] for e in background_events), default=None)
    elapsed = (dt.datetime.fromisoformat(last) - start) if last else dt.timedelta(0)
    cursor = start + (elapsed // slot + 1) * slot
    variants = (False, True) if padded_copies else (False,)
    for padded in variants:
        for scenario in scenarios:
            if padded and not scenario.rule.requires_content:
                continue
            for index, case in enumerate(scenario.cases):
                if duration(case) >= slot.total_seconds():
                    raise ValueError(
                        f"{scenario.rule.relpath}: case {case.name!r} does not fit in one slot"
                    )
                identity = case_identity(scenario, index) + ("-padded" if padded else "")
                case_events = materialize(scenario, index, start=cursor, identity=identity)
                for event in case_events:
                    if padded:
                        _pad_content(event)
                    labels[event["event.id"]] = Label(
                        "scenario", scenario.rule.relpath, case.name, case.expect, padded
                    )
                events.extend(case_events)
                cursor += slot

    events.sort(key=lambda e: (e["timestamp"], e["event.id"]))
    for event in events:
        problems = validate_event(event)
        if problems or scan_event(event):
            raise ValueError(f"generated event {event['event.id']} is invalid: {problems}")
    return Dataset(tuple(events), labels)


def write_jsonl(path: Path, events: Iterable[Mapping[str, Any]]) -> int:
    """Write events as JSON Lines; return the number written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def filler(characters: int) -> str:
    """Benign text of at least ``characters`` characters."""
    sentences: list[str] = []
    length = 0
    index = 0
    while length < characters:
        sentence = _FILLER_SENTENCES[index % len(_FILLER_SENTENCES)]
        sentences.append(sentence)
        length += len(sentence) + 1
        index += 1
    return " ".join(sentences)


def _background(rng: random.Random, count: int, start: dt.datetime) -> list[dict[str, Any]]:
    users = [(tenant, f"user-{tenant[7:]}-{n}") for tenant in _TENANTS for n in range(4)]
    long_every = max(count // 3, 1)
    events: list[dict[str, Any]] = []
    moment = start
    for position in range(count):
        tenant, user = users[position % len(users)]
        conversation = f"conv-{user[5:]}-{position // len(users)}"
        long = position % long_every == long_every - 1
        operation = rng.choices(
            ("chat", "generate_content", "embeddings", "execute_tool", "invoke_agent"),
            weights=(55, 10, 5, 25, 5),
        )[0]
        if long:
            operation = "chat"
        event = base_event("background", operation)
        event.update(
            {
                "user.tenant.id": tenant,
                "user.id": user,
                "gen_ai.conversation.id": conversation,
                "timestamp": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "event.id": _background_id(position),
            }
        )
        if operation in ("execute_tool", "invoke_agent"):
            chain = list(rng.choice(_TOOL_CHAINS))
            event.update(
                {
                    "gen_ai.tool.name": chain[-1],
                    "tool.call.chain": chain,
                    "tool.call.depth": len(chain),
                }
            )
        else:
            _background_completion(rng, event, long=long)
        events.append(event)
        moment += dt.timedelta(seconds=rng.randint(45, 105))
    return events


def _background_completion(rng: random.Random, event: dict[str, Any], *, long: bool) -> None:
    provider, model = rng.choice(_MODELS)
    tokens_in, tokens_out = rng.randint(60, 1800), rng.randint(20, 700)
    choice = rng.randrange(len(_PROMPTS))
    prompt = _PROMPTS[choice]
    if long:
        prompt = f"Summarize this report for the leadership team. {filler(LARGE_EVENT_CHARACTERS)}"
        tokens_in = LARGE_EVENT_CHARACTERS // 4
    event.update(
        {
            "gen_ai.provider.name": provider,
            "gen_ai.request.model": model,
            "gen_ai.response.model": model,
            "gen_ai.request.max_tokens": rng.choice((1024, 2048, 4096, 8192)),
            "gen_ai.usage.input_tokens": tokens_in,
            "gen_ai.usage.output_tokens": tokens_out,
            "usage.total_tokens": tokens_in + tokens_out,
            "cost.usd": round(
                tokens_in * INPUT_PRICE_PER_TOKEN + tokens_out * OUTPUT_PRICE_PER_TOKEN, 6
            ),
            "gen_ai.input.messages": [text_messages("user", prompt)],
            "gen_ai.output.messages": [
                {**text_messages("assistant", _RESPONSES[choice]), "finish_reason": "stop"}
            ],
        }
    )
    if event["gen_ai.operation.name"] == "embeddings":
        for name in ("gen_ai.output.messages", "gen_ai.response.finish_reasons"):
            event.pop(name, None)
        return
    if rng.random() < 0.2:
        event["gen_ai.input.messages"].append(text_messages("tool", rng.choice(_RETRIEVED)))
        event["rag.retrieved.count"] = rng.randint(1, 5)
        event["rag.source.types"] = rng.sample(["db", "web", "file"], k=rng.randint(1, 2))
    if rng.random() < 0.1:
        event["content.output.pii.types"] = ["email"]
    if rng.random() < 0.1:
        event["gen_ai.response.finish_reasons"] = ["length"]
    if rng.random() < 0.15:
        event["output.sink"] = rng.choice(("markdown", "html_render", "downstream_api"))
        event["output.rendered_unsanitized"] = event["output.sink"] == "markdown"


def _background_id(position: int) -> str:
    digest = hashlib.sha256(f"{_NAMESPACE}#{position}".encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _pad_content(event: dict[str, Any]) -> None:
    padding = filler(LARGE_EVENT_CHARACTERS)
    for name in ("gen_ai.input.messages", "gen_ai.output.messages"):
        for message in event.get(name, []):
            for part in message.get("parts", []):
                if part.get("type") == "text":
                    part["content"] = f"{padding} {part['content']}"


__all__ = [
    "DATASET_START",
    "DEFAULT_BACKGROUND",
    "LARGE_EVENT_CHARACTERS",
    "Dataset",
    "Label",
    "build_dataset",
    "filler",
    "slot_seconds",
    "write_jsonl",
]
