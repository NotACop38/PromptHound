"""Unit tests for the shared windowed correlation evaluator (prompthound.correlate).

The per-rule suites (test_dos_cost_abuse.py, test_jailbreak.py, ...) prove the
shipped correlations fire/stay silent on their samples; these tests pin the
*evaluator's own semantics* on a minimal synthetic rule: threshold boundaries,
fixed UTC buckets, group isolation, the fail-loud contract for
unsupported correlation shapes, and the selection/correlation file dispatch.

Run just these with ``pytest -k correlate -q``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from prompthound.correlate import (
    CorrelationAlert,
    correlation_hits,
    evaluate_rule_file,
    is_correlation_file,
    load_correlation_file,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# A minimal correlation: >= 3 chat events per user.id inside 5 minutes.
CORRELATION_RULE = """\
title: Chat burst building block
name: chat_event
id: 0b0d35f5-6f5c-4a52-9fc6-3b0f5f3e9d01
status: experimental
description: test base rule
author: PromptHound tests
date: 2026-06-11
logsource:
  product: llm_gateway
detection:
  sel:
    event.action: chat
  condition: sel
falsepositives:
  - none
level: low
---
title: Chat burst per principal
id: 0b0d35f5-6f5c-4a52-9fc6-3b0f5f3e9d02
status: experimental
description: test correlation
author: PromptHound tests
date: 2026-06-11
correlation:
  type: event_count
  rules:
    - chat_event
  group-by:
    - user.id
  timespan: 5m
  condition:
    gte: 3
falsepositives:
  - none
level: medium
"""


@pytest.fixture
def rule_file(tmp_path: Path) -> Path:
    path = tmp_path / "chat_burst.yml"
    path.write_text(CORRELATION_RULE, encoding="utf-8")
    return path


def _event(minute: float, user: str = "u-1", action: str = "chat") -> dict:
    whole = int(minute)
    seconds = round((minute - whole) * 60)
    return {
        "timestamp": f"2026-06-11T12:{whole:02d}:{seconds:02d}Z",
        "event.action": action,
        "user.id": user,
    }


# --- threshold and window semantics ---------------------------------------------


def test_correlate_fires_at_exact_threshold(rule_file: Path) -> None:
    events = [_event(0), _event(1), _event(2)]
    assert correlation_hits(rule_file, events) == [(("u-1",), 3)]


def test_correlate_silent_one_under_threshold(rule_file: Path) -> None:
    assert correlation_hits(rule_file, [_event(0), _event(1)]) == []


def test_correlate_window_is_fixed_and_half_open(rule_file: Path) -> None:
    # Three matches spread over 8 minutes: no 5-minute window anchored at a
    # match holds all three, so the correlation must stay silent.
    spread = [_event(0), _event(4), _event(8)]
    assert correlation_hits(rule_file, spread) == []
    # The window is [start, start + span): an event exactly at start + 5m falls
    # outside the first anchor but a later anchor can still catch a burst.
    edge = [_event(0), _event(1), _event(5)]
    assert correlation_hits(rule_file, edge) == []
    caught_later = [_event(0), _event(4), _event(4.5), _event(5)]
    assert correlation_hits(rule_file, caught_later) == [(("u-1",), 3)]


def test_correlate_groups_are_isolated(rule_file: Path) -> None:
    # Two users with two events each: the global count crosses the threshold
    # but no single group does, so nothing fires.
    interleaved = [_event(0, "u-a"), _event(0.5, "u-b"), _event(1, "u-a"), _event(1.5, "u-b")]
    assert correlation_hits(rule_file, interleaved) == []
    # One user crossing the threshold alerts once, for that group only.
    burst = interleaved + [_event(2, "u-a")]
    assert correlation_hits(rule_file, burst) == [(("u-a",), 3)]


def test_correlate_base_detection_filters_events(rule_file: Path) -> None:
    # Non-matching events (action != chat) never count toward the window.
    events = [_event(0), _event(1), _event(2, action="execute_tool")]
    assert correlation_hits(rule_file, events) == []


def test_correlate_day_scale_timespans_keep_their_full_span(tmp_path: Path) -> None:
    # pySigma's SigmaCorrelationTimespan.seconds is the TOTAL span (1d -> 86400),
    # so day-scale windows must work at full width — this pins that a `1d`
    # window is not truncated modulo a day (e.g. to 0 seconds).
    path = tmp_path / "daily_burst.yml"
    path.write_text(CORRELATION_RULE.replace("timespan: 5m", "timespan: 1d"), encoding="utf-8")

    def at(hour: int) -> dict:
        day, hh = divmod(hour, 24)
        return {
            "timestamp": f"2026-06-{11 + day:02d}T{hh:02d}:00:00Z",
            "event.action": "chat",
            "user.id": "u-1",
        }

    # Three matches over 20 hours: inside one 24h window -> fires.
    assert correlation_hits(path, [at(0), at(10), at(20)]) == [(("u-1",), 3)]
    # Three matches spread over 26 hours, max 2 per 24h window -> silent.
    assert correlation_hits(path, [at(0), at(13), at(26)]) == []


def test_correlate_alert_is_tuple_compatible(rule_file: Path) -> None:
    [alert] = correlation_hits(rule_file, [_event(0), _event(1), _event(2)])
    assert isinstance(alert, CorrelationAlert)
    assert alert.group == ("u-1",)
    assert alert.event_count == 3
    assert alert == (("u-1",), 3)  # plain-tuple expectations keep working


# --- fail-loud contract ----------------------------------------------------------


def test_correlate_rejects_event_without_timestamp(rule_file: Path) -> None:
    with pytest.raises(ValueError, match="timestamp"):
        correlation_hits(rule_file, [{"event.action": "chat", "user.id": "u-1"}] * 3)


def test_correlate_load_rejects_plain_rule_file() -> None:
    plain = REPO_ROOT / "rules" / "dos_cost_abuse" / "oversized_max_tokens.yml"
    with pytest.raises(ValueError, match="one base rule"):
        load_correlation_file(plain)


# --- file dispatch ----------------------------------------------------------------


def test_correlate_detects_file_shape(rule_file: Path) -> None:
    assert is_correlation_file(rule_file)
    assert not is_correlation_file(
        REPO_ROOT / "rules" / "insecure_output" / "unsanitized_output_to_sink.yml"
    )


def test_correlate_evaluate_rule_file_counts_alerts(rule_file: Path) -> None:
    events = [_event(0), _event(1), _event(2), _event(0, "u-2")]
    result = evaluate_rule_file(rule_file, events)
    assert result.is_correlation
    assert result.hits == 1  # one alerting group, not four matching events


def test_correlate_evaluate_rule_file_counts_selection_matches() -> None:
    rule = REPO_ROOT / "rules" / "dos_cost_abuse" / "oversized_max_tokens.yml"
    events = [
        {"event.action": "chat", "gen_ai.request.max_tokens": 200000},
        {"event.action": "chat", "gen_ai.request.max_tokens": 4096},
    ]
    result = evaluate_rule_file(rule, events)
    assert not result.is_correlation
    assert result.hits == 1
