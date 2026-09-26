from __future__ import annotations

from prompthound import generator, rules
from prompthound.evaluate import alerts_for, evaluate


def test_selection_alerts(by_stem: dict[str, rules.Rule], dataset: generator.Dataset) -> None:
    alerts = alerts_for(by_stem["oversized_max_tokens"], dataset.events)
    assert len(alerts) == 2
    record = alerts[0].to_dict()
    assert set(record) == {"rule_id", "rule", "title", "level", "time", "event_ids"}
    assert record["rule"] == "dos_cost_abuse/oversized_max_tokens.yml"
    assert len(record["event_ids"]) == 1


def test_correlation_alerts(by_stem: dict[str, rules.Rule], dataset: generator.Dataset) -> None:
    alerts = alerts_for(by_stem["denied_tool_retry_loop"], dataset.events)
    assert [a.count for a in alerts] == [3, 3]
    record = alerts[0].to_dict()
    assert record["window_seconds"] == 300
    assert set(record["group"]) == {"user.tenant.id", "gen_ai.conversation.id"}
    assert len(record["event_ids"]) == record["count"]
    assert record["time"].endswith(":00Z")


def test_evaluate_orders_alerts_by_time(pack: list[rules.Rule], dataset: generator.Dataset) -> None:
    alerts = evaluate(pack, dataset.events)
    assert alerts
    keys = [(a.time, a.rule.title) for a in alerts]
    assert keys == sorted(keys)
    assert evaluate(pack, []) == []
