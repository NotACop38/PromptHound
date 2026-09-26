"""Offline demonstration: build the synthetic dataset and evaluate the rule pack.

The demo needs no SIEM and contacts no model. It builds the scenario dataset,
runs every scenario case on its own, evaluates the whole rule pack over the
combined dataset, and checks that background traffic raised no alerts.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from prompthound import generator, rules, scenarios
from prompthound.evaluate import Alert, evaluate


@dataclass(frozen=True)
class RuleSummary:
    rule: rules.Rule
    cases_passed: int
    cases_total: int
    alerts: int


@dataclass(frozen=True)
class Result:
    seed: int
    dataset: generator.Dataset
    summaries: tuple[RuleSummary, ...]
    alerts: tuple[Alert, ...]
    background_alerts: int

    @property
    def cases_passed(self) -> int:
        return sum(s.cases_passed for s in self.summaries)

    @property
    def cases_total(self) -> int:
        return sum(s.cases_total for s in self.summaries)

    @property
    def ok(self) -> bool:
        return self.cases_passed == self.cases_total and self.background_alerts == 0


def run(
    *,
    seed: int = 0,
    rules_dir: Path | None = None,
    scenarios_dir: Path | None = None,
) -> Result:
    pack = rules.load_rules(rules_dir)
    loaded = scenarios.load_scenarios(pack, scenarios_dir)
    dataset = generator.build_dataset(loaded, seed=seed)
    alerts = evaluate(pack, dataset.events)
    per_rule: dict[str, int] = {}
    for alert in alerts:
        per_rule[alert.rule.relpath] = per_rule.get(alert.rule.relpath, 0) + 1
    background = {
        event_id for event_id, label in dataset.labels.items() if label.source == "background"
    }
    background_alerts = sum(1 for a in alerts if set(a.event_ids) & background)
    summaries = []
    for scenario in loaded:
        results = scenarios.run(scenario)
        summaries.append(
            RuleSummary(
                scenario.rule,
                sum(r.passed for r in results),
                len(results),
                per_rule.get(scenario.rule.relpath, 0),
            )
        )
    return Result(seed, dataset, tuple(summaries), tuple(alerts), background_alerts)


def render(result: Result) -> str:
    labels = result.dataset.labels.values()
    background = sum(1 for label in labels if label.source == "background")
    lines = [
        "PromptHound demo: synthetic telemetry, evaluated offline",
        "",
        f"Dataset: {len(result.dataset.events)} events — {background} background, "
        f"{len(result.dataset.events) - background} from {result.cases_total} scenario cases "
        f"(seed {result.seed})",
        "",
    ]
    rows = [
        (
            s.rule.title,
            s.rule.level,
            f"{s.cases_passed}/{s.cases_total}",
            str(s.alerts),
        )
        for s in sorted(result.summaries, key=lambda s: (s.rule.category, s.rule.title))
    ]
    lines += table(("Rule", "Level", "Cases", "Alerts"), rows, right=(2, 3))
    lines += [
        "",
        f"{result.cases_passed} of {result.cases_total} scenario cases behave as expected; "
        f"background traffic raised {result.background_alerts} alerts.",
        "Alerts include rules firing on other rules' scenarios; each case is also checked alone.",
    ]
    return "\n".join(lines)


def table(
    headers: Sequence[str], rows: Sequence[Sequence[str]], right: Sequence[int] = ()
) -> list[str]:
    """Plain-text table with aligned columns."""
    widths = [max(len(str(r[i])) for r in [headers, *rows]) for i in range(len(headers))]

    def line(cells: Sequence[str]) -> str:
        return "  ".join(
            str(c).rjust(w) if i in right else str(c).ljust(w)
            for i, (c, w) in enumerate(zip(cells, widths, strict=True))
        ).rstrip()

    return [line(headers), line(["-" * w for w in widths]), *(line(r) for r in rows)]


__all__ = ["Result", "RuleSummary", "render", "run", "table"]
