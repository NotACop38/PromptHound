"""Command-line interface: ``prompthound <command>``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from prompthound import __version__, fields
from prompthound.demo import table

Handler = Callable[[argparse.Namespace], int]


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _telemetry(rule: Any) -> str:
    if rule.requires_content:
        return "raw content"
    return "content detector" if rule.derived_fields else "metadata"


def _load_rules(args: argparse.Namespace) -> list[Any]:
    from prompthound.rules import load_rules

    return load_rules(args.rules)


def _read(args: argparse.Namespace) -> Any:
    from prompthound.events import read_events

    loaded = read_events(args.events)
    for invalid in loaded.invalid[: args.max_errors]:
        print(f"line {invalid.line}: {'; '.join(invalid.problems)}", file=sys.stderr)
    hidden = len(loaded.invalid) - args.max_errors
    if hidden > 0:
        print(f"... and {hidden} more invalid events", file=sys.stderr)
    return loaded


# --- commands -----------------------------------------------------------------


def cmd_rules(args: argparse.Namespace) -> int:
    pack = _load_rules(args)
    if args.format == "json":
        _print_json(
            [
                {
                    "id": r.id,
                    "rule": r.relpath,
                    "title": r.title,
                    "level": r.level,
                    "logic": r.kind,
                    "telemetry": _telemetry(r),
                    "fields": list(r.fields),
                    "owasp_llm": list(r.mappings.owasp_llm) if r.mappings else [],
                    "owasp_agentic": list(r.mappings.owasp_agentic) if r.mappings else [],
                    "atlas": list(r.mappings.atlas) if r.mappings else [],
                    "attack": list(r.mappings.attack) if r.mappings else [],
                }
                for r in pack
            ]
        )
        return 0
    rows = [(r.level, r.kind, _telemetry(r), r.title, r.relpath) for r in pack]
    print("\n".join(table(("Level", "Logic", "Telemetry", "Title", "File"), rows)))
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    from prompthound import rules, scenarios

    pack = rules.load_rules(args.rules)
    problems = rules.check_policy(pack)
    for problem in problems:
        print(f"policy: {problem}")
    total = failed = 0
    for scenario in scenarios.load_scenarios(pack, args.scenarios):
        for result in scenarios.run(scenario):
            total += 1
            if not result.passed:
                failed += 1
                expected = (
                    f"{result.case.alerts} alerts"
                    if result.case.alerts is not None
                    else ("an alert" if result.case.expect == "alert" else "no alert")
                )
                print(
                    f"FAIL {scenario.rule.relpath}: {result.case.name}: "
                    f"expected {expected}, got {result.alerts}"
                )
    print(
        f"{total - failed} of {total} scenario cases passed across {len(pack)} rules; "
        f"{len(problems)} policy problems"
    )
    return 1 if failed or problems else 0


def cmd_generate(args: argparse.Namespace) -> int:
    from prompthound import generator, rules, scenarios

    pack = rules.load_rules(args.rules)
    dataset = generator.build_dataset(
        scenarios.load_scenarios(pack, args.scenarios),
        seed=args.seed,
        background=args.background,
        padded_copies=args.large_copies,
    )
    count = generator.write_jsonl(args.output, dataset.events)
    print(f"wrote {count} events to {args.output}")
    if args.labels:
        labels = {
            event_id: {k: v for k, v in vars(label).items() if v not in (None, False)}
            for event_id, label in dataset.labels.items()
        }
        args.labels.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
        print(f"wrote labels for {len(labels)} events to {args.labels}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    loaded = _read(args)
    print(f"{len(loaded.events)} of {loaded.total} events are valid")
    return 1 if loaded.invalid else 0


def cmd_normalize(args: argparse.Namespace) -> int:
    from prompthound.normalize import NormalizationError, normalize_file

    try:
        count = normalize_file(args.events, args.output)
    except (NormalizationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {count} normalized events to {args.output}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    from prompthound.evaluate import evaluate

    pack = _load_rules(args)
    loaded = _read(args)
    alerts = evaluate(pack, loaded.events)
    if args.format == "json":
        _print_json([a.to_dict() for a in alerts])
    else:
        print(
            f"{len(alerts)} alerts from {len(pack)} rules over {len(loaded.events)} valid events"
            + (f" ({len(loaded.invalid)} invalid events skipped)" if loaded.invalid else "")
        )
        for alert in alerts:
            detail = (
                "  ".join(f"{k}={v}" for k, v in alert.group) + f"  count={alert.count}"
                if alert.group
                else f"event {alert.event_ids[0]}"
            )
            print(f"{alert.time}  {alert.rule.level:<6}  {alert.rule.title}\n    {detail}")
    return 1 if alerts and args.fail_on_alert else 0


def cmd_readiness(args: argparse.Namespace) -> int:
    from prompthound.readiness import assess

    pack = _load_rules(args)
    loaded = _read(args)
    report = assess(pack, loaded.events)
    if args.format == "json":
        _print_json(report.to_dict())
        return 0
    print(f"Field presence across {len(loaded.events)} valid events:\n")
    rows = [
        (f.name, fields.get(f.name).data_class, f"{f.present}", f"{f.share:.0%}")
        for f in report.fields
    ]
    print("\n".join(table(("Field", "Class", "Events", "Share"), rows, right=(2, 3))))
    print()
    order = {"blocked": 0, "partial": 1, "ready": 2}
    rule_rows = [
        (r.status, r.rule.title, ", ".join(r.missing))
        for r in sorted(report.rules, key=lambda r: (order[r.status], r.rule.title))
    ]
    print("\n".join(table(("Status", "Rule", "Missing fields"), rule_rows)))
    counts = {status: sum(r.status == status for r in report.rules) for status in order}
    print(
        f"\n{counts['ready']} ready, {counts['partial']} partial, {counts['blocked']} blocked "
        f"of {len(report.rules)} rules. Ready means every field a rule reads is present in "
        "some event; it does not guarantee an alert."
    )
    return 0


def cmd_convert(args: argparse.Namespace) -> int:
    from prompthound.convert import convert

    pack = _load_rules(args)
    targets = ("splunk", "sentinel") if args.target == "all" else (args.target,)
    for rule in pack:
        queries = convert(rule, splunk_macro=args.splunk_macro, sentinel_table=args.sentinel_table)
        for target in targets:
            query, suffix = (queries.spl, "spl") if target == "splunk" else (queries.kql, "kql")
            if args.output is None:
                print(f"// {rule.title} ({target})\n{query}\n")
                continue
            path = args.output / target / rule.relpath.replace(".yml", f".{suffix}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(query + "\n", encoding="utf-8")
    if args.output is not None:
        print(f"wrote {len(pack) * len(targets)} queries under {args.output}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from prompthound import demo, generator
    from prompthound.normalize import normalize_event

    result = demo.run(seed=args.seed)
    print(demo.render(result))
    if args.output:
        events = args.output / "events.jsonl"
        siem = args.output / "siem.jsonl"
        generator.write_jsonl(events, result.dataset.events)
        generator.write_jsonl(siem, (normalize_event(e) for e in result.dataset.events))
        print(f"\nwrote {events} (audit events) and {siem} (SIEM column layout)")
    return 0 if result.ok else 1


# --- parser -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prompthound",
        description="Detection rules for LLM applications and AI agents: evaluate, "
        "test, convert and generate.",
    )
    parser.add_argument("--version", action="version", version=f"prompthound {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    def command(name: str, handler: Handler, summary: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=summary, description=summary)
        sub.set_defaults(handler=handler)
        return sub

    def rules_option(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--rules", type=Path, metavar="DIR", help="rule directory (default: bundled pack)"
        )

    def scenarios_option(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--scenarios",
            type=Path,
            metavar="DIR",
            help="scenario directory (default: bundled scenarios)",
        )

    def events_input(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("events", help="audit events, one JSON object per line (- for stdin)")
        sub.add_argument(
            "--max-errors", type=int, default=20, metavar="N", help="invalid events to list"
        )

    def output_format(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--format", choices=("text", "json"), default="text")

    sub = command("rules", cmd_rules, "List the rules with their levels and mappings.")
    rules_option(sub)
    output_format(sub)

    sub = command("test", cmd_test, "Run every rule's scenarios and the publication checks.")
    rules_option(sub)
    scenarios_option(sub)

    sub = command("generate", cmd_generate, "Write a synthetic audit-event dataset.")
    sub.add_argument("-o", "--output", type=Path, required=True, help="JSON Lines file to write")
    sub.add_argument("--seed", type=int, default=0, help="random seed (default: 0)")
    sub.add_argument(
        "--background", type=int, default=48, help="benign background events (default: 48)"
    )
    sub.add_argument(
        "--large-copies",
        action="store_true",
        help="add copies of content cases with long prompts",
    )
    sub.add_argument("--labels", type=Path, help="also write each event's source as JSON")
    rules_option(sub)
    scenarios_option(sub)

    sub = command("validate", cmd_validate, "Check audit events against the schema.")
    events_input(sub)

    sub = command("normalize", cmd_normalize, "Convert audit events to the SIEM column layout.")
    sub.add_argument("events", type=Path, help="audit events (JSON Lines)")
    sub.add_argument("-o", "--output", type=Path, required=True, help="JSON Lines file to write")

    sub = command("evaluate", cmd_evaluate, "Run the rules over audit events.")
    events_input(sub)
    rules_option(sub)
    output_format(sub)
    sub.add_argument("--fail-on-alert", action="store_true", help="exit 1 when any rule alerts")

    sub = command("readiness", cmd_readiness, "Report which rules your telemetry supports.")
    events_input(sub)
    rules_option(sub)
    output_format(sub)

    sub = command("convert", cmd_convert, "Print or write Splunk SPL and Sentinel KQL.")
    rules_option(sub)
    sub.add_argument("--target", choices=("splunk", "sentinel", "all"), default="all")
    sub.add_argument("-o", "--output", type=Path, metavar="DIR", help="write files under DIR")
    sub.add_argument("--splunk-macro", default=fields.DEFAULT_SPLUNK_MACRO)
    sub.add_argument("--sentinel-table", default=fields.DEFAULT_SENTINEL_TABLE)

    sub = command("demo", cmd_demo, "Evaluate the rule pack on synthetic telemetry.")
    sub.add_argument("--seed", type=int, default=0, help="random seed (default: 0)")
    sub.add_argument("-o", "--output", type=Path, metavar="DIR", help="also write the dataset")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    from prompthound.rules import RuleError
    from prompthound.scenarios import ScenarioError

    args = build_parser().parse_args(argv)
    handler: Handler = args.handler
    try:
        return handler(args)
    except (RuleError, ScenarioError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # The reader went away (for example `prompthound evaluate ... | head`).
        # Silence the flush at interpreter exit as well.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 1


__all__ = ["build_parser", "main"]
