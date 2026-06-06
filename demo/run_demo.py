"""PromptHound one-command demo (PRD §1 / §7 item 6; CHECKLIST Phase 5).

The 10-second "wow", entirely offline. In one command it:

  1. **Generates** a mixed synthetic telemetry dataset (benign traffic plus, for
     every declared signature, a should-alert positive and a should-not-alert
     negative) — :mod:`prompthound.generator`, schema-valid and P1-safe.
  2. **Evaluates** the whole shipped Sigma rule pack against that dataset using
     the backend-agnostic offline matcher (:mod:`prompthound.matcher`) — single
     events for selection rules, windowed group-by counting for ``event_count``
     correlations — and prints a hits summary table (rule · OWASP · ATLAS · tier
     · #hits).
  3. **Builds** the OWASP × ATLAS coverage map from rule metadata
     (:mod:`coverage.build_coverage`) and prints where to open it.

No live LLM is ever contacted (principles P1–P2, PRD §8): the generator only
writes files, and rule evaluation is pure Python over plain dicts. Everything is
reproducible — a given ``--seed`` yields a byte-identical dataset and identical
hits.

    python demo/run_demo.py --seed 0        # or: make demo
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
# Importable when run as `python demo/run_demo.py` from a fresh clone. The
# prompthound/coverage imports are done lazily inside the functions that need
# them (the project convention, see prompthound/convert.py): it keeps the module
# top-level stdlib-only so `python demo/run_demo.py` resolves after this insert.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OUT_DIR = REPO_ROOT / "out"
TELEMETRY_PATH = OUT_DIR / "telemetry.jsonl"
BAR = "─" * 78


# --- rule evaluation ----------------------------------------------------------
#
# Two rule shapes ship in the pack (PRD §11/§12): plain *selection* rules, which
# the offline matcher evaluates one event at a time, and *correlation* rules
# (all `event_count`), whose alert is a per-group windowed count crossing a
# threshold — the windowing the single-event matcher can't express. We mirror the
# evaluator the tests use (tests/test_dos_cost_abuse.py) so demo hits agree with
# what `pytest` proves.


@dataclass(frozen=True)
class RuleHits:
    rel: str  # rule path relative to rules/
    owasp: str
    atlas: str
    tier: str
    hits: int
    is_correlation: bool


def _parse_ts(event: dict) -> dt.datetime:
    return dt.datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))


def _correlation_alerts(base: Any, correlation: Any, events: list[dict]) -> int:
    """Number of groups/windows whose `event_count` crosses the threshold."""
    from prompthound.matcher import rule_matches

    if str(correlation.type) != "event_count":
        # The pack only ships event_count correlations; anything else is reported
        # as "unsupported" (0) rather than silently miscounted.
        return 0
    group_by = correlation.group_by
    span = dt.timedelta(seconds=correlation.timespan.seconds)
    threshold = correlation.condition.count
    op = correlation.condition.op.name
    passes = {
        "GTE": lambda c: c >= threshold,
        "GT": lambda c: c > threshold,
        "LTE": lambda c: c <= threshold,
        "LT": lambda c: c < threshold,
    }[op]

    groups: dict[tuple, list[dt.datetime]] = defaultdict(list)
    for event in events:
        if not rule_matches(base, event):
            continue
        key = tuple(event.get(g) for g in group_by)
        groups[key].append(_parse_ts(event))

    alerts = 0
    for times in groups.values():
        times.sort()
        for start in times:  # window anchored at each matched event
            if passes(sum(1 for t in times if start <= t < start + span)):
                alerts += 1
                break
    return alerts


def evaluate_rule(path: Path, events: list[dict]) -> tuple[int, bool]:
    """Return ``(#hits, is_correlation)`` for one rule file over the dataset.

    Selection rule → number of matching events. Correlation rule → number of
    groups that fire (each is one alert).
    """
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule

    from prompthound.matcher import load_rule, rule_matches

    collection = SigmaCollection.load_ruleset([str(path)])
    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    if correlations:
        base = next(r for r in collection.rules if not isinstance(r, SigmaCorrelationRule))
        return _correlation_alerts(base, correlations[0], events), True
    rule = load_rule(path)
    return sum(1 for e in events if rule_matches(rule, e)), False


def _meta_strings(path: Path) -> tuple[str, str, str]:
    """``(owasp, atlas, tier)`` display strings from a rule's metadata tags."""
    from coverage.build_coverage import load_rule_meta

    errors: list[str] = []
    meta = load_rule_meta(path, errors)
    if meta is None:
        return ("?", "?", "?")
    owasp = ", ".join(meta.owasp) or "-"
    atlas = ", ".join(meta.atlas_techniques + meta.atlas_tactics) or "-"
    tier = ", ".join(meta.tiers) or "-"
    return (owasp, atlas, tier)


def evaluate_all(events: list[dict]) -> list[RuleHits]:
    from coverage.build_coverage import RULES_DIR

    rule_files = sorted(RULES_DIR.glob("**/*.yml")) + sorted(RULES_DIR.glob("**/*.yaml"))
    results: list[RuleHits] = []
    for path in rule_files:
        owasp, atlas, tier = _meta_strings(path)
        hits, is_corr = evaluate_rule(path, events)
        results.append(
            RuleHits(
                rel=str(path.relative_to(RULES_DIR)),
                owasp=owasp,
                atlas=atlas,
                tier=tier,
                hits=hits,
                is_correlation=is_corr,
            )
        )
    return results


# --- rendering ----------------------------------------------------------------


def _print_table(rows: list[RuleHits]) -> None:
    headers = ("Rule", "OWASP", "ATLAS", "Tier", "Hits")

    def cells(r: RuleHits) -> tuple[str, str, str, str, str]:
        kind = "corr" if r.is_correlation else "sel"
        hit = f"{r.hits}" if r.hits else "·"
        return (f"{r.rel}", r.owasp, r.atlas, f"{r.tier}/{kind}", hit)

    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(cells(r)):
            widths[i] = max(widths[i], len(c))

    def fmt(cols: tuple[str, ...]) -> str:
        # Left-align everything except the final Hits column.
        out = [cols[i].ljust(widths[i]) for i in range(len(cols) - 1)]
        out.append(cols[-1].rjust(widths[-1]))
        return "  ".join(out)

    print(f"  {fmt(headers)}")
    print(f"  {'  '.join('─' * w for w in widths)}")
    for r in rows:
        print(f"  {fmt(cells(r))}")


def banner(text: str) -> None:
    print(f"\n{BAR}\n{text}\n{BAR}")


# --- main ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    from coverage.build_coverage import OUT_DIR as COVERAGE_OUT_DIR
    from coverage.build_coverage import generate_artifacts, write_artifacts
    from prompthound.generator import (
        DEFAULT_BENIGN,
        build_samples,
        iter_events,
        write_jsonl,
    )

    parser = argparse.ArgumentParser(
        prog="python demo/run_demo.py",
        description="One-command offline demo: generate telemetry → run the rule "
        "pack → print hits → build the OWASP × ATLAS coverage map.",
    )
    parser.add_argument(
        "--seed", type=int, default=0, help="Deterministic dataset seed (default: 0)."
    )
    parser.add_argument(
        "--benign",
        type=int,
        default=DEFAULT_BENIGN,
        help=f"Standalone benign events mixed in (default: {DEFAULT_BENIGN}).",
    )
    args = parser.parse_args(argv)

    print("PromptHound: offline detection demo")
    print("    generate synthetic telemetry → run the rule pack → coverage map")
    print(f"    no live LLM is ever contacted (PRD §8 P1-P2) · seed={args.seed}")

    # 1. Generate ---------------------------------------------------------------
    banner("1. Generate synthetic telemetry")
    samples = build_samples(seed=args.seed, n_benign=args.benign, enforce_p1=True)
    events = list(iter_events(samples))
    n_benign = sum(len(s.events) for s in samples if s.polarity == "benign")
    n_pos = sum(len(s.events) for s in samples if s.polarity == "positive")
    n_neg = sum(len(s.events) for s in samples if s.polarity == "negative")
    write_jsonl(TELEMETRY_PATH, events)
    print(
        f"  {len(events)} schema-valid events  "
        f"({n_benign} benign · {n_pos} positive · {n_neg} negative signatures)"
    )
    print(f"  → wrote {TELEMETRY_PATH.relative_to(REPO_ROOT)}")

    # 2. Evaluate ---------------------------------------------------------------
    banner("2. Evaluate the rule pack against the dataset")
    rows = evaluate_all(events)
    _print_table(rows)
    fired = sum(1 for r in rows if r.hits)
    total_alerts = sum(r.hits for r in rows)
    print()
    print(
        f"  {fired}/{len(rows)} rules fired · {total_alerts} total hits across "
        f"{len(events)} events (Tier = T1 operational / T2 content; "
        "sel = selection, corr = correlation)"
    )

    # 3. Coverage map -----------------------------------------------------------
    banner("3. Build the OWASP × ATLAS coverage map")
    artifacts, errors = generate_artifacts()
    if errors:
        for error in errors:
            print(f"  ERROR  {error}")
        print("\n  coverage build failed: fix the rule tags above.")
        return 1
    write_artifacts(artifacts)
    for path in sorted(artifacts):
        print(f"  → wrote {path.relative_to(REPO_ROOT)}")
    html = COVERAGE_OUT_DIR / "coverage.html"
    print()
    print("  Open the visual coverage map in a browser:")
    print(f"    {html.as_uri()}")
    cov_rel = COVERAGE_OUT_DIR.relative_to(REPO_ROOT)
    print(f"  Markdown / ATLAS Navigator layer alongside it under {cov_rel}/")

    banner("Demo complete (reproducible: re-run with the same --seed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
