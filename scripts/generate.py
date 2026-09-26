"""Regenerate every committed artifact derived from the rules, scenarios and schema.

    python scripts/generate.py          # rewrite the artifacts
    python scripts/generate.py --check  # exit 1 if any artifact is out of date

Generated files:

* ``siem/splunk/<category>/<rule>.spl`` and ``siem/sentinel/<category>/<rule>.kql``
* ``siem/splunk/app/prompthound/``: a Splunk app (props, macros, saved searches)
* ``siem/sentinel/table.json``: column definitions for the Sentinel table
* ``docs/rules.md`` and ``docs/atlas-navigator-layer.json``
* the rule table in ``README.md`` and the field tables in ``docs/schema.md``,
  between ``<!-- name:start -->`` and ``<!-- name:end -->`` markers

Every file under ``siem/`` is generated; a file there without a source is stale.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from prompthound import catalog, convert, rules, scenarios

ROOT = Path(__file__).resolve().parent.parent
SIEM = ROOT / "siem"


def splice(text: str, name: str, content: str) -> str:
    """Replace the block between ``<!-- name:start -->`` and ``<!-- name:end -->``."""
    pattern = re.compile(rf"(<!-- {name}:start -->\n).*?(<!-- {name}:end -->)", flags=re.DOTALL)
    if len(pattern.findall(text)) != 1:
        raise ValueError(f"expected exactly one {name}:start/{name}:end marker pair")
    return pattern.sub(lambda m: m.group(1) + content + m.group(2), text)


def artifacts() -> dict[Path, str]:
    """Every generated artifact, keyed by path."""
    pack = rules.load_rules()
    cases = scenarios.load_scenarios(pack)
    queries = [convert.convert(rule) for rule in pack]
    result: dict[Path, str] = {}
    for item in queries:
        stem = item.rule.relpath.removesuffix(".yml")
        result[SIEM / "splunk" / f"{stem}.spl"] = item.spl + "\n"
        result[SIEM / "sentinel" / f"{stem}.kql"] = item.kql + "\n"
    app = SIEM / "splunk" / "app" / convert.SPLUNK_APP
    result[app / "default" / "app.conf"] = convert.app_conf()
    result[app / "default" / "macros.conf"] = convert.macros_conf()
    result[app / "default" / "props.conf"] = convert.props_conf()
    result[app / "default" / "savedsearches.conf"] = convert.savedsearches_conf(queries)
    result[app / "metadata" / "default.meta"] = convert.default_meta()
    result[SIEM / "sentinel" / "table.json"] = convert.sentinel_table()
    result[ROOT / "docs" / "rules.md"] = catalog.rule_catalog(pack, cases)
    result[ROOT / "docs" / "atlas-navigator-layer.json"] = catalog.atlas_layer(pack)
    readme = ROOT / "README.md"
    result[readme] = splice(readme.read_text("utf-8"), "rules", catalog.readme_rule_table(pack))
    schema_doc = ROOT / "docs" / "schema.md"
    result[schema_doc] = splice(schema_doc.read_text("utf-8"), "fields", catalog.schema_reference())
    return result


def stale(expected: dict[Path, str]) -> list[Path]:
    """Files under ``siem/`` that no source produces any more."""
    present = {p for p in SIEM.rglob("*") if p.is_file()} if SIEM.is_dir() else set()
    return sorted(present - set(expected))


def check() -> list[str]:
    """Problems with the committed artifacts (empty when everything is current)."""
    expected = artifacts()
    problems = [
        f"{path.relative_to(ROOT)} is out of date"
        for path, content in sorted(expected.items())
        if not path.is_file() or path.read_text("utf-8") != content
    ]
    problems += [f"{path.relative_to(ROOT)} has no source" for path in stale(expected)]
    return problems


def write() -> int:
    expected = artifacts()
    for path in stale(expected):
        path.unlink()
        print(f"removed {path.relative_to(ROOT)}")
    changed = 0
    for path, content in sorted(expected.items()):
        if path.is_file() and path.read_text("utf-8") == content:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        changed += 1
        print(f"wrote {path.relative_to(ROOT)}")
    print(f"{changed} of {len(expected)} artifacts updated")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only report out-of-date artifacts")
    args = parser.parse_args(argv)
    if not args.check:
        return write()
    problems = check()
    for problem in problems:
        print(f"  {problem}")
    if problems:
        print("run `python scripts/generate.py` and commit the result")
        return 1
    print("all generated artifacts are current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
