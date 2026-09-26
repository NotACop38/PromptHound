"""Refresh the vendored MITRE ATLAS technique catalog.

Downloads an ATLAS release from https://github.com/mitre-atlas/atlas-data and
writes ``src/prompthound/data/atlas.json`` with every technique's ID, display
name and tactics. Rule mappings are validated against this file, so a mapped
technique that MITRE renames or retires fails the test suite after a refresh.

    python scripts/update_atlas.py               # latest release
    python scripts/update_atlas.py --release 2026.09
    python scripts/update_atlas.py --file ATLAS-2026.09.yaml   # offline
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

import yaml

BASE_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/"
OUTPUT = Path(__file__).resolve().parent.parent / "src" / "prompthound" / "data" / "atlas.json"


def _fetch(url: str) -> str:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS URL: {url}")
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310  # nosec B310
        return str(response.read().decode("utf-8"))


def build_catalog(data: dict[str, Any]) -> dict[str, Any]:
    """Reduce an ATLAS v6 release document to the catalog PromptHound vendors."""
    tactics = {tid: t["name"] for tid, t in data["tactics"].items()}
    relationships = data["relationships"]
    raw = data["techniques"]

    def related(source: str, kind: str) -> list[str]:
        return [r["target"] for r in relationships.get(source, {}).get(kind, [])]

    techniques: dict[str, dict[str, Any]] = {}
    for tid in sorted(raw):
        # Sub-techniques "specialize" a parent and are displayed as
        # "Parent: Sub-technique", matching atlas.mitre.org.
        parents = related(tid, "specializes")
        name = raw[tid]["name"]
        if parents:
            name = f"{raw[parents[0]]['name']}: {name}"
        techniques[tid] = {
            "name": name,
            "tactics": sorted(tactics[t] for t in related(tid, "achieves") if t in tactics),
        }
    return {
        "name": "MITRE ATLAS",
        "version": str(data["collection"]["version"]),
        "url": "https://atlas.mitre.org/",
        "techniques": techniques,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--release", help="ATLAS content version, e.g. 2026.09")
    source.add_argument("--file", type=Path, help="Local ATLAS release YAML")
    args = parser.parse_args(argv)

    if args.file:
        text = args.file.read_text(encoding="utf-8")
    else:
        release = args.release or _fetch(BASE_URL + "ATLAS-latest.yaml").strip()
        if not release.startswith("ATLAS-"):
            release = f"ATLAS-{release}.yaml"
        text = _fetch(BASE_URL + release)
    catalog = build_catalog(yaml.safe_load(text))
    OUTPUT.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"wrote {OUTPUT.name}: ATLAS {catalog['version']}, {len(catalog['techniques'])} techniques"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
