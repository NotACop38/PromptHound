"""PromptHound coverage-map generator (PRD §7 item 5; CHECKLIST Phase 4).

Auto-generated, never-stale coverage built **from rule metadata only** (PRD §5,
§17). It reads the OWASP LLM Top 10, MITRE ATLAS, ATT&CK cross-ref and Tier tags
off every Sigma rule under ``rules/`` and renders three artifacts into
``out/coverage/``:

  * ``atlas_navigator_layer.json`` -- a MITRE ATLAS Navigator layer scoring each
    referenced technique by how many rules cover it (drop into the ATLAS
    Navigator at https://mitre-atlas.github.io/atlas-navigator/);
  * ``coverage.html`` -- a self-contained (inline-CSS, no external assets) page
    with the OWASP LLM Top 10 grid, the ATLAS technique breakdown and the Tier
    breakdown;
  * ``coverage.md`` -- the same OWASP grid + ATLAS + Tier tables as Markdown.

Because the map is derived purely from rule tags it cannot drift out of sync: a
rule with a missing required tag (OWASP + Tier + at least one technique mapping)
or an *unknown* tag the catalog below does not recognise fails the build, so a
typo or an un-catalogued technique is caught here and in CI rather than silently
shipping a stale map.

    python coverage/build_coverage.py    # writes out/coverage/, exits non-zero on error

Reads YAML directly (stdlib + PyYAML); it deliberately does **not** depend on
pySigma, so coverage builds from metadata alone with the lean dependency set.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
OUT_DIR = REPO_ROOT / "out" / "coverage"

# --- Tag catalogs (the canonical vocabulary; unknown tags fail the build) ------
#
# These are the single source of truth for what a PromptHound rule may claim.
# A referenced id that is absent here is an *unknown* tag -> build error, which
# is what forces an explicit, reviewed catalog update when a new technique is
# mapped (PRD §17 "Coverage map goes stale" mitigation).

# OWASP Top 10 for LLM Applications (2025) -- the user-facing taxonomy (PRD D2).
OWASP_LLM: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# MITRE ATLAS techniques (and sub-techniques) the rule pack maps to (PRD §11).
ATLAS_TECHNIQUES: dict[str, str] = {
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0029": "Denial of ML Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0085.001": "AI Agent Tools",
}

# MITRE ATLAS tactics (ATLAS v5.1.0 added AML.TA0015, PRD D2).
ATLAS_TACTICS: dict[str, str] = {
    "AML.TA0015": "Command and Control",
}

# MITRE ATT&CK enterprise techniques -- cross-reference only where genuine (PRD D2).
ATTACK_TECHNIQUES: dict[str, str] = {
    "T1059": "Command and Scripting Interpreter",
}

# PromptHound detection tiers (PRD D4).
TIERS: dict[str, str] = {
    "T1": "Operational / metadata (always-on)",
    "T2": "Content inspection (opt-in)",
}


# --- Tag parsing ---------------------------------------------------------------


@dataclass(frozen=True)
class ParsedTag:
    kind: str  # owasp | atlas_technique | atlas_tactic | attack | tier | unknown
    cid: str  # canonical id (e.g. LLM07, AML.T0056, T1059, T2) or the raw tag


def parse_tag(tag: str) -> ParsedTag:
    """Classify one rule tag into a (kind, canonical-id) pair.

    Returns ``kind == "unknown"`` for any tag whose family or shape the coverage
    vocabulary does not recognise -- the caller turns that into a build error.
    """
    if tag.startswith("owasp-llm."):
        m = re.fullmatch(r"llm(\d{2})", tag[len("owasp-llm.") :])
        return ParsedTag("owasp", f"LLM{m.group(1)}") if m else ParsedTag("unknown", tag)
    if tag.startswith("attack.atlas.aml."):
        suffix = tag[len("attack.atlas.aml.") :]
        if re.fullmatch(r"ta\d{4}", suffix):
            return ParsedTag("atlas_tactic", f"AML.{suffix.upper()}")
        if re.fullmatch(r"t\d{4}(?:\.\d{3})?", suffix):
            return ParsedTag("atlas_technique", f"AML.{suffix.upper()}")
        return ParsedTag("unknown", tag)
    if tag.startswith("attack."):
        m = re.fullmatch(r"t(\d{4})(?:\.(\d{3}))?", tag[len("attack.") :])
        if not m:
            return ParsedTag("unknown", tag)
        cid = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
        return ParsedTag("attack", cid)
    if tag.startswith("prompthound.tier."):
        m = re.fullmatch(r"t(\d)", tag[len("prompthound.tier.") :])
        return ParsedTag("tier", f"T{m.group(1)}") if m else ParsedTag("unknown", tag)
    return ParsedTag("unknown", tag)


# --- Rule loading --------------------------------------------------------------


@dataclass
class RuleMeta:
    path: Path  # relative to RULES_DIR
    category: str
    title: str
    owasp: list[str] = field(default_factory=list)
    atlas_techniques: list[str] = field(default_factory=list)
    atlas_tactics: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    tiers: list[str] = field(default_factory=list)


def _validate_id(parsed: ParsedTag, catalog: dict[str, str], rel: str, errors: list[str]) -> bool:
    if parsed.cid not in catalog:
        errors.append(f"{rel}: unknown {parsed.kind} id not in catalog: {parsed.cid}")
        return False
    return True


def load_rule_meta(path: Path, errors: list[str]) -> RuleMeta | None:
    """Parse one rule's metadata and validate its tags against the catalogs."""
    rel = str(path.relative_to(RULES_DIR))
    try:
        # A rule file may hold several YAML documents: a Sigma *correlation* rule
        # is a base detection doc plus the correlation doc that carries the alert
        # metadata (tags/title). Read them all and merge the tags.
        docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d is not None]
    except yaml.YAMLError as exc:
        errors.append(f"{rel}: YAML parse error: {exc}")
        return None
    if not docs or not all(isinstance(d, dict) for d in docs):
        errors.append(f"{rel}: not a Sigma rule document")
        return None

    # Tags live on the alerting doc; title preferred from the doc carrying tags.
    tags: list[Any] = []
    title = ""
    for doc in docs:
        doc_tags = doc.get("tags")
        if isinstance(doc_tags, list):
            tags.extend(doc_tags)
            title = str(doc.get("title") or title)
        elif doc_tags is not None:
            errors.append(f"{rel}: tags is not a list")
            return None
        if not title:
            title = str(doc.get("title") or "")

    meta = RuleMeta(
        path=path.relative_to(RULES_DIR),
        category=path.relative_to(RULES_DIR).parts[0],
        title=title or rel,
    )

    for raw in tags:
        parsed = parse_tag(str(raw))
        if parsed.kind == "owasp" and _validate_id(parsed, OWASP_LLM, rel, errors):
            meta.owasp.append(parsed.cid)
        elif parsed.kind == "atlas_technique" and _validate_id(
            parsed, ATLAS_TECHNIQUES, rel, errors
        ):
            meta.atlas_techniques.append(parsed.cid)
        elif parsed.kind == "atlas_tactic" and _validate_id(parsed, ATLAS_TACTICS, rel, errors):
            meta.atlas_tactics.append(parsed.cid)
        elif parsed.kind == "attack" and _validate_id(parsed, ATTACK_TECHNIQUES, rel, errors):
            meta.attack.append(parsed.cid)
        elif parsed.kind == "tier" and _validate_id(parsed, TIERS, rel, errors):
            meta.tiers.append(parsed.cid)
        elif parsed.kind == "unknown":
            errors.append(f"{rel}: unknown tag (not a recognised family): {raw}")

    # Required metadata gate (PRD §15): OWASP + Tier + >=1 technique mapping.
    if not meta.owasp:
        errors.append(f"{rel}: missing required OWASP LLM tag")
    if not meta.tiers:
        errors.append(f"{rel}: missing required prompthound.tier tag")
    if not (meta.atlas_techniques or meta.atlas_tactics or meta.attack):
        errors.append(f"{rel}: missing required technique mapping (ATLAS or ATT&CK)")
    return meta


def load_rules(errors: list[str]) -> list[RuleMeta]:
    rule_files = sorted(RULES_DIR.glob("**/*.yml")) + sorted(RULES_DIR.glob("**/*.yaml"))
    if not rule_files:
        errors.append("no rule files found under rules/")
        return []
    metas: list[RuleMeta] = []
    for path in rule_files:
        meta = load_rule_meta(path, errors)
        if meta is not None:
            metas.append(meta)
    return metas


# --- Coverage model ------------------------------------------------------------


def build_model(rules: list[RuleMeta]) -> dict[str, Any]:
    """Aggregate per-rule metadata into the OWASP / ATLAS / Tier coverage model."""

    def rules_for(predicate: Any) -> list[str]:
        return sorted(str(r.path) for r in rules if predicate(r))

    owasp = [
        {
            "id": oid,
            "name": name,
            "rules": rules_for(lambda r, oid=oid: oid in r.owasp),
        }
        for oid, name in OWASP_LLM.items()
    ]
    for entry in owasp:
        entry["count"] = len(entry["rules"])
        entry["covered"] = entry["count"] > 0

    atlas: list[dict[str, Any]] = []
    for cid, name in {**ATLAS_TECHNIQUES, **ATLAS_TACTICS}.items():
        is_tactic = cid in ATLAS_TACTICS
        covering = rules_for(
            lambda r, cid=cid, t=is_tactic: cid in (r.atlas_tactics if t else r.atlas_techniques)
        )
        if covering:
            atlas.append(
                {
                    "id": cid,
                    "name": name,
                    "kind": "tactic" if is_tactic else "technique",
                    "rules": covering,
                    "count": len(covering),
                }
            )
    atlas.sort(key=lambda e: e["id"])

    attack = [
        {"id": cid, "name": name, "rules": rules_for(lambda r, cid=cid: cid in r.attack)}
        for cid, name in ATTACK_TECHNIQUES.items()
    ]
    attack = [{**e, "count": len(e["rules"])} for e in attack if e["rules"]]

    tiers = [
        {
            "id": tid,
            "name": name,
            "rules": rules_for(lambda r, tid=tid: tid in r.tiers),
        }
        for tid, name in TIERS.items()
    ]
    for entry in tiers:
        entry["count"] = len(entry["rules"])

    covered_owasp = sum(1 for e in owasp if e["covered"])
    return {
        "rule_count": len(rules),
        "owasp": owasp,
        "owasp_covered": covered_owasp,
        "owasp_total": len(OWASP_LLM),
        "atlas": atlas,
        "attack": attack,
        "tiers": tiers,
    }


# --- Renderers -----------------------------------------------------------------


def atlas_navigator_layer(model: dict[str, Any]) -> str:
    """A MITRE ATLAS Navigator layer scoring each referenced technique by rule count."""
    techniques = [
        {
            "techniqueID": entry["id"],
            "score": entry["count"],
            "enabled": True,
            "comment": "; ".join(entry["rules"]),
        }
        for entry in model["atlas"]
        if entry["kind"] == "technique"
    ]
    max_score = max((t["score"] for t in techniques), default=1)
    layer = {
        "name": "PromptHound — ATLAS coverage",
        "versions": {"attack": "5.1.0", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "mitre-atlas",
        "description": (
            "Auto-generated from PromptHound rule metadata (coverage/build_coverage.py). "
            f"Score = number of rules mapping to each ATLAS technique; {model['rule_count']} "
            "rules total. Do not hand-edit."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0b5cad"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [],
        "showTacticRowBackground": False,
        "hideDisabled": False,
    }
    return json.dumps(layer, indent=2, sort_keys=False) + "\n"


def coverage_markdown(model: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# PromptHound coverage map")
    lines.append("")
    lines.append(
        "> Auto-generated from rule metadata by `coverage/build_coverage.py`. Do not hand-edit."
    )
    lines.append("")
    lines.append(
        f"**{model['rule_count']} rules** · OWASP LLM Top 10 covered: "
        f"**{model['owasp_covered']}/{model['owasp_total']}**"
    )
    lines.append("")

    lines.append("## OWASP LLM Top 10 (2025)")
    lines.append("")
    lines.append("| OWASP | Category | Covered | Rules | Rule files |")
    lines.append("|---|---|:---:|:---:|---|")
    for e in model["owasp"]:
        mark = "✅" if e["covered"] else "—"
        files = "<br>".join(f"`{r}`" for r in e["rules"]) if e["rules"] else ""
        lines.append(f"| {e['id']} | {e['name']} | {mark} | {e['count']} | {files} |")
    lines.append("")

    lines.append("## MITRE ATLAS")
    lines.append("")
    lines.append("| ATLAS ID | Name | Kind | Rules | Rule files |")
    lines.append("|---|---|---|:---:|---|")
    for e in model["atlas"]:
        files = "<br>".join(f"`{r}`" for r in e["rules"])
        lines.append(f"| {e['id']} | {e['name']} | {e['kind']} | {e['count']} | {files} |")
    lines.append("")

    if model["attack"]:
        lines.append("## MITRE ATT&CK (cross-reference)")
        lines.append("")
        lines.append("| ATT&CK ID | Name | Rules | Rule files |")
        lines.append("|---|---|:---:|---|")
        for e in model["attack"]:
            files = "<br>".join(f"`{r}`" for r in e["rules"])
            lines.append(f"| {e['id']} | {e['name']} | {e['count']} | {files} |")
        lines.append("")

    lines.append("## Tier breakdown")
    lines.append("")
    lines.append("| Tier | Description | Rules |")
    lines.append("|---|---|:---:|")
    for e in model["tiers"]:
        lines.append(f"| {e['id']} | {e['name']} | {e['count']} |")
    lines.append("")
    return "\n".join(lines)


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PromptHound coverage map</title>
<style>
  :root { --ok: #0b5cad; --ok-bg: #e6f0fb; --miss: #e7e7e7; --ink: #1c2330; --muted: #5b6472; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial,
         sans-serif; margin: 0; color: var(--ink); background: #fafbfc; }
  main { max-width: 980px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
  h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
  h2 { margin: 2.25rem 0 .75rem; font-size: 1.15rem; border-bottom: 1px solid #e2e6ea;
       padding-bottom: .35rem; }
  .note { color: var(--muted); font-size: .85rem; margin: 0 0 1rem; }
  .summary { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0 .5rem; }
  .stat { background: #fff; border: 1px solid #e2e6ea; border-radius: 10px; padding: .75rem 1rem;
          min-width: 130px; }
  .stat .n { font-size: 1.5rem; font-weight: 700; }
  .stat .l { color: var(--muted); font-size: .78rem; text-transform: uppercase;
             letter-spacing: .04em; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: .6rem; }
  .cell { border: 1px solid #e2e6ea; border-radius: 10px; padding: .7rem .8rem; background: var(--miss);
          opacity: .65; }
  .cell.covered { background: var(--ok-bg); border-color: #bcd8f5; opacity: 1; }
  .cell .id { font-weight: 700; font-size: .82rem; }
  .cell .nm { font-size: .82rem; color: var(--ink); }
  .cell .ct { font-size: .72rem; color: var(--muted); margin-top: .3rem; }
  .cell.covered .ct { color: var(--ok); font-weight: 600; }
  table { border-collapse: collapse; width: 100%; font-size: .85rem; background: #fff; }
  th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #eceff2;
           vertical-align: top; }
  th { background: #f3f5f7; font-size: .74rem; text-transform: uppercase; letter-spacing: .03em;
       color: var(--muted); }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .78rem; }
  .bar { height: 10px; border-radius: 5px; background: var(--ok); display: inline-block;
         vertical-align: middle; }
  .pill { display: inline-block; background: var(--ok-bg); color: var(--ok); border-radius: 999px;
          padding: .05rem .5rem; font-size: .72rem; font-weight: 600; }
</style>
</head>
<body>
<main>
  <h1>PromptHound coverage map</h1>
  <p class="note">Auto-generated from rule metadata by
    <code>coverage/build_coverage.py</code> — never hand-edited.</p>

  <div class="summary">
    <div class="stat"><div class="n">{{ m.rule_count }}</div><div class="l">Rules</div></div>
    <div class="stat"><div class="n">{{ m.owasp_covered }}/{{ m.owasp_total }}</div>
      <div class="l">OWASP covered</div></div>
    <div class="stat"><div class="n">{{ m.atlas|length }}</div>
      <div class="l">ATLAS mapped</div></div>
  </div>

  <h2>OWASP LLM Top 10 (2025)</h2>
  <div class="grid">
  {% for e in m.owasp %}
    <div class="cell {{ 'covered' if e.covered else '' }}">
      <div class="id">{{ e.id }}</div>
      <div class="nm">{{ e.name }}</div>
      <div class="ct">{% if e.covered %}{{ e.count }} rule{{ 's' if e.count != 1 }}{% else %}no coverage{% endif %}</div>
    </div>
  {% endfor %}
  </div>

  <h2>MITRE ATLAS</h2>
  <table>
    <tr><th>ID</th><th>Name</th><th>Kind</th><th>Rules</th><th>Rule files</th></tr>
  {% for e in m.atlas %}
    <tr>
      <td><code>{{ e.id }}</code></td><td>{{ e.name }}</td><td>{{ e.kind }}</td>
      <td><span class="pill">{{ e.count }}</span></td>
      <td>{% for r in e.rules %}<code>{{ r }}</code><br>{% endfor %}</td>
    </tr>
  {% endfor %}
  </table>

  {% if m.attack %}
  <h2>MITRE ATT&amp;CK (cross-reference)</h2>
  <table>
    <tr><th>ID</th><th>Name</th><th>Rules</th><th>Rule files</th></tr>
  {% for e in m.attack %}
    <tr>
      <td><code>{{ e.id }}</code></td><td>{{ e.name }}</td>
      <td><span class="pill">{{ e.count }}</span></td>
      <td>{% for r in e.rules %}<code>{{ r }}</code><br>{% endfor %}</td>
    </tr>
  {% endfor %}
  </table>
  {% endif %}

  <h2>Tier breakdown</h2>
  <table>
    <tr><th>Tier</th><th>Description</th><th>Rules</th><th></th></tr>
  {% for e in m.tiers %}
    <tr>
      <td><code>{{ e.id }}</code></td><td>{{ e.name }}</td><td>{{ e.count }}</td>
      <td><span class="bar" style="width: {{ e.count * 28 }}px"></span></td>
    </tr>
  {% endfor %}
  </table>
</main>
</body>
</html>
"""


def coverage_html(model: dict[str, Any]) -> str:
    env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    return env.from_string(_HTML_TEMPLATE).render(m=model).rstrip("\n") + "\n"


# --- Public API ----------------------------------------------------------------


def generate_artifacts() -> tuple[dict[Path, str], list[str]]:
    """Build the coverage artifacts in memory. Returns ``(artifacts, errors)``.

    A non-empty ``errors`` list (missing/unknown tags, no rules, parse failures)
    means the caller must NOT write -- the map would be stale or wrong.
    """
    errors: list[str] = []
    rules = load_rules(errors)
    if errors:
        return {}, errors
    model = build_model(rules)
    artifacts = {
        OUT_DIR / "atlas_navigator_layer.json": atlas_navigator_layer(model),
        OUT_DIR / "coverage.html": coverage_html(model),
        OUT_DIR / "coverage.md": coverage_markdown(model),
    }
    return artifacts, errors


def write_artifacts(artifacts: dict[Path, str]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for path, content in sorted(artifacts.items()):
        path.write_text(content, encoding="utf-8")


def main() -> int:
    artifacts, errors = generate_artifacts()
    if errors:
        for error in errors:
            print(f"  ERROR  {error}")
        print(f"\ncoverage build failed: {len(errors)} problem(s) -- fix the tags above.")
        return 1
    write_artifacts(artifacts)
    for path in sorted(artifacts):
        print(f"  wrote  out/coverage/{path.name}")
    print(f"\nbuilt {len(artifacts)} coverage artifact(s) into {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
