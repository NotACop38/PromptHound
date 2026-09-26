"""Framework catalogs that rule mappings are validated against.

Each catalog is pinned to a published version of its framework:

* OWASP Top 10 for LLM Applications 2025
* OWASP Top 10 for Agentic Applications 2026
* MITRE ATLAS — vendored from MITRE's release data (``data/atlas.json``,
  refreshed with ``scripts/update_atlas.py``)
* MITRE ATT&CK — only the techniques and tactics the rule pack uses

An identifier that is not in its catalog is a validation error, so a typo or a
renamed technique cannot reach the generated documentation.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from types import MappingProxyType


@dataclass(frozen=True)
class Taxonomy:
    """A versioned framework and the identifiers it defines."""

    key: str
    name: str
    version: str
    url: str
    entries: Mapping[str, str]

    def label(self, entry_id: str) -> str:
        """``"LLM01 Prompt Injection"``-style label for an identifier."""
        return f"{entry_id} {self.entries[entry_id]}"


OWASP_LLM = Taxonomy(
    key="owasp_llm",
    name="OWASP Top 10 for LLM Applications",
    version="2025",
    url="https://genai.owasp.org/llm-top-10/",
    entries=MappingProxyType(
        {
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
    ),
)

OWASP_AGENTIC = Taxonomy(
    key="owasp_agentic",
    name="OWASP Top 10 for Agentic Applications",
    version="2026",
    url="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    entries=MappingProxyType(
        {
            "ASI01": "Agent Goal Hijack",
            "ASI02": "Tool Misuse and Exploitation",
            "ASI03": "Identity and Privilege Abuse",
            "ASI04": "Agentic Supply Chain Vulnerabilities",
            "ASI05": "Unexpected Code Execution",
            "ASI06": "Memory and Context Poisoning",
            "ASI07": "Insecure Inter-Agent Communication",
            "ASI08": "Cascading Failures",
            "ASI09": "Human-Agent Trust Exploitation",
            "ASI10": "Rogue Agents",
        }
    ),
)

#: ATT&CK techniques and tactics referenced through standard Sigma ``attack.*`` tags.
ATTACK = Taxonomy(
    key="attack",
    name="MITRE ATT&CK Enterprise",
    version="19.2",
    url="https://attack.mitre.org/",
    entries=MappingProxyType(
        {
            "T1059": "Command and Scripting Interpreter",
            "execution": "Execution",
        }
    ),
)


@functools.cache
def atlas() -> Taxonomy:
    """MITRE ATLAS techniques from the vendored release catalog."""
    raw = json.loads(resources.files("prompthound").joinpath("data/atlas.json").read_text("utf-8"))
    names = {tid: str(entry["name"]) for tid, entry in raw["techniques"].items()}
    return Taxonomy(
        key="atlas",
        name=str(raw["name"]),
        version=str(raw["version"]),
        url=str(raw["url"]),
        entries=MappingProxyType(names),
    )


@functools.cache
def atlas_tactics() -> Mapping[str, tuple[str, ...]]:
    """ATLAS tactic names per technique identifier."""
    raw = json.loads(resources.files("prompthound").joinpath("data/atlas.json").read_text("utf-8"))
    return MappingProxyType({tid: tuple(e["tactics"]) for tid, e in raw["techniques"].items()})


def atlas_url(technique_id: str) -> str:
    return f"https://atlas.mitre.org/techniques/{technique_id}"


def attack_url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


__all__ = [
    "ATTACK",
    "OWASP_AGENTIC",
    "OWASP_LLM",
    "Taxonomy",
    "atlas",
    "atlas_tactics",
    "atlas_url",
    "attack_url",
]
