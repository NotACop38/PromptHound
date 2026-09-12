"""PromptHound — defensive SIEM detection content for attacks against LLM apps and agents.

This package holds the small amount of shared, importable library code. The
operational components live in sibling top-level directories per the repository
layout in ``docs/PRD.md`` §14: ``rules/``, ``pipelines/``, ``generator/``,
``coverage/``, ``demo/`` and ``scripts/``. The canonical schema is package data.

``docs/PRD.md`` and ``docs/CHECKLIST.md`` are the source of truth for this project.
"""

from __future__ import annotations

__all__ = ["SCHEMA_VERSION", "__version__"]

#: PromptHound package version.
__version__ = "0.2.0"

#: Version of the LLM Gateway / Agent audit-log schema (see PRD §10).
SCHEMA_VERSION = "0.1"
