"""PromptHound: Sigma detection rules for LLM applications and AI agents.

The package bundles the rule pack and its scenarios and provides the tooling
around them: an offline evaluator whose results match the generated Splunk and
Microsoft Sentinel queries, a synthetic telemetry generator, an audit-event
normalizer and a telemetry readiness report. See ``prompthound --help``.
"""

from __future__ import annotations

__version__ = "0.3.0"

__all__ = ["__version__"]
