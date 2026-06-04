"""PromptHound pySigma processing pipelines (PRD §12, decision D5).

These map the PromptHound audit-log schema (PRD §10, ``logsource: product:
llm_gateway``) onto each SIEM and drive the conversion backends:

* :mod:`pipelines.prompthound_splunk` — Splunk SPL (+ ``savedsearches.conf``).
* :mod:`pipelines.prompthound_kusto` — Sentinel/Kusto KQL.

This is a top-level content directory per the repository layout (PRD §14), but it
is also packaged in the wheel so ``prompthound.convert`` can import it whether
PromptHound is run from a checkout or installed as a dependency.
"""

from __future__ import annotations
