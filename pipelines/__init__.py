"""PromptHound pySigma processing pipelines and conversion helpers (PRD §12, D5).

Sigma is authored once and converted to Splunk SPL and Microsoft Sentinel KQL
via pySigma. This package holds the schema->backend processing pipelines and
thin ``convert_*`` helpers used by the conversion-snapshot tests, the local CI
runner, and ``scripts/release.py``.
"""

from __future__ import annotations
