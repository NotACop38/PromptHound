"""Locate the rule pack and scenarios shipped with PromptHound.

In an installed wheel they live under ``prompthound/_bundled/``; in a source
checkout (including an editable install) they are the repository's top-level
``rules/`` and ``scenarios/`` directories.
"""

from __future__ import annotations

from pathlib import Path

_PACKAGE = Path(__file__).resolve().parent


def content_root() -> Path:
    """Directory that contains the bundled ``rules/`` and ``scenarios/``."""
    bundled = _PACKAGE / "_bundled"
    if (bundled / "rules").is_dir():
        return bundled
    checkout = _PACKAGE.parent.parent
    if (checkout / "rules").is_dir() and (checkout / "pyproject.toml").is_file():
        return checkout
    raise FileNotFoundError(
        "PromptHound's rule pack was not found; reinstall the package or run from a checkout"
    )


def rules_dir() -> Path:
    return content_root() / "rules"


def scenarios_dir() -> Path:
    return content_root() / "scenarios"


__all__ = ["content_root", "rules_dir", "scenarios_dir"]
