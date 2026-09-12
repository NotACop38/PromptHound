"""Security stage for the local CI runner (PRD §8 P1–P4, §17).

This makes PromptHound's defensive posture and supply-chain hygiene *enforceable
locally* rather than only in review. The stage bundles three independent,
fail-on-finding checks; the orchestrator :func:`security_stage` runs all three
and is green only if every one passes. ``scripts/ci.py`` wires it into the
ordered stage list and exposes it standalone::

    python scripts/ci.py --only security

The three checks:

* **pip-audit** — audits the pinned ``requirements.lock`` against the advisory
  database (PRD §17: pySigma/backend version drift). A small, *documented*
  ignore-list covers advisories with no fixed release that fall outside the
  threat model (see :data:`IGNORED_VULNS` and ``docs/THREAT-MODEL.md``).
* **bandit** — static security analysis over the first-party Python in
  ``prompthound/`` and ``scripts/``. Lines that are security-reviewed and safe
  carry an inline ``# nosec <ID>`` justification.
* **secrets scan** — a lean regex sweep of tracked and unignored new files for committed
  credentials (AWS keys, private-key blocks, provider/API tokens). Deliberate
  example values (the canonical AWS docs key, the P1-guard test fixtures) are
  exempted with an inline ``pragma: allowlist secret`` marker.

The module is import-clean (no work at import time) so the invariant/security
tests can exercise the secrets scanner and the ignore-list directly.
"""

from __future__ import annotations

import re
import shutil

# Used only to invoke pinned dev security tools (pip-audit/bandit/git) by fixed
# argv, never a shell string.
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent

#: First-party Python that bandit scans (PRD §14: the importable library plus the
#: local CI/CD scripts). Generated content, rules, and samples are not code.
BANDIT_TARGETS: tuple[str, ...] = ("prompthound", "scripts", "pipelines", "coverage", "demo")

#: Advisories accepted with justification because no fixed release exists *and*
#: the scenario is outside PromptHound's threat model (docs/THREAT-MODEL.md).
#: Each entry is a standing, reviewed decision — revisit when a fix ships. Keep
#: this list as short as the advisory database forces it to be.
IGNORED_VULNS: dict[str, str] = {
    # diskcache is a DIRECT dependency of the pinned pySigma runtime, even when
    # sigma-cli is not installed. No fixed release exists (through 5.6.3).
    # Exploitation needs an attacker who already has write access to the
    # local on-disk cache directory — a local-trust scenario PromptHound does not
    # defend (offline, single-user, no shared/untrusted cache). See THREAT-MODEL.
    "CVE-2025-69872": (
        "diskcache pickle RCE: no fix released; needs local cache write access (out of scope)."
    ),
}


# --- secrets scan -------------------------------------------------------------
#
# High-confidence credential shapes only; this is not a complete detector for
# arbitrary secrets. A line
# carrying the inline marker below is treated as a vetted example, not a leak.

#: Inline marker (detect-secrets convention) flagging a deliberate example value.
ALLOWLIST_MARKER = "pragma: allowlist secret"

#: Canonical placeholder credentials that are safe wherever they appear (AWS's
#: own documentation example key); never a real secret.
KNOWN_EXAMPLES: frozenset[str] = frozenset({"AKIAIOSFODNN7EXAMPLE"})

#: Single-line credential shapes, scanned line by line for precise excerpts.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    # Classic / OAuth / server / refresh tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    # and the github_pat_ prefix used by fine-grained PATs.
    ("github-token", re.compile(r"\bgh[opsru]_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
)

#: Credential shapes that span lines — a PEM private-key *block* (header plus a
#: base64 body line). Requiring the body keeps a bare ``-----BEGIN ... KEY-----``
#: header (as used in the P1-guard unit test) from tripping the scan.
_MULTILINE_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----\s*\r?\n\S")),
)


class SecretFinding(NamedTuple):
    """One committed-credential hit located in a tracked file."""

    path: str
    line: int
    kind: str
    excerpt: str


def _tracked_files(root: Path) -> list[Path]:
    """Tracked and unignored new files; venvs/build outputs follow .gitignore."""
    # Fixed argv, no shell; git is resolved from PATH (B607 accepted).
    result = subprocess.run(  # nosec B603 B607
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [root / name for name in result.stdout.split("\0") if name]


def scan_text(rel: str, text: str) -> list[SecretFinding]:
    """Scan one file's text for committed credentials (the per-file core).

    A line is skipped when it carries the :data:`ALLOWLIST_MARKER` or matches only
    a value in :data:`KNOWN_EXAMPLES` — that is how the deliberate exploit-pattern
    test fixtures stay green. Multiline patterns (a private-key block) are matched
    against the whole text; single-line patterns line by line for precise excerpts.
    """
    findings: list[SecretFinding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if ALLOWLIST_MARKER in line:
            continue
        # Never echo a discovered credential into local logs or public CI output.
        excerpt = "[redacted credential]"
        for kind, pattern in _SECRET_PATTERNS:
            # Walk *every* match so a known-example value earlier on the line can't
            # mask a real credential later on it; exempt only the example itself.
            if any(m.group(0).strip() not in KNOWN_EXAMPLES for m in pattern.finditer(line)):
                findings.append(SecretFinding(rel, lineno, kind, excerpt))
    for kind, pattern in _MULTILINE_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            lineno = text.count("\n", 0, match.start()) + 1
            # Honor the marker on the block's first line OR the line above it —
            # a pragma comment naturally sits just before a PEM header.
            marked_lines = lines[max(lineno - 2, 0) : lineno]
            if any(ALLOWLIST_MARKER in line for line in marked_lines):
                continue
            findings.append(SecretFinding(rel, lineno, kind, match.group(0).splitlines()[0]))
    return findings


def scan_for_secrets(root: Path | None = None) -> list[SecretFinding]:
    """Scan tracked and unignored new files for credential patterns."""
    root = root or REPO_ROOT
    findings: list[SecretFinding] = []
    for path in _tracked_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: nothing text-scannable here
        findings.extend(scan_text(str(path.relative_to(root)), text))
    return findings


# --- external tool runners ----------------------------------------------------


def _have(tool: str) -> bool:
    if shutil.which(tool) is None:
        print(f"  tool not found on PATH: {tool} (install the 'security' extra)")
        return False
    return True


def run_pip_audit() -> bool:
    """Audit requirements.lock; ignore only the documented, out-of-scope advisories."""
    if not _have("pip-audit"):
        return False
    cmd = [
        "pip-audit",
        "--requirement",
        str(REPO_ROOT / "requirements.lock"),
        "--requirement",
        str(REPO_ROOT / "requirements-dev.lock"),
    ]
    for cve, why in IGNORED_VULNS.items():
        cmd += ["--ignore-vuln", cve]
        print(f"  ignoring {cve}: {why}")
    print(f"  $ {' '.join(cmd)}")
    # Fixed argv (no shell); tool presence checked above.
    return subprocess.run(cmd, cwd=REPO_ROOT, check=False).returncode == 0  # nosec B603


def run_bandit() -> bool:
    """Static security scan of first-party Python; nosec lines carry justifications."""
    if not _have("bandit"):
        return False
    targets = [t for t in BANDIT_TARGETS if (REPO_ROOT / t).exists()]
    cmd = ["bandit", "-r", "-q", *targets]
    print(f"  $ {' '.join(cmd)}")
    # Fixed argv (no shell); tool presence checked above.
    return subprocess.run(cmd, cwd=REPO_ROOT, check=False).returncode == 0  # nosec B603


def run_secrets_scan() -> bool:
    """Fail on any committed credential in a tracked file (PRD §8 P4, §10.1 api_key.id)."""
    findings = scan_for_secrets(REPO_ROOT)
    if not findings:
        print("  no credential-pattern findings in tracked or unignored new files")
        return True
    for f in findings:
        print(f"  SECRET  {f.path}:{f.line}  [{f.kind}]  {f.excerpt}")
    return False


def security_stage() -> bool:
    """Run pip-audit + bandit + secrets scan; green only if all three pass."""
    checks = (
        ("pip-audit (runtime + development locks)", run_pip_audit),
        ("bandit (first-party Python)", run_bandit),
        ("secrets scan (tracked files)", run_secrets_scan),
    )
    ok = True
    for name, check in checks:
        print(f"  -- {name}")
        if not check():
            ok = False
            print(f"     [FAIL] {name}")
        else:
            print(f"     [ ok ] {name}")
    return ok


if __name__ == "__main__":
    sys.exit(0 if security_stage() else 1)
