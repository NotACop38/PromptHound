"""Supply-chain and secret checks for the CI gate.

Three independent checks, each failing on any finding:

* **pip-audit** audits both lockfiles against the Python advisory database.
  :data:`ACCEPTED_ADVISORIES` lists the advisories accepted with a written
  justification; keep it as short as the database allows.
* **bandit** scans first-party Python (``src/`` and ``scripts/``). A line that
  is reviewed and safe carries ``# nosec <ID>``, with the reason in a comment
  above it.
* **secret scan** searches tracked and unignored new files for credential
  shapes. A deliberate example carries ``pragma: allowlist secret``.

    python scripts/security.py
"""

from __future__ import annotations

import re
import shutil
import subprocess  # Fixed arguments, never a shell.  # nosec B404
import sys
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent

#: First-party Python that bandit scans.
BANDIT_TARGETS = ("src", "scripts")

#: Advisories accepted after review: no fixed release exists and PromptHound does
#: not reach the vulnerable code. Revisit each when a fix ships.
ACCEPTED_ADVISORIES: dict[str, str] = {
    "CVE-2025-69872": (
        "diskcache <=5.6.3 unpickles its cache files; no fixed release. It is a pySigma "
        "dependency used only by pySigma's MITRE data loaders, which PromptHound never "
        "calls (tests/test_security.py asserts no cache is opened). Exploitation also "
        "needs write access to the local cache directory."
    ),
}

#: Marker that exempts a line holding a deliberate example credential.
ALLOWLIST_MARKER = "pragma: allowlist secret"

#: AWS's documented example key, safe wherever it appears.
KNOWN_EXAMPLES = frozenset({"AKIAIOSFODNN7EXAMPLE"})

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # OpenAI (sk-, sk-proj-, sk-svcacct-) and Anthropic (sk-ant-) API keys.
    ("provider-api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("github-token", re.compile(r"\bgh[opsru]_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
)

# A private key *block*: header plus a body line. A bare header, as used in the
# payload-guard tests, is not a secret.
_PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----\s*\r?\n\S")


class SecretFinding(NamedTuple):
    path: str
    line: int
    kind: str


def scan_text(path: str, text: str) -> list[SecretFinding]:
    """Credential findings in one file's text. Findings never include the value."""
    findings: list[SecretFinding] = []
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        if ALLOWLIST_MARKER in line:
            continue
        for kind, pattern in _SECRET_PATTERNS:
            if any(m.group(0) not in KNOWN_EXAMPLES for m in pattern.finditer(line)):
                findings.append(SecretFinding(path, number, kind))
    for match in _PRIVATE_KEY_BLOCK.finditer(text):
        number = text.count("\n", 0, match.start()) + 1
        # The marker may sit on the header line or on the line just above it.
        if not any(ALLOWLIST_MARKER in line for line in lines[max(number - 2, 0) : number]):
            findings.append(SecretFinding(path, number, "private-key-block"))
    return findings


def _candidate_files(root: Path) -> list[Path]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("the secret scan needs git to list files")
    # git, with fixed arguments.
    listing = subprocess.run(  # noqa: S603  # nosec B603
        [git, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [root / name for name in listing.stdout.split("\0") if name]


def scan_repository(root: Path = REPO_ROOT) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for path in _candidate_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings.extend(scan_text(path.relative_to(root).as_posix(), text))
    return findings


def _run(tool: str, *args: str) -> bool:
    executable = shutil.which(tool)
    if executable is None:
        print(f"  {tool} is not installed (install requirements-dev.lock)")
        return False
    print(f"  $ {tool} {' '.join(args)}")
    # A pinned tool, with arguments chosen by this script.
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [executable, *args], cwd=REPO_ROOT, check=False
    )
    return completed.returncode == 0


def pip_audit() -> bool:
    args = ["--require-hashes", "-r", "requirements.lock", "-r", "requirements-dev.lock"]
    for advisory, reason in ACCEPTED_ADVISORIES.items():
        print(f"  accepted {advisory}: {reason}")
        args += ["--ignore-vuln", advisory]
    return _run("pip-audit", *args)


def bandit() -> bool:
    return _run("bandit", "-q", "-r", *BANDIT_TARGETS)


def secrets() -> bool:
    findings = scan_repository()
    for finding in findings:
        print(f"  {finding.path}:{finding.line}: possible {finding.kind}")
    if not findings:
        print("  no credential patterns found")
    return not findings


def main() -> int:
    ok = True
    for name, check in (("pip-audit", pip_audit), ("bandit", bandit), ("secret scan", secrets)):
        print(f"-- {name}")
        passed = check()
        print(f"   {'ok' if passed else 'FAILED'}")
        ok &= passed
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
