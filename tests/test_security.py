"""Security-stage tests (PRD §8 P1–P4, §17).

Cover the units behind ``python scripts/ci.py --only security``:

  * the secrets scanner finds planted credentials, stays clean on this repo, and
    honours both the inline allowlist marker and the known-example exemption;
  * the supply-chain ignore-list is documented (no silent suppression);
  * the bandit scan targets resolve to real first-party source trees.

The pip-audit / bandit *executions* themselves are exercised by running the
stage; here we test the configuration and the first-party scanner logic so the
suite stays fast and offline. Run just these with ``pytest -k security -q``.
"""

from __future__ import annotations

from pathlib import Path

from scripts.security import (
    BANDIT_TARGETS,
    IGNORED_VULNS,
    KNOWN_EXAMPLES,
    scan_for_secrets,
    scan_text,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# --- secrets scanner ----------------------------------------------------------


def test_security_repo_has_no_committed_secrets() -> None:
    findings = scan_for_secrets(REPO_ROOT)
    assert findings == [], f"committed secrets found in tracked files: {findings}"


def test_security_secrets_scan_flags_aws_key() -> None:
    findings = scan_text("config.py", "AWS_KEY = 'AKIA1234567890ABCDEF'\n")
    assert [f.kind for f in findings] == ["aws-access-key"]
    assert findings[0].line == 1


def test_security_secrets_scan_flags_provider_and_token_shapes() -> None:
    samples = {
        "openai-api-key": "key = 'sk-abcdefghijklmnopqrstuvwxyz0123'",
        "github-token": "tok = 'ghp_" + "a" * 36 + "'",
        "slack-token": "s = 'xoxb-123456789012-abcdefghijkl'",
    }
    for expected_kind, line in samples.items():
        kinds = [f.kind for f in scan_text("f.py", line)]
        assert expected_kind in kinds, f"{expected_kind} not detected in {line!r}"


def test_security_secrets_scan_flags_private_key_block() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----\n"
    findings = scan_text("id_rsa", pem)
    assert [f.kind for f in findings] == ["private-key-block"]


def test_security_secrets_scan_ignores_bare_private_key_header() -> None:
    # A header with no key body (as in the P1-guard unit test) is not a secret.
    assert scan_text("t.py", "'-----BEGIN RSA PRIVATE KEY-----'\n") == []


def test_security_secrets_scan_honours_allowlist_marker() -> None:
    line = "AWS_KEY = 'AKIA1234567890ABCDEF'  # pragma: allowlist secret\n"
    assert scan_text("config.py", line) == []


def test_security_secrets_scan_allows_known_example() -> None:
    assert "AKIAIOSFODNN7EXAMPLE" in KNOWN_EXAMPLES
    assert scan_text("doc.md", "example key AKIAIOSFODNN7EXAMPLE in the docs\n") == []


# --- supply-chain ignore-list -------------------------------------------------


def test_security_ignored_vulns_are_documented() -> None:
    # Every accepted advisory must carry a justification — no silent suppression.
    for cve, why in IGNORED_VULNS.items():
        assert cve.startswith(("CVE-", "GHSA-", "PYSEC-")), f"unexpected advisory id: {cve}"
        assert isinstance(why, str) and len(why.strip()) >= 20, f"{cve} needs a real reason"


# --- bandit targets -----------------------------------------------------------


def test_security_bandit_targets_resolve() -> None:
    present = [t for t in BANDIT_TARGETS if (REPO_ROOT / t).is_dir()]
    assert present, "no bandit scan targets resolve to directories"
    assert "prompthound" in present and "scripts" in present
