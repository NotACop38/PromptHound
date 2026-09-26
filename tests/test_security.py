from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import security
from tests.helpers import ROOT

# Credential-shaped values are assembled at run time; see test_payload_guard.py.
KEYS = {
    "aws-access-key": "AKIA" + "B" * 16,
    "provider-api-key": "sk-ant-" + "x1Y2" * 6,
    "github-token": "ghp_" + "a" * 36,
    "github-fine-grained-pat": "github_pat_" + "A" * 22,
    "slack-token": "xoxb-" + "1234567890-abc",
    "google-api-key": "AIza" + "C" * 35,
}
HEADER = "-----BEGIN " + "PRIVATE KEY-----"


@pytest.mark.parametrize(("kind", "value"), KEYS.items(), ids=list(KEYS))
def test_credential_shapes_are_found_without_their_values(kind: str, value: str) -> None:
    findings = security.scan_text("config.env", f"token = {value}\n")
    assert findings == [security.SecretFinding("config.env", 1, kind)]
    assert value not in repr(findings)


def test_allowlisted_lines_and_documented_examples_are_ignored() -> None:
    text = (
        f"key = {KEYS['aws-access-key']}  # {security.ALLOWLIST_MARKER}\n"
        "example = AKIAIOSFODNN7EXAMPLE\n"
    )
    assert security.scan_text("docs.md", text) == []


def test_private_key_blocks_need_a_body() -> None:
    block = f"{HEADER}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
    assert security.scan_text("key.pem", "intro\n" + block) == [
        security.SecretFinding("key.pem", 2, "private-key-block")
    ]
    assert security.scan_text("guard.py", f'"{HEADER}"\n') == []
    marked = f"# {security.ALLOWLIST_MARKER}\n{block}"
    assert security.scan_text("fixture.pem", marked) == []


def test_the_repository_has_no_credentials() -> None:
    assert security.scan_repository(ROOT) == []


def test_the_scan_needs_git(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="needs git"):
        security.scan_repository(ROOT)


def test_missing_tools_fail_their_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert security.bandit() is False
    assert "bandit is not installed" in capsys.readouterr().out


def test_pip_audit_ignores_only_accepted_advisories(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def run(tool: str, *args: str) -> bool:
        calls.append((tool, *args))
        return True

    monkeypatch.setattr(security, "_run", run)
    assert security.pip_audit()
    [call] = calls
    assert call[:6] == (
        "pip-audit", "--require-hashes", "-r", "requirements.lock", "-r", "requirements-dev.lock"
    )  # fmt: skip
    ignored = [call[i + 1] for i, arg in enumerate(call) if arg == "--ignore-vuln"]
    assert ignored == list(security.ACCEPTED_ADVISORIES)


def test_every_accepted_advisory_is_justified() -> None:
    for advisory, reason in security.ACCEPTED_ADVISORIES.items():
        assert advisory.startswith(("CVE-", "GHSA-", "PYSEC-"))
        assert len(reason) > 80


@pytest.mark.parametrize("failing", ["pip_audit", "bandit", "secrets"])
def test_any_failing_check_fails_the_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], failing: str
) -> None:
    for name in ("pip_audit", "bandit", "secrets"):
        monkeypatch.setattr(security, name, lambda name=name: name != failing)
    assert security.main() == 1
    assert "FAILED" in capsys.readouterr().out


def test_secrets_check_reports_findings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    finding = security.SecretFinding("a.txt", 3, "slack-token")
    monkeypatch.setattr(security, "scan_repository", lambda: [finding])
    assert security.secrets() is False
    assert "a.txt:3: possible slack-token" in capsys.readouterr().out
    monkeypatch.setattr(security, "scan_repository", list)
    assert security.secrets() is True


def test_pysigma_mitre_caches_are_never_opened(tmp_path: Path) -> None:
    """The justification for accepting CVE-2025-69872 (diskcache) depends on this."""
    code = """
import json, sys
from prompthound import convert, evaluate, generator, rules, scenarios
pack = rules.load_rules()
assert rules.check_policy(pack) == []
for rule in pack:
    convert.convert(rule)
dataset = generator.build_dataset(scenarios.load_scenarios(pack))
evaluate.evaluate(pack, dataset.events)
caches = {}
for name in ("sigma.data.mitre_attack", "sigma.data.mitre_d3fend"):
    module = sys.modules.get(name)
    caches[name] = None if module is None else repr(module._cache)
print(json.dumps(caches))
"""
    env = {**os.environ, "HOME": str(tmp_path), "XDG_CACHE_HOME": str(tmp_path / "cache")}
    process = subprocess.run(  # noqa: S603 - runs this test's own code
        [sys.executable, "-c", code], env=env, cwd=ROOT, capture_output=True, text=True, check=True
    )
    caches = json.loads(process.stdout)
    assert set(caches.values()) <= {None, "None"}
    assert not (tmp_path / ".cache" / "pysigma").exists()
