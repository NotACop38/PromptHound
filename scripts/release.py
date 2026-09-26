"""Build the versioned release artifacts.

    python scripts/release.py                # from a clean checkout with current artifacts
    python scripts/release.py --allow-dirty  # local test build; the manifest records it

Writes to ``dist/``:

* ``prompthound-detections-<version>.tar.gz`` — rules, generated SIEM content,
  schema, documentation and licenses, with ``MANIFEST.json`` listing the SHA-256
  of every file and the source commit;
* ``prompthound-<version>-splunk-app.tgz`` — the Splunk app, installable with
  "Install app from file".

Both archives are byte-reproducible: the same commit always yields the same
bytes.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess  # Fixed arguments, never a shell.  # nosec B404
import sys
import tarfile
from collections.abc import Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST = REPO_ROOT / "dist"

#: Repository paths included in the content bundle, and their names inside it.
BUNDLE: Mapping[str, str] = {
    "rules": "rules",
    "siem": "siem",
    "src/prompthound/data/audit_log.schema.json": "schema/audit_log.schema.json",
    "docs/rules.md": "docs/rules.md",
    "docs/schema.md": "docs/schema.md",
    "docs/deployment.md": "docs/deployment.md",
    "docs/verification.md": "docs/verification.md",
    "docs/atlas-navigator-layer.json": "docs/atlas-navigator-layer.json",
    "CHANGELOG.md": "CHANGELOG.md",
    "LICENSE": "LICENSE",
    "LICENSE-RULES": "LICENSE-RULES",
    "NOTICE": "NOTICE",
}
SPLUNK_APP = "siem/splunk/app/prompthound"

_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?")


def package_version() -> str:
    text = (REPO_ROOT / "src" / "prompthound" / "__init__.py").read_text("utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', text, re.MULTILINE)
    if match is None or not _VERSION.fullmatch(match.group(1)):
        raise ValueError("cannot read a semantic version from src/prompthound/__init__.py")
    return match.group(1)


def _git(*args: str) -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to record release provenance")
    # git, with arguments chosen by this script.
    result = subprocess.run(  # noqa: S603  # nosec B603
        [git, *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True
    )
    return result.stdout


def collect(inputs: Mapping[str, str] = BUNDLE) -> dict[str, bytes]:
    """Bundle members (name inside the archive -> content), in sorted order."""
    members: dict[str, bytes] = {}
    for source, target in inputs.items():
        path = REPO_ROOT / source
        if path.is_symlink():
            raise ValueError(f"refusing to bundle a symbolic link: {source}")
        if path.is_file():
            members[target] = path.read_bytes()
        elif path.is_dir():
            for item in sorted(path.rglob("*")):
                if item.is_symlink():
                    raise ValueError(f"refusing to bundle a symbolic link: {item}")
                if item.is_file():
                    relative = item.relative_to(path).as_posix()
                    members[f"{target}/{relative}" if target else relative] = item.read_bytes()
        else:
            raise ValueError(f"release input is missing: {source}")
    return dict(sorted(members.items()))


def manifest(version: str, commit: str, dirty: bool, members: Mapping[str, bytes]) -> bytes:
    document = {
        "name": "prompthound-detections",
        "version": version,
        "source_commit": commit,
        "source_dirty": dirty,
        "files": [
            {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in members.items()
        ],
    }
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def write_archive(path: Path, root: str, members: Mapping[str, bytes]) -> None:
    """A gzip-compressed tar whose bytes depend only on ``members``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with (
        path.open("wb") as raw,
        gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))


def build(version: str, commit: str, dirty: bool) -> list[Path]:
    members = collect()
    readme = (
        f"PromptHound detection content {version}\n\n"
        "rules/     Sigma rules (DRL 1.1)\n"
        "siem/      Generated Splunk SPL, Splunk app and Microsoft Sentinel KQL (DRL 1.1)\n"
        "schema/    Audit-event JSON Schema (Apache-2.0)\n"
        "docs/      Rule catalog, schema reference, deployment and verification guides\n"
        "           (Apache-2.0)\n\n"
        "Read docs/deployment.md before enabling any query as an alert.\n"
        "MANIFEST.json lists the SHA-256 of every file and the source commit.\n"
    )
    members = {**members, "README.txt": readme.encode(), "VERSION": f"{version}\n".encode()}
    members["MANIFEST.json"] = manifest(version, commit, dirty, members)

    bundle = DIST / f"prompthound-detections-{version}.tar.gz"
    write_archive(bundle, f"prompthound-detections-{version}", members)
    app = DIST / f"prompthound-{version}-splunk-app.tgz"
    write_archive(app, "prompthound", collect({SPLUNK_APP: ""}))
    return [bundle, app]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--allow-dirty", action="store_true", help="build from uncommitted changes (local only)"
    )
    args = parser.parse_args(argv)

    version = package_version()
    status = _git("status", "--porcelain", "--untracked-files=all").splitlines()
    if status and not args.allow_dirty:
        print("refusing to release from a checkout with uncommitted changes:")
        print("\n".join(f"  {line}" for line in status[:20]))
        return 1
    # This repository's generator, with fixed arguments.
    check = subprocess.run(  # nosec B603
        [sys.executable, "scripts/generate.py", "--check"], cwd=REPO_ROOT, check=False
    )
    if check.returncode:
        return 1
    commit = _git("rev-parse", "HEAD").strip()
    for path in build(version, commit, dirty=bool(status)):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        shown = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
        print(f"wrote {shown}  sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
