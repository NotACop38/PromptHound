"""PromptHound local CD / release builder (PRD §12, §14; CHECKLIST Phase 6).

Two jobs, in order:

1. **Regenerate every generated artifact into ``out/``** — each rule's SPL, KQL
   and ``savedsearches.conf`` (via ``scripts.conversion``) and the OWASP × ATLAS
   coverage map + MITRE ATLAS Navigator layer (via ``prompthound.coverage``),
   plus the README coverage SVG. This is the *writer* the read-only ``convert``
   and ``coverage-build`` stages of ``scripts/ci.py`` check for drift, so run it
   after changing a rule, pipeline, or backend pin and commit the ``out/`` diff.

2. **Stamp the version and produce a releasable bundle** — a single, *byte
   reproducible* ``out/dist/prompthound-detections-<version>.tar.gz`` containing
   the generated Splunk/Sentinel queries and coverage map, a ``MANIFEST.json``
   (version, source commit, per-file sha256), a ``VERSION`` stamp and the
   licenses. This is the "raw queries" v1 packaging of decision D8 (PRD §9);
   deployable per-SIEM packaging remains a documented fast-follow.

    python scripts/release.py                 # regenerate out/ + build the bundle
    python scripts/release.py --no-bundle      # only regenerate out/ (no archive)
    python scripts/release.py --version 0.2.0   # override the stamped version

``out/dist/`` is git-ignored: the bundle is a build artifact, not committed
content. Everything else under ``out/`` is committed and snapshot-checked by CI.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re

# Used only for a best-effort, fixed-argv `git rev-parse` (no shell) for provenance.
import subprocess  # nosec B404
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DIST_DIR = REPO_ROOT / "out" / "dist"
# Generated out/ subtrees that go into the released bundle (the deployable content).
BUNDLE_SUBTREES = ("splunk", "kusto", "coverage")
# Licenses shipped inside the bundle so a downstream copy carries its terms (D7).
LICENSE_FILES = ("LICENSE", "LICENSE-RULES", "NOTICE")


def _resolve_version(override: str | None) -> str:
    from prompthound import __version__

    version = override if override is not None else __version__
    if len(version) > 128 or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version
    ):
        raise ValueError("version must be a safe semantic version such as 0.2.0 or 0.2.0-rc.1")
    return version


def _git_commit() -> str:
    """Best-effort full commit for provenance; ``"unknown"`` outside a checkout."""
    try:
        # Fixed argv, no shell; failure is non-fatal (e.g. tarball of a non-repo).
        result = subprocess.run(  # nosec B603 B607
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() or "unknown"
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def _git_status_entries() -> list[str]:
    """Return porcelain status entries for provenance-sensitive tree dirtiness.

    ``git status --porcelain`` is stable for scripts and respects ``.gitignore``
    by default, so ignored release byproducts such as ``out/dist/`` do not block
    a release. Untracked, non-ignored files are included because the conversion
    and coverage builders can consume a newly added rule before it has been
    committed, which would make the stamped ``source_commit`` misleading.
    """
    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise ValueError("cannot establish git release provenance") from exc
    return [line for line in result.stdout.splitlines() if line.strip()]


def _print_dirty_release_blocker(entries: list[str]) -> None:
    """Explain why a bundle release cannot be stamped from a dirty checkout."""
    print("  ERROR  refusing to build release bundle from a dirty git checkout")
    print("         commit or discard these changes, then rerun scripts/release.py:")
    for entry in entries[:20]:
        print(f"         {entry}")
    if len(entries) > 20:
        print(f"         ... and {len(entries) - 20} more")
    print("         (use --allow-dirty only for local, non-public test bundles)")


def regenerate_out() -> tuple[list[Path], int]:
    """Rewrite every generated artifact under ``out/``.

    Returns ``(written_paths, error_count)``. On any conversion or coverage tag
    error nothing partial is trusted: the error count is non-zero and the caller
    aborts before stamping a release.
    """
    from prompthound.coverage import generate_artifacts as coverage_artifacts
    from prompthound.coverage import generate_presentation_assets
    from prompthound.coverage import write_artifacts as write_coverage
    from scripts.conversion import OUT_DIR, build_artifacts, committed_outputs

    written: list[Path] = []

    # 1. SPL + KQL + savedsearches.conf (the per-rule conversion artifacts).
    artifacts, errors = build_artifacts()
    if errors:
        for error in errors:
            print(f"  ERROR  {error}")
        print("\nrelease aborted: fix the conversion errors above.")
        return written, len(errors)

    cov_artifacts, cov_errors = coverage_artifacts()
    assets, asset_errors = generate_presentation_assets()
    cov_errors += asset_errors
    if cov_errors:
        for error in cov_errors:
            print(f"  ERROR  {error}")
        return written, len(cov_errors)

    for path in sorted(committed_outputs() - set(artifacts)):
        path.unlink()
        print(f"  removed  out/{path.relative_to(OUT_DIR)}")
    for path, content in sorted(artifacts.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        written.append(path)
        print(f"  wrote    out/{path.relative_to(OUT_DIR)}")

    write_coverage(cov_artifacts)
    write_coverage(assets)
    for path in sorted(cov_artifacts):
        written.append(path)
        print(f"  wrote    out/{path.relative_to(OUT_DIR)}")
    for path in sorted(assets):
        written.append(path)
        print(f"  wrote    {path.relative_to(REPO_ROOT)}")

    return written, 0


def _collect_bundle_files() -> list[Path]:
    """Every generated file (sorted) that belongs in the released bundle."""
    from prompthound.coverage import generate_artifacts
    from scripts.conversion import OUT_DIR, build_artifacts

    queries, errors = build_artifacts()
    coverage, coverage_errors = generate_artifacts()
    if errors or coverage_errors:
        raise ValueError("cannot bundle invalid generated artifacts")
    expected = {**queries, **coverage}
    found = {p for sub in BUNDLE_SUBTREES for p in (OUT_DIR / sub).rglob("*") if p.is_file()}
    if found != set(expected):
        raise ValueError("bundle subtrees contain missing or unexpected files")
    for path, content in expected.items():
        if path.is_symlink() or path.read_text(encoding="utf-8") != content:
            raise ValueError("bundle contains a symlink or stale generated artifact")
    return sorted(expected)


def _bundle_readme(version: str, commit: str) -> str:
    return (
        f"PromptHound — detection content bundle v{version} (commit {commit})\n"
        "=" * 64 + "\n\n"
        "Experimental SIEM query templates auto-converted from the\n"
        "PromptHound Sigma rule pack (https://github.com/notacop38/prompthound).\n\n"
        "Read docs/deployment.md before ingestion or enabling alerts.\n\n"
        "Contents:\n"
        "  splunk/    Splunk SPL (.spl) + savedsearches.conf per rule\n"
        "  kusto/     Microsoft Sentinel KQL (.kql) per rule\n"
        "  coverage/  OWASP × ATLAS coverage map (md/html) + ATLAS Navigator layer\n"
        "  MANIFEST.json  version, source commit, and a sha256 for every file\n\n"
        "Licensing (PRD D7):\n"
        "  Code            Apache-2.0   (see LICENSE)\n"
        "  Detection rules DRL 1.1      (see LICENSE-RULES) — the generated\n"
        "                  queries here are derived from those rules; retain the\n"
        "                  author/attribution and a link to the rule set.\n"
    )


def build_bundle(version: str) -> Path | None:
    """Stamp the version and write a deterministic ``out/dist/`` release archive.

    The tarball is byte-reproducible for a given commit: members are sorted and
    their mtimes/uids zeroed and the gzip header timestamp is fixed, so re-running
    the release on an unchanged tree yields an identical archive.
    """
    from scripts.conversion import OUT_DIR

    version = _resolve_version(version)
    commit = _git_commit()
    try:
        dirty: bool | None = bool(_git_status_entries())
    except ValueError:
        dirty = None
    files = _collect_bundle_files()
    if not files:
        return None

    payload: dict[str, bytes] = {
        "VERSION": f"{version}\n".encode(),
        "README.txt": _bundle_readme(version, commit).encode("utf-8"),
    }
    for name in (*LICENSE_FILES, "docs/deployment.md", "prompthound/llm_audit_log.schema.json"):
        src = REPO_ROOT / name
        if not src.is_file() or src.is_symlink():
            raise ValueError(f"missing or unsafe release input: {name}")
        payload[name] = src.read_bytes()
    for path in files:
        payload[str(path.relative_to(OUT_DIR))] = path.read_bytes()
    manifest_files = [
        {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        for name, data in sorted(payload.items())
    ]
    manifest = {
        "name": "prompthound-detections",
        "version": version,
        "source_commit": commit,
        "source_dirty": dirty,
        "file_count": len(manifest_files),
        "files": manifest_files,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    payload["MANIFEST.json"] = manifest_bytes
    root = f"prompthound-detections-{version}"
    members = {f"{root}/{name}": data for name, data in payload.items()}

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    bundle_path = DIST_DIR / f"{root}.tar.gz"
    with (
        open(bundle_path, "wb") as raw,
        gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tar,
    ):  # type: ignore[arg-type]
        for arcname, data in sorted(members.items()):
            info = tarfile.TarInfo(name=arcname)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))

    # Drop the manifest beside the archive too, so it is inspectable unextracted.
    (DIST_DIR / "MANIFEST.json").write_bytes(manifest_bytes)

    print(f"  stamped  version {version} (commit {commit})")
    print(f"  wrote    out/dist/{bundle_path.name}  ({len(members)} entries)")
    print("  wrote    out/dist/MANIFEST.json")
    return bundle_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python scripts/release.py",
        description="Regenerate every out/ artifact, then stamp + bundle a release (PRD §12).",
    )
    parser.add_argument(
        "--version", help="Override the stamped version (default: package version)."
    )
    parser.add_argument(
        "--no-bundle",
        action="store_true",
        help="Only regenerate out/; skip the versioned bundle.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Build a bundle even when git has uncommitted/untracked non-ignored changes "
        "(for local testing only; public releases should stay clean).",
    )
    args = parser.parse_args(argv)

    try:
        version = _resolve_version(args.version)
    except ValueError as exc:
        parser.error(str(exc))
    written, errors = regenerate_out()
    if errors:
        return 1
    print(f"\nregenerated {len(written)} artifact(s) into out/")

    if args.no_bundle:
        return 0

    try:
        dirty_entries = _git_status_entries()
    except ValueError as exc:
        if not args.allow_dirty:
            print(f"  ERROR  {exc}")
            return 1
        dirty_entries = []
    if dirty_entries and not args.allow_dirty:
        _print_dirty_release_blocker(dirty_entries)
        return 1

    print(f"\nbuilding release bundle for v{version} ...")
    try:
        if build_bundle(version) is None:
            return 1
    except ValueError as exc:
        print(f"  ERROR  {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
