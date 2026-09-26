"""Verify the generated queries by running them in real query engines.

The scenario dataset (background traffic, every scenario case, and large
padded copies of the content cases) is normalized and loaded into

* Splunk Enterprise, with the generated Splunk app installed — every saved
  search is dispatched as shipped, through the app's macro and sourcetype; and
* the Kusto emulator, the Azure Data Explorer engine that also runs KQL for
  Microsoft Sentinel — every generated KQL query is executed.

The conformance cases in ``tests/conformance.yml`` (one detection feature
each, over events built to expose the edge cases) are loaded alongside and run
as ad-hoc searches and queries.

Each engine's results must equal the offline evaluator's exactly: the same
event IDs for single-event rules, and the same groups, windows and counts for
correlations. Any difference fails the run.

    # Start throwaway containers with Docker, verify, and remove them:
    python scripts/verify_siem.py --containers

    # Or point at instances you started yourself (test instances only; the
    # harness creates an index and a table and loads synthetic data):
    python scripts/verify_siem.py --kusto-url http://localhost:8080 \\
        --splunk-url http://localhost:8089 --splunk-password '<admin password>'

Splunk must already have ``siem/splunk/app/prompthound`` installed;
``--containers`` installs it.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import secrets
import shutil
import subprocess  # Fixed arguments, never a shell.  # nosec B404
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from prompthound import correlate, fields, generator, rules, scenarios, schema
from prompthound.convert import SPLUNK_APP, SPLUNK_SOURCETYPE, convert
from prompthound.normalize import normalize_event

ROOT = Path(__file__).resolve().parent.parent
KUSTO_IMAGE = "mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest"
SPLUNK_IMAGE = "splunk/splunk:latest"
TABLE = fields.DEFAULT_SENTINEL_TABLE
INDEX = "prompthound"
CONFORMANCE = ROOT / "tests" / "conformance.yml"
#: The conformance events precede the scenario dataset.
CONFORMANCE_START = generator.DATASET_START - dt.timedelta(days=1)

Row = tuple[Any, ...]


# --- conformance cases --------------------------------------------------------


@dataclass(frozen=True)
class ConformanceCase:
    name: str
    rule: rules.Rule
    matches: frozenset[str]


@dataclass(frozen=True)
class Conformance:
    events: tuple[dict[str, Any], ...]
    cases: tuple[ConformanceCase, ...]


def conformance(directory: Path, source: Path = CONFORMANCE) -> Conformance:
    """Load the conformance suite, writing each case as a rule file under ``directory``."""
    document = yaml.safe_load(source.read_text(encoding="utf-8"))
    events = []
    for index, (name, values) in enumerate(document["events"].items()):
        moment = CONFORMANCE_START + dt.timedelta(seconds=index)
        event = {
            "schema_version": schema.schema_version(),
            "timestamp": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event.id": f"conformance-{name}",
            "event.outcome": "success",
            "gen_ai.operation.name": "chat",
            **values,
        }
        problems = schema.validate_event(event)
        if problems:
            raise ValueError(f"conformance event {name!r}: {'; '.join(problems)}")
        events.append(event)
    cases = []
    for index, case in enumerate(document["cases"]):
        if not isinstance(case.get("name"), str):
            raise ValueError(f"conformance case {index}: 'name' must be a string")
        detection = dict(case["detection"])
        detection.setdefault("condition", " and ".join(detection))
        rule_document = {
            "title": f"Conformance: {case['name']}",
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"prompthound:conformance:{case['name']}")),
            "status": "test",
            "logsource": {"product": "llm_gateway"},
            "detection": detection,
            "level": "informational",
        }
        path = directory / f"case_{index:02d}.yml"
        path.write_text(yaml.safe_dump(rule_document, sort_keys=False), encoding="utf-8")
        matches = frozenset(f"conformance-{name}" for name in case["matches"])
        cases.append(ConformanceCase(case["name"], rules.load_rule(path, directory), matches))
    return Conformance(tuple(events), tuple(cases))


# --- expected results ---------------------------------------------------------


def expected_rows(rule: rules.Rule, events: Sequence[dict[str, Any]]) -> frozenset[Row]:
    """Offline results in the comparison form shared with both engines."""
    if rule.correlation is None:
        return frozenset((e["event.id"],) for e in events if rule.matches(e))
    windows = correlate.evaluate(rule.correlation, rule.predicate, events)
    return frozenset(
        (*(str(v) for v in w.group), int(w.start.timestamp()), w.count) for w in windows
    )


def _epoch(value: str) -> int:
    return int(dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


# --- HTTP ---------------------------------------------------------------------


def _request(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 120,
) -> bytes:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"unsupported URL scheme: {url}")
    request = urllib.request.Request(url, data=data, headers=headers or {})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
            return bytes(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:2000]
        raise RuntimeError(f"{exc.code} from {url.split('?')[0]}: {detail}") from None


# --- Kusto --------------------------------------------------------------------


class Kusto:
    """Minimal client for the Kusto REST API (v1) of the emulator."""

    def __init__(self, url: str, database: str = "NetDefaultDB") -> None:
        self.url = url.rstrip("/")
        self.database = database

    def _call(self, kind: str, csl: str) -> list[list[Any]]:
        body = json.dumps({"db": self.database, "csl": csl}).encode()
        raw = _request(
            f"{self.url}/v1/rest/{kind}", data=body, headers={"Content-Type": "application/json"}
        )
        tables = json.loads(raw)["Tables"]
        rows: list[list[Any]] = tables[0]["Rows"]
        return rows

    def ready(self) -> bool:
        try:
            self._call("mgmt", ".show version")
        except (OSError, RuntimeError):
            return False
        return True

    def version(self) -> str:
        body = json.dumps({"db": self.database, "csl": ".show version"}).encode()
        raw = _request(
            f"{self.url}/v1/rest/mgmt", data=body, headers={"Content-Type": "application/json"}
        )
        table = json.loads(raw)["Tables"][0]
        names = [c["ColumnName"] for c in table["Columns"]]
        return str(table["Rows"][0][names.index("BuildVersion")])

    def load(self, events: Sequence[dict[str, Any]]) -> None:
        columns = ", ".join(
            ["TimeGenerated:datetime"]
            + [f"{f.column}:{f.sentinel_type}" for f in fields.registry().values()]
        )
        self._call("mgmt", f".drop table {TABLE} ifexists")
        self._call("mgmt", f".create table {TABLE} ({columns})")
        for start in range(0, len(events), 50):
            lines = [
                json.dumps({"TimeGenerated": e["timestamp"], **e}, ensure_ascii=False)
                for e in events[start : start + 50]
            ]
            self._call(
                "mgmt",
                f'.ingest inline into table {TABLE} with (format="json") <|\n' + "\n".join(lines),
            )
        count = self._call("query", f"{TABLE} | count")[0][0]
        if count != len(events):
            raise RuntimeError(f"Kusto ingested {count} of {len(events)} events")

    def rows(self, rule: rules.Rule, kql: str) -> frozenset[Row]:
        if rule.correlation is None:
            return frozenset((r[0],) for r in self._call("query", kql + "\n| project event_id"))
        columns = [fields.get(n).column for n in rule.correlation.group_by]
        projection = ", ".join([*columns, "timestamp", "event_count"])
        result = self._call("query", f"{kql}\n| project {projection}")
        width = len(columns)
        return frozenset(
            (*(str(v) for v in r[:width]), _epoch(r[width]), int(r[width + 1])) for r in result
        )


# --- Splunk -------------------------------------------------------------------


class Splunk:
    """Minimal client for the Splunk REST API."""

    def __init__(self, url: str, username: str, password: str) -> None:
        self.url = url.rstrip("/")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}"}

    def _call(self, path: str, form: dict[str, Any] | None = None, **query: Any) -> Any:
        query.setdefault("output_mode", "json")
        url = f"{self.url}{path}?{urllib.parse.urlencode(query, doseq=True)}"
        data = urllib.parse.urlencode(form, doseq=True).encode() if form is not None else None
        return json.loads(_request(url, data=data, headers=self.headers))

    def ready(self) -> bool:
        try:
            self._call("/services/server/info")
        except (OSError, RuntimeError):
            return False
        return True

    def version(self) -> str:
        return str(self._call("/services/server/info")["entry"][0]["content"]["version"])

    def saved_searches(self) -> set[str]:
        entries = self._call(
            f"/servicesNS/-/{SPLUNK_APP}/saved/searches", count=0, search="PromptHound"
        )["entry"]
        return {e["name"] for e in entries if e["acl"]["app"] == SPLUNK_APP}

    def load(self, events: Sequence[dict[str, Any]]) -> None:
        indexes = self._call("/services/data/indexes", count=0)["entry"]
        if INDEX not in {e["name"] for e in indexes}:
            self._call("/services/data/indexes", {"name": INDEX})
        existing = self.search(f"search index={INDEX} | stats count")
        if existing and int(existing[0]["count"]):
            raise RuntimeError(f"index {INDEX!r} already holds events; use an empty test instance")
        query = urllib.parse.urlencode(
            {"index": INDEX, "sourcetype": SPLUNK_SOURCETYPE, "source": "prompthound-verify"}
        )
        for start in range(0, len(events), 100):
            body = "".join(
                fields.canonical_json(e) + "\n" for e in events[start : start + 100]
            ).encode("utf-8")
            _request(
                f"{self.url}/services/receivers/simple?{query}", data=body, headers=self.headers
            )
        _wait(
            lambda: (
                int(self.search(f"search index={INDEX} | stats count")[0]["count"]) == len(events)
            ),
            "Splunk to index every event",
        )

    def search(self, spl: str) -> list[dict[str, Any]]:
        job = self._call(
            "/services/search/jobs",
            {"search": spl, "earliest_time": "0", "latest_time": "now", "exec_mode": "blocking"},
        )
        return self._results(job["sid"])

    def dispatch(self, name: str, *field_names: str) -> list[dict[str, Any]]:
        path = f"/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{urllib.parse.quote(name, safe='')}"
        job = self._call(
            f"{path}/dispatch",
            {"dispatch.earliest_time": "0", "dispatch.latest_time": "now", "trigger_actions": "0"},
        )
        _wait(
            lambda: self._call(f"/services/search/jobs/{job['sid']}")["entry"][0]["content"][
                "isDone"
            ],
            f"saved search {name!r}",
        )
        return self._results(job["sid"], *field_names)

    def _results(self, sid: str, *field_names: str) -> list[dict[str, Any]]:
        query: dict[str, Any] = {"count": 0}
        if field_names:
            query["f"] = list(field_names)
        results: list[dict[str, Any]] = self._call(f"/services/search/jobs/{sid}/results", **query)[
            "results"
        ]
        return results

    def search_rows(self, spl: str) -> frozenset[Row]:
        """Event IDs matched by an ad-hoc single-event search."""
        return frozenset((r["event_id"],) for r in self.search(f"search {spl} | table event_id"))

    def rows(self, rule: rules.Rule) -> frozenset[Row]:
        name = f"PromptHound - {rule.title}"
        if rule.correlation is None:
            # Saved searches extract only the fields they reference, so read the
            # event ID from each matched event's raw JSON.
            matched = self.dispatch(name, "_raw")
            return frozenset((json.loads(r["_raw"])["event_id"],) for r in matched)
        results = self.dispatch(name)
        columns = [fields.get(n).splunk_name for n in rule.correlation.group_by]
        return frozenset(
            (*(str(r[c]) for c in columns), _epoch(r["_time"]), int(r["event_count"]))
            for r in results
        )


# --- orchestration ------------------------------------------------------------


def _wait(condition: Callable[[], bool], what: str, timeout: float = 600) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if condition():
                return
        except (OSError, RuntimeError, KeyError, IndexError):
            pass
        time.sleep(3)
    raise RuntimeError(f"timed out waiting for {what}")


@dataclass
class Containers:
    """Throwaway Kusto emulator and Splunk containers managed through the docker CLI."""

    password: str
    kusto: str = "prompthound-verify-kusto"
    splunk: str = "prompthound-verify-splunk"

    def _docker(self, *args: str) -> None:
        docker = shutil.which("docker")
        if docker is None:
            raise RuntimeError("--containers needs the docker CLI")
        subprocess.run([docker, *args], check=True, stdout=subprocess.DEVNULL)  # noqa: S603  # nosec B603

    def start(self) -> None:
        self.stop()
        self._docker(
            "run", "-d", "--name", self.kusto, "-e", "ACCEPT_EULA=Y",
            "-p", "127.0.0.1:8080:8080", KUSTO_IMAGE,
        )  # fmt: skip
        self._docker(
            "run", "-d", "--name", self.splunk, "-p", "127.0.0.1:8089:8089",
            "-e", "SPLUNK_START_ARGS=--accept-license",
            "-e", "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com",
            "-e", f"SPLUNK_PASSWORD={self.password}",
            "-e", "SPLUNKD_SSL_ENABLE=false",
            SPLUNK_IMAGE,
        )  # fmt: skip

    def install_splunk_content(self, splunk: Splunk) -> None:
        _wait(splunk.ready, "Splunk to start")
        app = ROOT / "siem" / "splunk" / "app" / SPLUNK_APP
        self._docker("cp", str(app), f"{self.splunk}:/opt/splunk/etc/apps/{SPLUNK_APP}")
        self._docker(
            "exec", "-u", "root", self.splunk,
            "chown", "-R", "splunk:splunk", f"/opt/splunk/etc/apps/{SPLUNK_APP}",
        )  # fmt: skip
        self._docker("exec", "-u", "splunk", self.splunk, "/opt/splunk/bin/splunk", "restart")
        _wait(splunk.ready, "Splunk to restart")

    def stop(self) -> None:
        docker = shutil.which("docker")
        if docker:
            subprocess.run(  # noqa: S603  # nosec B603
                # -v also removes the anonymous volumes the Splunk image declares.
                [docker, "rm", "-f", "-v", self.kusto, self.splunk],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


def _mismatch(expected: frozenset[Row], actual: frozenset[Row]) -> str:
    missing, extra = sorted(expected - actual), sorted(actual - expected)
    return f"missing {missing[:3]}{'...' if len(missing) > 3 else ''}, " + (
        f"unexpected {extra[:3]}{'...' if len(extra) > 3 else ''}"
    )


def _compare(label: str, expected: frozenset[Row], results: dict[str, frozenset[Row]]) -> bool:
    ok = True
    marks = []
    for engine, actual in results.items():
        same = actual == expected
        ok &= same
        marks.append("  ok  " if same else " FAIL ")
        if not same:
            print(f"  {engine} {label}: {_mismatch(expected, actual)}")
    print(f"{label:62} {len(expected):>7} {' '.join(marks)}")
    return ok


def verify(kusto: Kusto, splunk: Splunk, seed: int) -> bool:
    pack = rules.load_rules()
    dataset = generator.build_dataset(scenarios.load_scenarios(pack), seed=seed, padded_copies=True)
    with tempfile.TemporaryDirectory() as directory:
        suite = conformance(Path(directory))
        events = [*dataset.events, *suite.events]
        normalized = [normalize_event(e) for e in events]
        largest = max(len(json.dumps(e)) for e in events)
        print(f"dataset: {len(events)} events, largest {largest} bytes")

        missing = {f"PromptHound - {r.title}" for r in pack} - splunk.saved_searches()
        if missing:
            raise RuntimeError(f"Splunk app is missing saved searches: {sorted(missing)}")
        print(f"Splunk {splunk.version()}: loading...")
        splunk.load(normalized)
        print(f"Kusto {kusto.version()}: loading...")
        kusto.load(normalized)

        ok = True
        print(f"\n{'rule (saved search / KQL file)':62} {'offline':>7}  splunk  kusto")
        for rule in pack:
            results = {"splunk": splunk.rows(rule), "kusto": kusto.rows(rule, convert(rule).kql)}
            ok &= _compare(rule.relpath, expected_rows(rule, events), results)

        print(f"\n{'conformance case (ad-hoc query)':62} {'offline':>7}  splunk  kusto")
        for case in suite.cases:
            queries = convert(case.rule)
            results = {
                "splunk": splunk.search_rows(queries.spl),
                "kusto": kusto.rows(case.rule, queries.kql),
            }
            ok &= _compare(case.name, expected_rows(case.rule, events), results)
    print("\nall engines agree with the offline evaluator" if ok else "\nMISMATCH")
    return ok


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--containers", action="store_true", help="manage throwaway containers")
    parser.add_argument("--keep", action="store_true", help="leave containers running")
    parser.add_argument("--kusto-url", default="http://localhost:8080")
    parser.add_argument("--splunk-url", default="http://localhost:8089")
    parser.add_argument("--splunk-user", default="admin")
    parser.add_argument("--splunk-password")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(list(argv) if argv is not None else None)

    password = args.splunk_password or ("Ph-" + secrets.token_urlsafe(12))
    if not args.containers and not args.splunk_password:
        parser.error("--splunk-password is required without --containers")
    kusto = Kusto(args.kusto_url)
    splunk = Splunk(args.splunk_url, args.splunk_user, password)
    containers = Containers(password) if args.containers else None
    try:
        if containers:
            containers.start()
            containers.install_splunk_content(splunk)
        _wait(kusto.ready, "the Kusto emulator")
        return 0 if verify(kusto, splunk, args.seed) else 1
    finally:
        if containers and not args.keep:
            containers.stop()


if __name__ == "__main__":
    sys.exit(main())
