from __future__ import annotations

import io
import json
import os
import runpy
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml

from prompthound import __version__, cli, generator
from tests.helpers import ROOT

CaptureFixture = pytest.CaptureFixture[str]


def run(capsys: CaptureFixture, *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture(scope="module")
def events_file(tmp_path_factory: pytest.TempPathFactory, dataset: generator.Dataset) -> Path:
    path = tmp_path_factory.mktemp("events") / "events.jsonl"
    generator.write_jsonl(path, dataset.events)
    return path


def test_version(capsys: CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"prompthound {__version__}\n"


def test_python_dash_m(capsys: CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["prompthound", "rules", "--format", "json"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("prompthound", run_name="__main__")
    assert exit_info.value.code == 0
    assert len(json.loads(capsys.readouterr().out)) == 16


def test_a_command_is_required(capsys: CaptureFixture) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main([])
    assert exit_info.value.code == 2
    assert "required" in capsys.readouterr().err


def test_rules(capsys: CaptureFixture, pack: list[Any]) -> None:
    code, out, _ = run(capsys, "rules")
    assert code == 0
    lines = out.splitlines()
    assert lines[0].split() == ["Level", "Logic", "Telemetry", "Title", "File"]
    assert len(lines) == len(pack) + 2
    code, out, _ = run(capsys, "rules", "--format", "json")
    records = json.loads(out)
    assert [r["id"] for r in records] == [r.id for r in pack]
    assert set(records[0]) == {
        "id", "rule", "title", "level", "logic", "telemetry", "fields",
        "owasp_llm", "owasp_agentic", "atlas", "attack",
    }  # fmt: skip
    assert {r["telemetry"] for r in records} == {"metadata", "content detector", "raw content"}


def test_test_passes_on_the_bundled_pack(capsys: CaptureFixture) -> None:
    code, out, _ = run(capsys, "test")
    assert code == 0
    assert out.strip().endswith("scenario cases passed across 16 rules; 0 policy problems")
    assert "FAIL" not in out


@pytest.fixture
def pack_copy(tmp_path: Path) -> tuple[Path, Path]:
    rules_dir, scenarios_dir = tmp_path / "rules", tmp_path / "scenarios"
    shutil.copytree(ROOT / "rules", rules_dir)
    shutil.copytree(ROOT / "scenarios", scenarios_dir)
    return rules_dir, scenarios_dir


def test_test_reports_failing_cases(capsys: CaptureFixture, pack_copy: tuple[Path, Path]) -> None:
    rules_dir, scenarios_dir = pack_copy
    path = rules_dir / "dos_cost_abuse" / "request_rate_burst_per_principal.yml"
    path.write_text(path.read_text().replace("gte: 20", "gte: 19"))
    code, out, _ = run(capsys, "test", "--rules", str(rules_dir), "--scenarios", str(scenarios_dir))
    assert code == 1
    assert "FAIL dos_cost_abuse/request_rate_burst_per_principal.yml: " in out


def test_test_reports_policy_problems(capsys: CaptureFixture, pack_copy: tuple[Path, Path]) -> None:
    rules_dir, scenarios_dir = pack_copy
    path = rules_dir / "insecure_output" / "unsanitized_output_to_sink.yml"
    document = yaml.safe_load(path.read_text())
    del document["falsepositives"]
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    code, out, _ = run(capsys, "test", "--rules", str(rules_dir), "--scenarios", str(scenarios_dir))
    assert code == 1
    assert "policy: insecure_output/unsanitized_output_to_sink.yml:" in out
    assert "1 policy problems" in out


def test_generate(capsys: CaptureFixture, tmp_path: Path, dataset: generator.Dataset) -> None:
    output, labels = tmp_path / "events.jsonl", tmp_path / "labels.json"
    code, out, _ = run(capsys, "generate", "-o", str(output), "--labels", str(labels))
    assert code == 0
    assert out.splitlines()[0] == f"wrote {len(dataset.events)} events to {output}"
    lines = output.read_text().splitlines()
    assert [json.loads(line) for line in lines] == list(dataset.events)
    recorded = json.loads(labels.read_text())
    assert set(recorded) == set(dataset.labels)
    assert all(None not in v.values() and False not in v.values() for v in recorded.values())

    code, _, _ = run(capsys, "generate", "-o", str(output), "--background", "0", "--large-copies")
    assert code == 0


def _mixed_events(path: Path, dataset: generator.Dataset) -> Path:
    good = [json.dumps(e) for e in dataset.events[:2]]
    bad_schema = json.dumps({**dataset.events[0], "event.outcome": "maybe"})
    path.write_text("\n".join([good[0], "{broken", "", bad_schema, good[1]]) + "\n")
    return path


def test_validate(capsys: CaptureFixture, tmp_path: Path, dataset: generator.Dataset) -> None:
    path = _mixed_events(tmp_path / "mixed.jsonl", dataset)
    code, out, err = run(capsys, "validate", str(path))
    assert code == 1
    assert out == "2 of 4 events are valid\n"
    assert err.splitlines()[0].startswith("line 2: not valid JSON")
    assert err.splitlines()[1].startswith("line 4: ")
    code, _, err = run(capsys, "validate", str(path), "--max-errors", "1")
    assert err.splitlines()[-1] == "... and 1 more invalid events"


def test_validate_reads_standard_input(
    capsys: CaptureFixture, monkeypatch: pytest.MonkeyPatch, dataset: generator.Dataset
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(dataset.events[0]) + "\n"))
    assert run(capsys, "validate", "-") == (0, "1 of 1 events are valid\n", "")


def test_normalize(capsys: CaptureFixture, tmp_path: Path, events_file: Path) -> None:
    output = tmp_path / "siem.jsonl"
    code, out, _ = run(capsys, "normalize", str(events_file), "-o", str(output))
    assert code == 0
    assert out.startswith("wrote ")
    assert "user_tenant_id" in output.read_text().splitlines()[0]
    code, _, err = run(capsys, "normalize", str(tmp_path / "missing.jsonl"), "-o", str(output))
    assert code == 2
    assert err.startswith("error: ")


def test_evaluate(capsys: CaptureFixture, events_file: Path) -> None:
    code, out, _ = run(capsys, "evaluate", str(events_file))
    assert code == 0
    first = out.splitlines()[0]
    assert first.endswith("valid events")
    assert " alerts from 16 rules over " in first
    assert "count=" in out
    assert "event " in out
    code, out, _ = run(capsys, "evaluate", str(events_file), "--format", "json")
    alerts = json.loads(out)
    assert alerts
    assert {"rule_id", "time", "event_ids"} <= set(alerts[0])
    assert run(capsys, "evaluate", str(events_file), "--fail-on-alert")[0] == 1


def test_evaluate_skips_invalid_events(
    capsys: CaptureFixture, tmp_path: Path, dataset: generator.Dataset
) -> None:
    path = _mixed_events(tmp_path / "mixed.jsonl", dataset)
    code, out, err = run(capsys, "evaluate", str(path), "--fail-on-alert")
    assert code == 0
    assert out.startswith("0 alerts from 16 rules over 2 valid events (2 invalid events skipped)")
    assert "line 2" in err


def test_readiness(capsys: CaptureFixture, events_file: Path) -> None:
    code, out, _ = run(capsys, "readiness", str(events_file))
    assert code == 0
    assert "16 ready, 0 partial, 0 blocked of 16 rules." in out
    code, out, _ = run(capsys, "readiness", str(events_file), "--format", "json")
    report = json.loads(out)
    assert {r["status"] for r in report["rules"]} == {"ready"}


def test_readiness_orders_blocked_rules_first(capsys: CaptureFixture, tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({**_minimal(), "gen_ai.request.max_tokens": 10}) + "\n")
    code, out, _ = run(capsys, "readiness", str(path))
    assert code == 0
    rules_table = out.split("\n\n")[2].splitlines()
    assert rules_table[2].startswith("blocked")
    assert rules_table[-1].startswith("ready")


def _minimal() -> dict[str, Any]:
    return {
        "schema_version": "0.2",
        "timestamp": "2026-06-01T12:00:00Z",
        "event.id": "e-1",
        "event.outcome": "success",
        "gen_ai.operation.name": "chat",
    }


def test_convert_prints_or_writes_queries(capsys: CaptureFixture, tmp_path: Path) -> None:
    code, out, _ = run(capsys, "convert", "--target", "splunk")
    assert code == 0
    assert out.count("(splunk)\n`prompthound_audit` ") == 16
    assert "(sentinel)" not in out
    code, out, _ = run(capsys, "convert", "-o", str(tmp_path), "--sentinel-table", "Llm_CL")
    assert out == f"wrote 32 queries under {tmp_path}\n"
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*.*"))
    assert len(written) == 32
    kql = (tmp_path / "sentinel" / "agent_tool_abuse" / "denied_tool_retry_loop.kql").read_text()
    assert kql.startswith("Llm_CL\n")


def test_convert_rejects_invalid_names(capsys: CaptureFixture) -> None:
    code, _, err = run(capsys, "convert", "--splunk-macro", "not valid")
    assert code == 2
    assert "not a valid Splunk macro name" in err


def test_demo(capsys: CaptureFixture, tmp_path: Path) -> None:
    code, out, _ = run(capsys, "demo", "-o", str(tmp_path))
    assert code == 0
    assert "scenario cases behave as expected; background traffic raised 0 alerts." in out
    events = (tmp_path / "events.jsonl").read_text().splitlines()
    siem = (tmp_path / "siem.jsonl").read_text().splitlines()
    assert len(events) == len(siem) > 0
    assert "event.id" in json.loads(events[0])
    assert "event_id" in json.loads(siem[0])


def test_a_failing_demo_exits_with_status_1(
    capsys: CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from prompthound import demo

    result = demo.run()
    monkeypatch.setattr(demo, "run", lambda seed: replace(result, background_alerts=1))
    assert run(capsys, "demo")[0] == 1


def test_rule_errors_exit_with_status_2(capsys: CaptureFixture, tmp_path: Path) -> None:
    code, _, err = run(capsys, "rules", "--rules", str(tmp_path))
    assert code == 2
    assert err.startswith("error: no rule files found")
    code, _, err = run(capsys, "evaluate", str(tmp_path / "missing.jsonl"))
    assert code == 2


def test_a_closed_pipe_exits_quietly(
    capfd: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def closed(_: object) -> int:
        raise BrokenPipeError

    monkeypatch.setattr(cli, "cmd_rules", closed)
    redirected: list[int] = []
    monkeypatch.setattr(os, "dup2", lambda source, target: redirected.append(target))
    assert cli.main(["rules"]) == 1
    assert redirected == [sys.stdout.fileno()]


@pytest.mark.parametrize("unbuffered", [False, True], ids=["buffered", "unbuffered"])
def test_a_closed_pipe_in_a_real_process(unbuffered: bool) -> None:
    # Buffered output fits in the pipe buffer and fails only when flushed.
    env = {name: value for name, value in os.environ.items() if name != "PYTHONUNBUFFERED"}
    if unbuffered:
        env["PYTHONUNBUFFERED"] = "1"
    reader, writer = os.pipe()
    os.close(reader)
    process = subprocess.run(
        [sys.executable, "-m", "prompthound", "rules"],
        stdout=writer,
        stderr=subprocess.PIPE,
        check=False,
        cwd=ROOT,
        env=env,
    )
    os.close(writer)
    assert process.returncode == 1
    assert process.stderr == b""
