import json
import plistlib
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from conftest import AS_OF, Router
from kitsunox import __version__, cli
from kitsunox.cli import app
from kitsunox.collect import SANDBOX_RESULTS_ENV
from kitsunox.core.run import DataDir, IngestRequest, PopularityMode, record_ingest
from kitsunox.ecosystems.npm.registry import FEED_PAGE_LIMIT, REPLICATE_URL, NpmEcosystem
from kitsunox.notify import Message, Tick, TickRecord, append_tick, read_ticks
from kitsunox.util.disk import GIB

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def recorded_run(tmp_path: Path, router: Router) -> str:
    router.add_json(f"{REPLICATE_URL}/_changes?since=1&limit={FEED_PAGE_LIMIT}", {"results": []})
    request = IngestRequest(
        as_of=datetime(2026, 10, 27, tzinfo=UTC), since=1, until=2, popularity=PopularityMode.NONE
    )
    return record_ingest(DataDir(tmp_path), NpmEcosystem, request, client=router.client()).run_id


def test_replay_reports_identical(tmp_path: Path, router: Router) -> None:
    run_id = recorded_run(tmp_path, router)
    result = runner.invoke(app, ["ingest", "replay", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("identical: ")


def test_replay_detects_mismatch(tmp_path: Path, router: Router) -> None:
    run_id = recorded_run(tmp_path, router)
    manifest_path = DataDir(tmp_path).run_dir(run_id) / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["changes_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    result = runner.invoke(app, ["ingest", "replay", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "MISMATCH" in result.output


def test_record_without_watchlist_explains_and_exits(tmp_path: Path) -> None:
    # Fails before any network access: the watchlist is resolved first.
    result = runner.invoke(app, ["ingest", "record", "--data-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "kitsunox watchlist build" in result.output


def test_schedule_plist_runs_collect(tmp_path: Path) -> None:
    result = runner.invoke(app, ["schedule", "plist", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    agent = plistlib.loads(result.stdout_bytes)
    assert agent["ProgramArguments"][-3:] == ["collect", "--data-dir", str(tmp_path.resolve())]
    assert agent["StartInterval"] == 3600


def test_schedule_refuses_paths_that_break_unit_files(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["schedule", "systemd", "--data-dir", str(tmp_path / "a\nExecStartPre=/bin/true")]
    )
    assert result.exit_code == 2 and "unsupported path" in result.output


def test_schedule_systemd_runs_collect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "pro ject$x"  # only ExecStart= quotes and expands `$`
    project.mkdir()
    monkeypatch.chdir(project)
    data, units = tmp_path / "da ta%", tmp_path / "units"
    result = runner.invoke(
        app,
        [
            "schedule",
            "systemd",
            "--data-dir",
            str(data),
            "--unit-dir",
            str(units),
            "--keep-days",
            "2",
            "--keep-repo-days",
            "2",
        ],
    )
    assert result.exit_code == 0, result.output
    service = (units / "kitsunox-collect.service").read_text()
    exec_start = next(line for line in service.splitlines() if line.startswith("ExecStart="))
    # Quoted for systemd: the space would split the argument, `%` would be a specifier.
    escaped = str(data.resolve()).replace("%", "%%")
    assert exec_start.endswith(f'collect --data-dir "{escaped}" --keep-days 2 --keep-repo-days 2')
    assert "Type=oneshot" in service
    assert f"WorkingDirectory={project.resolve()}\n" in service  # literal, no quotes
    assert f"StandardOutput=append:{escaped}/logs/collect.log\n" in service
    if shutil.which("systemd-analyze"):
        verify = subprocess.run(  # noqa: S603 - fixed argv, our own generated files
            ["systemd-analyze", "--user", "verify", *sorted(map(str, units.iterdir()))],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
        assert verify.returncode == 0, verify.stderr
    timer = (units / "kitsunox-collect.timer").read_text()
    assert "OnUnitActiveSec=60min" in timer
    assert "WantedBy=timers.target" in timer


def test_prune_needs_labels(tmp_path: Path) -> None:
    result = runner.invoke(app, ["data", "prune", "--data-dir", str(tmp_path)])
    assert result.exit_code == 2


def test_collect_skips_when_locked(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    with data.lock():
        result = runner.invoke(app, ["collect", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "skipped" in result.stdout


def test_triage_writes_candidates(tmp_path: Path, router: Router) -> None:
    run_id = recorded_run(tmp_path, router)
    result = runner.invoke(app, ["triage", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("0 changes, 0 forwarded")
    assert (DataDir(tmp_path).run_dir(run_id) / "triage.jsonl").exists()


def test_static_needs_triage_first(tmp_path: Path, router: Router) -> None:
    run_id = recorded_run(tmp_path, router)
    result = runner.invoke(app, ["static", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 2
    runner.invoke(app, ["triage", run_id, "--data-dir", str(tmp_path)])
    result = runner.invoke(app, ["static", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("0 batches, 0 versions")


def test_ast_needs_static_first(tmp_path: Path, router: Router) -> None:
    run_id = recorded_run(tmp_path, router)
    result = runner.invoke(app, ["ast", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 2
    runner.invoke(app, ["triage", run_id, "--data-dir", str(tmp_path)])
    runner.invoke(app, ["static", run_id, "--data-dir", str(tmp_path)])
    assert runner.invoke(app, ["correlate", run_id, "--data-dir", str(tmp_path)]).exit_code == 2
    result = runner.invoke(app, ["ast", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("0 batches, 0 versions: 0 flagged")
    result = runner.invoke(app, ["correlate", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("0 versions: 0 to report")
    result = runner.invoke(app, ["report", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("0 versions, 0 to review")


def test_sandbox_needs_stage4_and_a_results_directory(
    tmp_path: Path, router: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(SANDBOX_RESULTS_ENV, raising=False)
    monkeypatch.chdir(tmp_path)  # no .env
    data = tmp_path / "data"
    run_id = recorded_run(data, router)
    args = ["sandbox", run_id, "--data-dir", str(data)]
    assert runner.invoke(app, args).exit_code == 2  # no correlate.jsonl
    (data / "runs" / run_id / "correlate.jsonl").write_text("")
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("0 of 0 reported versions have install hooks")
    assert "nothing exported" in result.stdout
    missing = runner.invoke(app, [*args, "--results", str(tmp_path / "absent")])
    assert missing.exit_code == 2 and "not a directory" in missing.output
    results = tmp_path / "results"
    results.mkdir()
    monkeypatch.setenv(SANDBOX_RESULTS_ENV, str(results))
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "export: 0 jobs in " in result.stdout
    replayed = runner.invoke(app, [*args, "--replay"])
    assert replayed.exit_code == 0 and "export:" not in replayed.stdout
    with DataDir(data).lock():
        assert runner.invoke(app, args).exit_code == 2


def test_collect_posts_a_daily_summary_and_a_crash_once_a_day(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted: list[tuple[str | None, str]] = []

    def post(url: str | None, message: Message, log: object) -> bool:
        posted.append((url, str(message)))
        return url is not None

    monkeypatch.setattr(cli, "post_update", post)
    monkeypatch.setenv("KITSUNOX_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/1/x")
    monkeypatch.setattr(cli, "collect", lambda data, **_: Tick(manifest=None))
    args = ["collect", "--data-dir", str(tmp_path)]
    state = tmp_path / "state"
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert posted == []  # no tick ran yesterday: nothing to summarise
    assert len(read_ticks(state)) == 1

    result = runner.invoke(app, [*args, "--notify-each-tick"])
    ((_, content),) = posted
    assert "nothing written" in content  # the old per-tick update, on request

    posted.clear()  # a tick logged yesterday: today's first tick posts that day's summary
    yesterday = datetime.now(UTC) - timedelta(days=1)
    record = TickRecord(started=yesterday, minutes=9, run_id="r", versions=5000, reports=("r",))
    append_tick(state, record)  # run r's report is gone (pruned): the summary goes without it
    runner.invoke(app, args)
    ((_, content),) = posted
    assert f"daily summary · {yesterday:%a %d %b %Y}" in content
    posted.clear()
    runner.invoke(app, args)
    assert posted == []  # posted once

    def crash(data: DataDir, **_: object) -> Tick:
        raise ValueError("boom")

    monkeypatch.setattr(cli, "collect", crash)
    result = runner.invoke(app, args)
    assert isinstance(result.exception, ValueError)  # still fails loudly for systemd
    ((_, content),) = posted
    assert "crashed" in content and "ValueError" in content and "boom" not in content
    assert read_ticks(state)[-1].crashed is not None
    posted.clear()
    runner.invoke(app, args)
    assert posted == []  # a crash loop posts once a day

    monkeypatch.setattr(cli, "collect", lambda data, **_: Tick(manifest=None))
    monkeypatch.delenv("KITSUNOX_DISCORD_WEBHOOK")  # an unreadable .env turns posts off
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_bytes(b"KITSUNOX_DISCORD_WEBHOOK=\xff\n")
    result = runner.invoke(app, [*args, "--notify-each-tick"])
    assert result.exit_code == 0, result.output
    assert "notify: off, .env unreadable (UnicodeDecodeError)" in result.output
    assert [url for url, _ in posted] == [None]

    posted.clear()
    with DataDir(tmp_path).lock():
        runner.invoke(app, [*args, "--notify-each-tick"])
    assert posted == []  # a skipped tick is silent


def test_run_does_the_whole_pipeline(
    tmp_path: Path, registry: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_client = httpx.Client
    monkeypatch.setattr(  # every client the stages make talks to the mock registry
        httpx,
        "Client",
        lambda *a, **kw: real_client(transport=httpx.MockTransport(registry.handler)),
    )
    registry.add_json(
        f"{REPLICATE_URL}/_changes?since=0&limit={FEED_PAGE_LIMIT}",
        {"results": [{"seq": 150, "id": "kx-fixture"}]},
    )
    registry.add_json(
        f"{REPLICATE_URL}/_changes?since=150&limit={FEED_PAGE_LIMIT}", {"results": []}
    )
    args = ["run", "--data-dir", str(tmp_path), "--since-seq", "0", "--until-seq", "200"]
    result = runner.invoke(
        app, [*args, "--as-of", f"{AS_OF:%Y-%m-%dT%H:%M:%S}", "--popularity", "none"]
    )
    assert result.exit_code == 0, result.output
    assert "changes:  4" in result.stdout
    assert "stages:   4 triaged" in result.stdout
    (run_dir,) = (tmp_path / "runs").iterdir()
    assert (run_dir / "report" / "report.json").exists()
    assert DataDir(tmp_path).read_checkpoint("npm") is None  # an explicit range moves nothing


def test_view_refuses_every_interface(tmp_path: Path) -> None:
    result = runner.invoke(app, ["view", "--data-dir", str(tmp_path), "--host", "0.0.0.0"])  # noqa: S104 - refused
    assert result.exit_code == 2
    assert "error:" in result.output


def test_view_serves_on_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    def fake_serve(data_dir: Path, host: str, port: int, **kwargs: object) -> None:
        calls.append((data_dir, host, port, kwargs["allow_remote"]))

    monkeypatch.setattr("kitsunox.web.serve", fake_serve)
    result = runner.invoke(app, ["view", "--data-dir", str(tmp_path), "--port", "0"])
    assert result.exit_code == 0, result.output
    assert calls == [(tmp_path, "127.0.0.1", 0, False)]


def test_verdict_records_from_the_shell_and_verdicts_lists_them(tmp_path: Path) -> None:
    from conftest import make_report, report_entry, run_manifest
    from kitsunox.core.models import Severity
    from kitsunox.reporting.report import write_report

    run_id = "20261029T210500Z-npm"
    run_dir = DataDir(tmp_path).run_dir(run_id)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(run_manifest(run_id).model_dump_json())
    write_report(
        run_dir, make_report(run_id, report_entry(1, "evil-pkg", "1.0.3", 14, Severity.HIGH))
    )
    args = ["--data-dir", str(tmp_path)]
    result = runner.invoke(
        app, ["verdict", run_id, "1", "malicious", "--note", "exfil", "--by", "claude", *args]
    )
    assert result.exit_code == 0, result.output
    assert result.stdout.strip() == "evil-pkg@1.0.3: malicious (by claude)"
    listed = runner.invoke(app, ["verdicts", *args])
    assert listed.stdout.splitlines()[0] == "1 malicious, 0 unwanted, 0 benign, 0 unverified"
    assert "evil-pkg@1.0.3 (claude," in listed.stdout and listed.stdout.rstrip().endswith(": exfil")
    probe = runner.invoke(app, ["verdict", run_id, "1", "malicious", "--probe", *args])
    assert probe.stdout.strip() == "evil-pkg@1.0.3: malicious [probe] (by owner)"
    listed = runner.invoke(app, ["verdicts", *args])
    assert listed.stdout.splitlines()[0] == (
        "1 malicious (probes: 1), 0 unwanted, 0 benign, 0 unverified"
    )
    assert "evil-pkg@1.0.3 [probe] (owner," in listed.stdout
    grey = runner.invoke(app, ["verdict", run_id, "1", "unverified", "--reason", "remote", *args])
    assert grey.stdout.strip() == "evil-pkg@1.0.3: unverified (remote payload) (by owner)"
    listed = runner.invoke(app, ["verdicts", "unverified", *args])
    assert listed.stdout.splitlines()[0] == (
        "0 malicious, 0 unwanted, 0 benign, 1 unverified (remote 1)"
    )
    assert "evil-pkg@1.0.3 [remote] (owner," in listed.stdout
    pua = runner.invoke(app, ["verdict", run_id, "1", "unwanted", "--probe", *args])
    assert pua.stdout.strip() == "evil-pkg@1.0.3: unwanted [probe] (by owner)"
    # --expect guards against ranks that moved when the report was rebuilt
    wrong = runner.invoke(app, ["verdict", run_id, "1", "benign", "--expect", "x@1", *args])
    assert wrong.exit_code == 2
    assert "entry 1 of run 20261029T210500Z-npm is evil-pkg@1.0.3; x@1 isn't in it" in (
        wrong.output
    )
    right = ["verdict", run_id, "1", "unwanted", "--expect", "evil-pkg@1.0.3", *args]
    assert runner.invoke(app, right).exit_code == 0
    for bad in (
        ["verdict", run_id, "1", "reopened", "--probe", *args],
        ["verdict", run_id, "1", "evil", *args],
        ["verdict", run_id, "9", "benign", *args],
        ["verdict", "20261029T000000Z-npm", "1", "benign", *args],
        ["verdict", run_id, "1", "benign", "--by", "Bad Name", *args],
        ["verdict", run_id, "1", "inconclusive", *args],  # no longer recorded
        ["verdict", run_id, "1", "unverified", *args],  # needs --reason
        ["verdict", run_id, "1", "unverified", "--reason", "lost", *args],
        ["verdict", run_id, "1", "malicious", "--reason", "gone", *args],
        ["verdict", run_id, "1", "reopened", "--reason", "gone", *args],
    ):
        assert runner.invoke(app, bad).exit_code == 2, bad


def test_takedowns_scans_new_runs_and_lists_what_it_keeps(tmp_path: Path) -> None:
    from conftest import run_manifest
    from kitsunox.core.models import Change, PackageVersionRef, PublishInfo, VersionSnapshot
    from kitsunox.stages.ingest import write_jsonl

    run_id = "20261029T210500Z-npm"
    run_dir = DataDir(tmp_path).run_dir(run_id)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(run_manifest(run_id).model_dump_json())
    holder = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="evil\x1b[2J", version="0.0.1-security"),
        publish=PublishInfo(published_at=AS_OF, publisher="npm"),
        manifest={},
    )
    write_jsonl(run_dir / "changes.jsonl", [Change(new=holder)])
    args = ["takedowns", "--data-dir", str(tmp_path)]
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    assert "'evil\\x1b[2J' 0.0.1-security" in first.stdout  # package text is repr'd, inert
    assert first.stdout.splitlines()[-1] == "1 new in 1 runs scanned; 1 takedowns kept"
    again = runner.invoke(app, args)
    assert again.stdout.splitlines()[-1] == "0 new in 0 runs scanned; 1 takedowns kept"


def test_collect_posts_a_low_disk_alert_at_once_and_then_every_six_hours(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted: list[str] = []

    def post(url: str | None, message: Message, log: object) -> bool:
        posted.append(str(message))
        return True

    monkeypatch.setattr(cli, "post_update", post)
    monkeypatch.setenv("KITSUNOX_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/1/x")
    low = Tick(manifest=None, disk_free=21 * GIB, disk_lowest=9 * GIB, disk_low=True)
    monkeypatch.setattr(cli, "collect", lambda data, **_: low)
    args = ["collect", "--data-dir", str(tmp_path)]
    assert runner.invoke(app, args).exit_code == 0
    (alert,) = posted
    assert "disk low" in alert and "9.0 GB free" in alert
    assert runner.invoke(app, args).exit_code == 0
    assert len(posted) == 1  # within six hours: not again
    (record, _) = read_ticks(tmp_path / "state")
    assert record.disk_low and record.disk_lowest_gb == 9.0
