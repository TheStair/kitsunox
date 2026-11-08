"""`kitsunox collect`: one unattended tick against a mocked registry."""

import json
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import NoReturn

import pytest

import kitsunox.collect
from conftest import AS_OF, Disk, Router, save_watchlist
from kitsunox.collect import (
    REPORT_ONLY,
    RESCORE_INFO,
    RESCORE_ORIGINALS,
    _resume_from,
    collect,
    rescore_run,
    run_stages,
)
from kitsunox.core.models import Candidate, Finding, PackageBatch, Severity, StageDecision
from kitsunox.core.run import MAX_RUN_FEED_SPAN, Checkpoint, DataDir
from kitsunox.ecosystems.npm.registry import FEED_PAGE_LIMIT, REPLICATE_URL
from kitsunox.evaluation.labels import LabelSet, label_store
from kitsunox.stages.static import STAGE_ID as STATIC_STAGE
from kitsunox.stages.static import WILL_RETRY
from kitsunox.util import disk
from kitsunox.util.disk import GIB


def save_labels(data: DataDir) -> None:
    labels = LabelSet(
        ecosystem="npm",
        source="test",
        fetched_at=AS_OF - timedelta(hours=1),
        source_sha256="0" * 64,
        labels={},
    )
    label_store(data).save("npm", labels.id, labels)


def feed_from(registry: Router, since: int) -> None:
    registry.add_json(
        f"{REPLICATE_URL}/_changes?since={since}&limit={FEED_PAGE_LIMIT}",
        {"results": [{"seq": 150, "id": "kx-fixture"}]} if since == 0 else {"results": []},
    )
    if since == 0:
        feed_from(registry, 150)


def test_ticks_chain_and_prune_once_a_day(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    log: list[str] = []

    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    first = tick.manifest
    assert first is not None
    assert first.chained_from is None and first.change_count == 4
    assert [r.run_id for r in tick.reports] == [first.run_id] and tick.failed == ()
    assert not any(line.startswith(("watchlist", "labels")) for line in log)  # both fresh
    assert any(line.startswith("prune: 0 runs pruned") for line in log)
    # Stages 1 and 2 ran on the new run; the mock serves no tarballs, so Stage 2 has no files.
    stages = next(line for line in log if line.startswith("stages: "))
    assert stages.startswith("stages: 4 triaged"), stages
    assert (data.run_dir(first.run_id) / "static.jsonl").exists()
    assert (data.run_dir(first.run_id) / "ast.jsonl").exists()
    assert (tmp_path / "queue" / "queue.json").exists()
    assert any(line.startswith("queue: 1 packages (1 versions) from 1 runs") for line in log), log
    assert any(line.startswith("takedowns: 0 new in 1 runs, 0 kept") for line in log), log

    log.clear()
    second = collect(
        data, now=AS_OF + timedelta(hours=1), log=log.append, clients=registry.client
    ).manifest
    assert second is not None
    assert second.chained_from == first.run_id
    assert not any(line.startswith("prune") for line in log)  # pruned an hour ago


def test_a_catch_up_slice_is_logged(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    head = MAX_RUN_FEED_SPAN + 50_000
    registry.add_json(f"{REPLICATE_URL}/", {"update_seq": head})
    data.write_checkpoint(
        "npm", Checkpoint(cursor=0, run_id="prev", as_of=AS_OF - timedelta(days=3))
    )
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is not None and tick.manifest.cursor_until == MAX_RUN_FEED_SPAN
    line = next(line for line in log if line.startswith("ingest: run"))
    assert "catching up (50000 of the feed left for the next ticks)" in line, line


def test_failed_refresh_is_logged_and_ingest_still_runs(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    feed_from(registry, 0)
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is not None and tick.manifest.change_count == 4
    assert any(line.startswith("labels: FAILED") for line in log)  # OSV export is a 404 here
    assert tick.failed == ("labels",)
    assert "prune: skipped: no label set to decide which packuments to keep" in log


def test_offline_tick_writes_nothing(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    registry.offline.add(f"{REPLICATE_URL}/")
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is None and tick.reports == ()
    assert any(line.startswith("ingest: OFFLINE") for line in log)
    assert data.read_checkpoint("npm") is None


def test_unfinished_stages_are_caught_up(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    ignored: list[str] = []
    first = collect(data, now=AS_OF, log=ignored.append, clients=registry.client).manifest
    assert first is not None
    (data.run_dir(first.run_id) / "static.jsonl").unlink()  # as if Stage 2 had crashed

    log: list[str] = []
    tick = collect(data, now=AS_OF + timedelta(hours=1), log=log.append, clients=registry.client)
    assert tick.reports[0].run_id == first.run_id  # catch-ups first, then the new run
    assert any(
        line.startswith(f"stages (catch-up {first.run_id} from Stage 1): ") for line in log
    ), log
    assert (data.run_dir(first.run_id) / "static.jsonl").exists()
    assert (data.run_dir(first.run_id) / "correlate.jsonl").exists()

    (data.run_dir(first.run_id) / "correlate.jsonl").unlink()  # only Stage 4 is redone
    log.clear()
    collect(
        data, now=AS_OF + timedelta(hours=1, minutes=30), log=log.append, clients=registry.client
    )
    (line,) = [line for line in log if "catch-up" in line]
    assert "from Stage 4" in line and "triaged" not in line and "Stage 4" in line

    log.clear()  # nothing left to catch up
    collect(data, now=AS_OF + timedelta(hours=2), log=log.append, clients=registry.client)
    assert not any("catch-up" in line for line in log)


def test_a_missing_report_alone_is_redone(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    ignored: list[str] = []
    first = collect(data, now=AS_OF, log=ignored.append, clients=registry.client).manifest
    assert first is not None
    report = data.run_dir(first.run_id) / "report"
    damage: list[Callable[[], object]] = [
        (report / "report.json").unlink,  # as if writing the report had failed after Stage 4
        (report / "index.md").unlink,  # written last: report.json alone isn't a report
        lambda: (report / "report.json").write_bytes(  # another schema version
            (report / "report.json")
            .read_bytes()
            .replace(b'"schema_version": 1', b'"schema_version": 0')
        ),
    ]
    for hour, broken in enumerate(damage, start=1):
        broken()
        log: list[str] = []
        now = AS_OF + timedelta(hours=hour)
        tick = collect(data, now=now, log=log.append, clients=registry.client)
        (line,) = [line for line in log if "catch-up" in line]
        assert line.startswith(f"stages (catch-up {first.run_id} from the report): "), line
        assert "compared" not in line  # Stage 4 wasn't redone
        assert (report / "index.md").exists() and tick.reports[0].run_id == first.run_id


def test_an_interrupted_rerun_leaves_no_stale_report(
    tmp_path: Path, registry: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    first = collect(data, now=AS_OF, log=lambda _: None, clients=registry.client).manifest
    assert first is not None
    run_dir = data.run_dir(first.run_id)

    def killed(*_: object, **__: object) -> NoReturn:
        raise KeyboardInterrupt  # as if the tick were stopped during Stage 4

    monkeypatch.setattr(kitsunox.collect, "run_correlate_stage", killed)
    with pytest.raises(KeyboardInterrupt):
        run_stages(data, first.run_id, registry.client, start=1)
    # The old report would otherwise count as complete for the rewritten Stage 1-3 outputs.
    assert not (run_dir / "report" / "index.md").exists()
    assert _resume_from(run_dir) == REPORT_ONLY


def test_only_a_stage2_decision_to_retry_resumes_from_stage1(
    tmp_path: Path, registry: Router
) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    first = collect(data, now=AS_OF, log=lambda _: None, clients=registry.client).manifest
    assert first is not None
    run_dir = data.run_dir(first.run_id)
    static = run_dir / "static.jsonl"
    (batch,) = [PackageBatch.load_json(line) for line in static.read_bytes().splitlines()]
    version = batch.versions[-1]
    assert _resume_from(run_dir) is None

    def rewrite(candidate: Candidate) -> None:
        changed = batch.model_copy(update={"versions": (*batch.versions[:-1], candidate)})
        static.write_bytes(b"\n" + changed.model_dump_json().encode() + b"\n\n")

    # The text alone (here in a finding's explanation) is not a decision to retry.
    quoted = Finding(
        rule_id="x",
        rule_version=1,
        severity=Severity.LOW,
        weight=0.0,
        title="x",
        explanation=f"files unavailable, {WILL_RETRY}TransientFetchError: x",
    )
    rewrite(version.model_copy(update={"findings": (*version.findings, quoted)}))
    assert WILL_RETRY.encode() in static.read_bytes()
    assert _resume_from(run_dir) is None

    retry = StageDecision(
        stage=STATIC_STAGE,
        forwarded=False,
        reason=f"files unavailable, {WILL_RETRY}TransientFetchError: x",
    )
    rewrite(version.model_copy(update={"history": (*version.history[:-1], retry)}))
    assert _resume_from(run_dir) == 1


def test_stage5_runs_only_with_a_results_root(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path / "data")
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is not None
    assert not any(line.startswith("sandbox") for line in log)
    assert not (data.run_dir(tick.manifest.run_id) / "sandbox.jsonl").exists()

    results = tmp_path / "pa-results"
    results.mkdir()
    feed_from(registry, 200)
    log.clear()
    later = collect(
        data,
        now=AS_OF + timedelta(hours=1),
        log=log.append,
        clients=registry.client,
        sandbox_results=results,
    )
    assert later.manifest is not None and later.failed == ()
    (line,) = [line for line in log if line.startswith("sandbox")]
    # The mock serves no tarballs: the reported version can't be inspected, nothing exported.
    assert line.startswith(f"sandbox {later.manifest.run_id}: 0 of "), line
    assert "export: 0 jobs in " in line
    assert (data.run_dir(later.manifest.run_id) / "sandbox.jsonl").exists()


def test_a_rescore_redoes_the_stages_and_keeps_the_ticks_outputs(
    tmp_path: Path, registry: Router
) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    ignored: list[str] = []
    first = collect(data, now=AS_OF, log=ignored.append, clients=registry.client).manifest
    assert first is not None
    run_dir = data.run_dir(first.run_id)
    tick_output = (run_dir / "correlate.jsonl").read_bytes()

    summary = rescore_run(data, first.run_id, registry.client, AS_OF + timedelta(days=1))
    assert "triaged" in summary and summary.endswith(
        "1 to review (report/index.md); was 1 to review"
    )
    originals = run_dir / RESCORE_ORIGINALS
    assert (originals / "correlate.jsonl").read_bytes() == tick_output
    assert (originals / "report" / "index.md").exists()
    # The same rules on the same recorded inputs: the same Stage 4 output.
    assert (run_dir / "correlate.jsonl").read_bytes() == tick_output
    info = json.loads((run_dir / RESCORE_INFO).read_bytes())
    assert info["rescored_at"].startswith("2026") and (
        info["reported_before"],
        info["reported"],
    ) == (1, 1)

    # A second re-score keeps the first originals.
    rescore_run(data, first.run_id, registry.client, AS_OF + timedelta(days=2))
    assert (originals / "correlate.jsonl").read_bytes() == tick_output
    assert not (run_dir / f"{RESCORE_ORIGINALS}.partial").exists()


def test_low_disk_prunes_first_and_writes_nothing(
    tmp_path: Path, registry: Router, free_disk: Disk
) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    free_disk.free = 20 * GIB  # below STOP_BELOW even after the prune
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is None and tick.disk_low and tick.failed == ("disk",)
    assert tick.disk_free == tick.disk_lowest == 20 * GIB
    assert log[0] == "disk: 20.0 GB free"
    assert any(line.startswith("prune (disk low, 20.0 GB free): ") for line in log), log
    assert "disk: 20.0 GB free, below 25.0 GB: this tick skipped (resumed later)" in log
    assert data.read_checkpoint("npm") is None and not (tmp_path / "runs").exists()


def test_disk_running_low_mid_tick_leaves_the_stages_for_later(
    tmp_path: Path, registry: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    checks = Disk()  # collect's own checks only (the blob store has plenty)
    monkeypatch.setattr(kitsunox.collect, "free_bytes", checks)
    # start, room for the tick, then too little for the new run's stages
    checks.readings = [500 * GIB, 500 * GIB, 24 * GIB, 24 * GIB]
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is not None and tick.disk_low and "disk" in tick.failed
    assert tick.disk_lowest == 24 * GIB and tick.reports == ()
    assert not (data.run_dir(tick.manifest.run_id) / "static.jsonl").exists()
    assert any(line.startswith("prune (disk low, 24.0 GB free): ") for line in log), log

    log.clear()  # room again: the run's stages are caught up
    later = collect(data, now=AS_OF + timedelta(hours=1), log=log.append, clients=registry.client)
    assert not later.disk_low
    assert any(
        line.startswith(f"stages (catch-up {tick.manifest.run_id} from Stage 1): ") for line in log
    ), log
    assert log[-1] == "disk: 500.0 GB free (lowest this tick 500.0 GB)"


def test_the_blob_floor_stops_an_ingest_without_skipping_packages(
    tmp_path: Path, registry: Router, free_disk: Disk, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    free_disk.free = 30 * GIB  # room to start, but under the blob floor
    monkeypatch.setattr(disk, "BLOB_FLOOR", 40 * GIB)
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is None and tick.disk_low
    assert any(line.startswith("ingest: blob store: 30.0 GB free") for line in log), log
    assert data.read_checkpoint("npm") is None  # the next tick covers the window


def test_a_tick_writes_ledgers_and_runs_live_eval_once_a_day(
    tmp_path: Path, registry: Router
) -> None:
    from kitsunox.evaluation.ledger import LIVE_DIR, ledgers

    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.failed == ()
    assert tick.manifest is not None
    run_id = tick.manifest.run_id
    assert f"ledger {run_id}: written ({run_id}.jsonl.zst)" in log
    written = ledgers(tmp_path / LIVE_DIR)
    assert [lg.header.run_id for lg in written] == [run_id]
    assert written[0].header.pipeline is not None  # this process ran the stages
    assert any(line.startswith("live-eval: labels ") for line in log), log
    assert (tmp_path / LIVE_DIR / "log.jsonl").exists()
    log.clear()
    collect(data, now=AS_OF + timedelta(hours=1), log=log.append, clients=registry.client)
    assert not any(line.startswith("live-eval") for line in log)  # not due yet
    log.clear()
    collect(data, now=AS_OF + timedelta(hours=22), log=log.append, clients=registry.client)
    assert any(line.startswith("live-eval: labels ") for line in log), log


def test_live_eval_waits_for_a_label_set(tmp_path: Path, registry: Router) -> None:
    from kitsunox.collect import _last_live_eval, _live_eval

    data = DataDir(tmp_path)
    assert _live_eval(data, AS_OF) == "skipped: no label set yet"
    assert _last_live_eval(data) is None
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "live-eval.json").write_text("{}")
    assert _last_live_eval(data) is None
