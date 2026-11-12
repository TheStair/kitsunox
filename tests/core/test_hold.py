import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

import kitsunox.collect
from conftest import REPORT_AS_OF, LiveVersion, write_live_run
from kitsunox.collect import hold_now, is_npm_tarball
from kitsunox.core import retention as R
from kitsunox.core.run import DataDir
from kitsunox.evaluation.ledger import LIVE_DIR, backfill
from kitsunox.evaluation.live import LiveReport, LogLine, hold_requests, live_paths
from kitsunox.evaluation.sample import write_samples
from kitsunox.reporting.verdicts import VerdictRecord, append_verdict
from kitsunox.util.http import Snapshot

NOW = REPORT_AS_OF + timedelta(hours=1)
RUN = "20261029T210500Z-npm"


def blob(data: DataDir, sha: str, size: int = 10) -> Path:
    path = data.root / "blobs" / sha[:2] / f"{sha}.zst"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    return path


def sha(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()  # what write_live_run records


def held(reason: R.HoldReason, until_days: int | None = 30, size: int = 0) -> R.HeldBlob:
    until = None if until_days is None else NOW + timedelta(days=until_days)
    return R.HeldBlob(until=until, size=size, reason=reason, ref="a@1", run_id=RUN)


def test_update_merges_expires_and_drops_missing_blobs(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    for s in ("a" * 64, "b" * 64, "c" * 64):
        blob(data, s)
    hold, report = R.update_hold(
        data,
        [
            ("a" * 64, held("small")),
            ("a" * 64, held("reported", 40)),  # higher priority, later
            ("b" * 64, held("small", -1)),  # expired
            ("c" * 64, held("sample", 5)),
            ("c" * 64, held("small", None)),  # until None wins
            ("d" * 64, held("small")),  # no blob
        ],
        now=NOW,
    )
    assert (report.added, report.expired, report.missing, report.held) == (4, 1, 1, 2)
    a = hold.blobs["a" * 64]
    assert a.reason == "reported" and a.until == NOW + timedelta(days=40) and a.size == 10
    c = hold.blobs["c" * 64]
    assert c.reason == "sample" and c.until is None
    assert R.read_hold(data) == hold
    assert R.held_digests(data, NOW) == {"a" * 64, "c" * 64}
    assert R.held_digests(data, NOW + timedelta(days=41)) == {"c" * 64}
    _, again = R.update_hold(data, [], now=NOW)
    assert again.added == 0 and again.held == 2


def test_cap_drops_the_lowest_priority_oldest_first(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    names: dict[str, R.HoldReason] = {
        "l": "labeled",
        "r": "reported",
        "s": "sample",
        "o": "small",
        "n": "small",
    }
    for key in names:
        blob(data, key * 64, size=100)
    requests = [(k * 64, held(r, None if r == "labeled" else 30)) for k, r in names.items()]
    requests[3] = ("o" * 64, held("small", 10))  # the older small one
    hold, report = R.update_hold(data, requests, now=NOW, cap_bytes=250)
    assert set(hold.blobs) == {"l" * 64, "r" * 64}
    assert (report.dropped, report.dropped_bytes, report.held_bytes) == (3, 300, 200)
    hold, report = R.update_hold(data, [], now=NOW, cap_bytes=50)
    assert set(hold.blobs) == {"l" * 64}  # labeled is never dropped


def test_empty_blob_counts_as_absent(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    blob(data, "e" * 64, size=0)
    hold, report = R.update_hold(data, [("e" * 64, held("small"))], now=NOW)
    assert hold.blobs == {} and report.missing == 1
    assert R.held_digests(DataDir(tmp_path / "none"), NOW) == set()


def finished_run(data: DataDir) -> None:
    run_dir = write_live_run(
        data.root / "runs",
        RUN,
        [
            LiveVersion("tiny", tarball_size=1000, base_size=2000),
            LiveVersion("huge", tarball_size=10**6, reported=True, score=9),
        ],
    )
    (run_dir / "changes.jsonl").write_text("")
    Snapshot().save(run_dir / "snapshot.json")


def test_small_tarballs_of_unpruned_runs(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    finished_run(data)
    found = R.small_tarballs(data, is_artifact=is_npm_tarball)
    assert {s for s, _ in found} == {
        sha(LiveVersion("tiny").tarball_url),
        sha(LiveVersion("tiny").base_url),
    }
    assert all(h.until == REPORT_AS_OF + timedelta(days=R.HOLD_DAYS) for _, h in found)
    (data.run_dir(RUN) / "retention.json").write_text("{}")
    assert R.small_tarballs(data, is_artifact=is_npm_tarball) == []
    assert R.small_tarballs(DataDir(tmp_path / "x"), is_artifact=is_npm_tarball) == []


def test_prune_keeps_held_blobs(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    finished_run(data)
    kept, gone = blob(data, "1" * 64), blob(data, "2" * 64)
    report = R.prune(
        data,
        now=REPORT_AS_OF + timedelta(days=3),
        keep_days=2,
        pinned_names=(),
        metadata_url=str,
        held={"1" * 64},
    )
    assert report.runs_pruned == (RUN,) and report.blobs_held == 1
    assert kept.exists() and not gone.exists()


def test_live_requests_reported_sampled_and_labeled(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    finished_run(data)
    write_live_run(
        data.root / "runs",
        "20261030T010500Z-npm",
        [LiveVersion("next")],
        as_of=REPORT_AS_OF + timedelta(hours=4),
    )
    live = tmp_path / LIVE_DIR
    backfill(data.root / "runs", live)
    write_samples(data.root / "runs", live)
    requests = hold_requests(data.root, live)
    why = {(h.ref, h.reason) for _, h in requests}
    assert ("huge@1.0.1", "reported") in why and ("tiny@1.0.1", "sample") in why
    # The newest live report labels tiny malicious: held for good, even once pruned.
    report = LiveReport(
        dataset="live-x",
        dataset_sha256="0",
        as_of=NOW,
        headline_d=7,
        windows={},
        timing={},
        unfinished_runs=0,
        unfinished_changes=0,
        pending_runs=0,
        misses=(),
        malicious=("tiny@1.0.1",),
    )
    path = live_paths(live, "live-x")[0]
    path.parent.mkdir(parents=True)
    path.write_text(report.model_dump_json())
    line = LogLine(
        built_at=NOW,
        dataset="live-x",
        dataset_sha256="0",
        label_set="x",
        versions=1,
        malicious=1,
        reported_malicious=0,
        recall=0.0,
        precision=None,
        newly_labeled=1,
    )
    (live / "log.jsonl").write_text(line.model_dump_json() + "\n")
    (data.run_dir(RUN) / "retention.json").write_text("{}")
    labeled = [(s, h) for s, h in hold_requests(data.root, live) if h.reason == "labeled"]
    assert {h.ref for _, h in labeled} == {"tiny@1.0.1"} and all(
        h.until is None for _, h in labeled
    )
    assert not any(
        h.reason == "reported" and h.run_id == RUN for _, h in hold_requests(data.root, live)
    )
    path.write_text("not json")
    assert not any(h.reason == "labeled" for _, h in hold_requests(data.root, live))


def test_malicious_verdict_held_for_good_before_any_report(tmp_path: Path) -> None:
    """A reviewer's malicious verdict pins the version's tarball for good at once, without
    waiting for the daily live report to label it, even after its run is pruned; another
    verdict, or a later reopening, does not."""
    data = DataDir(tmp_path)
    finished_run(data)
    live = tmp_path / LIVE_DIR
    backfill(data.root / "runs", live)
    (data.run_dir(RUN) / "retention.json").write_text("{}")

    def verdict(name: str, verdict: str) -> None:
        append_verdict(
            data.root,
            VerdictRecord(
                ecosystem="npm",
                name=name,
                version="1.0.1",
                verdict=verdict,
                at=NOW,
                by="claude",
                run_id=RUN,
                rank=1,
                score=5.0,
                severity="medium",
            ),
        )

    assert not any(h.reason == "labeled" for _, h in hold_requests(data.root, live))
    verdict("tiny", "malicious")
    verdict("huge", "benign")
    labeled = [h for _, h in hold_requests(data.root, live) if h.reason == "labeled"]
    assert {h.ref for h in labeled} == {"tiny@1.0.1"} and all(h.until is None for h in labeled)
    verdict("tiny", "reopened")
    assert not any(h.reason == "labeled" for _, h in hold_requests(data.root, live))


def test_hold_now_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = DataDir(tmp_path)
    finished_run(data)
    for v in (LiveVersion("tiny"),):
        blob(data, sha(v.tarball_url))
    digests, summary = hold_now(data, NOW)
    assert digests == {sha(LiveVersion("tiny").tarball_url)}
    assert summary.startswith("hold: 1 blobs") and "1 gone" in summary

    def boom(*_: object, **__: object) -> None:
        raise OSError("disk")

    monkeypatch.setattr(kitsunox.collect, "update_hold", boom)
    digests, summary = hold_now(data, NOW)
    assert digests == {sha(LiveVersion("tiny").tarball_url)} and "update FAILED" in summary
    R.hold_path(data).write_text("garbage")
    digests, summary = hold_now(data, NOW)
    assert digests == set() and "UNREADABLE" in summary


def test_cap_is_logged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = DataDir(tmp_path)
    finished_run(data)
    blob(data, sha(LiveVersion("tiny").tarball_url), size=100)
    blob(data, sha(LiveVersion("tiny").base_url), size=100)
    monkeypatch.setattr(R, "HOLD_CAP_BYTES", 150)
    monkeypatch.setattr(
        kitsunox.collect,
        "update_hold",
        lambda d, r, *, now: R.update_hold(d, r, now=now, cap_bytes=150),
    )
    _, summary = hold_now(data, NOW)
    assert "1 dropped over the 0 GB cap" in summary
