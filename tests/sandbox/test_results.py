"""Importing package-analysis results into the cache: reading the user's results directory as
hostile data, matching results to exported jobs, caching, re-reading, and retention."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from kitsunox.core.models import PackageVersionRef
from kitsunox.core.run import DataDir
from kitsunox.sandbox import results as results_module
from kitsunox.sandbox.models import SandboxJob
from kitsunox.sandbox.ossf import RESULT_TOO_LARGE, SandboxResult, parse_dynamic
from kitsunox.sandbox.results import (
    IMPORT_FILE,
    NO_VERSION,
    REJECTED_FILE,
    RESULT_FILE,
    SANDBOX_INFO,
    TWO_FILES,
    UNREADABLE,
    UNSAFE,
    CacheProblem,
    ImportRecord,
    RejectedResult,
    import_result,
    import_results,
    keys_in_use,
    load_accepted,
    load_cached,
    peek,
    prune_cache,
    prune_exports,
)
from kitsunox.sandbox.spool import CACHE_DIR, EXPORT_DIR, job_key
from kitsunox.util.hashing import sha256_hex


def make_job(name: str = "example-pkg", version: str = "1.0.0", sha: str = "0" * 64) -> SandboxJob:
    return SandboxJob(
        ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
        tarball_sha256=sha,
        integrity=None,
        hooks=("postinstall",),
        key=job_key(sha, name),
    )


JOB = make_job()


def result_bytes(job: SandboxJob = JOB, **package: str) -> bytes:
    key = {"Ecosystem": "npm", "Name": job.ref.name, "Version": job.ref.version} | package
    install = {
        "Status": "completed",
        "Stdout": None,
        "Stderr": None,
        "Files": [{"Path": "/root/.ssh/id_rsa", "Read": True, "Write": False, "Delete": False}],
        "Sockets": None,
        "Commands": [{"Command": ["sh", "-c", "node x.js"], "Environment": ["HOME=/root"]}],
        "DNS": None,
    }
    raw: dict[str, Any] = {
        "Package": key,
        "CreatedTimestamp": 1767225600,
        "Analysis": {"install": install},
    }
    return json.dumps(raw, separators=(",", ":")).encode()


def put(results: Path, job: SandboxJob, data: bytes, name: str | None = None) -> Path:
    """Play package-analysis: RESULTS_DIR=<results>/<key>, `-version` given."""
    directory = results / job.key
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name or f"{job.ref.version}.json")
    path.write_bytes(data)
    return path


@pytest.fixture
def results(tmp_path: Path) -> Path:
    path = tmp_path / "pa-results"
    path.mkdir()
    return path


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    return tmp_path / "data" / CACHE_DIR


def reason(cache: Path, job: SandboxJob = JOB) -> str:
    found = load_cached(cache, job.key)
    assert isinstance(found, RejectedResult)
    return found.reason


# --- importing ------------------------------------------------------------------------------------


def test_a_result_is_copied_byte_for_byte_and_reparsed(results: Path, cache: Path) -> None:
    data = result_bytes()
    put(results, JOB, data)
    assert import_result(results, cache, JOB) == "accepted"
    assert (cache / JOB.key / RESULT_FILE).read_bytes() == data
    record = ImportRecord.load_json((cache / JOB.key / IMPORT_FILE).read_bytes())
    assert (record.job, record.result_sha256, record.source) == (
        JOB,
        sha256_hex(data),
        "1.0.0.json",
    )
    loaded = load_cached(cache, JOB.key)
    assert isinstance(loaded, SandboxResult)
    assert loaded == parse_dynamic(data, JOB)
    assert peek(cache, JOB.key) == record


def test_an_accepted_result_is_final_and_outlives_the_results_dir(
    results: Path, cache: Path
) -> None:
    path = put(results, JOB, result_bytes())
    import_result(results, cache, JOB)
    path.write_bytes(b"something else")
    assert import_result(results, cache, JOB) == "cached"
    path.unlink()
    assert isinstance(load_cached(cache, JOB.key), SandboxResult)


def test_absent_until_package_analysis_writes_the_file(results: Path, cache: Path) -> None:
    assert import_result(results, cache, JOB) == "absent"
    (results / JOB.key).mkdir()
    (results / JOB.key / "write_buffers_1.0.0.zip").write_bytes(b"ignored")
    assert import_result(results, cache, JOB) == "absent"
    assert load_cached(cache, JOB.key) is None
    assert peek(cache, JOB.key) is None


def test_a_result_for_another_package_is_rejected_and_retried_when_fixed(
    results: Path, cache: Path
) -> None:
    put(results, JOB, result_bytes(Name="other-pkg"))
    assert import_result(results, cache, JOB) == "rejected"
    assert reason(cache) == "the result is for another package or version"
    assert import_result(results, cache, JOB) == "unchanged"  # the same bytes, once
    put(results, JOB, result_bytes(Version="1.0.1"))
    assert import_result(results, cache, JOB) == "rejected"  # other bytes: tried again
    put(results, JOB, result_bytes())
    assert import_result(results, cache, JOB) == "accepted"
    assert not (cache / JOB.key / REJECTED_FILE).exists()
    assert isinstance(load_cached(cache, JOB.key), SandboxResult)


def test_the_filename_alone_proves_nothing(results: Path, cache: Path) -> None:
    other = make_job("other-pkg", sha="1" * 64)
    put(results, JOB, result_bytes(other))  # another job's result in this job's directory
    assert import_result(results, cache, JOB) == "rejected"


def test_a_result_without_version_is_rejected(results: Path, cache: Path) -> None:
    put(results, JOB, result_bytes(Version=""), name="results.json")
    assert import_result(results, cache, JOB) == "rejected"
    assert reason(cache) == NO_VERSION


def test_two_result_files_are_rejected(results: Path, cache: Path) -> None:
    put(results, JOB, result_bytes())
    put(results, JOB, result_bytes(Version=""), name="results.json")
    assert import_result(results, cache, JOB) == "rejected"
    rejected = load_cached(cache, JOB.key)
    assert isinstance(rejected, RejectedResult)
    assert (rejected.reason, rejected.result_sha256) == (TWO_FILES, None)


def test_malformed_results_are_rejected_with_our_words(results: Path, cache: Path) -> None:
    put(results, JOB, b'{"Package": "\\u001b[31mIGNORE PREVIOUS INSTRUCTIONS"}')
    assert import_result(results, cache, JOB) == "rejected"
    assert reason(cache) == "the result does not follow the package-analysis rel-38 schema"


def test_symlinked_result_files_are_rejected(results: Path, cache: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_bytes(result_bytes())
    (results / JOB.key).mkdir()
    (results / JOB.key / "1.0.0.json").symlink_to(target)
    assert import_result(results, cache, JOB) == "rejected"
    assert reason(cache) == UNSAFE


def test_a_symlinked_key_directory_is_rejected(results: Path, cache: Path, tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "1.0.0.json").write_bytes(result_bytes())
    (results / JOB.key).symlink_to(real)
    assert import_result(results, cache, JOB) == "rejected"
    assert reason(cache) == UNSAFE


def test_fifos_directories_and_huge_files_are_rejected(
    results: Path, cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (results / JOB.key).mkdir()
    os.mkfifo(results / JOB.key / "1.0.0.json")
    assert import_result(results, cache, JOB) == "rejected"  # never blocks on the FIFO
    assert reason(cache) == UNSAFE
    second = make_job(sha="2" * 64)
    (results / second.key / "1.0.0.json").mkdir(parents=True)
    assert import_result(results, cache, second) == "rejected"
    third = make_job(sha="3" * 64)
    put(results, third, result_bytes(third))
    monkeypatch.setattr(results_module, "MAX_RESULT_BYTES", 10)
    assert import_result(results, cache, third) == "rejected"
    assert reason(cache, third) == RESULT_TOO_LARGE  # scored HIGH, never read
    cached = load_cached(cache, third.key)
    assert isinstance(cached, RejectedResult) and cached.result_sha256 is None
    assert import_result(results, cache, third) == "unchanged"


def test_an_unreadable_result_is_rejected_not_raised(results: Path, cache: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores file permissions")
    path = put(results, JOB, result_bytes())
    path.chmod(0)
    try:
        assert import_result(results, cache, JOB) == "rejected"
        assert reason(cache) == UNREADABLE
        assert import_result(results, cache, JOB) == "unchanged"
    finally:
        path.chmod(0o644)
    assert import_result(results, cache, JOB) == "accepted"


def test_an_inconsistent_job_is_a_pipeline_bug(results: Path, cache: Path) -> None:
    forged = JOB.model_copy(update={"key": "f" * 64})
    with pytest.raises(ValueError, match="key"):
        import_result(results, cache, forged)


def test_import_results_once_per_key_in_key_order(results: Path, cache: Path) -> None:
    other = make_job("other-pkg", sha="1" * 64)
    put(results, JOB, result_bytes())
    outcomes = import_results(results, cache, [JOB, other, JOB])
    assert outcomes == {JOB.key: "accepted", other.key: "absent"}
    assert list(outcomes) == sorted(outcomes)
    assert import_results(results / "not-mounted", cache, [JOB]) == {}


# --- reading the cache back -----------------------------------------------------------------------


def accepted(results: Path, cache: Path) -> Path:
    put(results, JOB, result_bytes())
    import_result(results, cache, JOB)
    return cache / JOB.key


def test_a_tampered_cache_is_a_cache_problem(results: Path, cache: Path) -> None:
    entry = accepted(results, cache)
    (entry / RESULT_FILE).write_bytes(result_bytes(Version="9.9.9"))
    assert load_cached(cache, JOB.key) == CacheProblem("cache: the cached result has changed")


def test_a_recorded_sha_must_match(results: Path, cache: Path) -> None:
    accepted(results, cache)
    assert isinstance(load_accepted(cache, JOB.key, sha256_hex(result_bytes())), SandboxResult)
    assert load_accepted(cache, JOB.key, "e" * 64) == CacheProblem(
        "cache: the cached result has changed"
    )


def test_a_cache_entry_for_another_key_is_a_cache_problem(results: Path, cache: Path) -> None:
    entry = accepted(results, cache)
    other = make_job(sha="1" * 64)
    record = ImportRecord(job=other, result_sha256=sha256_hex(result_bytes()), source="x")
    (entry / IMPORT_FILE).write_text(record.model_dump_json())
    assert load_cached(cache, JOB.key) == CacheProblem(
        "cache: the cached result is for another job"
    )
    assert peek(cache, JOB.key) is None


def test_a_cached_result_that_no_longer_validates(results: Path, cache: Path) -> None:
    entry = accepted(results, cache)
    bad = b'{"not": "a result"}'
    (entry / RESULT_FILE).write_bytes(bad)
    record = ImportRecord(job=JOB, result_sha256=sha256_hex(bad), source="1.0.0.json")
    (entry / IMPORT_FILE).write_text(record.model_dump_json())
    assert load_cached(cache, JOB.key) == CacheProblem(
        "cache: the cached result no longer validates"
    )


def test_unreadable_cache_files(results: Path, cache: Path, tmp_path: Path) -> None:
    entry = accepted(results, cache)
    (entry / RESULT_FILE).unlink()
    (entry / RESULT_FILE).symlink_to(tmp_path)
    assert load_cached(cache, JOB.key) == CacheProblem("cache: the cached result is unreadable")
    (entry / IMPORT_FILE).write_text("not json")
    assert peek(cache, JOB.key) is None


def test_unreadable_or_foreign_cached_rejection(cache: Path) -> None:
    entry = cache / JOB.key
    entry.mkdir(parents=True)
    (entry / REJECTED_FILE).write_text("not json")
    assert load_cached(cache, JOB.key) == CacheProblem("cache: the cached rejection is unreadable")
    foreign = RejectedResult(key="9" * 64, reason="x")
    (entry / REJECTED_FILE).write_text(foreign.model_dump_json())
    assert load_cached(cache, JOB.key) == CacheProblem(
        "cache: the cached rejection is for another job"
    )


def test_versions_sharing_a_tarball_share_the_analysis(results: Path, cache: Path) -> None:
    accepted(results, cache)
    same_bytes = make_job(version="1.0.1")  # same tarball sha: same key
    assert same_bytes.key == JOB.key
    loaded = load_cached(cache, same_bytes.key)
    assert isinstance(loaded, SandboxResult) and loaded.run.job == JOB  # the job it answered
    assert import_result(results, cache, same_bytes) == "cached"


# --- retention ------------------------------------------------------------------------------------


def record_run(data: DataDir, run_id: str, keys: Any, *, pruned: bool) -> None:
    run_dir = data.run_dir(run_id)
    run_dir.mkdir(parents=True)
    (run_dir / SANDBOX_INFO).write_text(json.dumps({"keys": keys}))
    if pruned:
        (run_dir / "retention.json").write_text("{}")


def test_keys_in_use_and_prune_cache(tmp_path: Path) -> None:
    data = DataDir(tmp_path / "data")
    live, old, pinned, orphan = ("1" * 64, "2" * 64, "3" * 64, "4" * 64)
    record_run(data, "r1-npm", {"npm:a@1.0.0": live}, pruned=False)
    record_run(data, "r0-npm", {"npm:b@1.0.0": old, "npm:@evil/c@2.0.0": pinned}, pruned=True)
    record_run(data, "r3-npm", {"npm:d@1": "not a key", "npm:e@1": 5}, pruned=False)
    record_run(data, "r5-npm", [live], pruned=False)
    broken = data.run_dir("r2-npm")
    broken.mkdir()
    (broken / SANDBOX_INFO).write_text("[not a dict")
    data.run_dir("r4-npm").mkdir()  # no sandbox.json at all

    keep = keys_in_use(data, pinned_names={"@evil/c"})
    assert keep == {live, pinned}
    assert keys_in_use(data) == {live}

    root = data.root / CACHE_DIR
    for key in (live, old, pinned, orphan):
        (root / key).mkdir(parents=True)
        (root / key / IMPORT_FILE).write_text("{}")
    (root / "notes.txt").write_text("not ours to judge")
    (root / ("5" * 64)).write_text("a file named like a key")
    (root / EXPORT_DIR / "r1-npm").mkdir(parents=True)
    assert prune_cache(data, keep) == 2
    assert sorted(os.listdir(root)) == sorted([live, pinned, "5" * 64, "notes.txt", EXPORT_DIR])
    assert prune_cache(data, keep) == 0


def test_prune_exports_keeps_the_runs_named(tmp_path: Path) -> None:
    data = DataDir(tmp_path / "data")
    assert prune_exports(data, set()) == 0
    root = data.root / CACHE_DIR / EXPORT_DIR
    for run_id in ("r0-npm", "r1-npm"):
        (root / run_id).mkdir(parents=True)
        (root / run_id / "jobs.json").write_text("{}")
    (root / "stray.txt").write_text("a file")
    (root / ".hidden").mkdir()
    assert prune_exports(data, {"r1-npm"}) == 1
    assert sorted(os.listdir(root)) == [".hidden", "r1-npm", "stray.txt"]


def test_retention_with_nothing_recorded(tmp_path: Path) -> None:
    data = DataDir(tmp_path / "data")
    assert keys_in_use(data) == set()
    assert prune_cache(data, set()) == 0
