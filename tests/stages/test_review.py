"""Stage 4's npm wiring: repository lookups through the fetcher, and retries of those that
failed on the network (decision 0009; decision 0010 addendum)."""

import hashlib
import json
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from conftest import Router, TarEntry, make_tar_gz, sri_sha512
from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    Evidence,
    EvidenceKind,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    StageDecision,
    VersionSnapshot,
    Window,
)
from kitsunox.core.run import DataDir, RunManifest
from kitsunox.core.watchlist import WatchEntry, Watchlist
from kitsunox.ecosystems.npm.registry import packument_url
from kitsunox.stages.correlate import (
    CORRELATE_INFO,
    NETWORK_UNCOMPARED,
    NOT_EVALUATED,
    OUTAGE_MIN,
    CorrelationContext,
    correlate,
    correlate_run,
    decide,
    repo_network_failures,
)
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.review import (
    CORRELATION_RULES,
    MAX_DEPENDENCY_LOOKUPS,
    MAX_LOOKUPS_PER_RELEASE,
    PACKAGE_FILES_NETWORK,
    NpmDependencyLookup,
    dependency_cap,
    repo_lookup,
    run_watchlist,
)
from kitsunox.util.http import BlobStore, FetchMode, HttpFetcher, RetryPolicy, Snapshot

A = "a" * 40
B = "b" * 40  # a second commit of o/r; tests that use it give it its own route
REFS = "https://github.com/o/r.git/info/refs?service=git-upload-pack"
ARCHIVE = f"https://codeload.github.com/o/r/tar.gz/{A}"
ARCHIVE_B = f"https://codeload.github.com/o/r/tar.gz/{B}"
TARBALL = "https://registry.npmjs.org/kx/-/kx-1.0.1.tgz"  # `serve`'s default
CTX = CorrelationContext(as_of=datetime(2026, 10, 29, tzinfo=UTC))
ATTEMPTS = 2  # the fetcher's own attempts per request


def pkt(text: str) -> bytes:
    return f"{len(text) + 4:04x}".encode() + text.encode()


def serve(router: Router, name: str = "kx", commit: str = A) -> Candidate:
    """A flagged release of `name` at `commit` (gitHead), its tarball, and the repository o/r
    at A."""
    files = [("package.json", b'{"name": "%s"}' % name.encode()), ("index.js", b"x = 1\n")]
    tarball = make_tar_gz(TarEntry(f"package/{p}", c) for p, c in files)
    url = f"https://registry.npmjs.org/{name}/-/{name}-1.0.1.tgz"
    router.add_bytes(url, tarball)
    router.add_bytes(REFS, pkt(f"{A} refs/heads/main\n") + b"0000")
    router.add_bytes(ARCHIVE, make_tar_gz(TarEntry(f"r-{A}/{p}", c) for p, c in files))
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version="1.0.1"),
        publish=PublishInfo(git_head=commit),
        manifest={"name": name},
        artifact=ArtifactRef(url=url, integrity=sri_sha512(tarball)),
    )
    decision = StageDecision(stage="static", forwarded=True, reason="rules: s2")
    change = Change(new=snapshot, repository_url="https://github.com/o/r")
    return Candidate(change=change, history=(decision,))


def failing(router: Router, url: str, times: int, status: int = 503) -> httpx.Client:
    """The router, except that the first `times` requests for `url` get `status`."""
    left = {"n": times}

    def handle(request: httpx.Request) -> httpx.Response:
        if str(request.url) == url and left["n"] > 0:
            left["n"] -= 1
            router.requests.append(url)
            return httpx.Response(status)
        return router.handler(request)

    return httpx.Client(transport=httpx.MockTransport(handle))


def run_all(
    tmp_path: Path,
    candidates: list[Candidate],
    client: httpx.Client,
    *,
    snapshot: Snapshot | None = None,
    workers: int = 8,
) -> tuple[tuple[Candidate, ...], Snapshot]:
    """Stage 4 over `candidates`, recording (or, given a snapshot, replaying) its requests."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(run_dir / "triage.jsonl", candidates)
    (run_dir / "ast.jsonl").write_bytes(b"")
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=snapshot if snapshot is not None else Snapshot(),
        mode=FetchMode.RECORD if snapshot is None else FetchMode.REPLAY,
        immutable_index=tmp_path / "index",
        client=client,
        retry=RetryPolicy(max_attempts=ATTEMPTS),
    )
    results = correlate_run(
        run_dir, CTX, CORRELATION_RULES, repo=repo_lookup(fetcher), workers=workers
    )
    fetcher.close()
    return tuple(results), fetcher.snapshot


def network_info(tmp_path: Path) -> dict[str, object]:
    info = json.loads((tmp_path / "run" / CORRELATE_INFO).read_bytes())
    network = info["repo_network"]
    assert isinstance(network, dict)
    return network


def run(tmp_path: Path, candidate: Candidate, client: httpx.Client) -> tuple[Candidate, Snapshot]:
    (result,), snapshot = run_all(tmp_path, [candidate], client)
    return result, snapshot


def offline() -> httpx.Client:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"replay went to the network: {request.url}")

    return httpx.Client(transport=httpx.MockTransport(refuse))


def compared(candidate: Candidate) -> str:
    (found,) = (f for f in candidate.findings if f.rule_id == "repo.compared")
    return found.explanation


def test_a_network_failure_that_clears_is_compared(tmp_path: Path, router: Router) -> None:
    candidate = serve(router)
    result, snapshot = run(tmp_path, candidate, failing(router, ARCHIVE, ATTEMPTS))
    assert compared(result).startswith("1 code files against o/r at aaaaaaaaaaaa (gitHead)")
    assert router.requests.count(ARCHIVE) == ATTEMPTS + 1  # first pass failed, retry worked
    assert router.requests.count(REFS) == 1  # refs from the first pass are reused
    assert f"GET {ARCHIVE}" in snapshot.entries  # recorded, so the run replays
    assert repo_network_failures([result]) == 0


def test_a_network_failure_that_persists_stays_visible(tmp_path: Path, router: Router) -> None:
    candidate = serve(router)
    result, snapshot = run(tmp_path, candidate, failing(router, ARCHIVE, 100))
    assert compared(result) == "No comparison: network: o/r@aaaaaaaaaaaa archive unavailable."
    assert result.history[-1].reason.endswith(NETWORK_UNCOMPARED)
    assert router.requests.count(ARCHIVE) == 2 * ATTEMPTS  # one retry pass: nothing recovered
    assert f"GET {ARCHIVE}" not in snapshot.entries
    assert repo_network_failures([result]) == 1
    # The error itself is in `correlate.json`, once per failed request.
    errors = {"o/r@aaaaaaaaaaaa archive": f"GET {ARCHIVE} failed after 2 attempts: HTTP 503"}
    assert network_info(tmp_path)["errors"] == errors


def test_a_refs_failure_is_retried_not_cached(tmp_path: Path, router: Router) -> None:
    candidate = serve(router)
    result, snapshot = run(tmp_path, candidate, failing(router, REFS, ATTEMPTS))
    assert compared(result).startswith("1 code files against o/r at aaaaaaaaaaaa (gitHead)")
    assert router.requests.count(REFS) == ATTEMPTS + 1  # the retry pass went to the network
    assert f"GET {REFS}" in snapshot.entries
    assert repo_network_failures([result]) == 0


def test_a_failed_repository_fails_fast_within_a_pass(tmp_path: Path, router: Router) -> None:
    versions = [serve(router, name) for name in ("kx", "ky", "kz")]
    results, _ = run_all(tmp_path, versions, failing(router, REFS, ATTEMPTS))
    # First pass: kx pays the fetcher's attempts, ky and kz fail at once without a request.
    # Retry pass: the memory is cleared, kx fetches the refs again, ky and kz reuse them.
    assert router.requests.count(REFS) == ATTEMPTS + 1
    assert all(compared(r).startswith("1 code files against o/r") for r in results)
    assert repo_network_failures(results) == 0


def test_a_repository_still_down_says_why(tmp_path: Path, router: Router) -> None:
    versions = [serve(router, name) for name in ("kx", "ky")]
    (kx, ky), _ = run_all(tmp_path, versions, failing(router, REFS, 100))
    assert router.requests.count(REFS) == 2 * ATTEMPTS  # once per pass, not once per version
    # One version sent the request and the other was refused, but which one did depends on the
    # workers, so both read the same.
    assert compared(kx) == compared(ky) == "No comparison: network: o/r refs unavailable."
    assert repo_network_failures([kx, ky]) == 2
    errors = {"o/r refs": f"GET {REFS} failed after 2 attempts: HTTP 503"}
    assert network_info(tmp_path)["errors"] == errors


def test_a_recovered_run_replays_identically(tmp_path: Path, router: Router) -> None:
    versions = [serve(router, name) for name in ("kx", "ky")]
    recorded, snapshot = run_all(tmp_path, versions, failing(router, ARCHIVE, ATTEMPTS))
    assert repo_network_failures(recorded) == 0  # recovered in the retry pass
    correlated = (tmp_path / "run" / "correlate.jsonl").read_bytes()
    snapshot.save(tmp_path / "correlate-snapshot.json")
    saved = Snapshot.load(tmp_path / "correlate-snapshot.json")
    replayed, _ = run_all(tmp_path, versions, offline(), snapshot=saved)
    assert replayed == recorded
    assert (tmp_path / "run" / "correlate.jsonl").read_bytes() == correlated


def test_a_missing_commit_is_not_retried(tmp_path: Path, router: Router) -> None:
    candidate = serve(router)
    result, _ = run(tmp_path, candidate, failing(router, ARCHIVE, 100, status=404))
    assert compared(result).startswith(f"No comparison: archive: {ARCHIVE}: HTTP 404")
    assert router.requests.count(ARCHIVE) == 1
    assert repo_network_failures([result]) == 0


def test_lookup_failures_are_classified(tmp_path: Path, router: Router) -> None:
    candidate = serve(router)
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=router.client(),
        retry=RetryPolicy(max_attempts=1),
    )
    lookup = repo_lookup(fetcher)
    router.offline.add(TARBALL)  # the release's own files: Stage 2 retries those, not Stage 4
    offline = lookup(candidate)
    assert offline is not None and offline.files_transient and not offline.transient
    assert offline.unavailable == PACKAGE_FILES_NETWORK
    router.offline.clear()
    router.add_bytes(REFS, b"zzzz")  # a malformed ref advertisement: not the network
    malformed = lookup(candidate)
    assert malformed is not None and not malformed.transient
    assert malformed.unavailable == "ref advertisement: malformed pkt-line"
    fetcher.close()


def test_release_files_on_the_network_are_not_retried(tmp_path: Path, router: Router) -> None:
    router.offline.add(TARBALL)  # Stage 2 failed on it too, and redoes the run next tick
    result, _ = run(tmp_path, serve(router), router.client())
    assert compared(result) == f"No comparison: {PACKAGE_FILES_NETWORK}."
    assert router.requests.count(TARBALL) == ATTEMPTS  # the first pass only
    assert repo_network_failures([result]) == 0  # not a repository failure
    network = network_info(tmp_path)
    assert network["first_pass"] == network["still_failing"] == network["requests"] == 0
    assert network["package_files_network"] == 1


def test_one_bad_commit_does_not_fail_other_commits(tmp_path: Path, router: Router) -> None:
    router.add_bytes(ARCHIVE_B, b"", status=503)  # always down
    versions = [serve(router, "kbad", B), *(serve(router, f"k{i}") for i in range(3))]
    results, _ = run_all(tmp_path, versions, router.client(), workers=1)
    bad, *good = results
    assert compared(bad) == "No comparison: network: o/r@bbbbbbbbbbbb archive unavailable."
    assert all(compared(r).startswith("1 code files against o/r at aaaaaaaaaaaa") for r in good)
    assert repo_network_failures(results) == 1
    assert router.requests.count(ARCHIVE) == 1  # its versions wait for, then share, one fetch
    assert router.requests.count(ARCHIVE_B) == 2 * ATTEMPTS  # once per pass
    network = network_info(tmp_path)
    assert (network["requests"], network["failed_requests"]) == (3, 1)  # refs, A, B


def test_a_cached_archive_is_never_refused(tmp_path: Path, router: Router) -> None:
    # The first run puts the archive at A in the immutable index. In the second, the network
    # fails it, but the fetcher holds it, so the memory of failures is never asked.
    run(tmp_path / "first", serve(router), router.client())
    first = tmp_path / "first"
    (second,), _ = run_all(first, [serve(router, "ky")], failing(router, ARCHIVE, 100))
    assert compared(second).startswith("1 code files against o/r at aaaaaaaaaaaa")
    assert router.requests.count(ARCHIVE) == 1  # the first run's
    assert network_info(first)["requests"] == 1  # the refs: the archive is no request


def test_one_failed_request_in_a_monorepo_burst_is_no_outage(
    tmp_path: Path, router: Router
) -> None:
    # 30 packages of one repository at one commit (an aws-sdk or babel release): their refs
    # request failed once. That is one failed request, not 30 failed lookups.
    versions = [serve(router, f"k{i:02}") for i in range(OUTAGE_MIN + 10)]
    results, _ = run_all(tmp_path, versions, failing(router, REFS, ATTEMPTS))
    assert router.requests.count(REFS) == ATTEMPTS + 1
    assert repo_network_failures(results) == 0
    network = network_info(tmp_path)
    assert network["first_pass"] == OUTAGE_MIN + 10
    assert (network["requests"], network["failed_requests"]) == (1, 1)
    assert network["retry_passes"] == 1 and network["retry_skipped"] is None
    assert network["still_failing"] == 0


def delayed(router: Router, url: str, seconds: float) -> httpx.Client:
    """The router, except that responses for `url` arrive `seconds` late."""

    def handle(request: httpx.Request) -> httpx.Response:
        if str(request.url) == url:
            time.sleep(seconds)
        return router.handler(request)

    return httpx.Client(transport=httpx.MockTransport(handle))


def test_the_output_does_not_depend_on_thread_timing(tmp_path: Path, router: Router) -> None:
    # One repository whose refs are down, and one whose archive at B is down while A works:
    # whichever thread asks first, every version reads the same.
    router.offline.add(REFS)
    router.add_bytes(ARCHIVE_B, b"", status=503)
    other = "https://github.com/o/s.git/info/refs?service=git-upload-pack"
    router.add_bytes(other, pkt(f"{A} refs/heads/main\n") + b"0000")
    router.add_bytes(f"https://codeload.github.com/o/s/tar.gz/{B}", b"", status=503)
    router.add_bytes(
        f"https://codeload.github.com/o/s/tar.gz/{A}",
        make_tar_gz([TarEntry(f"s-{A}/index.js", b"x = 1\n")]),
    )

    def at_s(name: str, commit: str) -> Candidate:
        candidate = serve(router, name, commit)
        change = candidate.change.model_copy(update={"repository_url": "https://github.com/o/s"})
        return candidate.model_copy(update={"change": change})

    versions = [
        *(serve(router, n) for n in ("kx", "ky", "kz")),
        at_s("sbad", B),
        *(at_s(f"s{i}", A) for i in range(3)),
    ]
    clients = [
        lambda: router.client(),
        lambda: delayed(router, "https://registry.npmjs.org/kx/-/kx-1.0.1.tgz", 0.05),
        lambda: delayed(router, f"https://codeload.github.com/o/s/tar.gz/{B}", 0.05),
    ]
    outputs, infos = set(), set()
    for i in range(21):
        directory = tmp_path / str(i)
        run_all(directory, versions, clients[i % 3](), workers=(1, 8)[i % 2])
        outputs.add((directory / "run" / "correlate.jsonl").read_bytes())
        infos.add((directory / "run" / CORRELATE_INFO).read_bytes())
    assert len(outputs) == 1 and len(infos) == 1


def test_replay_of_a_failure_records_no_requests(tmp_path: Path, router: Router) -> None:
    versions = [serve(router)]
    _, snapshot = run_all(tmp_path, versions, failing(router, ARCHIVE, 100))
    recorded = network_info(tmp_path)
    assert (recorded["requests"], recorded["failed_requests"], recorded["still_failing"]) == (
        2,
        1,
        1,
    )
    snapshot.save(tmp_path / "correlate-snapshot.json")
    saved = Snapshot.load(tmp_path / "correlate-snapshot.json")
    (replayed,), _ = run_all(tmp_path, versions, offline(), snapshot=saved)
    # Nothing was recorded for the failed archive: on replay it is a permanent replay miss.
    assert compared(replayed).startswith(f"No comparison: archive: replay miss: GET {ARCHIVE}")
    network = network_info(tmp_path)
    assert network["lookups"] == 1  # unchanged; the network counts are zero
    assert network["first_pass"] == network["requests"] == network["failed_requests"] == 0
    assert network["retry_passes"] == network["still_failing"] == 0


def test_a_rejected_archive_is_downloaded_once(
    tmp_path: Path, router: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = HttpFetcher.__init__

    def small(self: HttpFetcher, *args: Any, **kwargs: Any) -> None:
        kwargs["max_bytes"] = 4000  # the archive below is larger: rejected, not recorded
        original(self, *args, **kwargs)

    monkeypatch.setattr(HttpFetcher, "__init__", small)
    versions = [serve(router, f"k{i}") for i in range(5)]
    noise = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(256)) * 3
    router.add_bytes(ARCHIVE, make_tar_gz([TarEntry(f"r-{A}/blob.bin", noise)]))
    results, _ = run_all(tmp_path, versions, router.client(), workers=8)
    assert router.requests.count(ARCHIVE) == 1  # the other four versions reuse the rejection
    texts = {compared(r) for r in results}
    assert len(texts) == 1 and "archive" in next(iter(texts)), texts


# --- Dependency lookups (`npm.dependency.fresh-foreign`) -----------------------------------

DEP_AS_OF = datetime(2026, 10, 29, 12, tzinfo=UTC)


def dependent(name: str, *deps: str, update: bool = False) -> Candidate:
    """A new package `name` (or, with `update`, a new version of it) published by `me` an hour
    before `DEP_AS_OF`, depending on `deps`; never routed, so Stage 4 doesn't compare it with a
    repository."""
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version="1.0.1"),
        publish=PublishInfo(
            published_at=DEP_AS_OF - timedelta(hours=1), publisher="me", maintainers=("me",)
        ),
        manifest={"dependencies": dict.fromkeys(deps, "^1.0.0")},
    )
    previous = None
    if update:
        previous = snapshot.model_copy(
            update={
                "ref": snapshot.ref.model_copy(update={"version": "1.0.0"}),
                "manifest": {},
            }
        )
    return Candidate(change=Change(new=snapshot, previous=previous))


def serve_packument(router: Router, name: str, *, hours_old: float = 20) -> str:
    first = (DEP_AS_OF - timedelta(hours=hours_old)).isoformat()
    people = [{"name": "stranger"}]
    url = packument_url(name)
    router.add_json(
        url,
        {
            "name": name,
            "maintainers": people,
            "time": {"created": first, "1.0.0": first},
            "versions": {"1.0.0": {"name": name, "maintainers": people}},
        },
    )
    return url


def run_dependencies(
    tmp_path: Path,
    candidates: list[Candidate],
    client: httpx.Client,
    *,
    snapshot: Snapshot | None = None,
    cap: int | None = MAX_DEPENDENCY_LOOKUPS,
    workers: int = 8,
) -> tuple[tuple[Candidate, ...], Snapshot, dict[str, Any]]:
    """Stage 4 with a dependency lookup over `candidates`, recording (or replaying) requests.
    Returns the results, the snapshot and `correlate.json`'s `dependency_lookups`."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(run_dir / "triage.jsonl", candidates)
    (run_dir / "ast.jsonl").write_bytes(b"")
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=snapshot if snapshot is not None else Snapshot(),
        mode=FetchMode.RECORD if snapshot is None else FetchMode.REPLAY,
        client=client,
        retry=RetryPolicy(max_attempts=ATTEMPTS),
    )
    ctx = CorrelationContext(as_of=DEP_AS_OF, dependencies=NpmDependencyLookup(fetcher, cap=cap))
    results = correlate_run(
        run_dir, ctx, CORRELATION_RULES, repo=repo_lookup(fetcher), workers=workers
    )
    fetcher.close()
    info = json.loads((run_dir / CORRELATE_INFO).read_bytes())
    return tuple(results), fetcher.snapshot, info["dependency_lookups"]


def dependency_findings(candidate: Candidate) -> list[tuple[str, str]]:
    return [
        (f.severity.value, f.explanation)
        for f in candidate.findings
        if f.rule_id == "npm.dependency.fresh-foreign"
    ]


def test_dependency_lookup_is_recorded_once_per_name(tmp_path: Path, router: Router) -> None:
    url = serve_packument(router, "fresh-dep")
    candidates = [dependent(f"app-{i}", "fresh-dep") for i in range(5)]
    results, snapshot, info = run_dependencies(tmp_path, candidates, router.client())
    assert router.requests.count(url) == 1  # one request for the run, however many dependents
    assert f"GET {url} accept=application/json" in snapshot.entries  # the key Stage 0 uses
    for result in results:
        ((severity, text),) = dependency_findings(result)
        assert severity == "medium" and "first published 19.0 hours before" in text
        assert result.history[-1].forwarded
    assert info == {
        "cap": MAX_DEPENDENCY_LOOKUPS,
        "per_release": MAX_LOOKUPS_PER_RELEASE,
        "names": 1,
        "undeclared": 0,
        "capped": 0,
        "releases_limited": 0,
        "looked_up": 1,
        "found": 1,
        "missing": 0,
        "failed": 0,
        "first_pass": 0,
        "requests": 1,
        "failed_requests": 0,
        "retry_passes": 0,
        "retry_skipped": None,
        "still_failing": 0,
        "versions_not_evaluated": 0,
        "errors": {},
    }


def test_dependency_lookup_replays_byte_identically(tmp_path: Path, router: Router) -> None:
    serve_packument(router, "fresh-dep")
    serve_packument(router, "old-dep", hours_old=24 * 400)
    candidates = [dependent("app", "fresh-dep", "old-dep", "missing-dep"), dependent("b", "x")]
    recorded, snapshot, info = run_dependencies(tmp_path, candidates, router.client())
    assert info["found"] == 2 and info["missing"] == 2
    # The 404s are what the run recorded: a finding now, and the same one in the replay.
    for result, name in zip(recorded, ("missing-dep", "x"), strict=True):
        (found,) = (f for f in result.findings if f.rule_id == "npm.dependency.missing")
        assert f"`{name}`" in found.explanation and result.history[-1].forwarded
    correlated = (tmp_path / "run" / "correlate.jsonl").read_bytes()
    correlate_json = (tmp_path / "run" / CORRELATE_INFO).read_bytes()
    snapshot.save(tmp_path / "correlate-snapshot.json")
    saved = Snapshot.load(tmp_path / "correlate-snapshot.json")
    replayed, _, replay_info = run_dependencies(tmp_path, candidates, offline(), snapshot=saved)
    assert replayed == recorded
    assert (tmp_path / "run" / "correlate.jsonl").read_bytes() == correlated
    # The same counts, except that a replay sends no requests (like repository lookups).
    assert (info["requests"], replay_info["requests"]) == (4, 0)
    recorded_json = json.loads(correlate_json)
    recorded_json["dependency_lookups"]["requests"] = 0
    assert json.loads((tmp_path / "run" / CORRELATE_INFO).read_bytes()) == recorded_json


def test_dependency_network_failure_is_not_evaluated(tmp_path: Path, router: Router) -> None:
    url = serve_packument(router, "fresh-dep")
    router.offline.add(url)
    candidates = [dependent("app", "fresh-dep"), dependent("other", "fresh-dep")]
    results, snapshot, info = run_dependencies(tmp_path, candidates, router.client())
    # One back-off per pass, whatever the number of dependents: the first pass and one retry,
    # which recovered nothing, so no second retry.
    assert router.requests.count(url) == 2 * ATTEMPTS
    for result in results:
        ((severity, text),) = dependency_findings(result)
        assert severity == "info" and text.startswith(NOT_EVALUATED)
        assert not result.history[-1].forwarded  # not reported, and not "checked and clean"
        # A network failure is never a missing package (decision 0009).
        assert not any(f.rule_id == "npm.dependency.missing" for f in result.findings)
    assert f"GET {url} accept=application/json" not in snapshot.entries
    assert info["failed"] == info["still_failing"] == 1
    assert (info["first_pass"], info["requests"], info["failed_requests"]) == (1, 1, 1)
    assert info["retry_passes"] == 1 and info["retry_skipped"] is None
    assert info["versions_not_evaluated"] == 2
    assert info["errors"] == {
        "fresh-dep": f"GET {url} failed after 2 attempts: ConnectError: network is unreachable"
    }
    # A replay of the failed run reads the same (a replay miss is also "not fetched").
    correlated = (tmp_path / "run" / "correlate.jsonl").read_bytes()
    run_dependencies(tmp_path, candidates, offline(), snapshot=snapshot)
    assert (tmp_path / "run" / "correlate.jsonl").read_bytes() == correlated


def test_dependency_server_errors_and_malformed(tmp_path: Path, router: Router) -> None:
    router.add_bytes(packument_url("broken"), b"<html>captive portal</html>")
    router.add_json(packument_url("other-name"), {"name": "someone-else"})
    router.add_bytes(packument_url("down"), b"", status=503)
    candidates = [dependent("app", "broken", "down", "gone", "other-name")]
    (result,), _, info = run_dependencies(tmp_path, candidates, router.client())
    # A document that isn't the packument is not evaluated (not silently clean) and not
    # retried; a 503 that persists is retried, then not evaluated; a 404 gives nothing.
    found = dependency_findings(result)
    assert [s for s, _ in found] == ["info"] * 3
    assert [t.split("`")[1] for _, t in found] == ["broken", "down", "other-name"]
    assert router.requests.count(packument_url("broken")) == 1
    assert router.requests.count(packument_url("down")) == 2 * ATTEMPTS
    assert (info["missing"], info["failed"], info["still_failing"]) == (1, 3, 1)
    assert info["errors"]["broken"].startswith("malformed packument: ")
    assert (
        info["errors"]["down"] == f"GET {packument_url('down')} failed after 2 attempts: HTTP 503"
    )


def flaky(router: Router, url: str, times: int, *, delay: str | None = None) -> httpx.Client:
    """The router, except that the first `times` requests for `url` fail to connect, and
    responses for `delay` arrive late."""
    left = {"n": times}

    def handle(request: httpx.Request) -> httpx.Response:
        if str(request.url) == delay:
            time.sleep(0.02)
        if str(request.url) == url and left["n"] > 0:
            left["n"] -= 1
            router.requests.append(url)
            raise httpx.ConnectError("network is unreachable", request=request)
        return router.handler(request)

    return httpx.Client(transport=httpx.MockTransport(handle))


def test_dependency_network_failure_that_clears_is_evaluated(
    tmp_path: Path, router: Router
) -> None:
    url = serve_packument(router, "fresh-dep")
    candidates = [dependent("app", "fresh-dep"), dependent("other", "fresh-dep")]
    results, snapshot, info = run_dependencies(tmp_path, candidates, flaky(router, url, ATTEMPTS))
    assert router.requests.count(url) == ATTEMPTS + 1  # the retry pass got it
    for result in results:
        ((severity, _),) = dependency_findings(result)
        assert severity == "medium" and result.history[-1].forwarded
    assert f"GET {url} accept=application/json" in snapshot.entries
    assert (info["first_pass"], info["retry_passes"], info["still_failing"]) == (1, 1, 0)
    assert info["failed"] == info["versions_not_evaluated"] == 0 and info["errors"] == {}


def test_a_registry_outage_skips_dependency_retries(tmp_path: Path, router: Router) -> None:
    down = [f"down-{i:02}" for i in range(OUTAGE_MIN)]
    router.offline.update(packument_url(n) for n in down)
    serve_packument(router, "up-dep")
    candidates = [dependent("app", "up-dep", *down)]
    results, _, info = run_dependencies(tmp_path, candidates, router.client())
    assert info["retry_skipped"] == "outage" and info["retry_passes"] == 0
    assert (info["requests"], info["failed_requests"]) == (OUTAGE_MIN + 1, OUTAGE_MIN)
    assert info["still_failing"] == OUTAGE_MIN
    (result,) = results
    assert sum(s == "info" for s, _ in dependency_findings(result)) == OUTAGE_MIN


def test_dependency_lookup_cap_is_deterministic(tmp_path: Path, router: Router) -> None:
    for name in ("dep-a", "dep-b", "dep-c"):
        serve_packument(router, name)
    # Run order decides: dep-c (first seen) and dep-a are looked up, dep-b is over the cap.
    candidates = [dependent("app-1", "dep-c"), dependent("app-2", "dep-a", "dep-b")]
    (one, two), _, info = run_dependencies(tmp_path, candidates, router.client(), cap=2)
    assert packument_url("dep-b") not in router.requests
    assert [s for s, _ in dependency_findings(one)] == ["medium"]
    assert [s for s, _ in dependency_findings(two)] == ["medium", "info"]
    assert "1 added dependencies were not checked" in dependency_findings(two)[1][1]
    assert "`dep-b`" in dependency_findings(two)[1][1]
    assert (info["names"], info["capped"], info["looked_up"]) == (3, 1, 2)
    assert info["versions_not_evaluated"] == 1


def test_updates_are_planned_before_new_packages(tmp_path: Path, router: Router) -> None:
    for name in ("dep-new", "dep-upd"):
        serve_packument(router, name)
    candidates = [dependent("fresh", "dep-new"), dependent("app", "dep-upd", update=True)]
    (new, upd), _, info = run_dependencies(tmp_path, candidates, router.client(), cap=1)
    assert packument_url("dep-new") not in router.requests  # the update had the one lookup
    assert [s for s, _ in dependency_findings(upd)] == ["medium"]
    assert [s for s, _ in dependency_findings(new)] == ["info"]
    assert (info["names"], info["capped"]) == (2, 1)


def undeclared(candidate: Candidate, *names: str) -> Candidate:
    """`candidate` with Stage 3's `npm.undeclared-package` naming `names`."""
    finding = Finding(
        rule_id="npm.undeclared-package",
        rule_version=2,
        severity=Severity.INFO,
        weight=0.0,
        title="t",
        explanation="e",
        evidence=tuple(
            Evidence(kind=EvidenceKind.FILE_SPAN, path="a.js", snippet=f"[{n}] require('{n}')")
            for n in names
        ),
    )
    return candidate.model_copy(update={"findings": (finding,)})


def undeclared_findings(candidate: Candidate) -> list[str]:
    return [f.severity.value for f in candidate.findings if f.rule_id == "npm.undeclared.missing"]


def test_undeclared_names_are_planned_after_declared_ones(tmp_path: Path, router: Router) -> None:
    """A name the code loads without declaring it is looked up after every declared
    dependency, so it never takes one's place under the cap; a 404 reports."""
    serve_packument(router, "dep-a")
    candidates = [
        undeclared(dependent("wrapper", update=True), "payload-x"),
        dependent("app", "dep-a"),
    ]
    (wrapper, app), _, info = run_dependencies(
        tmp_path / "capped", candidates, router.client(), cap=1
    )
    assert packument_url("payload-x") not in router.requests
    assert [s for s, _ in dependency_findings(app)] == ["medium"]
    assert undeclared_findings(wrapper) == ["info"]  # over the cap: not evaluated
    assert (info["names"], info["undeclared"], info["capped"]) == (2, 1, 1)
    (wrapper, _), _, info = run_dependencies(tmp_path / "all", candidates, router.client())
    assert undeclared_findings(wrapper) == ["medium"] and wrapper.history[-1].forwarded
    assert (info["looked_up"], info["missing"]) == (2, 1)


def test_one_release_cannot_use_up_the_lookup_cap(tmp_path: Path, router: Router) -> None:
    # A release earlier in the feed adds 2,000 dependencies that don't exist (404s count:
    # nothing tells them apart before asking). It claims `MAX_LOOKUPS_PER_RELEASE` of the cap;
    # a later release's fresh dependency is still checked.
    url = serve_packument(router, "easy-day-js")
    junk = [f"junk-{i:04}" for i in range(2_000)]
    candidates = [dependent("flood", *junk, update=True), dependent("victim", "easy-day-js")]
    (flood, victim), _, info = run_dependencies(tmp_path, candidates, router.client(), cap=100)
    assert router.requests.count(url) == 1
    assert len(router.requests) == MAX_LOOKUPS_PER_RELEASE + 1
    assert [s for s, _ in dependency_findings(victim)] == ["medium"]
    assert victim.history[-1].forwarded
    ((severity, text),) = dependency_findings(flood)  # one finding for 1,960 names, not 1,960
    assert severity == "info" and text.startswith(f"{NOT_EVALUATED}1960 added dependencies")
    assert "`junk-0040`" in text and "(+1950 more)" in text
    assert (info["names"], info["capped"], info["releases_limited"]) == (2_001, 1_960, 1)
    assert (info["looked_up"], info["missing"], info["found"]) == (41, 40, 1)
    assert info["versions_not_evaluated"] == 1


def test_names_another_release_claimed_are_checked_for_free(tmp_path: Path, router: Router) -> None:
    serve_packument(router, "shared-dep")
    junk = [f"junk-{i:03}" for i in range(MAX_LOOKUPS_PER_RELEASE)]
    # `big` lists shared-dep after its own 40 names, but `small` already claimed it.
    candidates = [dependent("small", "shared-dep"), dependent("big", *junk, "zz-shared-dep")]
    candidates[1] = dependent("big", *junk, "shared-dep")
    (_, big), _, info = run_dependencies(tmp_path, candidates, router.client())
    assert [s for s, _ in dependency_findings(big)] == ["medium"]  # nothing over the limit
    assert info["releases_limited"] == 0 and info["capped"] == 0


def test_the_lookup_cap_scales_with_the_window() -> None:
    start = datetime(2026, 10, 1, tzinfo=UTC)
    for hours, days in ((1, 1), (24, 1), (25, 2), (24 * 7, 7)):
        window = Window(start=start, end=start + timedelta(hours=hours))
        assert dependency_cap(window) == MAX_DEPENDENCY_LOOKUPS * days


def test_dependency_output_does_not_depend_on_thread_timing(tmp_path: Path, router: Router) -> None:
    # A name that is down for the run, one that fails once and clears on the retry, a slow one,
    # names over the per-release limit and a cap that binds: whichever thread asks first, every
    # run writes the same files.
    names = ["clears", "down", "slow", *(f"n-{i:02}" for i in range(MAX_LOOKUPS_PER_RELEASE))]
    for name in names:
        serve_packument(router, name)
    router.offline.add(packument_url("down"))
    candidates = [
        dependent("big", *names[3:], "slow", update=True),
        *(dependent(f"app-{i}", "clears", "down", "slow") for i in range(6)),
        dependent("last", "n-00", "unknown"),
    ]
    outputs, infos = set(), set()
    for i in range(20):
        directory = tmp_path / str(i)
        client = flaky(router, packument_url("clears"), ATTEMPTS, delay=packument_url("slow"))
        _, _, info = run_dependencies(
            directory, candidates, client, cap=MAX_LOOKUPS_PER_RELEASE + 2, workers=(1, 8)[i % 2]
        )
        assert info["still_failing"] == 1 and info["capped"] == 2
        outputs.add((directory / "run" / "correlate.jsonl").read_bytes())
        infos.add((directory / "run" / CORRELATE_INFO).read_bytes())
    assert len(outputs) == 1 and len(infos) == 1


def test_run_watchlist_is_the_recorded_one(tmp_path: Path) -> None:
    data = DataDir(tmp_path / "data")
    watchlist = Watchlist(
        ecosystem="npm",
        source="t",
        built_at=datetime(2026, 10, 1, tzinfo=UTC),
        min_monthly_downloads=1,
        entries={"react": WatchEntry(monthly_downloads=10)},
    )
    _, sha = data.watchlists.save("npm", watchlist.id, watchlist)
    manifest = RunManifest(
        run_id="r",
        tool_version="t",
        ecosystem="npm",
        as_of=DEP_AS_OF,
        window=Window(start=DEP_AS_OF - timedelta(hours=1), end=DEP_AS_OF),
        cursor_since=0,
        cursor_until=1,
        snapshot_sha256="0",
        changes_sha256="0",
        change_count=0,
        skipped_count=0,
        packages_seen=0,
    )
    assert run_watchlist(data, manifest) is None
    recorded = manifest.model_copy(update={"watchlist_id": watchlist.id, "watchlist_sha256": sha})
    loaded = run_watchlist(data, recorded)
    assert loaded is not None and "react" in loaded.entries
    with pytest.raises(ValueError, match="changed since it was recorded"):
        run_watchlist(data, recorded.model_copy(update={"watchlist_sha256": "f" * 64}))


def test_versions_of_one_package_share_its_lookup_allowance(tmp_path: Path, router: Router) -> None:
    # 25 versions of one throwaway package, each adding 40 names that don't exist, would use up
    # an hourly run's cap if the allowance were per version. It is per package.
    url = serve_packument(router, "easy-day-js")
    flood = []
    for v in range(25):
        base = dependent("flood", *(f"junk-{v:02}-{i:02}" for i in range(40)), update=True)
        ref = base.change.new.ref.model_copy(update={"version": f"1.0.{v + 1}"})
        new = base.change.new.model_copy(update={"ref": ref})
        flood.append(
            base.model_copy(update={"change": base.change.model_copy(update={"new": new})})
        )
    candidates = [*flood, dependent("victim", "easy-day-js")]
    *_, victim = run_dependencies(tmp_path, candidates, router.client(), cap=1_000)[0]
    assert router.requests.count(url) == 1
    assert len(router.requests) == MAX_LOOKUPS_PER_RELEASE + 1  # flood's 40, then the victim's
    assert [s for s, _ in dependency_findings(victim)] == ["medium"]


def test_a_deeply_nested_packument_is_malformed_not_a_crash(tmp_path: Path, router: Router) -> None:
    router.add_bytes(packument_url("deep"), b"[" * 200_000)
    (result,), _, info = run_dependencies(tmp_path, [dependent("app", "deep")], router.client())
    ((severity, text),) = dependency_findings(result)
    assert severity == "info" and text.startswith(NOT_EVALUATED)  # one fixed text, details below
    assert info["failed"] == 1 and "nested too deeply" in json.dumps(info["errors"])


API_FACTS = "https://api.github.com/repos/o/r"
API_COMPARE = f"https://api.github.com/repos/o/r/compare/{A}...{A}?per_page=1&page=2"


def install_code_finding() -> Finding:
    return Finding(
        rule_id="npm.install-script-changed",
        rule_version=1,
        severity=Severity.MEDIUM,
        weight=3.0,
        title="t",
        explanation="e",
    )


def test_an_established_match_end_to_end(tmp_path: Path, router: Router) -> None:
    router.add_json(
        API_FACTS,
        {
            "full_name": "o/r",
            "fork": False,
            "archived": False,
            "created_at": "2020-01-01T00:00:00Z",
            "stargazers_count": 100,
            "default_branch": "main",
        },
    )
    router.add_json(API_COMPARE, {"status": "identical", "ahead_by": 0, "behind_by": 0})
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=router.client(),
    )
    lookup = repo_lookup(fetcher, token="t")  # noqa: S106
    plain = serve(router)  # flagged, but nothing MEDIUM: no API request
    assert lookup(plain) is not None and API_FACTS not in router.requests
    flagged = plain.model_copy(update={"findings": (install_code_finding(),)})
    comparison = lookup(flagged)
    assert comparison is not None and comparison.trust is not None
    assert comparison.trust.on_default_branch
    result = correlate(flagged, replace(CTX, repo=comparison), CORRELATION_RULES)
    assert "repo.established-match" in {f.rule_id for f in result.findings}
    assert result.history[-1].forwarded  # clearing is off (CLEAR_ESTABLISHED)
    cleared = decide(result.findings, clear_established=True)
    assert not cleared.forwarded and cleared.reason.endswith("cleared by repo.established-match")
    # Without a token the same version is reported, as before.
    untrusted = repo_lookup(fetcher)(flagged)
    assert untrusted is not None and untrusted.trust is None
    assert correlate(flagged, replace(CTX, repo=untrusted), CORRELATION_RULES).history[-1].forwarded
    fetcher.close()


def test_a_history_match_end_to_end(tmp_path: Path, router: Router) -> None:
    """An update whose release is the repository's code at a commit ahead of the previous
    release's: `repo.history-match`, which clears install code only when switched on."""
    old = "e" * 40
    router.add_json(
        API_FACTS,
        {
            "full_name": "o/r",
            "fork": False,
            "archived": False,
            "created_at": "2020-01-01T00:00:00Z",
            "stargazers_count": 1,
            "default_branch": "main",
        },
    )
    router.add_json(API_COMPARE, {"status": "identical", "ahead_by": 0, "behind_by": 0})
    history_url = f"https://api.github.com/repos/o/r/compare/{old}...{A}?per_page=1&page=2"
    router.add_json(history_url, {"status": "ahead", "ahead_by": 5, "behind_by": 0})
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=router.client(),
    )
    lookup = repo_lookup(fetcher, token="t")  # noqa: S106
    plain = serve(router)
    previous = plain.change.new.model_copy(
        update={
            "ref": plain.change.new.ref.model_copy(update={"version": "1.0.0"}),
            "publish": PublishInfo(git_head=old),
        }
    )
    update = plain.model_copy(
        update={
            "change": plain.change.model_copy(update={"previous": previous}),
            "findings": (install_code_finding(),),
        }
    )
    comparison = lookup(update)
    assert comparison is not None and comparison.history is not None
    assert (comparison.history.status, comparison.history.ahead_by) == ("ahead", 5)
    result = correlate(update, replace(CTX, repo=comparison), CORRELATION_RULES)
    ids = {f.rule_id for f in result.findings}
    assert "repo.history-match" in ids and "repo.established-match" not in ids  # 1 star
    assert result.history[-1].forwarded  # clearing is off (CLEAR_HISTORY)
    cleared = decide(result.findings, clear_history=True)
    assert not cleared.forwarded and cleared.reason.endswith("cleared by repo.history-match")
    # Unflagged, the range isn't asked: only the commit equality, which costs nothing. Not
    # even read from this run's answer, so a version's output doesn't depend on which other
    # versions the run looked up first.
    unflagged = lookup(update.model_copy(update={"findings": ()}))
    assert unflagged is not None and unflagged.history is not None
    assert unflagged.history.previous_commit == old and unflagged.history.status is None
    assert router.requests.count(history_url) == 1
    fetcher.close()
