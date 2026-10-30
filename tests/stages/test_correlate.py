"""Stage 4 core: correlation rules, score and report decision, and the run file."""

import json
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kitsunox.core.models import (
    Candidate,
    Change,
    Finding,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.stages import correlate as correlate_module
from kitsunox.stages.correlate import (
    CORRELATE_INFO,
    NETWORK_UNCOMPARED,
    OUTAGE_MIN,
    STAGE_VERSION,
    CorrelationContext,
    correlate,
    correlate_run,
    decide,
    repo_network_failures,
    score,
)
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.repo import NetworkRequests, RepoComparison

CTX = CorrelationContext(as_of=datetime(2026, 10, 28, tzinfo=UTC))


def finding(rule_id: str, severity: Severity, weight: float) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=1,
        severity=severity,
        weight=weight,
        title="t",
        explanation="e",
    )


def candidate(version: str = "1.0.1", *findings: Finding, name: str = "kx") -> Candidate:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
        publish=PublishInfo(),
        manifest={},
    )
    return Candidate(change=Change(new=snapshot), findings=findings)


def test_score_counts_each_rule_once_and_ignores_info() -> None:
    found = [
        finding("a", Severity.LOW, 1.0),
        finding("a", Severity.LOW, 1.0),  # Stage 2: one finding per matching file
        finding("b", Severity.LOW, 2.0),
        finding("c", Severity.INFO, 9.0),
    ]
    assert score(found) == 3.0


def test_report_on_severity_or_score() -> None:
    assert not decide([finding("a", Severity.LOW, 1.0)], report_score=3).forwarded
    lows = [finding("a", Severity.LOW, 1.0), finding("b", Severity.LOW, 2.0)]
    decision = decide(lows, report_score=3)
    assert decision.forwarded and decision.reason == "score 3 >= 3"
    medium = decide([finding("m", Severity.MEDIUM, 0.5)], report_score=3)
    assert medium.forwarded and medium.reason == "score 0.5; medium: m"


def test_an_unwatched_downgrade_alone_is_not_reported() -> None:
    weak = finding("npm.publish-method.downgrade", Severity.MEDIUM, 3.0)
    assert not decide([weak]).forwarded
    assert decide([weak, finding("m", Severity.MEDIUM, 1.0)]).forwarded
    assert decide(
        [weak, finding("a", Severity.LOW, 2.0), finding("b", Severity.LOW, 1.0)]
    ).forwarded
    assert decide([finding("npm.publish-method.downgrade", Severity.HIGH, 5.0)]).forwarded


class Echo:
    """Adds a LOW finding naming how many findings it saw."""

    version = 1

    def __init__(self, rule_id: str) -> None:
        self.id = rule_id

    def evaluate_candidate(self, c: Candidate, ctx: CorrelationContext) -> Sequence[Finding]:
        return [finding(f"{self.id}:{len(c.findings)}", Severity.LOW, 1.0)]


def test_rules_see_earlier_findings() -> None:
    result = correlate(
        candidate("1.0.1", finding("s1", Severity.LOW, 1.0)),
        CTX,
        [Echo("x"), Echo("y")],
        report_score=3,
    )
    assert [f.rule_id for f in result.findings] == ["s1", "x:1", "y:2"]
    assert result.history[-1].stage == "correlate" and result.history[-1].forwarded


def test_run_reads_every_triaged_version(tmp_path: Path) -> None:
    routed, quiet = candidate("1.0.1"), candidate("2.0.0", name="other")
    analysed = routed.model_copy(update={"findings": (finding("s2", Severity.MEDIUM, 3.0),)})
    write_jsonl(tmp_path / "triage.jsonl", [routed, quiet])
    batch = PackageBatch(ecosystem="npm", name="kx", base=None, versions=(analysed,))
    write_jsonl(tmp_path / "ast.jsonl", [batch])
    first, second = correlate_run(tmp_path, CTX, [Echo("x")], report_score=5)
    assert [f.rule_id for f in first.findings] == ["s2", "x:1"] and first.history[-1].forwarded
    assert [f.rule_id for f in second.findings] == ["x:0"] and not second.history[-1].forwarded
    assert len((tmp_path / "correlate.jsonl").read_bytes().splitlines()) == 2
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())
    assert info["known_bad"] is None and info["report_score"] == 5
    assert info["stage_version"] == STAGE_VERSION


def test_run_streams_in_order_across_write_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Five versions in windows of two; the last of two batches holding a version wins.
    versions = [candidate(f"1.0.{i}") for i in range(5)]
    stale = versions[3].model_copy(update={"findings": (finding("old", Severity.LOW, 1.0),)})
    fresh = versions[3].model_copy(update={"findings": (finding("s2", Severity.LOW, 1.0),)})
    write_jsonl(tmp_path / "triage.jsonl", versions)
    write_jsonl(
        tmp_path / "ast.jsonl",
        [
            PackageBatch(ecosystem="npm", name="kx", base=None, versions=(v,))
            for v in (stale, fresh)
        ],
    )
    monkeypatch.setattr(correlate_module, "WRITE_WINDOW", 2)
    out = correlate_run(tmp_path, CTX, [Echo("x")], report_score=5, workers=3)
    assert [c.change.new.ref.version for c in out] == [f"1.0.{i}" for i in range(5)]
    assert [f.rule_id for f in out[3].findings] == ["s2", "x:1"]
    assert [c.change.new.ref.version for c in out[1:3]] == ["1.0.1", "1.0.2"]
    lines = (tmp_path / "correlate.jsonl").read_bytes().splitlines()
    assert [Candidate.model_validate_json(line) for line in lines] == list(out)
    out.close()


def flagged(name: str) -> Candidate:
    """A version Stage 2 flagged, so Stage 4 compares it with its repository."""
    decision = StageDecision(stage="static", forwarded=True, reason="rules: s2")
    return candidate("1.0.1", name=name).model_copy(update={"history": (decision,)})


class FlakyRepo:
    """Repository lookups by package name: how many network failures each gets before it
    works (`ALWAYS`: never), or a permanent reason for no comparison. `shared` maps names to
    the one request they need (e.g. a monorepo's refs; default: their own); `files` names
    versions whose release files failed on the network."""

    ALWAYS = 99

    def __init__(
        self,
        failures: dict[str, int],
        permanent: dict[str, str],
        *,
        shared: dict[str, str] | None = None,
        files: frozenset[str] = frozenset(),
    ) -> None:
        self.failures = failures
        self.permanent = permanent
        self.shared = shared or {}
        self.files = files
        self.calls: Counter[str] = Counter()
        self.passes = 0
        self.sent: set[str] = set()
        self.failed: set[str] = set()

    def new_pass(self) -> None:
        self.passes += 1
        self.sent.clear()
        self.failed.clear()

    def requests(self) -> NetworkRequests:
        return NetworkRequests(len(self.sent), tuple((k, "HTTP 503") for k in sorted(self.failed)))

    def __call__(self, c: Candidate) -> RepoComparison:
        name = c.change.new.ref.name
        self.calls[name] += 1
        if name in self.files:
            return RepoComparison(unavailable="package files: network", files_transient=True)
        if name in self.permanent:
            return RepoComparison(unavailable=self.permanent[name])
        key = self.shared.get(name, name)
        self.sent.add(key)
        if self.calls[name] <= self.failures.get(name, 0):
            self.failed.add(key)
            return RepoComparison(unavailable=f"network: {key} unavailable", transient=True)
        return RepoComparison(code_files=1, identical=1)


def write_run(run_dir: Path, *candidates: Candidate) -> None:
    write_jsonl(run_dir / "triage.jsonl", candidates)
    (run_dir / "ast.jsonl").write_bytes(b"")


def test_network_failures_are_retried_after_the_first_pass(tmp_path: Path) -> None:
    write_run(tmp_path, flagged("flaky"), flagged("down"), flagged("gone"), candidate(name="quiet"))
    repo = FlakyRepo({"flaky": 1, "down": FlakyRepo.ALWAYS}, {"gone": "archive: HTTP 404"})
    flaky, down, gone, quiet = correlate_run(tmp_path, CTX, [], repo=repo, retry_passes=2)
    # `flaky` recovers on the first retry, so a second retry runs for `down`, which still fails.
    # A 404 is permanent and never retried; versions `wants_repo` skips are never looked up.
    assert repo.calls == Counter({"flaky": 2, "down": 3, "gone": 1})
    assert repo.passes == 2  # told before each retry pass, so it forgets the last one's failures
    assert flaky.history[-1].reason == "score 0"
    assert down.history[-1].reason == f"score 0{NETWORK_UNCOMPARED}"
    assert gone.history[-1].reason == quiet.history[-1].reason == "score 0"
    assert repo_network_failures((flaky, down, gone, quiet)) == 1
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())
    assert info["repo_network"] == {
        "lookups": 3,
        "first_pass": 2,
        "requests": 2,  # `gone` failed for good: a permanent answer, not a network request
        "failed_requests": 2,
        "retry_passes": 2,
        "retry_skipped": None,
        "still_failing": 1,
        "package_files_network": 0,
        "errors": {"down": "HTTP 503"},  # the last pass's failed requests
    }


def test_a_small_outage_costs_one_retry_pass(tmp_path: Path) -> None:
    write_run(tmp_path, flagged("a"), flagged("b"))  # all failing, but fewer than OUTAGE_MIN
    repo = FlakyRepo({"a": FlakyRepo.ALWAYS, "b": FlakyRepo.ALWAYS}, {})
    versions = correlate_run(tmp_path, CTX, [], repo=repo, retry_passes=5)
    assert repo.calls == Counter({"a": 2, "b": 2})  # nothing recovered, so no second retry
    assert repo_network_failures(versions) == 2
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())
    assert info["repo_network"] == {
        "lookups": 2,
        "first_pass": 2,
        "requests": 2,
        "failed_requests": 2,
        "retry_passes": 1,
        "retry_skipped": None,
        "still_failing": 2,
        "package_files_network": 0,
        "errors": {"a": "HTTP 503", "b": "HTTP 503"},
    }


def names(prefix: str, n: int) -> list[str]:
    return [f"{prefix}{i:03}" for i in range(n)]


def test_an_outage_skips_the_retry_passes(tmp_path: Path) -> None:
    down, up = names("down", OUTAGE_MIN), names("up", OUTAGE_MIN)  # half of the requests fail
    write_run(tmp_path, *(flagged(n) for n in down + up))
    repo = FlakyRepo(dict.fromkeys(down, 1), {})  # a retry would even have worked
    versions = correlate_run(tmp_path, CTX, [], repo=repo)
    assert set(repo.calls.values()) == {1} and repo.passes == 0
    assert repo_network_failures(versions) == OUTAGE_MIN
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())
    network = info["repo_network"]
    assert network.pop("errors") == dict.fromkeys(down, "HTTP 503")
    assert network == {
        "lookups": 2 * OUTAGE_MIN,
        "first_pass": OUTAGE_MIN,
        "requests": 2 * OUTAGE_MIN,
        "failed_requests": OUTAGE_MIN,
        "retry_passes": 0,
        "retry_skipped": "outage",
        "still_failing": OUTAGE_MIN,
        "package_files_network": 0,
    }


def test_many_failures_among_more_requests_are_retried(tmp_path: Path) -> None:
    down, up = names("down", OUTAGE_MIN), names("up", OUTAGE_MIN + 1)  # under half fail
    write_run(tmp_path, *(flagged(n) for n in down + up))
    repo = FlakyRepo(dict.fromkeys(down, 1), {})
    versions = correlate_run(tmp_path, CTX, [], repo=repo)
    assert repo.passes == 1 and repo_network_failures(versions) == 0
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())
    assert info["repo_network"]["retry_skipped"] is None


def test_retries_can_be_turned_off(tmp_path: Path) -> None:
    write_run(tmp_path, flagged("a"))
    repo = FlakyRepo({"a": 1}, {})
    (version,) = correlate_run(tmp_path, CTX, [], repo=repo, retry_passes=0)
    assert repo.calls == Counter({"a": 1}) and repo_network_failures([version]) == 1


def test_the_outage_guard_counts_requests_not_versions(tmp_path: Path) -> None:
    # A monorepo burst: many versions, one refs request, which failed once. One failure is no
    # outage, however many versions needed it (it was, while the guard counted versions).
    burst = names("pkg", 2 * OUTAGE_MIN)
    write_run(tmp_path, *(flagged(n) for n in burst))
    repo = FlakyRepo(dict.fromkeys(burst, 1), {}, shared=dict.fromkeys(burst, "o/r refs"))
    versions = correlate_run(tmp_path, CTX, [], repo=repo)
    assert repo.passes == 1 and repo_network_failures(versions) == 0
    network = json.loads((tmp_path / CORRELATE_INFO).read_text())["repo_network"]
    assert network["first_pass"] == 2 * OUTAGE_MIN
    assert (network["requests"], network["failed_requests"]) == (1, 1)
    assert network["retry_skipped"] is None and network["errors"] == {}


def test_release_files_failing_on_the_network_are_left_to_stage_2(tmp_path: Path) -> None:
    write_run(tmp_path, flagged("nofiles"), flagged("down"))
    repo = FlakyRepo({"down": FlakyRepo.ALWAYS}, {}, files=frozenset({"nofiles"}))
    nofiles, down = correlate_run(tmp_path, CTX, [], repo=repo)
    assert repo.calls == Counter({"nofiles": 1, "down": 2})  # not retried by Stage 4
    assert nofiles.history[-1].reason == "score 0"  # not a repository network failure
    assert repo_network_failures((nofiles, down)) == 1
    network = json.loads((tmp_path / CORRELATE_INFO).read_text())["repo_network"]
    assert network["first_pass"] == 1 and network["still_failing"] == 1
    assert network["package_files_network"] == 1
