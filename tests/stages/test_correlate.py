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
    Popularity,
    PublishInfo,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.stages import correlate as correlate_module
from kitsunox.stages.correlate import (
    BUDGET_UNCOMPARED,
    CORRELATE_INFO,
    LOW_CAP,
    NETWORK_UNCOMPARED,
    OUTAGE_MIN,
    STAGE_VERSION,
    CorrelationContext,
    correlate,
    correlate_run,
    decide,
    explained,
    repo_network_failures,
    repo_over_budget,
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


def test_low_rules_together_count_at_most_the_cap() -> None:
    """Six routine LOW regexes of a large release no longer reach the report score alone."""
    lows = [finding(f"static.{i}", Severity.LOW, 1.0) for i in range(6)]
    assert score(lows) == LOW_CAP
    assert not decide(lows).forwarded
    # A rule with any finding above LOW is outside the cap, at its largest weight.
    mixed = [*lows, finding("x", Severity.LOW, 1.0), finding("x", Severity.MEDIUM, 3.0)]
    assert score(mixed) == 3.0 + LOW_CAP
    weak = finding("npm.publish-method.downgrade", Severity.MEDIUM, 3.0)
    assert decide([weak, *lows]).forwarded  # a weak MEDIUM with three LOWs still reaches 6


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


def test_a_watched_downgrade_without_a_cosignal_alone_is_not_reported() -> None:
    """Downgrade v4 lowers a watched package's downgrade without a co-signal to MEDIUM 3:
    `WEAK_ALONE` then keeps it from reporting on its own (the `@knapsack/*` 4.110.0 shape)."""
    assert not decide([finding("npm.publish-method.downgrade", Severity.MEDIUM, 3.0)]).forwarded


def test_the_axios_shape_is_still_reported() -> None:
    """`axios@1.14.1` as `vm-day1` scores it (unwatched): the downgrade keeps MEDIUM 3 because
    a dependency was added, and the LOWs reach the cap: 3 + 3 = 6, exactly the bar."""
    findings = [
        finding("npm.publish-method.downgrade", Severity.MEDIUM, 3.0),
        finding("npm.dependency.added", Severity.LOW, 1.0),
        finding("npm.provenance.githead-dropped", Severity.LOW, 2.0),
        finding("npm.dependency.name-embeds-popular", Severity.LOW, 1.0),
    ]
    assert decide(findings).forwarded


def test_capability_gains_and_webhook_placeholders_alone_are_not_reported() -> None:
    for rule_id in ("code.capability-gained", "static.webhook-placeholder"):
        weak = finding(rule_id, Severity.MEDIUM, 3.0)
        assert not decide([weak]).forwarded, rule_id
        assert decide([weak, finding("m", Severity.MEDIUM, 1.0)]).forwarded, rule_id


def decide_clearing(findings: Sequence[Finding], report_score: float = 6.0) -> StageDecision:
    return decide(findings, report_score=report_score, clear_established=True)


def test_clearing_by_an_established_match_is_off_by_default() -> None:
    match = finding("repo.established-match", Severity.INFO, 0.0)
    changed = finding("npm.install-script-changed", Severity.MEDIUM, 3.0)
    assert decide([changed, match]).forwarded


def test_an_established_match_clears_install_code_findings() -> None:
    match = finding("repo.established-match", Severity.INFO, 0.0)
    changed = finding("npm.install-script-changed", Severity.MEDIUM, 3.0)
    code = finding("npm.install-script-code", Severity.MEDIUM, 2.0)
    assert decide_clearing([changed, code]).forwarded
    cleared = decide_clearing([changed, code, match])
    assert not cleared.forwarded
    assert cleared.reason == (
        "score 5; npm.install-script-changed, npm.install-script-code cleared by "
        "repo.established-match"
    )
    new_hook = finding("npm.install-hook", Severity.MEDIUM, 3.0)  # a new package's hook
    assert not decide_clearing([new_hook, match]).forwarded


def test_a_history_match_clears_install_code_only_when_switched_on() -> None:
    match = finding("repo.history-match", Severity.INFO, 0.0)
    changed = finding("npm.install-script-changed", Severity.MEDIUM, 3.0)
    assert decide([changed, match]).forwarded  # off by default
    assert decide([changed, match], clear_established=True).forwarded  # the other match's
    cleared = decide([changed, match], clear_history=True)
    assert not cleared.forwarded
    assert cleared.reason == "score 3; npm.install-script-changed cleared by repo.history-match"
    late = finding("repo.commit-after-release", Severity.MEDIUM, 3.0)
    assert decide([changed, late, match], clear_history=True).forwarded
    both = finding("repo.established-match", Severity.INFO, 0.0)
    cleared = decide([changed, match, both], clear_established=True, clear_history=True)
    assert cleared.reason.endswith("cleared by repo.established-match, repo.history-match")


def test_an_established_match_clears_nothing_else() -> None:
    match = finding("repo.established-match", Severity.INFO, 0.0)
    changed = finding("npm.install-script-changed", Severity.MEDIUM, 3.0)
    added_hook = finding("npm.install-hook", Severity.HIGH, 5.0)  # added to an update
    assert decide_clearing([added_hook, changed, match]).forwarded
    for other in (
        finding("static.hardcoded-ip", Severity.MEDIUM, 2.0),
        finding("sandbox.process-spawn", Severity.MEDIUM, 2.0),
        finding("static.exfil-endpoint", Severity.HIGH, 5.0),
    ):
        assert decide_clearing([changed, other, match]).forwarded, other.rule_id
    # The rest of the score still reports on its own (3 < 4 without the cleared finding).
    lows = [finding(f"low{i}", Severity.LOW, 1.0) for i in range(3)]
    assert not decide_clearing([changed, *lows, match], report_score=4).forwarded
    assert decide_clearing([changed, *lows, match], report_score=3).forwarded


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


def test_a_build_tool_explanation_makes_the_install_hook_low() -> None:
    """F2: Stage 3's `npm.install-build-tool` (every hook only runs a build tool, binding.gyp
    runs no command) makes `npm.install-hook` LOW, weight 1, with a note; nothing else."""
    hook = finding("npm.install-hook", Severity.MEDIUM, 5.0)
    added = finding("npm.install-hook", Severity.HIGH, 5.0)
    code = finding("npm.install-script-code", Severity.MEDIUM, 3.0)
    tool = finding("npm.install-build-tool", Severity.INFO, 0.0)
    result = correlate(candidate("1.0.1", hook, added, tool), CTX, [])
    assert not result.history[-1].forwarded
    assert [(f.severity, f.weight) for f in result.findings[:2]] == [(Severity.LOW, 1.0)] * 2
    assert result.findings[0].explanation.endswith("(npm.install-build-tool).")
    assert result.findings[2] == tool
    other = correlate(candidate("1.0.1", hook, code, tool), CTX, [])
    assert other.history[-1].forwarded  # the install code's own finding still reports
    assert other.findings[1] == code
    alone = correlate(candidate("1.0.1", hook), CTX, [])
    assert alone.findings == (hook,) and alone.history[-1].forwarded
    low = finding("npm.install-hook", Severity.LOW, 1.0)
    assert explained([low, tool]) == (low, tool)


def test_an_explained_install_makes_the_three_install_rules_low() -> None:
    """S1-S3: Stage 3's `npm.install-explained` explains `npm.install-hook`,
    `npm.install-script-changed` and `npm.install-script-code`; never a content finding or
    `code.capability-gained`."""
    hook = finding("npm.install-hook", Severity.HIGH, 5.0)
    changed = finding("npm.install-script-changed", Severity.MEDIUM, 3.0)
    code = finding("npm.install-script-code", Severity.MEDIUM, 3.0)
    shape = finding("npm.install-explained", Severity.INFO, 0.0)
    result = correlate(candidate("1.0.1", hook, changed, code, shape), CTX, [])
    assert not result.history[-1].forwarded
    assert [(f.severity, f.weight) for f in result.findings[:3]] == [(Severity.LOW, 1.0)] * 3
    assert all(f.explanation.endswith("(npm.install-explained).") for f in result.findings[:3])
    for content in (
        finding("npm.install-script-obfuscated", Severity.HIGH, 4.0),
        finding("static.exfil-endpoint", Severity.HIGH, 4.0),
        finding("agent.hostile-instructions", Severity.MEDIUM, 3.0),
    ):
        kept = correlate(candidate("1.0.1", hook, content, shape), CTX, [])
        assert kept.history[-1].forwarded and kept.findings[1] == content
    # A build tool's note comes first when both explanations are present.
    tool = finding("npm.install-build-tool", Severity.INFO, 0.0)
    both = explained([hook, tool, shape])
    assert both[0].explanation.endswith("(npm.install-build-tool).")


def test_an_inert_install_makes_only_the_install_hook_low() -> None:
    """Round 4 (B1): Stage 3's `npm.install-inert` explains `npm.install-hook` and nothing
    else: the install code's own findings and content findings (`static.channel-follow`, the
    Baileys forks' follow) still report."""
    hook = finding("npm.install-hook", Severity.MEDIUM, 5.0)
    inert = finding("npm.install-inert", Severity.INFO, 0.0)
    result = correlate(candidate("1.0.1", hook, inert), CTX, [])
    assert not result.history[-1].forwarded
    assert (result.findings[0].severity, result.findings[0].weight) == (Severity.LOW, 1.0)
    assert result.findings[0].explanation.endswith("(npm.install-inert).")
    for other in (
        finding("npm.install-script-changed", Severity.MEDIUM, 3.0),
        finding("static.channel-follow", Severity.MEDIUM, 3.0),
    ):
        kept = correlate(candidate("1.0.1", hook, other, inert), CTX, [])
        assert kept.history[-1].forwarded and kept.findings[1] == other


def test_a_missing_hook_target_makes_only_the_install_hook_low() -> None:
    """Round 6 (Q1): Stage 2's `npm.artifact.install-target-missing` (every hook runs a file
    the package doesn't ship) explains `npm.install-hook` and nothing else."""
    hook = finding("npm.install-hook", Severity.MEDIUM, 5.0)
    missing = finding("npm.artifact.install-target-missing", Severity.INFO, 0.0)
    result = correlate(candidate("1.0.1", hook, missing), CTX, [])
    assert not result.history[-1].forwarded
    assert (result.findings[0].severity, result.findings[0].weight) == (Severity.LOW, 1.0)
    assert result.findings[0].explanation.endswith("(npm.artifact.install-target-missing).")
    other = finding("static.obfuscated", Severity.MEDIUM, 3.0)
    kept = correlate(candidate("1.0.1", hook, other, missing), CTX, [])
    assert kept.history[-1].forwarded and kept.findings[1] == other


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


def watched_update(name: str) -> Candidate:
    """An update of a watched package that no stage flagged: compared if the budget allows."""
    plain = candidate(name=name)
    popularity = Popularity(source="watchlist:t", downloads=10**6, period_days=7, watched=True)
    previous = plain.change.new.model_copy(
        update={"ref": PackageVersionRef(ecosystem="npm", name=name, version="1.0.0")}
    )
    change = plain.change.model_copy(update={"previous": previous, "popularity": popularity})
    return plain.model_copy(update={"change": change})


def test_a_run_compares_at_most_its_budget_flagged_versions_first(tmp_path: Path) -> None:
    """The 4-day catch-up of 2026-11-07 wanted 80,934 comparisons and filled the disk."""
    write_run(
        tmp_path,
        watched_update("w1"),
        flagged("f1"),
        watched_update("w2"),
        candidate(name="quiet"),
        flagged("f2"),
        watched_update("w3"),
    )
    repo = FlakyRepo({}, {})
    out = list(correlate_run(tmp_path, CTX, [], repo=repo, max_comparisons=3))
    # Both flagged versions, then the first watched update in triage order.
    assert set(repo.calls) == {"f1", "f2", "w1"}
    reasons = {c.change.new.ref.name: c.history[-1].reason for c in out}
    assert reasons["w2"] == reasons["w3"] == f"score 0{BUDGET_UNCOMPARED}"
    assert reasons["w1"] == reasons["f1"] == reasons["quiet"] == "score 0"
    assert repo_over_budget(out) == 2
    assert repo_network_failures(out) == 0
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())
    assert info["repo_budget"] == {
        "max_comparisons": 3,
        "wanted": 5,
        "flagged": 2,
        "over_budget": 2,
    }
    assert info["repo_network"]["lookups"] == 3


def test_flagged_versions_over_the_budget_are_noted_too(tmp_path: Path) -> None:
    write_run(tmp_path, flagged("f1"), flagged("f2"), watched_update("w1"))
    repo = FlakyRepo({}, {})
    out = list(correlate_run(tmp_path, CTX, [], repo=repo, max_comparisons=1))
    assert set(repo.calls) == {"f1"}
    assert repo_over_budget(out) == 2


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
