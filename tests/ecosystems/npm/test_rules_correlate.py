"""Stage 4 npm rules: gitHead provenance and known malware (dependencies and the package)."""

from datetime import UTC, datetime, timedelta
from typing import Any

from conftest import mal, osv_zip
from kitsunox.core.models import (
    Candidate,
    Change,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.rules.correlate import (
    PROJECTION_DAYS,
    GitHeadDropped,
    KnownMalwareDependency,
    KnownMalwareSelf,
    RevivedWithNewDependency,
)
from kitsunox.evaluation.labels import AffectedRange, LabelSet, MalwareLabel, parse_osv_export
from kitsunox.stages.correlate import CorrelationContext, correlate
from kitsunox.stages.review import CORRELATION_RULES

T0 = datetime(2026, 10, 28, tzinfo=UTC)


def snap(version: str, manifest: dict[str, Any] | None = None, **publish: Any) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(**publish),
        manifest=manifest or {},
    )


def cand(new: VersionSnapshot, previous: VersionSnapshot | None = None) -> Candidate:
    return Candidate(change=Change(new=new, previous=previous))


def test_githead_dropped() -> None:
    rule, ctx = GitHeadDropped(), CorrelationContext(as_of=T0)
    (found,) = rule.evaluate_candidate(cand(snap("2"), snap("1", git_head="abc123")), ctx)
    assert found.evidence[0].before == "abc123"
    assert not rule.evaluate_candidate(cand(snap("2", git_head="d"), snap("1", git_head="a")), ctx)
    assert not rule.evaluate_candidate(cand(snap("2"), snap("1")), ctx)  # never had one
    assert not rule.evaluate_candidate(cand(snap("2")), ctx)  # new package
    assert (found.weight, found.rule_version) == (2.0, 2)


def test_githead_dropped_beside_a_downgrade_weighs_one() -> None:
    """v2 (round 5, G1): the downgrade already says the release left the CI path; an INFO
    downgrade finding (none is emitted today) would not count."""
    rule, ctx = GitHeadDropped(), CorrelationContext(as_of=T0)
    base = cand(snap("2"), snap("1", git_head="abc123"))

    def downgrade(severity: Severity) -> Finding:
        return Finding(
            rule_id="npm.publish-method.downgrade",
            rule_version=4,
            severity=severity,
            weight=3.0,
            title="t",
            explanation="1 was published from CI.",
        )

    for severity, weight in ((Severity.MEDIUM, 1.0), (Severity.LOW, 1.0), (Severity.INFO, 2.0)):
        with_downgrade = base.model_copy(update={"findings": (downgrade(severity),)})
        (found,) = rule.evaluate_candidate(with_downgrade, ctx)
        assert (found.severity, found.weight) == (Severity.LOW, weight)
        assert found.explanation.endswith("left the CI path.") is (weight == 1.0)


def label(
    published: datetime, *ranges: AffectedRange, versions: tuple[str, ...] = ()
) -> MalwareLabel:
    return MalwareLabel(id="MAL-1", published=published, versions=versions, ranges=ranges)


LABELS = LabelSet(
    ecosystem="npm",
    source="t",
    fetched_at=T0,
    source_sha256="0" * 64,
    labels={
        "evil": (label(T0, AffectedRange(introduced="0")),),
        "later": (label(datetime(2026, 11, 1, tzinfo=UTC), AffectedRange(introduced="0")),),
        "chalk": (label(T0, versions=("5.6.1",)),),  # one compromised release of a real package
        "com.unity.ugui": (label(T0, AffectedRange(introduced="0")),),  # an npm squat
    },
)


def test_known_malware_dependency() -> None:
    rule, ctx = KnownMalwareDependency(), CorrelationContext(as_of=T0, known_bad=LABELS)
    deps = {"evil": "^1.0.0", "later": "1", "chalk": "^5.0.0", "alias": "npm:evil@1.0.0"}
    found = rule.evaluate_candidate(cand(snap("1", {"dependencies": deps})), ctx)
    assert [f.evidence[0].path for f in found] == [
        "package.json:dependencies.alias",
        "package.json:dependencies.evil",
    ]
    # Unchanged since the previous release: not this release's doing.
    old = snap("0", {"dependencies": {"evil": "^1.0.0"}})
    assert not rule.evaluate_candidate(
        cand(snap("1", {"dependencies": {"evil": "^1.0.0"}}), old), ctx
    )
    assert not rule.evaluate_candidate(
        cand(snap("1", {"dependencies": deps})), CorrelationContext(as_of=T0)
    )


def test_a_dependency_only_npm_s_holder_satisfies_is_low() -> None:
    """`npm install fs` writes `^0.0.1-security`: the empty package npm holds the name with."""
    rule, ctx = KnownMalwareDependency(), CorrelationContext(as_of=T0, known_bad=LABELS)

    def found(spec: str) -> Finding:
        (only,) = rule.evaluate_candidate(cand(snap("1", {"dependencies": {"evil": spec}})), ctx)
        return only

    for spec in ("0.0.1-security", "^0.0.1-security", "~0.0.1-security", "npm:evil@0.0.1-security"):
        held = found(spec)
        assert (held.severity, held.weight) == (Severity.LOW, 1.0), spec
        assert "installs nothing" in held.explanation
    for spec in (">=0.0.1-security", "*", "0.0.1-security || 1.x", "npm:evil@1.0.0"):
        assert found(spec).severity is Severity.HIGH, spec


def test_revived_with_new_dependency() -> None:
    def low(rule_id: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            rule_version=1,
            severity=Severity.LOW,
            weight=1.0,
            title="t",
            explanation=f"{rule_id}.",
        )

    rule, ctx = RevivedWithNewDependency(), CorrelationContext(as_of=T0)
    both = cand(snap("1.1.0"), snap("1.0.0")).model_copy(
        update={"findings": (low("npm.dormant-revived"), low("npm.dependency.added"))}
    )
    (found,) = rule.evaluate_candidate(both, ctx)
    assert found.severity == Severity.MEDIUM
    one = both.model_copy(update={"findings": both.findings[:1]})
    assert not rule.evaluate_candidate(one, ctx)
    canary = both.model_copy(update={"change": cand(snap("2.0.0-canary.1"), snap("1")).change})
    assert not rule.evaluate_candidate(canary, ctx)
    typed = both.model_copy(
        update={
            "change": Change(
                new=snap("2.0.0", publisher="types").model_copy(
                    update={
                        "ref": PackageVersionRef(ecosystem="npm", name="@types/x", version="2.0.0")
                    }
                ),
                previous=snap("1.0.0", publisher="types"),
            )
        }
    )
    assert not rule.evaluate_candidate(typed, ctx)


def test_revived_by_the_same_account_is_low() -> None:
    """v2: the previous release's publisher comes back with no maintainer added (74 of 140
    live versions this rule alone reported, all benign); another account, the `xrpl@2.14.2`
    shape, or a maintainer added keeps MEDIUM."""

    def low(rule_id: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            rule_version=1,
            severity=Severity.LOW,
            weight=1.0,
            title="t",
            explanation=f"{rule_id}.",
        )

    rule, ctx = RevivedWithNewDependency(), CorrelationContext(as_of=T0)
    fired = (low("npm.dormant-revived"), low("npm.dependency.added"))

    def found(new: VersionSnapshot, old: VersionSnapshot) -> Finding:
        (result,) = rule.evaluate_candidate(
            cand(new, old).model_copy(update={"findings": fired}), ctx
        )
        return result

    old = snap("2.14.1", publisher="ckniffen", maintainers=("ckniffen",))
    same = found(snap("2.14.2", publisher="ckniffen", maintainers=("ckniffen",)), old)
    assert (same.severity, same.weight) == (Severity.LOW, 1.0)
    assert "who published the previous release" in same.explanation
    other = found(snap("2.14.2", publisher="mukulljangid", maintainers=("ckniffen",)), old)
    assert (other.severity, other.weight) == (Severity.MEDIUM, 2.0)
    # v5: maintainers added, the same account publishing (`@rbbn/distant-web@1.3.0`)
    added = found(snap("2.14.2", publisher="ckniffen", maintainers=("ckniffen", "m")), old)
    assert (added.severity, added.weight, added.rule_version) == (Severity.LOW, 1.0, 6)
    assert added.explanation.endswith(
        "who published the previous release, with maintainers added (m), none of whom published it."
    )
    # a maintainer who joined publishes (the event-stream handover): MEDIUM
    joined = found(snap("2.14.2", publisher="m", maintainers=("ckniffen", "m")), old)
    assert (joined.severity, joined.weight) == (Severity.MEDIUM, 2.0)
    unknown = found(snap("2.14.2"), snap("2.14.1"))
    assert unknown.severity == Severity.MEDIUM


def test_revived_with_provenance_is_low() -> None:
    """v3 (F7): a release with a provenance attestation came from the repository's CI; a
    takeover would need that CI too. 65 benign live reports, and the rule has no positive."""

    def low(rule_id: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            rule_version=1,
            severity=Severity.LOW,
            weight=1.0,
            title="t",
            explanation=f"{rule_id}.",
        )

    rule, ctx = RevivedWithNewDependency(), CorrelationContext(as_of=T0)
    fired = (low("npm.dormant-revived"), low("npm.dependency.added"))
    old = snap("2.14.1", publisher="ckniffen", maintainers=("ckniffen",))

    def found(new: VersionSnapshot) -> Finding:
        (result,) = rule.evaluate_candidate(
            cand(new, old).model_copy(update={"findings": fired}), ctx
        )
        return result

    ci = found(snap("2.14.2", publisher="GitHub Actions", has_provenance=True))
    assert (ci.severity, ci.weight) == (Severity.LOW, 1.0)
    assert ci.explanation.endswith(
        "Published with a provenance attestation (from the repository's CI)."
    )
    # the xrpl@2.14.2 shape: another account, no provenance, keeps MEDIUM
    hand = found(snap("2.14.2", publisher="mukulljangid", maintainers=("ckniffen",)))
    assert (hand.severity, hand.weight) == (Severity.MEDIUM, 2.0)
    # v4: trusted publishing without an attestation (`productenv@2.0.0`)
    oidc = found(snap("2.14.2", publisher="GitHub Actions", trusted_publisher="github"))
    assert (oidc.severity, oidc.weight) == (Severity.LOW, 1.0)
    assert oidc.explanation.endswith(
        "Published with trusted publishing (github) (from the repository's CI)."
    )


def _revived(new: VersionSnapshot, old: VersionSnapshot) -> Finding:
    fired = tuple(
        Finding(
            rule_id=rule_id,
            rule_version=1,
            severity=Severity.LOW,
            weight=1.0,
            title="t",
            explanation=f"{rule_id}.",
        )
        for rule_id in ("npm.dormant-revived", "npm.dependency.added")
    )
    (result,) = RevivedWithNewDependency().evaluate_candidate(
        cand(new, old).model_copy(update={"findings": fired}), CorrelationContext(as_of=T0)
    )
    return result


def test_revived_into_a_new_major_is_low() -> None:
    """v6 (round 7, W1): a new major is outside every range of an earlier release, so it
    doesn't reach the projects a takeover wants (`@capacitor/assets@4.0.0`). Inside the major
    (`vant@2.13.3`, `@antv/*` `1.6.13` -> `1.7.13`) and 0.x minors (`@antv/g2-extension-3d`
    `0.2.0` -> `0.3.0`) keep MEDIUM."""
    deps: dict[str, Any] = {"dependencies": {"new-dep": "^1.0.0"}}
    old: dict[str, Any] = {"publisher": "a", "maintainers": ("a", "b")}
    new: dict[str, Any] = {"publisher": "b", "maintainers": ("a", "b")}
    for before, after in (("3.0.5", "4.0.0"), ("0.5.2", "1.0.0"), ("0.27.0-next.3", "2.1.8")):
        found = _revived(snap(after, deps, **new), snap(before, **old))
        assert (found.severity, found.weight, found.rule_version) == (Severity.LOW, 1.0, 6)
        assert found.explanation.endswith(
            f"A new major version after {before}: npm gives it to no project whose range "
            "names an earlier major."
        )
    for before, after in (("2.13.2", "2.13.3"), ("1.6.13", "1.7.13"), ("0.2.0", "0.3.0")):
        kept = _revived(snap(after, deps, **new), snap(before, **old))
        assert (kept.severity, kept.weight) == (Severity.MEDIUM, 2.0), after


def test_revived_shipping_its_own_dev_dependencies_is_low() -> None:
    """v6 (W2): every added runtime dependency was a dev or peer dependency of the previous
    release (`imghash-cli@0.0.2`); one new package among them (`@mastra/speech-*` moving
    `@mastra/core` but adding `easy-day-js`) keeps MEDIUM."""
    old_manifest = {
        "dependencies": {"kept": "^1"},
        "devDependencies": {"imghash": "^1.1.5"},
        "peerDependencies": {"react": "^18"},
    }
    old = snap("0.0.1", old_manifest, publisher="a", maintainers=("a", "b"))

    def found(added: dict[str, str]) -> Finding:
        manifest = {"dependencies": {"kept": "^1", **added}}
        return _revived(snap("0.0.2", manifest, publisher="b", maintainers=("a", "b")), old)

    moved = found({"imghash": "^1.1.5", "react": "^18"})
    assert (moved.severity, moved.weight) == (Severity.LOW, 1.0)
    assert moved.explanation.endswith(
        "Each added dependency was already a dev or peer dependency of 0.0.1: none is new to "
        "the project."
    )
    assert found({"imghash": "^1.1.5", "easy-day-js": "^1.11.21"}).severity is Severity.MEDIUM
    assert found({"other": "1"}).severity is Severity.MEDIUM


def test_a_unity_package_s_built_in_module_is_low() -> None:
    rule, ctx = KnownMalwareDependency(), CorrelationContext(as_of=T0, known_bad=LABELS)
    deps = {"dependencies": {"com.unity.ugui": "2.0.0"}}
    (upm,) = rule.evaluate_candidate(cand(snap("1", {**deps, "unity": "6000.4"})), ctx)
    assert (upm.severity, upm.weight) == (Severity.LOW, 1.0)
    assert "Unity (UPM) package" in upm.explanation
    (plain,) = rule.evaluate_candidate(cand(snap("1", deps)), ctx)  # not a UPM package
    assert plain.severity is Severity.HIGH
    (evil,) = rule.evaluate_candidate(
        cand(snap("1", {"dependencies": {"evil": "1"}, "unity": "6000.4"})), ctx
    )
    assert evil.severity is Severity.HIGH  # only Unity's own namespace


# --- npm.known-malware.self (round 12 P) -------------------------------------------------------

RECORD_AT = datetime(2026, 10, 20, tzinfo=UTC)
SELF_LABELS = LabelSet(
    ecosystem="npm",
    source="t",
    fetched_at=T0,
    source_sha256="0" * 64,
    labels={
        # every version, published before the run
        "kx": (label(RECORD_AT, AffectedRange(introduced="0")),),
        # the compromised releases of a real package
        "real": (label(RECORD_AT, AffectedRange(introduced="2.0.0", fixed="2.0.2")),),
        "listed": (label(datetime(2025, 1, 1, tzinfo=UTC), versions=("1.0.0",)),),
        "future": (label(T0 + timedelta(hours=1), AffectedRange(introduced="0")),),
    },
)


def own(
    name: str,
    version: str,
    published: datetime | None = T0 - timedelta(hours=1),
    **publish: Any,
) -> Candidate:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
        publish=PublishInfo(published_at=published, **publish),
        manifest={},
    )
    return Candidate(change=Change(new=snapshot))


def self_findings(candidate: Candidate, labels: LabelSet | None = SELF_LABELS) -> list[Finding]:
    ctx = CorrelationContext(as_of=T0, known_bad=labels)
    return list(KnownMalwareSelf().evaluate_candidate(candidate, ctx))


def test_known_malware_self_reports_a_package_osv_calls_malware() -> None:
    (found,) = self_findings(own("kx", "1.2.3"))
    assert (found.rule_id, found.rule_version) == ("npm.known-malware.self", 1)
    assert (found.severity, found.weight) == (Severity.HIGH, 5.0)
    assert "MAL-1" in found.explanation and found.evidence[0].path == "osv:MAL-1"
    # Enough on its own to report the version.
    ctx = CorrelationContext(as_of=T0, known_bad=SELF_LABELS)
    decision = correlate(own("kx", "1.2.3"), ctx, CORRELATION_RULES).history[-1]
    assert decision.forwarded and "npm.known-malware.self" in decision.reason


def test_known_malware_self_needs_a_record_covering_this_release() -> None:
    assert not self_findings(own("other", "1.0.0"))  # no record
    assert not self_findings(own("kx", "1.0.0"), labels=None)  # no label set
    assert self_findings(own("real", "2.0.1"))  # inside the bounded range
    for version in ("1.9.9", "2.0.2", "3.0.0"):  # outside it
        assert not self_findings(own("real", version)), version
    assert self_findings(own("listed", "1.0.0"))  # named, whatever the record's age
    assert not self_findings(own("listed", "1.0.1"))


def test_known_malware_self_ignores_records_published_after_as_of() -> None:
    """Analysis never reads the clock: a record OSV published after the run's as_of (even one
    in the label set) doesn't count, so a replay gives the same answer."""
    assert not self_findings(own("future", "1.0.0"))
    late = CorrelationContext(as_of=T0 + timedelta(hours=2), known_bad=SELF_LABELS)
    assert KnownMalwareSelf().evaluate_candidate(own("future", "1.0.0"), late)


def test_known_malware_self_skips_withdrawn_records() -> None:
    """`labels sync` drops withdrawn records, so a withdrawn record never reaches the rule."""
    all_versions = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}
    export = osv_zip(
        {
            "MAL-1.json": {**mal("MAL-1", "gone", **all_versions), "withdrawn": "2026-10-01"},
            "MAL-2.json": mal("MAL-2", "kept", **all_versions),
        }
    )
    labels = LabelSet(
        ecosystem="npm",
        source="t",
        fetched_at=T0,
        source_sha256="0" * 64,
        labels=parse_osv_export(export, ecosystem="npm"),
    )
    assert not self_findings(own("gone", "1.0.0"), labels)
    assert self_findings(own("kept", "1.0.0"), labels)


def test_known_malware_self_projects_an_all_versions_record_only_while_recent() -> None:
    """A release the record doesn't name, published after it: counted within PROJECTION_DAYS,
    an INFO note after (a real package compromised once keeps releasing)."""
    days = timedelta(days=PROJECTION_DAYS)
    edge = RECORD_AT + days
    ctx = CorrelationContext(as_of=edge + timedelta(days=30), known_bad=SELF_LABELS)
    rule = KnownMalwareSelf()
    (recent,) = rule.evaluate_candidate(own("kx", "1.0.0", edge), ctx)
    assert recent.severity is Severity.HIGH
    (old,) = rule.evaluate_candidate(own("kx", "1.0.0", edge + timedelta(seconds=1)), ctx)
    assert (old.severity, old.weight) == (Severity.INFO, 0.0)
    assert old.explanation.startswith("Not counted:")
    assert not correlate(own("kx", "1.0.0", edge + days), ctx, [rule]).history[-1].forwarded
    # Published before the record: the record is evidence about it, however old it is now.
    (before,) = rule.evaluate_candidate(own("kx", "1.0.0", RECORD_AT - days), ctx)
    assert before.severity is Severity.HIGH
    # Without a publish time a projection can't be dated: not counted.
    (undated,) = rule.evaluate_candidate(own("kx", "1.0.0", None), ctx)
    assert undated.severity is Severity.INFO


def test_known_malware_self_skips_registry_placeholders() -> None:
    assert not self_findings(own("kx", "0.0.1-security", publisher="npm"))
    assert self_findings(own("kx", "0.0.1-security", publisher="someone"))


def test_known_malware_self_is_deterministic() -> None:
    second = label(RECORD_AT, AffectedRange(introduced="0")).model_copy(update={"id": "MAL-2"})
    labels = SELF_LABELS.model_copy(
        update={"labels": {"kx": (second, label(RECORD_AT, AffectedRange(introduced="0")))}}
    )
    first = self_findings(own("kx", "1.0.0"), labels)
    assert first == self_findings(own("kx", "1.0.0"), labels)
    assert "MAL-2, MAL-1" in first[0].explanation  # in the label set's order
