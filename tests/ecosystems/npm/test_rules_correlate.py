"""Stage 4 npm rules: gitHead provenance and known-malware dependencies."""

from datetime import UTC, datetime
from typing import Any

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
    GitHeadDropped,
    KnownMalwareDependency,
    RevivedWithNewDependency,
)
from kitsunox.evaluation.labels import AffectedRange, LabelSet, MalwareLabel
from kitsunox.stages.correlate import CorrelationContext

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
    both = cand(snap("2.0.0"), snap("1.0.0")).model_copy(
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
