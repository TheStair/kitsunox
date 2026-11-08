"""Stage 4 dependency-reputation rules: `npm.dependency.fresh-foreign`,
`npm.dependency.missing` and `npm.dependency.name-embeds-popular`, on hand-made packuments."""

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from kitsunox.core.models import (
    Candidate,
    Change,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.core.watchlist import WatchEntry, Watchlist
from kitsunox.ecosystems.npm.packument import Packument
from kitsunox.ecosystems.npm.rules.correlate import (
    AddedDependency,
    FreshForeignDependency,
    MissingDependency,
    NameEmbedsPopular,
    embedded_popular_name,
    foreign_added_dependencies,
    sibling_reason,
)
from kitsunox.reporting.report import stage_of
from kitsunox.stages.correlate import (
    NOT_EVALUATED,
    CorrelationContext,
    DependencyRecord,
    DependencyStatus,
    decide,
    score,
)
from kitsunox.stages.repo import NetworkRequests
from kitsunox.stages.review import dependency_record

PUBLISHED = datetime(2026, 6, 17, 1, 17, tzinfo=UTC)  # the dependent's publish time
AS_OF = PUBLISHED + timedelta(hours=1)

WATCHLIST = Watchlist(
    ecosystem="npm",
    source="t",
    built_at=datetime(2026, 6, 1, tzinfo=UTC),
    min_monthly_downloads=43_000,
    entries={
        "dayjs": WatchEntry(monthly_downloads=80_000_000),
        "crypto-js": WatchEntry(monthly_downloads=40_000_000),
        "react": WatchEntry(monthly_downloads=200_000_000),
        "left-pad": WatchEntry(monthly_downloads=500_000),  # watched, but below the bar
        "@babel/core": WatchEntry(monthly_downloads=100_000_000),  # scoped: never a target
        "vue": WatchEntry(monthly_downloads=30_000_000),  # too short to embed
        "tailwindcss": WatchEntry(monthly_downloads=60_000_000),
        "postcss": WatchEntry(monthly_downloads=300_000_000),
    },
)


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def packument(
    name: str,
    first: datetime,
    *,
    maintainers: Sequence[str] = ("stranger",),
    publisher: str | None = "stranger",
    removed: Sequence[str] = (),
    later: datetime | None = None,
) -> DependencyRecord:
    """A packument for `name` with version 1.0.0 published at `first` (and 1.0.1 at `later`),
    run through the real parser. Versions in `removed` keep only their `time` entry, as after a
    takedown."""
    people = [{"name": m} for m in maintainers]
    user = {"name": publisher} if publisher else None
    times = {"1.0.0": first} | ({"1.0.1": later} if later else {})
    doc: dict[str, Any] = {
        "name": name,
        "maintainers": people,
        "time": {"created": iso(first), "modified": iso(first)}
        | {v: iso(t) for v, t in times.items()},
        "versions": {
            v: {"name": name, "version": v, "maintainers": people, "_npmUser": user}
            for v in times
            if v not in removed
        },
    }
    return dependency_record(Packument(doc, expected_name=name))


class Lookup:
    def __init__(self, records: Mapping[str, DependencyRecord]) -> None:
        self.records = records
        self.asked: list[str] = []

    def plan(self, candidates: Sequence[Candidate], ctx: CorrelationContext) -> Sequence[str]:
        return ()

    def new_pass(self) -> None:
        pass

    def requests(self) -> NetworkRequests:
        return NetworkRequests()

    def __call__(self, name: str) -> DependencyRecord:
        self.asked.append(name)
        return self.records.get(name, DependencyRecord(name=name, status=DependencyStatus.MISSING))

    def stats(self) -> Mapping[str, object]:
        return {}


def snap(name: str, version: str, deps: Mapping[str, str], **publish: Any) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
        publish=PublishInfo(**publish),
        manifest={"dependencies": dict(deps)},
    )


def update(
    deps: Mapping[str, str],
    *,
    name: str = "@mastra/node-audio",
    before: Mapping[str, str] | None = None,
    maintainers: tuple[str, ...] = ("ehindero",),
) -> Candidate:
    new = snap(
        name,
        "0.1.8",
        deps,
        published_at=PUBLISHED,
        publisher=maintainers[0] if maintainers else None,
        maintainers=maintainers,
    )
    old = snap(name, "0.1.7", before or {}, publisher=maintainers[0] if maintainers else None)
    return Candidate(change=Change(new=new, previous=old))


def ctx(**records: DependencyRecord) -> CorrelationContext:
    return CorrelationContext(as_of=AS_OF, watchlist=WATCHLIST, dependencies=Lookup(records))


FRESH = PUBLISHED - timedelta(hours=18)
OLD = PUBLISHED - timedelta(days=200)


def fresh_foreign(candidate: Candidate, context: CorrelationContext) -> list[Any]:
    return list(FreshForeignDependency().evaluate_candidate(candidate, context))


def test_fresh_dependency_from_strangers_fires() -> None:
    record = packument("easy-day-js", FRESH, maintainers=("sergey2016",), publisher="sergey2016")
    (found,) = fresh_foreign(update({"easy-day-js": "^1.11.21"}), ctx(**{"easy-day-js": record}))
    assert found.severity is Severity.MEDIUM and found.weight == 3.0
    assert "first published 18.0 hours before this release" in found.explanation
    assert "(sergey2016; this package: ehindero)" in found.explanation
    assert found.evidence[0].path == "package.json:dependencies.easy-day-js"
    assert found.evidence[1].after == "sergey2016"
    assert found.evidence[1].snippet == "1.0.0 published 2026-06-16T07:17:00+00:00"
    assert score([found]) == 3.0


def test_old_or_shared_or_not_added_does_not_fire() -> None:
    old = packument("helper", OLD)
    assert not fresh_foreign(update({"helper": "^1"}), ctx(helper=old))
    # Just under the threshold fires; exactly 7 days doesn't.
    edge = packument("helper", PUBLISHED - timedelta(days=7))
    assert not fresh_foreign(update({"helper": "^1"}), ctx(helper=edge))
    near = packument("helper", PUBLISHED - timedelta(days=7) + timedelta(minutes=1))
    assert fresh_foreign(update({"helper": "^1"}), ctx(helper=near))
    # A maintainer in common (here the dependent's previous publisher) is not foreign.
    mine = packument("helper", FRESH, maintainers=("someone", "ehindero"), publisher="someone")
    assert not fresh_foreign(update({"helper": "^1"}), ctx(helper=mine))
    # Already a dependency of the previous version (only the range moved): not added.
    young = packument("helper", FRESH)
    assert not fresh_foreign(update({"helper": "^2"}, before={"helper": "^1"}), ctx(helper=young))


def test_alias_target_is_what_counts() -> None:
    record = packument("evil-pkg", FRESH)
    # Re-pointing an existing key at a new package through `npm:` adds that package.
    candidate = update({"helper": "npm:evil-pkg@1.0.0"}, before={"helper": "^1"})
    (found,) = fresh_foreign(candidate, ctx(**{"evil-pkg": record}))
    assert "`evil-pkg`" in found.explanation
    assert found.evidence[0].after == "helper: npm:evil-pkg@1.0.0"


def test_own_scope_watched_self_and_non_registry_are_exempt() -> None:
    record = packument("x", FRESH)
    lookup = Lookup({})
    context = CorrelationContext(as_of=AS_OF, watchlist=WATCHLIST, dependencies=lookup)
    deps = {
        "@mastra/core": "^1",  # own scope: only the scope's members can publish there
        "react": "^19",  # watched
        "@mastra/node-audio": "^0.1",  # itself
        "gh": "github:o/r",  # not from the registry (Stage 1's rule)
        "sib": "workspace:*",
    }
    assert not fresh_foreign(update(deps), context)
    assert lookup.asked == []  # none of them is even looked up
    # Another scope is foreign.
    assert foreign_added_dependencies(update({"@other/x": "1"}).change, WATCHLIST)
    _ = record


def test_new_package_counts_every_dependency() -> None:
    record = packument("fresh-lib", FRESH)
    new = snap("brand-new", "1.0.0", {"fresh-lib": "^1"}, published_at=PUBLISHED, publisher="me")
    (found,) = fresh_foreign(Candidate(change=Change(new=new)), ctx(**{"fresh-lib": record}))
    assert "this package: me" in found.explanation


def test_versions_after_as_of_and_removed_versions() -> None:
    # Only versions published by `as_of` count, for age and accounts.
    future = packument("late", AS_OF + timedelta(days=1))
    assert not fresh_foreign(update({"late": "^1"}), ctx(late=future))
    # A taken-down dependency keeps its version times but loses its manifests (accounts): the
    # top-level maintainers stand in; with none at all it is not evaluated, never "foreign".
    gone = packument("gone", FRESH, removed=("1.0.0",), maintainers=("sergey2016",))
    (found,) = fresh_foreign(update({"gone": "^1"}), ctx(gone=gone))
    assert found.severity is Severity.MEDIUM and "sergey2016" in found.explanation
    bare = packument("bare", FRESH, removed=("1.0.0",), maintainers=(), publisher=None)
    (info,) = fresh_foreign(update({"bare": "^1"}), ctx(bare=bare))
    assert info.severity is Severity.INFO and info.explanation.startswith(NOT_EVALUATED)
    assert "the dependency's registry record names no accounts" in info.explanation
    assert score([info]) == 0.0
    # After a takedown npm lists its own account: that is no account information either.
    held = packument("held", FRESH, removed=("1.0.0",), maintainers=("npm-support",))
    (info,) = fresh_foreign(update({"held": "^1"}), ctx(held=held))
    assert info.severity is Severity.INFO
    # A dependent without account information can't be compared either.
    nobody = update({"fresh": "^1"}, maintainers=())
    (info,) = fresh_foreign(nobody, ctx(fresh=packument("fresh", FRESH)))
    assert info.severity is Severity.INFO and "this package's registry record" in info.explanation


def test_lookups_that_failed_are_not_evaluated() -> None:
    for transient in (True, False):  # the same text either way, so a replay reads the same
        record = DependencyRecord(name="dep", status=DependencyStatus.FAILED, transient=transient)
        (info,) = fresh_foreign(update({"dep": "^1"}), ctx(dep=record))
        assert info.severity is Severity.INFO and info.weight == 0.0
        assert info.explanation == (
            f"{NOT_EVALUATED}`dep` was not checked for age and accounts: its registry record "
            "could not be fetched."
        )


def test_dependencies_over_the_limits_share_one_finding() -> None:
    capped = {
        f"dep-{i:02}": DependencyRecord(name=f"dep-{i:02}", status=DependencyStatus.CAPPED)
        for i in range(12)
    }
    fresh = packument("fresh", FRESH)
    deps = dict.fromkeys([*capped, "fresh"], "^1")
    medium, info = fresh_foreign(update(deps), ctx(fresh=fresh, **capped))
    assert medium.severity is Severity.MEDIUM and "`fresh`" in medium.explanation
    assert info.severity is Severity.INFO and info.weight == 0.0
    assert info.explanation == (
        f"{NOT_EVALUATED}12 added dependencies were not checked for age and accounts "
        "(`dep-00`, `dep-01`, `dep-02`, `dep-03`, `dep-04`, `dep-05`, `dep-06`, `dep-07`, "
        "`dep-08`, `dep-09` (+2 more)): over the dependency lookup limits (per release, or "
        "the run's cap)."
    )
    assert len(info.evidence) == 5


def test_a_dependency_published_after_its_dependent_says_after() -> None:
    later = packument("late", PUBLISHED + timedelta(minutes=30))  # still before AS_OF
    (found,) = fresh_foreign(update({"late": "^1"}), ctx(late=later))
    assert "first published 0.5 hours after this release" in found.explanation


def test_stray_time_keys_are_not_versions() -> None:
    doc = {
        "name": "dep",
        "time": {
            "created": iso(FRESH),
            "__proto__": iso(OLD),
            "constructor": iso(OLD),
            "1.0.0": iso(FRESH),
            "0.9.0": iso(FRESH - timedelta(hours=1)),  # removed in a takedown: still a version
        },
        "versions": {"1.0.0": {"name": "dep", "version": "1.0.0"}},
    }
    parsed = Packument(doc, expected_name="dep")
    assert set(parsed.version_times) == {"1.0.0", "0.9.0"}


def test_dependency_rules_are_attributed_to_stage_4() -> None:
    for rule in (FreshForeignDependency(), NameEmbedsPopular()):
        assert stage_of(rule.id) == "Stage 4: correlation"
    assert stage_of("npm.dependency.added") == "Stage 1: metadata"


def test_missing_dependency_gives_nothing() -> None:
    assert not fresh_foreign(update({"nope": "^1"}), ctx())  # 404: no finding
    no_lookup = CorrelationContext(as_of=AS_OF, watchlist=WATCHLIST)
    assert not fresh_foreign(update({"nope": "^1"}), no_lookup)


@pytest.mark.parametrize(
    ("name", "embedded"),
    [
        ("easy-day-js", "dayjs"),  # prefix, separators ignored
        ("plain-crypto-js", "crypto-js"),
        ("react-typesx", "react"),  # suffix
        ("dayjs-extra", "dayjs"),
        ("day-js", None),  # only separators differ: not a prefix/suffix match
        ("dayjs", None),  # the popular name itself
        ("abcdefghi-dayjs", None),  # prefix of 9 characters
        ("abcdefgh-dayjs", "dayjs"),  # 8
        ("left-pad-x", None),  # below POPULAR_MONTHLY
        ("vue-thing", None),  # popular name shorter than EMBED_MIN_LENGTH
        ("unrelated", None),
    ],
)
def test_embedded_popular_name(name: str, embedded: str | None) -> None:
    rule = NameEmbedsPopular()
    popular = rule._popular.of(WATCHLIST)
    assert "babelcore" not in popular  # scoped names never count
    assert embedded_popular_name(name, popular) == embedded


def test_name_embeds_popular_rule() -> None:
    rule = NameEmbedsPopular()
    context = CorrelationContext(as_of=AS_OF, watchlist=WATCHLIST)
    (found,) = rule.evaluate_candidate(update({"plain-crypto-js": "^4.2.1"}), context)
    assert found.severity is Severity.LOW and found.weight == 1.0
    assert "embeds the popular package `crypto-js` (40,000,000 downloads a month)" in (
        found.explanation
    )
    assert not rule.evaluate_candidate(update({"dayjs": "^1"}), context)  # watched, exact
    assert not rule.evaluate_candidate(update({"@evil/dayjs-x": "^1"}), context)  # scoped
    # Not added (already there before), or no watchlist: nothing.
    kept = update({"easy-day-js": "^1.11.22"}, before={"easy-day-js": "^1.11.21"})
    assert not rule.evaluate_candidate(kept, context)
    bare = CorrelationContext(as_of=AS_OF)
    assert not rule.evaluate_candidate(update({"plain-crypto-js": "^4"}), bare)


def test_name_embeds_popular_is_quiet_for_the_same_accounts() -> None:
    rule = NameEmbedsPopular()
    candidate = update({"dayjs-plugin-x": "^1"}, maintainers=("ehindero",))
    # The dependent's own maintainer publishes the dependency: a helper, not a lookalike.
    own = packument("dayjs-plugin-x", OLD, maintainers=("ehindero",), publisher="ehindero")
    assert not rule.evaluate_candidate(candidate, ctx(**{"dayjs-plugin-x": own}))
    # Only an account added after `as_of` in common: still fires.
    after = packument("dayjs-plugin-x", AS_OF + timedelta(hours=1), maintainers=("ehindero",))
    assert rule.evaluate_candidate(candidate, ctx(**{"dayjs-plugin-x": after}))
    # Strangers, a dependency not looked up (over the limits, failed) or not found: fires.
    stranger = packument("dayjs-plugin-x", OLD)
    for record in (
        stranger,
        DependencyRecord(name="dayjs-plugin-x", status=DependencyStatus.CAPPED),
        DependencyRecord(name="dayjs-plugin-x", status=DependencyStatus.FAILED),
    ):
        assert rule.evaluate_candidate(candidate, ctx(**{"dayjs-plugin-x": record}))
    assert rule.evaluate_candidate(candidate, ctx())  # 404


def test_both_rules_together_score_four() -> None:
    record = packument("easy-day-js", FRESH, maintainers=("sergey2016",), publisher="sergey2016")
    candidate = update({"easy-day-js": "^1.11.21"})
    context = ctx(**{"easy-day-js": record})
    found = [
        *FreshForeignDependency().evaluate_candidate(candidate, context),
        *NameEmbedsPopular().evaluate_candidate(candidate, context),
    ]
    assert score(found) == 4.0


# `npm.dependency.missing`: names and specifiers from the live runs of 2026-10-29 - 11-08.


def missing(candidate: Candidate, context: CorrelationContext) -> list[Any]:
    return list(MissingDependency().evaluate_candidate(candidate, context))


def new_package(name: str, version: str, deps: Mapping[str, str]) -> Candidate:
    return Candidate(change=Change(new=snap(name, version, deps, published_at=PUBLISHED)))


def test_a_missing_unrelated_dependency_reports_alone() -> None:
    # The Tailwind-wrapper campaign: the payload dependency is published after the wrapper.
    candidate = new_package(
        "tailwindcss-animate-bridge",
        "2.0.8",
        {"@utilitycraft/tailwindcss-motion-atelier": "^1.0.4", "kept": "^1"},
    )
    (found,) = missing(candidate, ctx(kept=packument("kept", OLD)))  # unknown names are 404
    assert found.rule_id == "npm.dependency.missing" and found.rule_version == 1
    assert found.severity is Severity.MEDIUM and found.weight == 3.0
    assert "`@utilitycraft/tailwindcss-motion-atelier`" in found.explanation
    assert "HTTP 404" in found.explanation and "`kept`" not in found.explanation
    assert found.evidence[0].path == (
        "package.json:dependencies.@utilitycraft/tailwindcss-motion-atelier"
    )
    assert decide([found]).forwarded  # not `WEAK_ALONE`: the wrappers had no other finding
    assert stage_of(found.rule_id) == "Stage 4: correlation"
    # An update that adds it fires too; one that already had it doesn't.
    deps = {"@nexlayerlabs/postcss-keyframe-utils": "^1.0.3"}
    assert missing(update(deps, name="tailwindcss-visual-kit"), ctx())
    assert not missing(update(deps, name="tailwindcss-visual-kit", before=deps), ctx())


def test_several_missing_dependencies_share_one_finding() -> None:
    deps = {f"dsh-tool-{i:02}": "^0.1.0" for i in range(12)}
    (found,) = missing(new_package("@capyclaw/ppt-suite", "2.4.0", deps), ctx())
    assert "`dsh-tool-00`" in found.explanation and "(+2 more)" in found.explanation
    assert len(found.evidence) == 5


def test_only_a_404_counts() -> None:
    candidate = update({"helper": "^1"}, name="wrapper")
    for status in (DependencyStatus.FAILED, DependencyStatus.CAPPED):
        record = DependencyRecord(name="helper", status=status, transient=True)
        assert not missing(candidate, ctx(helper=record))  # not evaluated, never "missing"
    assert not missing(candidate, ctx(helper=packument("helper", FRESH)))
    assert not missing(candidate, CorrelationContext(as_of=AS_OF, watchlist=WATCHLIST))
    # Own scope, watched and non-registry dependencies are never looked up.
    lookup = Lookup({})
    context = CorrelationContext(as_of=AS_OF, watchlist=WATCHLIST, dependencies=lookup)
    exempt = {"@mastra/core": "^1", "react": "^19", "gh": "github:o/r", "s": "workspace:*"}
    assert not missing(update(exempt), context)
    assert lookup.asked == []


def sibling(target: str, spec: str, own: str, version: str = "1.0.0") -> str | None:
    change = new_package(own, version, {target: spec}).change
    return sibling_reason(AddedDependency(key=target, spec=spec, target=target), change, WATCHLIST)


def test_siblings_are_info() -> None:
    # Release trains: the specifier is the release's own version.
    assert sibling("@allyhub-next/scaffold", "0.2.0-next.4", "allyhub", "0.2.0-next.4") == (
        "its specifier is this release's own version (0.2.0-next.4)"
    )
    assert sibling("text-engine", "=0.32.0", "domotion-svg", "0.32.0")
    assert sibling("x-core", "npm:y-core@1.2.0", "app", "1.2.0")  # an alias's version
    # Not a range: a campaign wrapper asked for `^1.0.1` of its payload at its own 1.0.1.
    assert (
        sibling("@claudeorg/universal-code-generator", "^1.0.1", "fast-deep-thinking", "1.0.1")
        is None
    )
    # Platform builds and other names that extend the package's, either way round.
    assert sibling("envdoc-cli-linux-x64", "0.1.3", "envdoc-cli", "0.1.2") == (
        "its name extends `envdoc-cli`"
    )
    assert sibling("@armyantsec/codegravity-darwin-x64", "^0.1", "codegravity")
    assert sibling("dsh-cli", "^0.1.0", "dsh-cli-flow")
    assert sibling("monolith-core-database", "^1.0.0", "monolith-core-cli") == (
        "its name starts with this package's `monolith`"
    )
    # A scope kin to a part of the package's name (equal, or one starts the other).
    assert sibling("@ocean/core", "2.0.0", "@amoree-code/ocean") == (
        "its scope `@ocean` matches this package's name"
    )
    assert sibling("@ranu/core", "0.1.0", "@ranujs/adapter-vercel", "0.1.6")
    assert sibling("@materialinstruments/colorscope", "10.2.1", "@instruments/materia-ui")
    candidate = new_package("envdoc-cli", "0.1.2", {"envdoc-cli-darwin-arm64": "0.1.2"})
    (found,) = missing(candidate, ctx())
    assert found.severity is Severity.INFO and found.weight == 0.0
    assert "`envdoc-cli-darwin-arm64`: its specifier is this release's own version" in (
        found.explanation
    )
    assert not decide([found]).forwarded and score([found]) == 0.0
    many = {f"envdoc-cli-{i:02}": "^9" for i in range(11)}
    (found,) = missing(new_package("envdoc-cli", "0.1.2", many), ctx())
    assert found.explanation.startswith("Depends on 11 package(s)") and "(+1 more)" in (
        found.explanation
    )


def test_popular_or_short_names_make_no_kin() -> None:
    # Every campaign wrapper's payload is unrelated, though some share `tailwindcss`, `postcss`.
    for target, spec, own, version in (
        (
            "@utilitycraft/tailwindcss-motion-atelier",
            "^1.0.4",
            "tailwindcss-animate-bridge",
            "2.0.8",
        ),
        ("@scott-rogers/postcss-signal-bridge", "^1.0.5", "signalledger-diagnostics", "2.0.8"),
        ("@doublekk61_pro/postcss-motion-animation", "1.0.4", "framer-motionanimate", "14.7.2"),
        ("@unipswap/postcss-animate-units", "^1.0.5", "tailwind-animatrix", "1.0.7"),
    ):
        assert sibling(target, spec, own, version) is None
    assert sibling("@tailwindcss-x/y", "^1", "tailwindcss-pixel-tools") is None  # watched part
    assert sibling("postcss-evil", "^1", "postcss") is None  # extends a watched name
    assert sibling("@vk/helper", "dev", "vk-scheduler") is None  # `vk` is too short
    assert sibling("vk-helper", "dev", "vk-scheduler") is None
    assert sibling("postcss-units", "^1", "postcss-motion-kit") is None  # a watched first part
    assert sibling("@pro/x", "^1", "prompt-kit") is None  # a 3-letter prefix is not kin
    bare = sibling_reason(
        AddedDependency(key="react-x", spec="^1", target="react-x"),
        new_package("react", "1.0.0", {}).change,
        None,
    )
    assert bare == "its name extends `react`"  # without a watchlist nothing is popular
