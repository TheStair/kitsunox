"""Stage 4 rules for npm: release provenance, known-malware dependencies and the reputation
of newly added dependencies.

Numbers are from `day1` (2026-10-28; "updates" are shape-A first releases, DataDog for
malicious) and, for the dependency rules, `docs/proposals/dependency-reputation.md` (run
`20261029T221803Z-npm`). See `docs/stages/correlate.md`.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from kitsunox.core.models import Candidate, Change, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.core.watchlist import Watchlist
from kitsunox.ecosystems.npm import semver
from kitsunox.ecosystems.npm.rules.metadata import (
    is_registry_spec,
    only_version_changed,
    runtime_dependencies,
    scripts,
)
from kitsunox.ecosystems.npm.rules.undeclared import UndeclaredPackage, undeclared_evidence
from kitsunox.stages.correlate import (
    NOT_EVALUATED,
    CorrelationContext,
    DependencyRecord,
    DependencyStatus,
)
from kitsunox.stages.repo import ManifestDifference

DEFINITELY_TYPED: Final = "types"  # the npm account that publishes `@types/*`
# `npm.dependency.fresh-foreign`: a dependency whose first version is younger than this, at the
# dependent's publish time. Measured (proposal section 2): < 1 day, 7 days and 30 days fire on
# 0, 3 and 9 of 101,232 benign updates; both malicious dependencies were ~18 hours old.
FRESH_DAYS: Final = 7
# npm's own accounts: a package npm took down lists them in place of its real maintainers (and
# publishes the `0.0.1-security` holder as `npm`). They say nothing about who published the
# dependency, so they are not its accounts. On `vm-day1` 3 DataDog new packages were "foreign"
# only through them.
REGISTRY_ACCOUNTS: Final = frozenset({"npm", "npm-support"})
# `npm.dependency.name-embeds-popular`: names at least this popular (monthly downloads, from the
# watchlist), at least `EMBED_MIN_LENGTH` characters after normalising, plus a prefix or suffix
# of at most `EMBED_MAX_AFFIX` characters (proposal section 4).
POPULAR_MONTHLY: Final = 1_000_000
EMBED_MIN_LENGTH: Final = 5
EMBED_MAX_AFFIX: Final = 8
_SEPARATORS: Final = re.compile(r"[-_.]")


class GitHeadDropped(BaseRule):
    """The previous release recorded the commit it was built from (`gitHead`) and this one
    doesn't: it was not published from a git checkout. npm records `gitHead` when `npm publish`
    runs in a git working tree, so its loss is typical of a stolen token used to publish a
    hand-edited tarball.

    | Updates | Benign | Malicious |
    |---|---|---|
    | previous had `gitHead`, this one lacks it | 0.4% | 46.5% |

    Most of those malicious releases are flagged anyway; on its own this is corroboration, so
    it is weighted below the report score.

    v2 (2026-11-10, `docs/proposals/precision-round5-K.md` G1): weight 1 when Stage 1's
    `npm.publish-method.downgrade` fired on the same release. Both then say the release left
    the CI path, and given a downgrade a dropped `gitHead` doesn't separate: 34 of the 149
    `vm-day1` malicious samples with a downgrade (23%) have it, against 81 of the 273 live
    benign verdicts with one (30%). The downgrade already reads it (its watched-package
    co-signal); counted at 2 beside it, it was the last 2 points of 9 benign score-only
    reports (`@volter/*`, `@runko/conformance`, `a5-to-geojson`) and of no positive.
    """

    id = "npm.provenance.githead-dropped"
    version = 2
    severity = Severity.LOW
    weight = 2.0
    title = "Published without the git commit the previous release recorded"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        change = candidate.change
        if change.previous is None:
            return ()
        before = change.previous.publish.git_head
        if before is None or change.new.publish.git_head is not None:
            return ()
        downgraded = any(
            f.rule_id == DOWNGRADE and f.severity is not Severity.INFO for f in candidate.findings
        )
        return (
            self.finding(
                f"{change.previous.ref.version} was published from commit {before[:12]}; this "
                "release records no commit, so it was not published from a git checkout."
                + (DOWNGRADE_NOTE if downgraded else ""),
                Evidence(kind=EvidenceKind.METADATA, path="gitHead", before=before, after=None),
                weight=1.0 if downgraded else None,
            ),
        )


DOWNGRADE: Final = "npm.publish-method.downgrade"
DOWNGRADE_NOTE: Final = (
    " Weight 1: the publish-method downgrade on this release already says it left the CI path."
)


def _dependency_name(name: str, spec: str) -> str:
    """The package npm installs: the alias target for `"x": "npm:evil@1.0.0"`."""
    if not spec.startswith("npm:"):
        return name
    target = spec.removeprefix("npm:")
    at = target.rfind("@")
    return target[:at] if at > 0 else target


# A specifier only npm's security holding package satisfies: `npm install fs` writes
# `"fs": "^0.0.1-security"` because npm holds the name (`packument.SECURITY_HOLDER_VERSION`).
_HOLDER_SPEC: Final = re.compile(r"[\^~=v\s]*0\.0\.1-security\s*")


class KnownMalwareDependency(BaseRule):
    """The release adds a dependency that an OSV `MAL-` record, published by the run's
    `as_of`, calls malware in every version. Only whole-package records count (see
    `LabelSet.known_malware`). On `day1`: 11 of 905 malicious new packages, no benign sample.

    v2 (2026-10-31): a dependency whose specifier only npm's empty `0.0.1-security` holding
    package satisfies is LOW (weight 1): it installs nothing, and benign authors who ran
    `npm install fs` have it. 3 of the rule's 4 live false positives were such specifiers (`fs:
    0.0.1-security`, twice `tree-sitter-dockerfile: ^0.0.1-security`); the fourth is a Unity
    module name, `com.unity.modules.terrain: 1.0.0`. Not skipped: on `vm-day1`, 6 of the 12
    malicious samples it fires on (a tailwind-icon campaign, `vite-support-kit`) have `fs:
    ^0.0.1-security` too, so it still counts towards the score; every one of the 6 is reported
    through other rules either way. The specifier is the package's own text, read here, not a
    takedown (decision 0016).

    v3 (2026-11-01): a Unity (UPM) package (its `package.json` has Unity's `unity` field)
    depending on a `com.unity.*` name is LOW too: Unity resolves those built-in modules from its
    own registry, while on npm the names are squats OSV calls malware. 41 `net.dreditor.*`
    releases in one live hour and `com.hidano.shadow-only-shader` were exactly that; no `vm-day1`
    sample has such a dependency. Anyone can add the `unity` field, so the finding stays (LOW)."""

    id = "npm.dependency.known-malware"
    version = 3
    severity = Severity.HIGH
    weight = 5.0
    title = "Depends on a known-malicious package"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        if ctx.known_bad is None:
            return ()
        change = candidate.change
        own = change.new.ref.name
        old = runtime_dependencies(change.previous.manifest) if change.previous else {}
        findings = []
        for name, spec in sorted(runtime_dependencies(change.new.manifest).items()):
            if old.get(name) == spec:
                continue
            target = _dependency_name(name, spec)
            records = ctx.known_bad.known_malware(target, ctx.as_of) if target != own else ()
            if not records:
                continue
            explanation = (
                f"Depends on `{target}`, which {', '.join(records[:3])} lists as malware in "
                "every version."
            )
            held = bool(_HOLDER_SPEC.fullmatch(_alias_range(spec)))
            unity = isinstance(change.new.manifest.get("unity"), str) and target.startswith(
                "com.unity."
            )
            if held:
                explanation += (
                    " The specifier only matches npm's empty `0.0.1-security` holding package, "
                    "so it installs nothing (benign authors who ran `npm install` on the name "
                    "have it too)."
                )
            elif unity:
                explanation += (
                    " This is a Unity (UPM) package, and Unity resolves `com.unity.*` modules "
                    "from its own registry, not npm."
                )
            held = held or unity
            findings.append(
                self.finding(
                    explanation,
                    Evidence(
                        kind=EvidenceKind.MANIFEST_FIELD,
                        path=f"package.json:dependencies.{name}",
                        after=f"{name}: {spec}"[:300],
                    ),
                    severity=Severity.LOW if held else None,
                    weight=1.0 if held else None,
                )
            )
        return findings


def _alias_range(spec: str) -> str:
    """The version range of `npm:target@range`; a plain specifier as it is."""
    if not spec.startswith("npm:"):
        return spec
    target = spec.removeprefix("npm:")
    at = target.rfind("@")
    return target[at + 1 :] if at > 0 else ""


def scope(name: str) -> str | None:
    """`@scope` of a scoped npm name, else None."""
    return name.split("/", 1)[0] if name.startswith("@") and "/" in name else None


@dataclass(frozen=True)
class AddedDependency:
    key: str  # the name in package.json
    spec: str
    target: str  # the package npm installs (the alias target for `npm:`)


def foreign_added_dependencies(
    change: Change, watchlist: Watchlist | None
) -> tuple[AddedDependency, ...]:
    """Registry runtime (and optional) dependencies this release adds, or re-points through an
    `npm:` alias, that need a look at who publishes them: not the package itself, not in its
    scope (only a scope's members can publish to it), and not on the watchlist. For a new
    package every dependency is added. `workspace:` specifiers name a monorepo sibling and are
    left out. Sorted by key. Both dependency-reputation rules, and the lookup plan, use this."""
    own = change.new.ref.name
    own_scope = scope(own)
    old = runtime_dependencies(change.previous.manifest) if change.previous else {}
    before = {_dependency_name(name, spec) for name, spec in old.items()}
    added = []
    for key, spec in sorted(runtime_dependencies(change.new.manifest).items()):
        if not is_registry_spec(spec) or spec.strip().startswith("workspace:"):
            continue
        target = _dependency_name(key, spec)
        if target in before or target == own or not target:
            continue
        if own_scope is not None and scope(target) == own_scope:
            continue
        if watchlist is not None and target in watchlist.entries:
            continue
        added.append(AddedDependency(key=key, spec=spec, target=target))
    return tuple(added)


def _accounts(change: Change) -> set[str]:
    """The dependent's accounts: maintainers and publishers of this and the previous version."""
    accounts: set[str] = set()
    for snapshot in (change.new, change.previous):
        if snapshot is not None:
            accounts.update(snapshot.publish.maintainers)
            if snapshot.publish.publisher:
                accounts.add(snapshot.publish.publisher)
    return accounts


def dependency_accounts(record: DependencyRecord, as_of: datetime) -> set[str]:
    """A found dependency's accounts: the maintainers and publishers of its versions published
    by `as_of`, else (those versions were taken down) its current top-level maintainers; none if
    it had no version by `as_of`. npm's own `REGISTRY_ACCOUNTS` are left out."""
    known = [v for v in record.versions if v.published_at <= as_of]
    if not known:
        return set()
    listed = {a for v in known for a in v.accounts} or set(record.maintainers)
    return listed - REGISTRY_ACCOUNTS


def _dependency_evidence(dep: AddedDependency) -> Evidence:
    return Evidence(
        kind=EvidenceKind.MANIFEST_FIELD,
        path=f"package.json:dependencies.{dep.key}",
        after=f"{dep.key}: {dep.spec}"[:300],
    )


def _hours(delta: timedelta) -> str:
    return f"{delta / timedelta(hours=1):.1f}"


def _age(delta: timedelta) -> str:
    """`18.0 hours before this release`, or `0.5 hours after` for a dependency published after
    its dependent (but by the run's `as_of`)."""
    if delta < timedelta(0):
        return f"{_hours(-delta)} hours after this release"
    return f"{_hours(delta)} hours before this release"


def _list(names: Sequence[str]) -> str:
    shown = ", ".join(names[:10])
    return shown + (f" (+{len(names) - 10} more)" if len(names) > 10 else "") if names else "none"


PRERELEASE_NOTE: Final = (
    " A prerelease, which npm installs only when asked for it by version or tag."
)
ESTABLISHED_SCOPE_NOTE: Final = (
    " Its scope `{scope}` also holds `{watched}`, a package on the run's watchlist: only the "
    "scope's owner can publish there."
)


class _WatchedScopes:
    """`{scope: the first watched package in it}` of one watchlist, built once per watchlist
    object (like `_PopularNames`)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._built: list[tuple[Watchlist, Mapping[str, str]]] = []  # keeps each list alive

    def of(self, watchlist: Watchlist) -> Mapping[str, str]:
        with self._lock:
            for seen, known in self._built:
                if seen is watchlist:
                    return known
            scopes: dict[str, str] = {}
            for name in sorted(watchlist.entries):
                if (owner := scope(name)) is not None:
                    scopes.setdefault(owner, name)
            self._built = [*self._built[-3:], (watchlist, scopes)]
            return scopes


class FreshForeignDependency(BaseRule):
    """The release adds a dependency (`foreign_added_dependencies`) whose first version was
    published less than `FRESH_DAYS` before this release, by accounts that have nothing to do
    with this package: none of the dependency's maintainers or publishers (on its versions
    published by `as_of`, else its current maintainers; npm's own `REGISTRY_ACCOUNTS` left out)
    is a maintainer or publisher of this release or the previous one. The shape of a
    dependency-chain attack: the payload is in a package registered the day before, and the
    dependent's own tarball carries nothing for Stages 2 and 3 to see.

    "First version" is the earliest `time[version]` no later than `as_of` (`time.created` is
    rewritten when npm takes a package down; version times survive). A dependency without any
    account information, a dependent without any, and a lookup that failed give an INFO
    `NOT_EVALUATED` finding instead, so a failed lookup never reads as "not fresh" (decision
    0009). Dependencies over the lookup limits (per release, per run) share one such finding,
    so a release with 2,000 of them has one, not 2,000. A dependency the registry doesn't have
    (404) gives nothing here: `npm.dependency.missing` reports it.

    | Proposal (run `20261029T221803Z-npm`) | Benign | Malicious (DataDog) |
    |---|---|---|
    | fires, < 7 days | 3 of 101,232 updates, 0 of 4,427 new | 120 of 965 updates (2 incidents) |

    The two incidents: `easy-day-js` (119 `@mastra/*` releases) and `plain-crypto-js`
    (`axios@1.14.1`), both ~18 hours old when the dependent was published.

    v3 (2026-11-09, `docs/proposals/precision-round3.md` X7): LOW, weight 1, on a prerelease
    (`0.2.2-alpha.2`, `0.0.41-canary-…`), which npm installs only when asked for it by version
    or tag, as `npm.publish-method.downgrade` v3 decided: alphas and release candidates that
    depend on their ecosystem's newest packages were 13 of the 33 benign live reports this rule
    carried alone, and none of the `vm-day1` malicious samples it fires on is a prerelease (the
    campaigns publish releases, which `npm install` picks).

    v4 (2026-11-10, `docs/proposals/precision-round4-C.md` F1): LOW, weight 1, when the fresh
    dependency is in an npm scope that also holds a package on the run's watchlist
    (`@earendil-works/pi-schema` beside the watched `@earendil-works/pi-ai`,
    `@deepseek-ai/dsh-fs-patch`, `@midnightntwrk/zkir-v3`). Only a scope's owner (the user or
    the organisation's members) can publish into it, so the new package comes from an
    established, popular publisher: the dependent's maintainers chose a sibling of a package
    they could already depend on, not a package registered for the attack. 11 of the 20 benign
    live reports this rule carried alone; every `vm-day1` dependency-chain payload it fires on
    is unscoped (`easy-day-js`, `plain-crypto-js`, `aethlong`, `elaverse`). Taking this over
    takes the popular scope's own account, whose new package is then a new package of its own
    in the feed, read by Stages 1-3 like any other.
    """

    id = "npm.dependency.fresh-foreign"
    version = 4  # 2: one finding for every dependency over the lookup limits; "N hours after"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "New dependency, days old, from unrelated accounts"

    def __init__(self) -> None:
        self._scopes = _WatchedScopes()

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        if ctx.dependencies is None:
            return ()
        change = candidate.change
        published = change.new.publish.published_at or ctx.as_of
        mine = _accounts(change)
        version = semver.parse(change.new.ref.version)
        prerelease = version is not None and version.is_prerelease
        scopes = self._scopes.of(ctx.watchlist) if ctx.watchlist is not None else {}
        findings = []
        capped = []
        for dep in foreign_added_dependencies(change, ctx.watchlist):
            record = ctx.dependencies(dep.target)
            if record.status is DependencyStatus.CAPPED:
                capped.append(dep)
                continue
            found = self._check(dep, record, published, mine, ctx.as_of)
            if found is not None and found.severity is not Severity.INFO:
                notes = PRERELEASE_NOTE if prerelease else ""
                owner = scope(dep.target)
                if owner is not None and owner in scopes:
                    notes += ESTABLISHED_SCOPE_NOTE.format(scope=owner, watched=scopes[owner])
                if notes:
                    found = found.model_copy(
                        update={
                            "severity": Severity.LOW,
                            "weight": 1.0,
                            "explanation": found.explanation + notes,
                        }
                    )
            if found is not None:
                findings.append(found)
        if capped:
            findings.append(self._capped(capped))
        return findings

    def _check(
        self,
        dep: AddedDependency,
        record: DependencyRecord,
        published: datetime,
        mine: set[str],
        as_of: datetime,
    ) -> Finding | None:
        if record.status is DependencyStatus.MISSING:
            return None
        if record.status is DependencyStatus.FAILED:
            return self._not_evaluated(dep, "its registry record could not be fetched.")
        known = [v for v in record.versions if v.published_at <= as_of]
        if not known:
            return None
        first = min(known, key=lambda v: (v.published_at, v.version))
        age = published - first.published_at
        if age >= timedelta(days=FRESH_DAYS):
            return None
        theirs = sorted(dependency_accounts(record, as_of))
        if not theirs or not mine:
            whose = "the dependency's" if not theirs else "this package's"
            return self._not_evaluated(
                dep,
                f"it was first published {_age(age)}, but {whose} registry record names no "
                "accounts.",
            )
        if mine.intersection(theirs):
            return None
        return self.finding(
            f"Depends on `{dep.target}`, first published {_age(age)} "
            f"({first.version} at {first.published_at.isoformat()}), by accounts that "
            f"maintain or publish none of this package's versions ({_list(theirs)}; this "
            f"package: {_list(sorted(mine))}).",
            _dependency_evidence(dep),
            Evidence(
                kind=EvidenceKind.METADATA,
                path=f"registry:{dep.target}",
                before=", ".join(sorted(mine))[:300],
                after=", ".join(theirs)[:300],
                snippet=f"{first.version} published {first.published_at.isoformat()}",
            ),
        )

    def _not_evaluated(self, dep: AddedDependency, why: str) -> Finding:
        return self._info(
            f"{NOT_EVALUATED}`{dep.target}` was not checked for age and accounts: {why}",
            _dependency_evidence(dep),
        )

    def _capped(self, deps: Sequence[AddedDependency]) -> Finding:
        names = [f"`{d.target}`" for d in deps]
        return self._info(
            f"{NOT_EVALUATED}{len(deps)} added dependencies were not checked for age and "
            f"accounts ({_list(names)}): over the dependency lookup limits (per release, or "
            "the run's cap).",
            *(_dependency_evidence(d) for d in deps[:5]),
        )

    def _info(self, explanation: str, *evidence: Evidence) -> Finding:
        finding = self.finding(explanation, *evidence, severity=Severity.INFO)
        return finding.model_copy(update={"weight": 0.0})


# `npm.dependency.missing`: how a dependency's name relates to its dependent's. Names are split
# into parts on `-_./@`; parts shorter than `KIN_MIN_PART` (`rn`, `ui`, `vk`) and parts that are
# a watched package's name (`tailwindcss`, `postcss`, `react`: anyone can borrow those) say
# nothing. Two parts are kin when equal, or when the shorter, at least `KIN_PREFIX_MIN` long,
# starts the longer (`ranu` / `ranujs`, `materia` / `materialinstruments`).
KIN_MIN_PART: Final = 3
KIN_PREFIX_MIN: Final = 4
_NAME_PARTS: Final = re.compile(r"[-_./@]+")
_NAME_EXTENSION: Final = ("-", "_", ".")
_EXACT_PREFIX: Final = re.compile(r"^[=v\s]+")


def _base(name: str) -> str:
    """A name without its scope: `@scope/pkg` -> `pkg`."""
    return name.split("/", 1)[1] if scope(name) is not None else name


def _parts(text: str, popular: Mapping[str, object]) -> set[str]:
    return {
        p for p in _NAME_PARTS.split(text.lower()) if len(p) >= KIN_MIN_PART and p not in popular
    }


def _kin(a: str, b: str) -> bool:
    short, long = sorted((a, b), key=len)
    return short == long or (len(short) >= KIN_PREFIX_MIN and long.startswith(short))


def sibling_reason(dep: AddedDependency, change: Change, watchlist: Watchlist | None) -> str | None:
    """Why a dependency looks like the dependent's own sibling, published on its own (or not
    yet), or None if nothing relates them:
    - its specifier is exactly the dependent's version (a release train:
      `@allyhub-next/scaffold: 0.2.0-next.4` from `allyhub@0.2.0-next.4`). Not a range:
      `fast-deep-thinking@1.0.1`, a campaign wrapper, asked for `^1.0.1` of its payload;
    - its name (without scope) extends the dependent's or the reverse (platform builds:
      `envdoc-cli-linux-x64` from `envdoc-cli`), or the two start with the same part
      (`monolith-core-database` from `monolith-core-cli`);
    - its scope is kin to a part of the dependent's name (`@ocean/core` from
      `@amoree-code/ocean`, `@allyhub-next/*` from `allyhub`).
    A watched name never makes them kin: `react-x` is not in `react`'s family, and
    `@utilitycraft/tailwindcss-motion-atelier` is not `tailwindcss-animate-bridge`'s."""
    own = change.new.ref.name
    version = change.new.ref.version
    if _EXACT_PREFIX.sub("", _alias_range(dep.spec)).strip() == version:
        return f"its specifier is this release's own version ({version})"
    popular: Mapping[str, object] = watchlist.entries if watchlist is not None else {}
    theirs, mine = _base(dep.target).lower(), _base(own).lower()
    for short, long in ((mine, theirs), (theirs, mine)):
        if short not in popular and any(long.startswith(short + s) for s in _NAME_EXTENSION):
            return f"its name extends `{short}`"
    lead = _NAME_PARTS.split(mine)[0]
    if lead == _NAME_PARTS.split(theirs)[0] and len(lead) >= KIN_MIN_PART and lead not in popular:
        return f"its name starts with this package's `{lead}`"
    their_scope = scope(dep.target)
    if their_scope is not None:
        own_parts = _parts(own, popular)
        for part in sorted(_parts(their_scope, popular)):
            if any(_kin(part, p) for p in own_parts):
                return f"its scope `{their_scope}` matches this package's name"
    return None


class MissingDependency(BaseRule):
    """The release adds a dependency (`foreign_added_dependencies`) that the registry doesn't
    have: its packument lookup in this run returned 404 (`DependencyStatus.MISSING`). `npm
    install` fails until someone publishes the name, and whoever does decides what runs. That
    is how a campaign of Tailwind-plugin wrappers worked in 2026-10/11
    (`tailwindcss-animate-bridge@2.0.8` -> `@utilitycraft/tailwindcss-motion-atelier`,
    MAL-2026-18468; `tailwindcss-visual-kit@1.3.7` -> `@nexlayerlabs/postcss-keyframe-utils`,
    MAL-2026-18407): a clean wrapper whose code requires a scoped postcss-style package
    published after it, the payload. The wrapper's own files carry nothing for Stages 2-3, and
    `fresh-foreign` can't age a package that doesn't exist yet.

    A dependency that looks like the release's own sibling (`sibling_reason`: monorepo
    packages published one by one, platform builds published after the main package, a
    specifier equal to the release's version) gives an INFO finding instead. Measured on the
    live runs of 2026-10-28 to 11-08 (10.7 days, `docs/stages/correlate.md`): 121 releases
    added a dependency that was 404, 86 of them only siblings; of the other 35, 16 were the
    campaign (all of its recorded wrappers that declared the payload) and 19 not (private
    registries' packages such as `@fortawesome/pro-*` and `@microchip/*`, names of a monorepo
    not published yet, a test `mm_no_such_module_xyz`), 4 of those reported already: ~1.4
    extra reports a day. A private package is a dependency-confusion exposure: worth a look.
    MEDIUM on its own (not `WEAK_ALONE`): 8 of the 16 wrappers had no other finding, the rest
    only LOW ones.

    Only a 404 counts. A lookup that failed (the network, a malformed record) is `FAILED`, not
    missing (decision 0009), and one over the lookup limits was never asked; `fresh-foreign`
    says both were not evaluated. The 404 is the run's recorded answer, so a replay reads the
    same. All unrelated missing dependencies share one MEDIUM finding, the siblings one INFO."""

    id = "npm.dependency.missing"
    version = 1
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Depends on a package the registry doesn't have"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        if ctx.dependencies is None:
            return ()
        change = candidate.change
        unrelated: list[AddedDependency] = []
        siblings: list[tuple[AddedDependency, str]] = []
        for dep in foreign_added_dependencies(change, ctx.watchlist):
            if ctx.dependencies(dep.target).status is not DependencyStatus.MISSING:
                continue
            why = sibling_reason(dep, change, ctx.watchlist)
            if why is None:
                unrelated.append(dep)
            else:
                siblings.append((dep, why))
        findings = []
        if unrelated:
            findings.append(
                self.finding(
                    f"Depends on {_list([f'`{d.target}`' for d in unrelated])}, which the "
                    "registry did not have when this run looked (HTTP 404), under a name "
                    "unrelated to this package's. Installing it fails until someone publishes "
                    "the name, and whoever does decides what runs: a payload published after "
                    "its wrapper looks like this, and so does a private registry's package (a "
                    "dependency-confusion exposure).",
                    *(_dependency_evidence(d) for d in unrelated[:5]),
                )
            )
        if siblings:
            listed = "; ".join(f"`{d.target}`: {why}" for d, why in siblings[:10])
            more = f" (+{len(siblings) - 10} more)" if len(siblings) > 10 else ""
            finding = self.finding(
                f"Depends on {len(siblings)} package(s) the registry did not have when this "
                f"run looked (HTTP 404) that look like this package's own: {listed}{more}.",
                *(_dependency_evidence(d) for d, _ in siblings[:5]),
                severity=Severity.INFO,
            )
            findings.append(finding.model_copy(update={"weight": 0.0}))
        return findings


@dataclass(frozen=True)
class UndeclaredLoad:
    """A package Stage 3's `npm.undeclared-package` named, with where the code loads it."""

    name: str
    evidence: Evidence


def undeclared_lookups(
    candidate: Candidate, watchlist: Watchlist | None
) -> tuple[UndeclaredLoad, ...]:
    """The packages that loading the release loads without declaring them (Stage 3's
    `npm.undeclared-package`) that need a registry lookup: not in the release's own scope
    (only its members can publish there), not on the watchlist (they exist), and not names
    that look like the release's own siblings (`sibling_reason`: a monorepo package published
    on its own). In the finding's order. The lookup plan and `npm.undeclared.missing` both use
    this."""
    change = candidate.change
    own_scope = scope(change.new.ref.name)
    found: dict[str, UndeclaredLoad] = {}
    for finding in candidate.findings:
        if finding.rule_id != UndeclaredPackage.id:
            continue
        for name, evidence in undeclared_evidence(finding):
            if name in found or (own_scope is not None and scope(name) == own_scope):
                continue
            if watchlist is not None and name in watchlist.entries:
                continue
            if sibling_reason(AddedDependency(key=name, spec="", target=name), change, watchlist):
                continue
            found[name] = UndeclaredLoad(name=name, evidence=evidence)
    return tuple(found.values())


class UndeclaredMissing(BaseRule):
    """Loading the release loads a package it doesn't declare (Stage 3's
    `npm.undeclared-package`: at module load, from its entry points or the files they load,
    not even a devDependency) and the registry doesn't have that name either: its lookup in
    this run returned 404. The Tailwind-wrapper template `tailwind-animate-engine@1.0.6`
    (2026-11-02, with `tailwind-animate-final@1.0.6` and `tailwind-animate-test` 1.0.1 and
    1.0.4) required its payload `@unipswap/postcss-animate-units` without declaring it, so
    `npm.dependency.missing` (declared names) could not see it; the payload was published
    later. Installed alone such a release fails; whoever publishes the name decides what its
    code runs.

    The names are `undeclared_lookups`' (own scope, watched names and siblings are never asked).
    Only a 404 counts (decision 0009): a lookup that failed, or one over the lookup limits,
    gives an INFO `NOT_EVALUATED` finding. MEDIUM, weight 3, like `npm.dependency.missing`:
    the wrapper's own code has nothing else to report. Measured in `docs/stages/correlate.md`."""

    id = "npm.undeclared.missing"
    version = 1
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Loads a package it doesn't declare and the registry doesn't have"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        if ctx.dependencies is None:
            return ()
        missing: list[UndeclaredLoad] = []
        unknown: list[UndeclaredLoad] = []
        for load in undeclared_lookups(candidate, ctx.watchlist):
            status = ctx.dependencies(load.name).status
            if status is DependencyStatus.MISSING:
                missing.append(load)
            elif status in (DependencyStatus.FAILED, DependencyStatus.CAPPED):
                unknown.append(load)
        findings = []
        if missing:
            findings.append(
                self.finding(
                    f"Loading this version loads {_list([f'`{m.name}`' for m in missing])}, "
                    "which its package.json does not declare and which the registry did not "
                    "have when this run looked (HTTP 404). Installed alone it fails until "
                    "someone publishes the name, and whoever does decides what this "
                    "package's code runs: a wrapper waiting for a payload published after it "
                    "looks like this.",
                    *(m.evidence for m in missing[:5]),
                )
            )
        if unknown:
            finding = self.finding(
                f"{NOT_EVALUATED}{_list([f'`{u.name}`' for u in unknown])} (loaded, not "
                "declared) could not be checked against the registry: the lookup failed or "
                "was over the dependency lookup limits.",
                *(u.evidence for u in unknown[:5]),
                severity=Severity.INFO,
            )
            findings.append(finding.model_copy(update={"weight": 0.0}))
        return findings


def normalize_name(name: str) -> str:
    """Lowercased, without `-`, `_` and `.`: `easy-day-js` -> `easydayjs`."""
    return _SEPARATORS.sub("", name.lower())


class _PopularNames:
    """Normalised popular unscoped names of one watchlist (`POPULAR_MONTHLY`,
    `EMBED_MIN_LENGTH`), built once per watchlist object."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._built: list[tuple[Watchlist, Mapping[str, str]]] = []  # keeps each list alive

    def of(self, watchlist: Watchlist) -> Mapping[str, str]:
        with self._lock:
            for seen, names in self._built:
                if seen is watchlist:
                    return names
            names = {}
            for name, entry in sorted(watchlist.entries.items()):
                key = normalize_name(name)
                if (
                    not name.startswith("@")
                    and entry.monthly_downloads >= POPULAR_MONTHLY
                    and len(key) >= EMBED_MIN_LENGTH
                ):
                    names.setdefault(key, name)
            self._built = [*self._built[-3:], (watchlist, names)]
            return names


def embedded_popular_name(name: str, popular: Mapping[str, str]) -> str | None:
    """The popular name that `name` is, after normalising, plus a prefix or a suffix of 1 to
    `EMBED_MAX_AFFIX` characters; the longest if several are (then the first by name)."""
    key = normalize_name(name)
    hits = {
        popular[part]
        for cut in range(1, EMBED_MAX_AFFIX + 1)
        for part in (key[cut:], key[:-cut])
        if len(part) >= EMBED_MIN_LENGTH and part in popular
    }
    return min(hits, key=lambda n: (-len(normalize_name(n)), n)) if hits else None


class NameEmbedsPopular(BaseRule):
    """The release adds an unscoped dependency (`foreign_added_dependencies`: not watched, not
    the package's own scope) whose name is a popular package's name plus a short prefix or
    suffix: `easy-day-js` (`dayjs`), `plain-crypto-js` (`crypto-js`). Names are compared
    lowercased without `-_.`; popular means `POPULAR_MONTHLY` downloads a month on the run's
    watchlist and at least `EMBED_MIN_LENGTH` characters; the affix is at most
    `EMBED_MAX_AFFIX` characters. A name that differs from a popular one only in separators is
    not matched (no true positive in the proposal's measurement). Needs no fetch, but when the
    run looked the dependency up (`fresh-foreign` does) and it shares an account with this
    package (`dependency_accounts`), it doesn't fire: `react-dom-utils` from React's own
    maintainers, a `dayjs-plugin-*` from the dependent's author. An unchecked dependency (over
    the limits, failed) still fires.

    | Proposal (run `20261029T221803Z-npm`) | Benign | Malicious (DataDog) |
    |---|---|---|
    | fires | 12 of 101,232 updates, 15 of 4,427 new | 120 of 965 updates, 17 of 905 new |

    LOW: evidence that orders the queue and names the pattern; it can't report alone.
    """

    id = "npm.dependency.name-embeds-popular"
    version = 2  # 2: not when the dependency shares an account with this package
    severity = Severity.LOW
    weight = 1.0
    title = "New dependency named after a popular package"

    def __init__(self) -> None:
        self._popular = _PopularNames()

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        if ctx.watchlist is None:
            return ()
        popular = self._popular.of(ctx.watchlist)
        mine = _accounts(candidate.change)
        findings = []
        for dep in foreign_added_dependencies(candidate.change, ctx.watchlist):
            if dep.target.startswith("@"):
                continue
            embedded = embedded_popular_name(dep.target, popular)
            if embedded is not None and not self._same_accounts(dep, mine, ctx):
                downloads = ctx.watchlist.entries[embedded].monthly_downloads
                findings.append(
                    self.finding(
                        f"Depends on `{dep.target}`, whose name embeds the popular package "
                        f"`{embedded}` ({downloads:,} downloads a month); `{dep.target}` "
                        "itself is not on the watchlist.",
                        _dependency_evidence(dep),
                    )
                )
        return findings

    @staticmethod
    def _same_accounts(dep: AddedDependency, mine: set[str], ctx: CorrelationContext) -> bool:
        if ctx.dependencies is None or not mine:
            return False
        record = ctx.dependencies(dep.target)
        if record.status is not DependencyStatus.FOUND:
            return False
        return bool(mine & dependency_accounts(record, ctx.as_of))


def _definitely_typed(change: Change) -> bool:
    publishers = {change.new.publish.publisher}
    if change.previous is not None:
        publishers.add(change.previous.publish.publisher)
    return change.new.ref.name.startswith("@types/") and publishers == {DEFINITELY_TYPED}


class RevivedWithNewDependency(BaseRule):
    """A package dormant for a long time (`npm.dormant-revived`) comes back with a new runtime
    dependency (`npm.dependency.added`). Each is common alone; together they are the shape of
    a takeover that pulls its payload in through a dependency.

    Prereleases are skipped: a `canary`/`experimental`/`pr-` channel can sit unused for years,
    so its next build is "revived", and new builds add dependencies. On `day1` all 3 benign
    updates this reported end to end were such builds; the malicious ones were all releases.
    DefinitelyTyped's `@types/*` packages are skipped when the `types` account published both
    versions: its bot republishes long-idle type packages, and they add dependencies (4 in one
    live hour on 2026-10-28; none carry provenance to tell them apart otherwise). Abusing that
    takes DefinitelyTyped's own publishing token.
    Caveat: the malicious ones are two campaigns (`@antv/*` and `@mastra/*` in the Shai-Hulud
    wave), so the recall figure says more about them than about takeovers in general.

    v2 (2026-11-08): LOW, weight 1, when the account that published the previous release
    publishes this one and no maintainer was added: the package's own maintainer coming back.
    It was 74 of the 140 live versions this rule alone reported (Oct 28 - Nov 3), all benign.
    The takeovers in `vm-day1` come from another account (`xrpl@2.14.2`: `mukulljangid` after
    `ckniffen`; `@mastra/*`), so none is lost. A dormant account hijacked as itself (an expired
    e-mail domain) is LOW here and needs its other signals (`leo-logger@1.0.8` has them).
    See `docs/proposals/stage1-precision.md`.

    v3 (2026-11-08): LOW, weight 1, too when the release carries a provenance attestation: a
    takeover that publishes with provenance needs the repository's CI as well as the npm
    account. 65 benign live reports (65 packages), and the rule has no positive live; the
    takeovers it catches on `vm-day1` (`xrpl@2.14.2`, `@mastra/*`) have no provenance. Only on
    this rule: provenance is no explanation for install code, where 37 `vm-day1` samples
    were published from compromised CI (`docs/proposals/precision-round2.md`, F7).

    v4 (2026-11-10, `docs/proposals/precision-round6-N.md` C1): trusted publishing (OIDC from
    CI) counts as v3's provenance does. npm records a trusted publisher on releases that carry
    no attestation (`productenv@2.0.0`, `@musedesignsystem/tokens@2.12.2`: published by
    `GitHub Actions`, `trusted_publisher` github, no provenance; both benign, reported by this
    rule alone). Trusted publishing is the stronger tie to the repository's CI: no token can
    stand in for it. No `vm-day1` sample the rule fires on has a trusted publisher without
    provenance.
    """

    id = "npm.combination.revived-with-new-dependency"
    version = 4
    severity = Severity.MEDIUM
    weight = 2.0
    title = "Dormant package revived with a new dependency"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        change = candidate.change
        version = semver.parse(change.new.ref.version)
        if version is None or version.is_prerelease or _definitely_typed(change):
            return ()
        fired = {f.rule_id: f for f in candidate.findings}
        revived, added = fired.get("npm.dormant-revived"), fired.get("npm.dependency.added")
        if revived is None or added is None:
            return ()
        if _same_account_returns(change):
            return (
                self.finding(
                    f"{revived.explanation} {added.explanation} Published by "
                    f"`{change.new.publish.publisher}`, who published the previous release, "
                    "with no maintainer added.",
                    *revived.evidence,
                    *added.evidence,
                    severity=Severity.LOW,
                    weight=1.0,
                ),
            )
        if change.new.publish.has_provenance or change.new.publish.trusted_publisher:
            how = (
                "a provenance attestation"
                if change.new.publish.has_provenance
                else f"trusted publishing ({change.new.publish.trusted_publisher})"
            )
            return (
                self.finding(
                    f"{revived.explanation} {added.explanation} Published with {how} (from "
                    "the repository's CI).",
                    *revived.evidence,
                    *added.evidence,
                    severity=Severity.LOW,
                    weight=1.0,
                ),
            )
        return (
            self.finding(
                f"{revived.explanation} {added.explanation}",
                *revived.evidence,
                *added.evidence,
            ),
        )


def _same_account_returns(change: Change) -> bool:
    """The previous release's publisher publishes this one, and no maintainer was added."""
    previous = change.previous
    if previous is None or change.new.publish.publisher is None:
        return False
    added = set(change.new.publish.maintainers) - set(previous.publish.maintainers)
    return change.new.publish.publisher == previous.publish.publisher and not added


class InstallScriptNotInRepo(BaseRule):
    """The release's `package.json` has an install hook (`preinstall`, `install`,
    `postinstall`) that the repository's `package.json` at the compared commit doesn't have, or
    has with a different command. What `npm install` runs never went through git.

    On `day1` (comparable updates): 51 of 55 malicious, 0 of 116 benign. Seen: Shai-Hulud 2.0's
    `node setup_bun.js`, and `@nativescript-community/*` running `node bundle.js` where the
    repository has `npm run setup`.

    v2: a hook a repository file writes (`ManifestDifference.built_by`: the files it runs are
    in the repository byte for byte, and a build script there holds the command) went through
    git after all; it is an INFO note naming that file. First VM day: `@nutui/nutui-react-taro`
    (`scripts/build-taro.mjs`), reported HIGH through this rule.

    v3: a hook the previous release shipped too (the same command, its own version string
    aside) is LOW: it isn't new in this release, so it isn't a stolen token's addition. On the
    first VM days that was every `@pulumi/*` hit (60 reported versions; Pulumi's code generator
    writes the hook). The first release that adds such a hook still fires HIGH.
    """

    id = "npm.repo.install-script-not-in-repo"
    version = 3
    severity = Severity.HIGH
    weight = 5.0
    title = "Install script that the repository doesn't have"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        if comparison is None:
            return ()
        hooks = [d for d in comparison.manifest if d.field.startswith("scripts.")]
        return tuple(_hook_finding(self, d, candidate.change) for d in hooks)


def _shipped_before(change: Change, field: str) -> bool:
    """The previous release had this hook with the same command (its version aside)."""
    previous = change.previous
    if previous is None:
        return False
    hook = field.removeprefix("scripts.")
    old, new = scripts(previous.manifest).get(hook), scripts(change.new.manifest).get(hook)
    if old is None or new is None:
        return False
    return old == new or only_version_changed(
        old, new, previous.ref.version, change.new.ref.version
    )


def _hook_finding(rule: BaseRule, d: ManifestDifference, change: Change) -> Finding:
    evidence = Evidence(
        kind=EvidenceKind.MANIFEST_FIELD,
        path=f"package.json:{d.field}",
        before=d.repo,
        after=d.package,
    )
    if _shipped_before(change, d.field):
        return rule.finding(
            f"`npm install` runs `{d.field}`, which the repository's package.json doesn't "
            "have; the previous release shipped the same hook, so it isn't new here.",
            evidence,
            severity=Severity.LOW,
            weight=1.0,
        )
    if d.built_by is not None:
        return rule.finding(
            f"`npm install` runs `{d.field}`, which the repository's package.json doesn't "
            f"have but its build writes: `{d.built_by}` holds the command, and the files it "
            "runs are in the repository byte for byte.",
            evidence,
            severity=Severity.INFO,  # scores nothing (`correlate.score`)
        )
    return rule.finding(
        f"`npm install` runs `{d.field}`, which the repository's package.json "
        + ("doesn't have." if d.repo is None else "has with a different command."),
        evidence,
    )


class NoNewCommits(BaseRule):
    """The release came from the previous release's commit, or an older one, though its code
    differs from the repository's there or couldn't be compared (the comparison isn't clean):
    what changed since the previous release never went through git. A clean match there is
    the previous release's code republished, which is harmless. Typical of a stolen token
    republishing an old build with a payload added, which keeps the old `gitHead` (Shai-Hulud
    2.0's victims).
    Stable versions only, and only a version number that went up: nightlies, canaries and
    prerelease promotions are built from one commit on purpose.

    | | Malicious | Benign |
    |---|---|---|
    | compared updates, same or older commit (any version shape) | 61 of 102 | 9 of 626 |
    | `vm-day1`, `pipeline+4` (2026-11-06) | 60 of 3,444 | 0 of 1,500 |

    Every one of the 60 is reported through other rules, and a developer publishing changes
    they haven't committed looks the same; so LOW, corroboration that orders the queue."""

    id = "npm.repo.no-new-commits"
    severity = Severity.LOW
    weight = 2.0
    title = "No new commits since the previous release"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        history = comparison.history if comparison is not None else None
        change = candidate.change
        if (
            comparison is None
            or history is None
            or change.previous is None
            or history.previous_commit is None
            or history.status not in ("identical", "behind")
            or comparison.clean
        ):
            return ()
        old, new = semver.parse(change.previous.ref.version), semver.parse(change.new.ref.version)
        if old is None or new is None or old.is_prerelease or new.is_prerelease or not old < new:
            return ()
        where = (
            "the same commit as"
            if history.status == "identical"
            else f"a commit {history.behind_by} commits older than"
        )
        code = (
            "yet its code differs from the repository's there: the change never went through git"
            if comparison.unavailable is None
            else f"and its code couldn't be compared ({comparison.unavailable})"
        )
        return (
            self.finding(
                f"{change.new.ref.version} was built from {where} {history.previous_version} "
                f"({history.previous_commit[:12]}), {code}.",
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="repository",
                    before=history.previous_commit,
                    after=comparison.source.commit if comparison.source else None,
                ),
            ),
        )


class DependencyNotInRepo(BaseRule):
    """A runtime dependency the repository's `package.json` doesn't name in any section. Weak:
    2 of 116 comparable benign updates, 7 of 55 malicious (before `repo.compared` v2, which
    stopped comparing monorepo packages with the root manifest: 14 of 121 and 30 of 57);
    evidence and a little weight, not a reason to report."""

    id = "npm.repo.dependency-not-in-repo"
    severity = Severity.LOW
    weight = 1.0
    title = "Dependency that the repository doesn't declare"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        if comparison is None:
            return ()
        deps = [d for d in comparison.manifest if d.field.startswith("dependencies.")]
        if not deps:
            return ()
        names = ", ".join(d.field.removeprefix("dependencies.") for d in deps[:10])
        return (
            self.finding(
                f"{len(deps)} runtime dependencies are not in the repository's package.json: "
                f"{names}" + ("..." if len(deps) > 10 else ""),
                *(
                    Evidence(
                        kind=EvidenceKind.MANIFEST_FIELD,
                        path=f"package.json:{d.field}",
                        after=d.package,
                    )
                    for d in deps[:5]
                ),
            ),
        )


RULES: Final = (
    GitHeadDropped(),
    KnownMalwareDependency(),
    RevivedWithNewDependency(),
    FreshForeignDependency(),
    MissingDependency(),
    UndeclaredMissing(),
    NameEmbedsPopular(),
    InstallScriptNotInRepo(),
    DependencyNotInRepo(),
    NoNewCommits(),
)
