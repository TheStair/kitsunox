"""Stage 1 metadata rules for npm. They read only the `Change` (manifests and publish info of
the new and previous versions), so they cost nothing beyond Stage 0's fetches.

Manifests are untrusted: every field is type-checked before use, and evidence snippets are
truncated. Severities are starting points; `docs/stages/triage.md` records the evaluation
numbers behind each.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from typing import Final

from kitsunox.core.models import Change, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule, Rule, RuleContext
from kitsunox.ecosystems.npm import semver

# Lifecycle scripts npm runs when a package is installed from the registry. `prepare` is left
# out: it runs for git dependencies and `npm pack`, not for registry installs.
INSTALL_HOOKS: Final = ("preinstall", "install", "postinstall")
SNIPPET_LIMIT: Final = 300
_PROTOCOL = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def _strings(value: object) -> dict[str, str]:
    """A manifest mapping of name -> string (scripts, dependencies); anything else is ignored."""
    if not isinstance(value, Mapping):
        return {}
    return {k: v for k, v in value.items() if isinstance(k, str) and isinstance(v, str)}


def scripts(manifest: Mapping[str, object]) -> dict[str, str]:
    return _strings(manifest.get("scripts"))


def runtime_dependencies(manifest: Mapping[str, object]) -> dict[str, str]:
    """Dependencies installed with the package by default."""
    return _strings(manifest.get("dependencies")) | _strings(manifest.get("optionalDependencies"))


def is_registry_spec(spec: str) -> bool:
    """True for semver ranges, dist-tags and `npm:` aliases; False for anything npm fetches
    from elsewhere (`git+https:`, `http(s):`, `file:`, `github:`, or `user/repo` shorthand)."""
    spec = spec.strip()
    if spec.startswith(("npm:", "workspace:", "catalog:")):
        # `workspace:` is a monorepo publish that wasn't rewritten: it fails to install, but
        # fetches nothing from outside the registry (seen 2026-10-27, `@synap-core/api-types`).
        # So is pnpm's `catalog:` (2026-10-30, `postflareai`).
        return True
    return not _PROTOCOL.match(spec) and "/" not in spec


def snippet(text: str | None) -> str | None:
    if text is None or len(text) <= SNIPPET_LIMIT:
        return text
    return text[:SNIPPET_LIMIT] + f"... [{len(text) - SNIPPET_LIMIT} more chars]"


def _field(path: str, *, after: str | None = None, before: str | None = None) -> Evidence:
    return Evidence(
        kind=EvidenceKind.MANIFEST_FIELD,
        path=f"package.json:{path}",
        before=snippet(before),
        after=snippet(after),
    )


def _watched(change: Change) -> bool:
    return bool(change.popularity and change.popularity.watched)


def has_install_hook(manifest: Mapping[str, object]) -> bool:
    """The manifest declares a non-empty `preinstall`, `install` or `postinstall`."""
    declared = scripts(manifest)
    return any(declared.get(hook, "").strip() for hook in INSTALL_HOOKS)


def only_version_changed(old: str, new: str, old_version: str, new_version: str) -> bool:
    """`new` is `old` with its own version string swapped for the new one, as generated
    commands do (`@pulumi/*`: `node scripts/install-pulumi-plugin.js resource command 1.3.0`).
    What the command runs is diffed in Stage 3 (`npm.install-script-changed`)."""
    return bool(old_version) and old_version in old and old.replace(old_version, new_version) == new


class InstallHook(BaseRule):
    """An install-time script is new or changed. The most common way npm malware runs: it
    executes on `npm install`, before any code imports the package.

    v2: a command whose only change is its own version string is not "changed" (39 of 52
    changed commands on the first VM day, all generated: `@pulumi/*`). Its files are compared
    in Stage 3, where every update with an install hook now goes (`triage.code_route`)."""

    id = "npm.install-hook"
    version = 2
    severity = Severity.HIGH
    weight = 5.0
    title = "Install script added or changed"

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        new = scripts(change.new.manifest)
        previous = change.previous
        old = scripts(previous.manifest) if previous else {}
        findings = []
        for hook in INSTALL_HOOKS:
            if hook not in new:
                continue
            if previous is None:
                findings.append(
                    self.finding(
                        f"New package with a `{hook}` script.",
                        _field(f"scripts.{hook}", after=new[hook]),
                        severity=Severity.MEDIUM,
                    )
                )
            elif hook not in old:
                findings.append(
                    self.finding(
                        f"`{hook}` script added since {previous.ref.version}.",
                        _field(f"scripts.{hook}", after=new[hook]),
                    )
                )
            elif old[hook] != new[hook] and not only_version_changed(
                old[hook], new[hook], previous.ref.version, change.new.ref.version
            ):
                findings.append(
                    self.finding(
                        f"`{hook}` script changed since {previous.ref.version}.",
                        _field(f"scripts.{hook}", before=old[hook], after=new[hook]),
                    )
                )
        return findings


# The registry's own tarball URL for a version of the named package: npm fetches it from the
# registry like a version range would.
_REGISTRY_TARBALL: Final = re.compile(
    r"https://registry\.npmjs\.org/(?P<name>(?:@[^/]+/)?[^/]+)/-/[^/]+\.tgz"
)
_LOCAL: Final = ("file:", "link:")
# Protocols a dependency spec can name that make npm fetch something (npm-package-arg's git,
# hosted-git and remote types, and local paths). Any other protocol (`backstage:^`,
# `portal:`, `patch:`) is an "Unsupported URL Type" to npm: the install fails, nothing is
# fetched.
_FETCHED_PROTOCOLS: Final = frozenset(
    {
        "git",
        "git+ssh",
        "git+http",
        "git+https",
        "git+file",
        "http",
        "https",
        "github",
        "gitlab",
        "bitbucket",
        "gist",
        "ssh",
        "file",
        "link",
    }
)


def fetches_nothing(spec: str) -> bool:
    """The spec names a protocol npm can't fetch from: installing it fails without a download.
    A spec without a protocol (`user/repo` shorthand) is not one of these."""
    protocol = _PROTOCOL.match(spec.strip())
    return protocol is not None and protocol.group(0)[:-1].lower() not in _FETCHED_PROTOCOLS


class NonRegistryDependency(BaseRule):
    """A new dependency resolved from a URL, git repository, GitHub shorthand or local path
    instead of the registry: it bypasses registry-side malware takedowns and is often used to
    pull a second stage.

    v2 (2026-10-30): the registry's own tarball URL for the same package is the registry
    (`@feedmepos/mf-connect` pins `https://registry.npmjs.org/@feedmepos/mf-upselling/-/...`).
    A local path (`file:`, `link:`) fetches nothing and is LOW, weight 1: it fails to install
    outside its monorepo (`@atairo/qixi`: `file:../../frontend/...`). On `vm-day1` the rule's
    malicious samples all used `github:` or `http(s):` URLs.

    v3 (2026-11-08): a protocol npm can't fetch (`backstage:^`, Backstage's yarn plugin) is not
    a finding: like `workspace:` and `catalog:`, the install fails and nothing is downloaded.
    It was 6 of the 71 live versions this rule alone reported (`@ai-crew-suite/*`, all
    benign); no malicious sample uses one. A dependency on a commit in the package's *own*
    repository still fires: that is how the `@opensearch-project/opensearch` and `@antv/*`
    attacks pulled their payload (`docs/proposals/stage1-precision.md`)."""

    id = "npm.dependency.non-registry"
    version = 3
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Dependency installed from outside the registry"

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        new = runtime_dependencies(change.new.manifest)
        old = runtime_dependencies(change.previous.manifest) if change.previous else {}
        findings = []
        for name, spec in sorted(new.items()):
            if old.get(name) == spec or is_registry_spec(spec) or fetches_nothing(spec):
                continue
            tarball = _REGISTRY_TARBALL.fullmatch(spec.strip())
            if tarball is not None and tarball["name"] == name:
                continue
            local = spec.strip().startswith(_LOCAL)
            findings.append(
                self.finding(
                    f"Dependency `{name}` comes from `{snippet(spec)}`."
                    + (" A local path: nothing is fetched." if local else ""),
                    _field(f"dependencies.{name}", after=spec, before=old.get(name)),
                    severity=Severity.LOW if local else None,
                    weight=1.0 if local else None,
                )
            )
        return findings


class DependencyAdded(BaseRule):
    """Runtime dependencies added to an existing package. Weak alone (normal development), but
    a compromised release often adds exactly one."""

    id = "npm.dependency.added"
    severity = Severity.LOW
    weight = 1.0
    title = "Runtime dependency added"

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        if change.previous is None:
            return []
        old = runtime_dependencies(change.previous.manifest)
        added = sorted(set(runtime_dependencies(change.new.manifest)) - set(old))
        if not added:
            return []
        return [
            self.finding(
                f"{len(added)} dependencies added: {', '.join(added[:10])}"
                + ("..." if len(added) > 10 else ""),
                _field("dependencies", after=", ".join(added)),
            )
        ]


class PublishMethodDowngrade(BaseRule):
    """The previous release was published with trusted publishing (OIDC from CI) or carried a
    provenance attestation, and this one has neither. Typical of a stolen token being used from
    an attacker's machine instead of the project's CI.

    v2: HIGH for a watched (popular) package; MEDIUM, weight 3, otherwise, and then it doesn't
    report a version alone (`correlate.WEAK_ALONE`). Alone it was the commonest
    reason for HIGH on the first VM days (242 reported versions), almost all small packages
    whose maintainer sometimes publishes by hand. On `vm-day1` no malicious sample lost its
    report by this (the compromises it catches alone, `axios@1.14.1` and `@nx/*`, are watched);
    one benign one is cleared.

    v3: LOW, weight 1, on a prerelease (`1.95.0-dev.2026…`, `0.6.0-canary.3`), watched or not.
    npm installs a prerelease only when asked for it by version or tag, and maintainers often
    publish their dev and canary builds by hand: 77 of the 101 live queue versions reported by
    this rule alone (2026-10-31) were prereleases (the 9 reviewed, all benign). On `vm-day1` it
    fires on 149 malicious samples, none a prerelease, so none is lost. The rule can't see
    dist-tags, so a prerelease an attacker also tags `latest` is LOW here; what it runs still
    meets the install and content rules.

    v4 (2026-11-08): full weight only with a co-signal, another Stage 1 rule firing on the same
    change (`DOWNGRADE_COSIGNALS`: what gets installed or who publishes changed too), or, for a
    watched package, a dropped `gitHead`. Otherwise one step lower: MEDIUM weight 3 (weak
    alone) when watched, LOW weight 1 when not. All 149 malicious `vm-day1` samples have a
    co-signal (42 an install hook, 107 a new dependency); of the 89 live versions reported
    only because of this rule (Oct 28 - Nov 3), 74 had none, all benign or inconclusive
    (27 were one `@knapsack/*` release). See `docs/proposals/stage1-precision.md`. A stolen
    token used for a code-only change that keeps `gitHead` now needs Stages 2-3 to see it."""

    id = "npm.publish-method.downgrade"
    version = 4
    severity = Severity.HIGH
    weight = 5.0
    title = "Published without the CI provenance the previous release had"

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        if change.previous is None:
            return []
        old, new = change.previous.publish, change.new.publish
        had = old.trusted_publisher is not None or old.has_provenance
        has = new.trusted_publisher is not None or new.has_provenance
        if not had or has:
            return []
        before = f"trusted_publisher={old.trusted_publisher}, provenance={old.has_provenance}"
        parsed = semver.parse(change.new.ref.version)
        watched = _watched(change)
        cosignals = [rule.id for rule in DOWNGRADE_COSIGNALS if rule.evaluate(change, ctx)]
        git_head_dropped = old.git_head is not None and new.git_head is None
        severity: Severity | None
        weight: float | None
        if parsed is not None and parsed.is_prerelease:
            severity, weight = Severity.LOW, 1.0
            note = ""
        elif cosignals or (watched and git_head_dropped):
            severity, weight = (None, None) if watched else (Severity.MEDIUM, 3.0)
            note = (
                f" With: {', '.join(cosignals)}."
                if cosignals
                else f" No git commit recorded, where {change.previous.ref.version} had one."
            )
        else:
            severity, weight = (Severity.MEDIUM, 3.0) if watched else (Severity.LOW, 1.0)
            note = " Nothing else about what gets installed, or who publishes it, changed."
        return [
            self.finding(
                f"{change.previous.ref.version} was published from CI "
                f"({old.trusted_publisher or 'provenance'}); this release was published by "
                f"`{new.publisher}` without it.{note}",
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="publish",
                    before=before,
                    after=f"publisher={new.publisher}",
                ),
                severity=severity,
                weight=weight,
            )
        ]


class UnfamiliarPublisher(BaseRule):
    """Published by an account that was not a maintainer of the previous release.

    v2: MEDIUM → LOW. On 2026-10-27 it fired on 2.57% of benign releases (2,712 of 105,520,
    almost all of Stage 1's benign forwarding: team members publish without being listed) but
    caught only 10 first-release DataDog samples that no other rule caught. It still adds to the
    score; it no longer forwards on its own."""

    id = "npm.publisher.unfamiliar"
    version = 2
    severity = Severity.LOW
    weight = 1.0
    title = "Publisher was not a previous maintainer"

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        if change.previous is None:
            return []
        publisher = change.new.publish.publisher
        known = set(change.previous.publish.maintainers) | {change.previous.publish.publisher}
        if publisher is None or publisher in known or not change.previous.publish.maintainers:
            return []
        return [
            self.finding(
                f"`{publisher}` published this release but was not a maintainer of "
                f"{change.previous.ref.version}.",
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="publish.publisher",
                    before=", ".join(sorted(change.previous.publish.maintainers)),
                    after=publisher,
                ),
            )
        ]


class MaintainerAdded(BaseRule):
    id = "npm.maintainer.added"
    severity = Severity.LOW
    weight = 1.0
    title = "Maintainer added"

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        if change.previous is None or not change.previous.publish.maintainers:
            return []
        added = sorted(
            set(change.new.publish.maintainers) - set(change.previous.publish.maintainers)
        )
        if not added:
            return []
        return [
            self.finding(
                f"Maintainers added since {change.previous.ref.version}: {', '.join(added)}.",
                Evidence(kind=EvidenceKind.METADATA, path="maintainers", after=", ".join(added)),
            )
        ]


def calendar_major(major: int, as_of_year: int) -> bool:
    """`major` reads as `YYYYMM` or `YYYYMMDD`: a real month (and day), and a year from 1990 to
    the year after `as_of_year`. `999999` and `99999999` are not dates."""
    digits = str(major)
    if len(digits) not in (6, 8):
        return False
    year, month = int(digits[:4]), int(digits[4:6])
    day = int(digits[6:]) if len(digits) == 8 else 1
    if not 1990 <= year <= as_of_year + 1:
        return False
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


class SuspiciousVersion(BaseRule):
    """Very high major versions (`99.9.9`, `999.0.0`) are the signature of dependency-confusion
    attacks: they outrank any internal package of the same name.

    v2: calendar versions (`2026.10.4`: a year-like major and a month-like minor) are exempt.
    They were most of this rule's benign hits on 2026-10-27.

    v3 (2026-11-08): a major that is itself a date, `YYYYMM` or `YYYYMMDD` with a real month
    and day and a year from 1990 to the year after `as_of` (`202610.31.30847`,
    `20261028.0.0`), is exempt too (`calendar_major`). In the 4-day run of 2026-11-07, 314 of
    1,438 reported versions were `@haybarn/*` new packages with such versions, reported by
    this rule alone. No DataDog sample and none of the 53,389 versions OSV lists explicitly as
    malware has a calendar-shaped major: confusion attacks use `99`, `999`, `9999`,
    `99999999` (`docs/proposals/stage1-precision.md`)."""

    id = "npm.version.suspicious"
    version = 3
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Dependency-confusion style version number"
    MIN_MAJOR: Final = 90

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        version = semver.parse(change.new.ref.version)
        if version is None or version.major < self.MIN_MAJOR:
            return []
        if 1990 <= version.major <= 2100 and 1 <= version.minor <= 12:
            return []  # CalVer
        if calendar_major(version.major, ctx.as_of.year):
            return []  # the major is a date: YYYYMM or YYYYMMDD
        if change.previous is not None:
            previous = semver.parse(change.previous.ref.version)
            if previous is not None and previous.major >= self.MIN_MAJOR:
                return []  # the package has always used such versions (e.g. date-based)
        return [
            self.finding(
                f"Version {change.new.ref.version} has major {version.major} "
                f"(threshold {self.MIN_MAJOR}).",
                Evidence(kind=EvidenceKind.METADATA, path="version", after=change.new.ref.version),
            )
        ]


class DormantRevived(BaseRule):
    """First release after a long pause. Abandoned packages are attractive takeover targets."""

    id = "npm.dormant-revived"
    severity = Severity.LOW
    weight = 1.0
    title = "Release after a long pause"
    MIN_GAP: Final = timedelta(days=365)

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        if change.previous is None:
            return []
        new_at, old_at = change.new.publish.published_at, change.previous.publish.published_at
        if new_at is None or old_at is None or new_at - old_at < self.MIN_GAP:
            return []
        days = (new_at - old_at).days
        return [
            self.finding(
                f"{days} days since {change.previous.ref.version}.",
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="time",
                    before=old_at.isoformat(),
                    after=new_at.isoformat(),
                ),
            )
        ]


# Stage 1 rules whose firing keeps `npm.publish-method.downgrade` at full weight: the release
# also changes what gets installed, or who publishes it.
DOWNGRADE_COSIGNALS: Final[tuple[Rule, ...]] = (
    InstallHook(),
    NonRegistryDependency(),
    DependencyAdded(),
    MaintainerAdded(),
    UnfamiliarPublisher(),
    SuspiciousVersion(),
)

RULES: Final = (
    InstallHook(),
    NonRegistryDependency(),
    DependencyAdded(),
    PublishMethodDowngrade(),
    UnfamiliarPublisher(),
    MaintainerAdded(),
    SuspiciousVersion(),
    DormantRevived(),
)
