"""Stage 1 metadata rules for npm. They read only the `Change` (manifests and publish info of
the new and previous versions), so they cost nothing beyond Stage 0's fetches.

Manifests are untrusted: every field is type-checked before use, and evidence snippets are
truncated. Severities are starting points; `docs/stages/triage.md` records the evaluation
numbers behind each.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Final

from kitsunox.core.models import Change, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule, RuleContext
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
    if spec.startswith(("npm:", "workspace:")):
        # `workspace:` is a monorepo publish that wasn't rewritten: it fails to install, but
        # fetches nothing from outside the registry (seen 2026-10-27, `@synap-core/api-types`).
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


class NonRegistryDependency(BaseRule):
    """A new dependency resolved from a URL, git repository, GitHub shorthand or local path
    instead of the registry: it bypasses registry-side malware takedowns and is often used to
    pull a second stage."""

    id = "npm.dependency.non-registry"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Dependency installed from outside the registry"

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]:
        new = runtime_dependencies(change.new.manifest)
        old = runtime_dependencies(change.previous.manifest) if change.previous else {}
        return [
            self.finding(
                f"Dependency `{name}` comes from `{snippet(spec)}`.",
                _field(f"dependencies.{name}", after=spec, before=old.get(name)),
            )
            for name, spec in sorted(new.items())
            if old.get(name) != spec and not is_registry_spec(spec)
        ]


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
    one benign one is cleared."""

    id = "npm.publish-method.downgrade"
    version = 2
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
        return [
            self.finding(
                f"{change.previous.ref.version} was published from CI "
                f"({old.trusted_publisher or 'provenance'}); this release was published by "
                f"`{new.publisher}` without it.",
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="publish",
                    before=before,
                    after=f"publisher={new.publisher}",
                ),
                severity=None if _watched(change) else Severity.MEDIUM,
                weight=None if _watched(change) else 3.0,
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


class SuspiciousVersion(BaseRule):
    """Very high major versions (`99.9.9`, `999.0.0`) are the signature of dependency-confusion
    attacks: they outrank any internal package of the same name.

    v2: calendar versions (`2026.10.4`: a year-like major and a month-like minor) are exempt.
    They were most of this rule's benign hits on 2026-10-27."""

    id = "npm.version.suspicious"
    version = 2
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
