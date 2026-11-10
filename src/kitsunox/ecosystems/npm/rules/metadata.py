"""Stage 1 metadata rules for npm. They read only the `Change` (manifests and publish info of
the new and previous versions), so they cost nothing beyond Stage 0's fetches.

Manifests are untrusted: every field is type-checked before use, and evidence snippets are
truncated. Severities are starting points; `docs/stages/triage.md` records the evaluation
numbers behind each.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Final

from kitsunox.core.models import Change, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule, Rule, RuleContext
from kitsunox.ecosystems.npm import semver
from kitsunox.ecosystems.npm.packument import normalize_repository_url

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
# Origins a vendor that left the npm registry distributes its own packages from: SheetJS
# publishes `xlsx` only on its CDN. The trailing `/` keeps the host exact
# (`https://cdn.sheetjs.com.evil.example/` is not it).
VENDOR_REGISTRIES: Final = ("https://cdn.sheetjs.com/",)
VENDOR_NOTE: Final = " The vendor's own registry: it publishes the package only there."
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


# Hosts whose first path segment is an account (user or organisation) that alone can write
# there, and GitHub's own download hosts, which serve the same `<owner>/<repo>` namespace.
_GITHUB_HOSTS: Final = frozenset(
    {"github.com", "www.github.com", "codeload.github.com", "raw.githubusercontent.com"}
)
_SHORTCUTS: Final = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}
_SHORTCUT: Final = re.compile(
    r"^(?P<host>github|gitlab|bitbucket):(?P<owner>[^/#\s]+)/[^#\s]+(?:#(?P<ref>.*))?$", re.I
)
# `owner/repo` with no protocol is GitHub to npm; a leading `@`, `.`, `/` or `~` is not.
_BARE: Final = re.compile(r"^(?P<owner>[^/#:@.~\s][^/#:@\s]*)/[^/#\s]+(?:#(?P<ref>.*))?$")
# scp-like git remotes: `git@github.com:owner/repo.git#ref`, `git+ssh://git@host:owner/repo`.
_SCP: Final = re.compile(
    r"^(?:git\+)?(?:ssh://)?[^@/\s]+@(?P<host>[^:/\s]+):(?P<owner>[^/\s]+)/[^#\s]+"
    r"(?:#(?P<ref>.*))?$",
    re.I,
)
_URL: Final = re.compile(
    r"^(?:git\+)?(?P<scheme>[a-z]+)://(?:[^@/\s]*@)?(?P<host>[^/:#?\s]+)(?::\d+)?"
    r"(?P<path>/[^#?\s]*)?(?:\?[^#\s]*)?(?:#(?P<ref>.*))?$",
    re.I,
)
# A commit id (git's 40 hex digits, or abbreviated; 64 for SHA-256 repositories) or a
# pull/merge-request ref. GitHub serves a commit pushed to *any fork* through the parent
# repository's URLs (`github:owner/repo#<commit>`, codeload and archive URLs), and every
# pull request from a fork gets a `refs/pull/N/head` there. Tags, branches and release
# assets can only be created by someone with write access to the repository itself.
_FORKABLE_TOKEN: Final = re.compile(r"[0-9a-f]{7,64}|pull|merge-requests", re.I)


@dataclass(frozen=True)
class DependencySource:
    """Where a non-registry dependency comes from: a host, the account on it that owns what
    is fetched (a GitHub/GitLab owner, a bucket, the first path segment), and whether the
    reference could have been planted from a fork (`_FORKABLE_TOKEN`)."""

    host: str
    owner: str
    forkable: bool


def dependency_source(spec: str) -> DependencySource | None:
    """The source of a git, GitHub-shorthand or URL dependency spec; None for anything else
    (registry specs, local paths, `gist:`) and for a URL without an owner segment."""
    text = spec.strip()
    host: str
    if (match := _SHORTCUT.match(text)) is not None:
        host, owner, rest = _SHORTCUTS[match["host"].lower()], match["owner"], match["ref"]
    elif not _PROTOCOL.match(text) and (match := _BARE.match(text)) is not None:
        host, owner, rest = "github.com", match["owner"], match["ref"]
    elif (match := _SCP.match(text)) is not None and "://" not in text.split("@", 1)[1]:
        host, owner, rest = match["host"], match["owner"], match["ref"]
    elif (match := _URL.match(text)) is not None and match["scheme"].lower() in (
        "git",
        "ssh",
        "http",
        "https",
    ):
        segments = [s for s in (match["path"] or "").split("/") if s]
        if not segments:
            return None
        host, owner = match["host"], segments[0]
        rest = "/".join(segments[1:]) + "#" + (match["ref"] or "")
        if host.lower() in _GITHUB_HOSTS and segments[2:4] == ["releases", "download"]:
            rest = ""  # a release asset: its tag lives in this repository, not a fork's
    else:
        return None
    host = host.lower()
    if host in _GITHUB_HOSTS:
        host = "github.com"
    tokens = re.split(r"[/#@:.+]", rest or "")
    return DependencySource(
        host=host,
        owner=owner.lower(),
        forkable=any(_FORKABLE_TOKEN.fullmatch(t) for t in tokens),
    )


def previous_repository_owner(change: Change) -> tuple[str, str] | None:
    """`("github.com", owner)` of the GitHub repository the *previous* release's manifest
    names; None for a new package, another host, or no repository. The previous release's
    value, not this one's: whoever publishes this release also writes its `repository`."""
    if change.previous is None:
        return None
    repo = change.previous.manifest.get("repository")
    if isinstance(repo, Mapping):
        repo = repo.get("url")
    if not isinstance(repo, str):
        return None
    url = normalize_repository_url(repo)
    if url is None or not url.startswith("https://github.com/"):
        return None
    source = dependency_source(url)
    return None if source is None else (source.host, source.owner)


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
    attacks pulled their payload (`docs/proposals/stage1-precision.md`).

    v4 (2026-11-08): a tarball on SheetJS's own CDN (`VENDOR_REGISTRIES`) is LOW, weight 1.
    SheetJS left the npm registry and distributes `xlsx` only there
    (`https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz`): 50 benign live reports (11
    packages), no positive, and none of the rule's 15 at-risk `vm-day1` malicious samples uses
    it. One literal origin, not a pattern; other vendors' hosts are each an owner decision
    (`docs/proposals/precision-round2.md`, F6b).

    v5 (2026-11-10, `docs/proposals/precision-round4-C.md` N1): on an update, LOW, weight 1,
    when the source was already trusted by the *previous* release and the new reference can't
    have been planted from a fork (`trusted_move`): the previous release took this same
    dependency from the same account (a tag bumped from `#v20.67.0` to `#v20.71.0`, the next
    GitHub release asset), or the previous release's `repository` is on GitHub under the
    account the dependency now comes from. A commit id or pull-request ref stays MEDIUM:
    GitHub serves a commit pushed to any fork through the parent repository's URLs, which is
    how every git-dependency attack on `vm-day1` pulled its payload
    (`github:opensearch-project/opensearch-js#d446803f…`, `github:antvis/G2#1916faa3…`,
    `github:tanstack/router#79ac49ee…`); a tag, branch or release asset needs write access
    to that account's repository. A new package has no earlier release to vouch for anything
    and keeps MEDIUM, as does a dependency from another account than before.

    v6 (2026-11-10, `docs/proposals/precision-round5-K.md` N2): the registry's own tarball URL
    of *another* package in the dependent's own npm scope is LOW, weight 1
    (`@atharva-again/pi-coding-agent` takes `@earendil-works/pi-ai` from
    `https://registry.npmjs.org/@atharva-again/pi-ai/-/pi-ai-1.3.0.tgz`). npm fetches it from
    the registry, where takedowns apply, only the scope's owner can publish into the scope, and
    that package is a release in the feed like any other, read by Stages 1-3 itself: the same
    as `npm:@atharva-again/pi-ai@1.3.0`, which is a registry spec and no finding. 2 benign live
    reports, no positive; no `vm-day1` sample uses a registry tarball URL. A tarball of a
    package outside the scope keeps MEDIUM: Stage 4's dependency lookups don't follow URLs.

    v7 (2026-11-11, `docs/proposals/precision-round6-S.md` S4): a spec npm reads as a local
    path is LOW, weight 1, as `file:` is (`npm_local_path`): npm-package-arg sends a spec
    with a `/` that is neither a URL nor a hosted-git shorthand to the file system, so
    `"esbuild": "@ohos-ports/esbuild@0.25.5-beta.1"` (OpenHarmony's alias syntax,
    `@ohos-ports/modern-js-node-bundle-require@2.32.1`) fetches nothing.

    v8 (2026-11-11, S5): on an update, a commit bump in the package's own repository account
    is LOW, weight 1 (`trusted_commit_bump`): the previous release already took this
    dependency from the same repository (`dependency_repository`), *and* the previous
    release's `repository` names that GitHub account (`@diffci.com/diffci`:
    `DiffCI/core.git#<commit>` release after release). Both facts come from the earlier
    release. A new git dependency (the `vm-day1` git-dependency attacks: `@antv/setup`,
    `@opensearch/setup`, `@tanstack/setup` were new names), one moved to another repository
    (`@opensearch-project/opensearch@3.8.0`: `opensearch-project/openearch#d446803f` in
    3.7.0, `opensearch-project/opensearch-js#d446803f` in 3.8.0, both malicious) and a bump
    with no earlier `repository` (`lane-m-snackager-probe@1.0.1`, unwanted) keep MEDIUM."""

    id = "npm.dependency.non-registry"
    version = 8
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
            own_scope = tarball is not None and _same_scope(tarball["name"], change.new.ref.name)
            local = spec.strip().startswith(_LOCAL) or npm_local_path(spec)
            vendor = spec.strip().startswith(VENDOR_REGISTRIES)
            moved = None if local or vendor or own_scope else trusted_move(change, name, spec)
            if moved is None and not (local or vendor or own_scope):
                moved = trusted_commit_bump(change, name, spec)
            low = local or vendor or own_scope or moved is not None
            findings.append(
                self.finding(
                    f"Dependency `{name}` comes from `{snippet(spec)}`."
                    + (" A local path: nothing is fetched." if local else "")
                    + (VENDOR_NOTE if vendor else "")
                    + (OWN_SCOPE_TARBALL_NOTE if own_scope else "")
                    + (moved or ""),
                    _field(f"dependencies.{name}", after=spec, before=old.get(name)),
                    severity=Severity.LOW if low else None,
                    weight=1.0 if low else None,
                )
            )
        return findings


OWN_SCOPE_TARBALL_NOTE: Final = (
    " The registry's own tarball of a package in this package's npm scope, which only the "
    "scope's owner can publish: as an `npm:` alias of it would be."
)


def npm_local_path(spec: str) -> bool:
    """npm-package-arg reads the spec as a path on disk (v7): it has no protocol, isn't a
    hosted-git shorthand (`owner/repo`, which can't start with `@`, `.`, `/` or `~`) and
    starts like a path or a scoped name with a `/` (npa's `hasSlashes` sends it to `fromFile`).
    Nothing is downloaded: the install fails unless that directory exists."""
    text = spec.strip()
    if _PROTOCOL.match(text) or "/" not in text:
        return False
    return text.startswith(("@", ".", "/", "~"))


COMMIT_BUMP_NOTE: Final = (
    " The previous release took it from the same account ({source}), the account of the "
    "repository that release names; only the pinned commit changed."
)


def trusted_commit_bump(change: Change, name: str, spec: str) -> str | None:
    """A note when a commit reference moved within the package's own repository account
    (v8, S5): the previous release took this dependency from the same repository, and
    the previous release's `repository` names that account. None otherwise (also for a
    reference a fork couldn't plant: `trusted_move` covers those)."""
    if change.previous is None:
        return None
    source = dependency_source(spec)
    if source is None or not source.forkable:
        return None
    before = runtime_dependencies(change.previous.manifest).get(name)
    if before is None or previous_repository_owner(change) != (source.host, source.owner):
        return None
    repository = dependency_repository(spec)
    if repository is None or dependency_repository(before) != repository:
        return None
    return COMMIT_BUMP_NOTE.format(source="/".join(repository))


_REPOSITORY: Final = (
    re.compile(r"^(?:github|gitlab|bitbucket):(?P<owner>[^/#\s]+)/(?P<repo>[^/#\s]+)", re.I),
    re.compile(r"^(?P<owner>[^/#:@.~\s][^/#:@\s]*)/(?P<repo>[^/#\s]+)"),
    re.compile(
        r"^(?:git\+)?(?:ssh://)?[^@/\s]+@[^:/\s]+:(?P<owner>[^/\s]+)/(?P<repo>[^/#\s]+)", re.I
    ),
    re.compile(
        r"^(?:git\+)?[a-z]+://(?:[^@/\s]*@)?[^/:#?\s]+(?::\d+)?/(?P<owner>[^/#?\s]+)"
        r"/(?P<repo>[^/#?\s]+)",
        re.I,
    ),
)


def dependency_repository(spec: str) -> tuple[str, str, str] | None:
    """(host, owner, repository) a git, GitHub-shorthand or URL dependency comes from, lower
    case and without `.git` (v8): `github:DiffCI/core#<commit>` and
    `git+https://github.com/DiffCI/core.git#<commit>` are both `github.com/diffci/core`; a
    codeload, archive or raw URL's second path segment is its repository. None when
    `dependency_source` has none."""
    source = dependency_source(spec)
    if source is None:
        return None
    text = spec.strip()
    for pattern in _REPOSITORY:
        if (match := pattern.match(text)) is not None:
            repo = match["repo"].lower().removesuffix(".git")
            return (source.host, source.owner, repo)
    return None


def _same_scope(dependency: str, own: str) -> bool:
    """Both names are in the same npm scope (`@s/a`, `@s/b`); unscoped names never are."""
    if not dependency.startswith("@") or not own.startswith("@"):
        return False
    scope_of = dependency.split("/", 1)[0]
    return "/" in dependency and "/" in own and scope_of == own.split("/", 1)[0]


MOVED_NOTE: Final = (
    " The previous release took it from the same account ({source}); only the tag, branch "
    "or release changed, which takes write access there."
)
OWN_REPOSITORY_NOTE: Final = (
    " From {source}, the account of the repository the previous release names, at a tag, "
    "branch or release, which takes write access there."
)


def trusted_move(change: Change, name: str, spec: str) -> str | None:
    """Why the previous release vouches for this non-registry dependency (a note for the
    finding), or None: see `NonRegistryDependency` v5."""
    if change.previous is None:
        return None
    source = dependency_source(spec)
    if source is None or source.forkable:
        return None
    account = (source.host, source.owner)
    before = runtime_dependencies(change.previous.manifest).get(name)
    earlier = dependency_source(before) if before is not None else None
    where = f"{source.host}/{source.owner}"
    if earlier is not None and (earlier.host, earlier.owner) == account:
        return MOVED_NOTE.format(source=where)
    if previous_repository_owner(change) == account:
        return OWN_REPOSITORY_NOTE.format(source=where)
    return None


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


SAME_ACCOUNT_CI_NOTE: Final = (
    " A dependency was added, but `{publisher}` also published {previous}, whose provenance "
    "came from CI with this account's own token (no trusted publishing): the same credential "
    "used by hand."
)


def token_ci_by_same_account(change: Change) -> bool:
    """The previous release has a provenance attestation but no trusted publisher (CI
    published it with an access token) and was published by the account that publishes this
    release (`PublishMethodDowngrade` v6)."""
    previous = change.previous
    if previous is None:
        return False
    old = previous.publish
    return (
        old.has_provenance
        and old.trusted_publisher is None
        and old.publisher is not None
        and old.publisher == change.new.publish.publisher
    )


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
    token used for a code-only change that keeps `gitHead` now needs Stages 2-3 to see it.

    v5 (2026-11-10, `docs/proposals/precision-round6-N.md` D1): a dropped `gitHead` is no
    longer a co-signal for a watched package. Given a downgrade it doesn't separate: 34 of the
    149 malicious `vm-day1` downgrades drop it (23%), against 81 of 273 live benign verdicts
    with a downgrade (30%; round 5, G1), and every one of the 149 has a co-signal of its own.
    It was the only thing keeping 9 benign watched releases HIGH alone (`@daytona/*` x6,
    `claude-mem`, `@adea-ai/themes`, `@react-native-kakao/user`). The finding still names the
    missing commit; `npm.provenance.githead-dropped` still reports it (weight 1 here). Known
    gap, as v4's: a stolen token used for a code-only release of a watched package is MEDIUM
    weight 3 here (weak alone) and needs Stages 2-3 to see its code.

    v6 (2026-11-10, round 6 N, D2): an added dependency alone is no co-signal when the
    previous release had provenance *without* trusted publishing and was published by the
    account that publishes this one (`token_ci_by_same_account`). Such a provenance came from
    CI running `npm publish --provenance` with that account's own access token, so the account
    publishing by hand is the same credential used a second way, not a move off OIDC. 13 benign
    live reports were exactly this (`@volter/*`, `@wenathlan/*` x3, `@oliverames/*` x2,
    `moshcode`, `pi-graphnav`, ...), each a maintainer's hand release adding a dependency. The
    38 `vm-day1` worm samples of this shape (`@ctrl/*`, `@squawk/*`, `@nx/*`, `ngx-toastr`)
    all add or change an install hook, which still counts; the 107 that count on an added
    dependency (`axios@1.14.1`, `@mastra/*`) left trusted publishing and keep it. A token
    thief who only adds a dependency in this shape is one step lower here; the dependency's
    own Stage 4 findings (fresh-foreign, known malware, non-registry) still apply."""

    id = "npm.publish-method.downgrade"
    version = 6
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
        elif cosignals == [DependencyAdded.id] and token_ci_by_same_account(change):
            severity, weight = (Severity.MEDIUM, 3.0) if watched else (Severity.LOW, 1.0)
            note = SAME_ACCOUNT_CI_NOTE.format(
                publisher=new.publisher, previous=change.previous.ref.version
            )
        elif cosignals:
            severity, weight = (None, None) if watched else (Severity.MEDIUM, 3.0)
            note = f" With: {', '.join(cosignals)}."
        else:
            severity, weight = (Severity.MEDIUM, 3.0) if watched else (Severity.LOW, 1.0)
            note = " Nothing else about what gets installed, or who publishes it, changed."
            if git_head_dropped:
                note += f" No git commit recorded, where {change.previous.ref.version} had one."
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


def calendar_version(major: int, minor: int, as_of_year: int) -> bool:
    """`major.minor` reads as a calendar version the v2 test misses: a year-like major (1990 to
    the year after `as_of_year`) whose minor is a month-day `MDD`/`MMDD` (`2026.706.0`,
    `2026.1107.0`), or is 0 in that very year (`2026.0.1` in 2026), or a `YYMM` major
    (`2611.5.1`: 20 <= YY <= the year after's, a real month). A month-day must exist (in a
    leap year: `229` is 29 February). A minor of 0 in another year is a confusion number:
    OSV lists 15 malware versions such as `2000.0.0`, `1999.0.1`, and `2026.0.1` in 2025."""
    if 1990 <= major <= as_of_year + 1:
        if minor == 0:
            return major == as_of_year
        month, day = divmod(minor, 100)
        try:
            date(2000, month, day)
        except ValueError:
            return False
        return True
    year, month = divmod(major, 100)
    return 20 <= year <= (as_of_year + 1) % 100 and 1 <= month <= 12


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
    `99999999` (`docs/proposals/stage1-precision.md`).

    v4 (2026-11-08): more calendar shapes (`calendar_version`): a year major with a month-day
    minor (`2026.1107.0`, `2026.706.0`) or, in that year, a minor of 0 (`2026.0.1`), and a
    `YYMM` major (`2611.5.1`). The proposal's "minor 0 in any year" would also exempt 15 OSV
    malware versions (`2000.0.0`, `1999.0.1`, `amazonui@2026.0.1` in 2025).
    47 benign live reports (`@4fu/arbor-*`, `@burdenoff/*`, `@runstructure/*`, `@beehexa/*`),
    no positive, none of the 6 at-risk `vm-day1` samples. The researchers' `99.x` placeholders
    are what is left (`docs/proposals/precision-round2.md`, F5)."""

    id = "npm.version.suspicious"
    version = 4
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
        if calendar_version(version.major, version.minor, ctx.as_of.year):
            return []  # YYYY.0, YYYY.MDD, YYYY.MMDD or a YYMM major
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
