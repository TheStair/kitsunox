"""Turn an untrusted npm packument (the registry's per-package JSON document) into Changes.

Packuments come from the network and are treated as hostile: every field is type-checked before
use, and anything malformed is ignored rather than trusted.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final

from kitsunox.core.interfaces import DIFF_BASE
from kitsunox.core.models import (
    ArtifactRef,
    Change,
    PackageVersionRef,
    PublishInfo,
    VersionSnapshot,
    Window,
)
from kitsunox.ecosystems.npm import semver

ECOSYSTEM = "npm"

# Large free-text fields that carry no detection value at this stage and can be megabytes.
_DROPPED_MANIFEST_KEYS = frozenset({"readme", "readmeFilename", "_npmOperationalInternal"})
# Keys of a packument's `time` object that are not versions.
_TIME_KEYS = frozenset({"created", "modified", "unpublished"})

# A diff base is a partial publish when it has under 1/PARTIAL_RATIO of the files of both the
# new version and the release before it (diff base 2, `Packument.previous_version`).
PARTIAL_RATIO: Final = 4
MIN_FULL_FILES: Final = 20  # below this many files, a smaller release isn't called partial
MIN_FULL_BYTES: Final = 64 * 1024  # the same by unpacked size, when a count is missing
MAX_PARTIAL_SKIPS: Final = 3
# A prerelease naming an OS and CPU (`0.5.4-latest-windows-x64`, `0.1.19-linux-x64`,
# `0.2.19-daily.20261029.win32-x64`): one platform's build of a release (diff base 3).
_OSES: Final = "win32|windows|darwin|macos|linux|android|freebsd|openbsd|sunos|aix"
_CPUS: Final = "x64|x86_64|amd64|arm64|aarch64|ia32|x86|arm|armv7l?|ppc64le?|s390x|riscv64"
_PLATFORM_BUILD: Final = re.compile(rf"(?:^|[.-])(?:{_OSES})[.-](?:{_CPUS})(?:$|[.-])", re.I)
# Diff base 4 adds OpenHarmony (`0.2.19-daily.20261030.ohos-arm64`).
_PLATFORM_BUILD_4: Final = re.compile(rf"(?:^|[.-])(?:{_OSES}|ohos)[.-](?:{_CPUS})(?:$|[.-])", re.I)

_GITHUB_REPO = re.compile(
    r"^(?:git\+)?(?:https?|git|ssh)://(?:git@)?(?:www\.)?github\.com[/:]"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/[^#]*)?(?:#.*)?$"
    r"|^git@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$"
    r"|^(?:github:)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:#.*)?$"
)


class PackumentError(ValueError):
    """The packument is missing required structure."""


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


class Packument:
    """Validated view over a packument's versions and publish times."""

    def __init__(self, doc: object, *, expected_name: str) -> None:
        root = _dict(doc)
        if root.get("name") != expected_name:
            raise PackumentError(f"packument name {root.get('name')!r} != {expected_name!r}")
        self.name = expected_name
        self.versions: dict[str, dict[str, Any]] = {
            v: m for v, m in _dict(root.get("versions")).items() if isinstance(m, dict)
        }
        self.publish_times: dict[str, datetime] = {}
        for version, raw in _dict(root.get("time")).items():
            moment = _parse_time(raw)
            if version in self.versions and moment is not None:
                self.publish_times[version] = moment
        self.unpublished = "unpublished" in _dict(root.get("time")) and not self.versions
        # Every version's publish time, including versions no longer listed: npm keeps a
        # version's `time` entry when it takes the package down and replaces its versions
        # (`time.created` and `maintainers` it rewrites). Stage 4 reads it to tell when a
        # dependency first existed. Only keys that are versions (listed, or valid semver) count,
        # so a stray key such as `__proto__` can't pose as the first version.
        self.version_times: dict[str, datetime] = {
            version: moment
            for version, raw in _dict(root.get("time")).items()
            if version not in _TIME_KEYS
            and (version in self.versions or semver.parse(version) is not None)
            and (moment := _parse_time(raw)) is not None
        }
        self.maintainers = _account_names(root.get("maintainers"))
        self.modified_at = _parse_time(_dict(root.get("time")).get("modified"))
        self.top_level_repository = root.get("repository")

    def versions_in(self, window: Window) -> list[str]:
        """Versions published inside the window, oldest first."""
        hits = [v for v, t in self.publish_times.items() if window.contains(t)]
        return sorted(hits, key=lambda v: (self.publish_times[v], v))

    def previous_version(self, version: str, *, diff_base: int = DIFF_BASE) -> str | None:
        """The version a new release should be diffed against.

        Among versions published before `version`, take the highest semver below it, which keeps
        backports on their own release line (a 1.4.1 published after 2.0.0 diffs against 1.4.0).
        If none qualifies (unparsable versions, or a release lower than everything before it),
        fall back to the most recently published earlier version.

        Stub versions are never a diff base. npm's staged publishing creates a `0.0.0-stage`
        placeholder (`"stub": true`, no code) before a package's first real release; diffing
        against it would make every first release look like an existing package that suddenly
        gained all its scripts and dependencies (98% of "new packages" in the 2026-10-27 run
        were such stubs). `stub` is publisher-controlled, so it only changes the diff base: a
        release marked as a stub is still emitted and analysed. Hiding earlier versions this
        way only makes the diff larger.

        Diff base 2 also passes over a partial publish (`_partial`): a release with under a
        quarter of the files of both the new version and the release before it, as
        `@nutui/nutui-react-taro@3.0.24-cpp-beta.3` (166 files between two of 5,215, without
        the build or the postinstall the releases around it had). Diffing against it made the
        next release look as if it had added all of them. A release smaller than the new one
        only is never passed over: a release can't push its diff base back by being large, so
        it can't skip to an older version that, say, already had its install script. The
        partial release itself is still analysed, against the release before it, and at most
        `MAX_PARTIAL_SKIPS` are passed over.

        Diff base 3 also passes over a platform build (`_PLATFORM_BUILD`) for a release that
        isn't one: `@ozyman42/ozy-cli@0.5.4` was diffed against `0.5.4-latest-windows-x64`,
        published just before it with a single platform's binary and no postinstall, so the
        release's own postinstall read as added (8 live reports on the first two VM days). A
        platform build is still analysed itself, and is still a base if nothing else is.
        Diff base 4 also knows OpenHarmony builds (`@bitfun-test/bitfun`'s daily `.ohos-arm64`)."""
        ranked = self._diff_bases(version)
        if diff_base >= 3 and not platform_build(version, diff_base=diff_base):
            ranked = [v for v in ranked if not platform_build(v, diff_base=diff_base)] or ranked
        if not ranked:
            return None
        if diff_base < 2:
            return ranked[0]
        for i, candidate in enumerate(ranked[: MAX_PARTIAL_SKIPS + 1]):
            before = ranked[i + 1] if i + 1 < len(ranked) else None
            if before is None or not (
                self._partial(candidate, version) and self._partial(candidate, before)
            ):
                return candidate
        return ranked[0]

    def _diff_bases(self, version: str) -> list[str]:
        """Possible diff bases, best first (`previous_version`'s order)."""
        published = self.publish_times.get(version)
        if published is None:
            return []
        earlier = [
            v
            for v, t in self.publish_times.items()
            if (t, v) < (published, version) and v != version and not self.is_stub(v)
        ]
        target = semver.parse(version)
        if target is not None:
            lower = [
                (sv, v) for v in earlier if (sv := semver.parse(v)) is not None and sv < target
            ]
            if lower:
                lower.sort(key=lambda pair: (pair[0], self.publish_times[pair[1]]), reverse=True)
                return [v for _, v in lower]
        return sorted(earlier, key=lambda v: (self.publish_times[v], v), reverse=True)

    def _partial(self, small: str, full: str) -> bool:
        """`small` has under 1/PARTIAL_RATIO of `full`'s files (`dist.fileCount`), or of its
        unpacked size when a count is missing; never when `full` is small itself."""
        a, b = _dist(self.versions.get(small, {})), _dist(self.versions.get(full, {}))
        for key, floor in (("fileCount", MIN_FULL_FILES), ("unpackedSize", MIN_FULL_BYTES)):
            x, y = _count(a.get(key)), _count(b.get(key))
            if x is not None and y is not None:
                return y >= floor and x * PARTIAL_RATIO < y
        return False

    def is_stub(self, version: str) -> bool:
        return self.versions.get(version, {}).get("stub") is True

    def snapshot(self, version: str) -> VersionSnapshot:
        manifest = self.versions[version]
        return VersionSnapshot(
            ref=PackageVersionRef(ecosystem=ECOSYSTEM, name=self.name, version=version),
            publish=publish_info(manifest, self.publish_times.get(version)),
            manifest={k: v for k, v in manifest.items() if k not in _DROPPED_MANIFEST_KEYS},
            artifact=artifact_ref(manifest),
        )

    def repository_url(self, version: str) -> str | None:
        repo = self.versions.get(version, {}).get("repository") or self.top_level_repository
        if isinstance(repo, Mapping):
            repo = repo.get("url")
        return normalize_repository_url(repo) if isinstance(repo, str) else None

    def changes_in(
        self, window: Window, *, feed_seq: int | None = None, diff_base: int = DIFF_BASE
    ) -> list[Change]:
        changes = []
        for version in self.versions_in(window):
            previous = self.previous_version(version, diff_base=diff_base)
            changes.append(
                Change(
                    new=self.snapshot(version),
                    previous=self.snapshot(previous) if previous is not None else None,
                    repository_url=self.repository_url(version),
                    feed_seq=feed_seq,
                )
            )
        return changes


SECURITY_HOLDER_VERSION: Final = "0.0.1-security"


def is_security_holder(snapshot: VersionSnapshot) -> bool:
    """npm's security holding package: the registry removed the package as malicious and
    published `0.0.1-security` (an empty package) from its own `npm` account in its place. The
    version string alone proves nothing (anyone can publish it); the publisher is npm's."""
    return snapshot.publish.publisher == "npm" and snapshot.ref.version == SECURITY_HOLDER_VERSION


def is_registry_placeholder(snapshot: VersionSnapshot) -> bool:
    """A version the registry created rather than the package's author. Two kinds:

    - **Security holding package**: npm's stand-in for a removed malicious package
      (`0.0.1-security`, or a stub), published by npm's own `npm` account.
    - **Staged-publishing placeholder**: `0.0.0-stage` with `"stub": true`, created before a
      new package's first real release.

    Only evaluation uses this, to keep placeholders out of both label sets. Because `stub` and
    the version string can be set by anyone, a staged placeholder only counts if it also has no
    install scripts and no dependencies, i.e. nothing a rule could flag."""
    publish, manifest = snapshot.publish, snapshot.manifest
    stub = manifest.get("stub") is True
    if is_security_holder(snapshot) or (publish.publisher == "npm" and stub):
        return True
    inert = not any(manifest.get(k) for k in ("scripts", "dependencies", "optionalDependencies"))
    return stub and snapshot.ref.version == "0.0.0-stage" and inert


def publish_info(manifest: Mapping[str, Any], published_at: datetime | None) -> PublishInfo:
    npm_user = _dict(manifest.get("_npmUser"))
    trusted = _dict(npm_user.get("trustedPublisher"))
    approver = _dict(npm_user.get("approver"))
    dist = _dict(manifest.get("dist"))
    return PublishInfo(
        published_at=published_at,
        publisher=_str(npm_user.get("name")),
        trusted_publisher=_str(trusted.get("id")),
        approver=_str(approver.get("name")),
        has_provenance=bool(_dict(dist.get("attestations")).get("provenance")),
        git_head=_str(manifest.get("gitHead")),
        maintainers=_account_names(manifest.get("maintainers")),
    )


def _account_names(raw: object) -> tuple[str, ...]:
    """Sorted account names from a `maintainers` list (`[{"name": ...}, ...]`)."""
    entries = raw if isinstance(raw, list) else []
    return tuple(sorted({name for m in entries if (name := _str(_dict(m).get("name")))}))


def _dist(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return _dict(manifest.get("dist"))


def _count(value: object) -> int | None:
    """A non-negative integer from untrusted JSON (`true` is not 1)."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def artifact_ref(manifest: Mapping[str, Any]) -> ArtifactRef | None:
    dist = _dict(manifest.get("dist"))
    url = _str(dist.get("tarball"))
    if url is None or not url.startswith("https://"):
        return None
    file_count = dist.get("fileCount")
    unpacked = dist.get("unpackedSize")
    return ArtifactRef(
        url=url,
        integrity=_str(dist.get("integrity")),
        shasum=_str(dist.get("shasum")),
        file_count=file_count if isinstance(file_count, int) else None,
        unpacked_size=unpacked if isinstance(unpacked, int) else None,
    )


def normalize_repository_url(raw: str) -> str | None:
    """Canonical `https://github.com/<owner>/<repo>` for GitHub repositories (any sub-path, as
    used by monorepos, is dropped); other hosts are returned trimmed but otherwise unchanged;
    empty input gives None."""
    text = raw.strip()
    if not text:
        return None
    match = _GITHUB_REPO.match(text)
    if match is None:
        return text
    owner, repo = next(
        (match.group(i), match.group(i + 1)) for i in (1, 3, 5) if match.group(i) is not None
    )
    return f"https://github.com/{owner}/{repo}"


def platform_build(version: str, *, diff_base: int = DIFF_BASE) -> bool:
    """`version`'s prerelease names an OS and CPU: one platform's build of a release."""
    prerelease = version.split("+", 1)[0].partition("-")[2]
    pattern = _PLATFORM_BUILD_4 if diff_base >= 4 else _PLATFORM_BUILD
    return bool(prerelease) and pattern.search(prerelease) is not None
