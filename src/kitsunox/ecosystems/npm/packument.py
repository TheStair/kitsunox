"""Turn an untrusted npm packument (the registry's per-package JSON document) into Changes.

Packuments come from the network and are treated as hostile: every field is type-checked before
use, and anything malformed is ignored rather than trusted.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

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
        self.modified_at = _parse_time(_dict(root.get("time")).get("modified"))
        self.top_level_repository = root.get("repository")

    def versions_in(self, window: Window) -> list[str]:
        """Versions published inside the window, oldest first."""
        hits = [v for v, t in self.publish_times.items() if window.contains(t)]
        return sorted(hits, key=lambda v: (self.publish_times[v], v))

    def previous_version(self, version: str) -> str | None:
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
        way only makes the diff larger."""
        published = self.publish_times.get(version)
        if published is None:
            return None
        earlier = [
            v
            for v, t in self.publish_times.items()
            if (t, v) < (published, version) and v != version and not self.is_stub(v)
        ]
        if not earlier:
            return None
        target = semver.parse(version)
        if target is not None:
            lower = [
                (sv, v) for v in earlier if (sv := semver.parse(v)) is not None and sv < target
            ]
            if lower:
                return max(lower, key=lambda pair: (pair[0], self.publish_times[pair[1]]))[1]
        return max(earlier, key=lambda v: (self.publish_times[v], v))

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

    def changes_in(self, window: Window, *, feed_seq: int | None = None) -> list[Change]:
        changes = []
        for version in self.versions_in(window):
            previous = self.previous_version(version)
            changes.append(
                Change(
                    new=self.snapshot(version),
                    previous=self.snapshot(previous) if previous is not None else None,
                    repository_url=self.repository_url(version),
                    feed_seq=feed_seq,
                )
            )
        return changes


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
    if publish.publisher == "npm" and (stub or snapshot.ref.version == "0.0.1-security"):
        return True
    inert = not any(manifest.get(k) for k in ("scripts", "dependencies", "optionalDependencies"))
    return stub and snapshot.ref.version == "0.0.0-stage" and inert


def publish_info(manifest: Mapping[str, Any], published_at: datetime | None) -> PublishInfo:
    npm_user = _dict(manifest.get("_npmUser"))
    trusted = _dict(npm_user.get("trustedPublisher"))
    approver = _dict(npm_user.get("approver"))
    dist = _dict(manifest.get("dist"))
    raw_maintainers = manifest.get("maintainers")
    maintainers = sorted(
        {
            name
            for m in (raw_maintainers if isinstance(raw_maintainers, list) else [])
            if (name := _str(_dict(m).get("name")))
        }
    )
    return PublishInfo(
        published_at=published_at,
        publisher=_str(npm_user.get("name")),
        trusted_publisher=_str(trusted.get("id")),
        approver=_str(approver.get("name")),
        has_provenance=bool(_dict(dist.get("attestations")).get("provenance")),
        git_head=_str(manifest.get("gitHead")),
        maintainers=tuple(maintainers),
    )


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
