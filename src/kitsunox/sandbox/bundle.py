"""Offline dependency bundles for Stage 5: the package plus every dependency npm would install.

The owner runs OpenSSF package-analysis on an airgapped VM, and every job runs with
`-offline` (`--network=none`). `npm install /<key>.tgz` builds the whole tree before any
lifecycle script runs, so a package with a registry dependency fails before its own
`preinstall` does. The owner's direction is to ship every dependency inside the one package
file. This module builds that file, following `docs/proposals/offline-dependency-bundle.md`
(the design note; section names below refer to it):

- `read_original` reads the package's own tarball with `extract_tar_gz` and refuses one that
  can't be repacked faithfully ("Original tarballs that can't be repacked faithfully"); link
  entries, a BOM and repeated keys are read as npm reads them, and recorded.
- `resolve` is the pure resolver ("Resolver"): a deterministic closure over `dependencies`,
  `optionalDependencies` and required peers (never `devDependencies`) in arborist's queue
  order, version picks by `ranges.pick` (npm-pick-manifest 11.0.3 with the run's `as_of`),
  npm-install-checks' platform and engines rules for linux/x64/glibc and node 24.15.0,
  simplified npm v3 placement (reuse what Node's lookup finds, else the top slot, else nest
  under the requirer), peer sets with arborist's parent preference and REPLACE, npm's pruning
  of failed optional subtrees, caps, and a final check that Node's lookup from every
  requiring package finds a satisfying copy.
- `fetch_dependencies` fetches each placed package's registry tarball through the run's
  `HttpFetcher` (only `https://registry.npmjs.org/` URLs, integrity-checked against
  `dist.integrity`/`shasum`) and reads it with `extract_tar_gz`, stripping the first path
  component as pacote does.
- `build_bundle` writes the bundle ("Layout", "Building the tarball"): the original's files byte
  for byte, `package.json` rewritten only to set an explicit sorted `bundleDependencies` and
  copy required peers into `dependencies`, each dependency under `package/node_modules/...`,
  as a deterministic tar (sorted entries, fixed metadata, gzip mtime 0), read back with
  `extract_tar_gz` as a self-check. It returns the bytes and a `BundleRecord` (the job
  manifest's `<key>.bundle.json`), whose `summary()` is `SandboxJob.bundle`.

Nothing here runs package code, npm or node. Every input (manifests, packuments, tarballs) is
untrusted data. Dependency names become path components only after they match npm's name
grammar (`select.NPM_NAME`), which has no `/` outside a scope, no leading `.`, and so no `..`.
Recorded reasons are fixed strings; package text appears only in fields that name it (name,
spec, version), for renderers to escape.

Network failures follow decision 0009: `TransientFetchError` (and any other `FetchError`, such
as a replay miss) propagates, so the job stays `pending`. Only a definite answer (a 404, an
invalid packument, an integrity mismatch, an unreadable tarball) is recorded as unresolved.
"""

from __future__ import annotations

import gzip
import heapq
import io
import json
import math
import re
import tarfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Final, Literal
from urllib.parse import urlsplit

from pydantic import Field, JsonValue

from kitsunox.core.models import ArtifactRef, Persisted, Record
from kitsunox.ecosystems.npm import ranges
from kitsunox.ecosystems.npm.packument import Packument, PackumentError, artifact_ref
from kitsunox.ecosystems.npm.ranges import NODE_VERSION, NPM_VERSION
from kitsunox.ecosystems.npm.registry import packument_url
from kitsunox.sandbox.models import JobBundle
from kitsunox.sandbox.select import GYP_FILE, MANIFEST, NPM_NAME, manifest_hooks
from kitsunox.util.archive import (
    ArchiveError,
    ArchiveLimitError,
    ArtifactTree,
    ExtractLimits,
    SkippedEntry,
    extract_tar_gz,
)
from kitsunox.util.hashing import IntegrityError, sha256_hex, verify_integrity
from kitsunox.util.http import FetchError, HttpFetcher

__all__ = [
    "BUNDLE_FORMAT",
    "DEFAULT_CAPS",
    "LINUX_X64_GLIBC",
    "NPM_PACK_MTIME",
    "REGISTRY_TARBALL_PREFIX",
    "AddedPackage",
    "BuiltBundle",
    "BundleCaps",
    "BundleError",
    "BundleRecord",
    "DependencyFetch",
    "EdgeType",
    "FetchedDependency",
    "OriginalPackage",
    "PackageJsonChange",
    "PackageJsonRecord",
    "PackumentSource",
    "PeerConflict",
    "PlacedPackage",
    "Platform",
    "PostCheckFailure",
    "PredictedNetwork",
    "RequiredBy",
    "Resolution",
    "SkippedPackage",
    "SpecKind",
    "SuppliedPackage",
    "UnbundledReason",
    "UnresolvedSpec",
    "build_bundle",
    "bundle_list",
    "classify_spec",
    "fetch_dependencies",
    "make_bundle",
    "parse_manifest",
    "platform_ok",
    "read_original",
    "registry_packuments",
    "registry_tarball_url",
    "required_peers",
    "resolve",
    "rewrite_manifest",
    "valid_name",
    "wants_bundle",
    "write_tar_gz",
]

# 2: file modes kept (0755 for an executable, else 0644); link entries of the original dropped,
#    a BOM and repeated keys in its package.json read as npm reads them; peer sets, REPLACE and
#    arborist's queue order in the resolver. 1: the first bundles (every file 0644).
BUNDLE_FORMAT: Final = "kitsunox-npm-bundle/2"
REGISTRY_TARBALL_PREFIX: Final = "https://registry.npmjs.org/"
# npm rewrites this host to the configured registry (`replace-registry-host`), so does Kitsunox.
_HTTP_REGISTRY_PREFIX: Final = "http://registry.npmjs.org/"
PREFIX: Final = "package"  # pacote strips the first component, whatever its name
# npm pack's fixed mtime, 1985-10-26T08:15:00Z (`NPM/node_modules/tar` via pacote).
NPM_PACK_MTIME: Final = 499162500
GZIP_LEVEL: Final = 9
MAX_PRUNING_PASSES: Final = 64
_BIN_DIR: Final = ".bin"
# validate-npm-package-name's blacklist (it compares lowercased names).
_BLACKLISTED_NAMES: Final = frozenset({"node_modules", "favicon.ico"})
# The fields compared between a registry manifest and the tarball's own package.json: what
# decides the tree and what runs. A difference is manifest confusion, recorded per package.
_COMPARED_FIELDS: Final = (
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "bundleDependencies",
    "bundledDependencies",
    "scripts",
    "os",
    "cpu",
    "libc",
    "engines",
)
# Install-time tools that download or build at install time, so fail offline
# ("Failure modes"). `node-gyp-build` only builds when no prebuild ships, so it isn't listed.
_NETWORK_TOOLS: Final = re.compile(
    r"(?<![\w@/-])(prebuild-install|node-pre-gyp|node-gyp(?!-build)|cmake-js)(?![\w-])"
)
# Packages whose own install hook downloads a binary or browser (`node install.js` and the
# like, which `_NETWORK_TOOLS` can't see). Checked 2026-10-30 against the latest tarballs'
# hook scripts: puppeteer (`install.mjs`, downloadBrowsers), node-sass (`scripts/install.js`),
# chromedriver and phantomjs-prebuilt (`install.js`), geckodriver (`dist/install.js`), ngrok
# (`postinstall.js`), electron-chromedriver (`@electron/get`). From their documented
# behaviour: cypress (its binary), @prisma/engines (the query engines), electron (versions
# before 45 had `node install.js`; a version without the hook is never listed). Left out
# because they download only when their platform package is missing, which the bundle ships:
# esbuild, @swc/core, @sentry/cli; and sharp (no hook since 0.33; older ones use
# prebuild-install, which `_NETWORK_TOOLS` matches).
_KNOWN_DOWNLOADERS: Final = frozenset(
    {
        "@prisma/engines",
        "chromedriver",
        "cypress",
        "electron",
        "electron-chromedriver",
        "geckodriver",
        "ngrok",
        "node-sass",
        "phantomjs-prebuilt",
        "puppeteer",
    }
)
# The manifest fields the resolver reads; a packument's versions keep only these (and `dist`
# only its tarball, digests and sizes), so a bundle never holds whole packuments.
_KEPT_FIELDS: Final = frozenset(
    {*_COMPARED_FIELDS, "name", "version", "deprecated", "stub", "dist", "_hasShrinkwrap"}
)
_KEPT_DIST: Final = frozenset({"tarball", "integrity", "shasum", "unpackedSize", "fileCount"})
# A package.json change's `before` is recorded as is up to this size and depth, else only by
# its sha256 (an untrusted value nested past pydantic's limit crashed the record).
_MAX_RECORDED_JSON: Final = 1_024
_MAX_RECORDED_DEPTH: Final = 32


# --- configuration --------------------------------------------------------------------------


@dataclass(frozen=True)
class Platform:
    """The environment npm runs in inside the sandbox image (package-analysis rel-38: amd64
    Ubuntu 24.04, node 24.15.0, npm 11.12.1; npm detects glibc through `process.report`)."""

    os: str = "linux"
    cpu: str = "x64"
    libc: str = "glibc"
    node: str = NODE_VERSION
    npm: str = NPM_VERSION

    def assumes(self) -> dict[str, str]:
        return {
            "npm": self.npm,
            "node": self.node,
            "os": self.os,
            "cpu": self.cpu,
            "libc": self.libc,
        }


LINUX_X64_GLIBC: Final = Platform()


@dataclass(frozen=True)
class BundleCaps:
    """Caps for one bundle ("Sizes and caps"). Over any of them the version is exported
    unbundled, never trimmed: a half-shipped closure would look complete to npm."""

    max_packages: int = 1_500
    max_compressed_bytes: int = 128 * 1024 * 1024  # the .tgz, and the dependencies' tarballs
    max_unpacked_bytes: int = 512 * 1024 * 1024
    max_files: int = 50_000
    max_depth: int = 64  # dependency-chain depth
    max_nesting: int = 8  # node_modules levels
    max_path_bytes: int = 1_024
    max_component_bytes: int = 255
    # Lookups: an edge costs work and a name a packument request even when nothing is placed.
    max_edges: int = 30_000  # edges walked in one resolution pass
    max_packuments: int = 3_000  # distinct names looked up (twice max_packages)
    max_packument_bytes: int = 512 * 1024 * 1024  # their response bodies, snapshot hits included

    def extract_limits(self) -> ExtractLimits:
        """One file may take the whole unpacked cap: `extract_tar_gz`'s default 64 MiB per file
        made native CLI binaries (bun, opencode) unreadable, 12 of 154 live bundles."""
        return ExtractLimits(
            max_compressed_bytes=self.max_compressed_bytes,
            max_total_bytes=self.max_unpacked_bytes,
            max_file_bytes=self.max_unpacked_bytes,
            max_files=self.max_files,
        )


DEFAULT_CAPS: Final = BundleCaps()

# Why a version with dependencies is exported unbundled (`ExportEntry.unbundled_reason`).
UnbundledReason = Literal[
    "nothing-to-bundle",
    "original-not-repackable",
    "over-cap",
    "resolution-mismatch",
    "self-check-failed",
]


class BundleError(ValueError):
    """The version can't be bundled; export it unbundled with `reason`. `detail` is a fixed
    string (a cap name, a check), never package text."""

    def __init__(self, reason: UnbundledReason, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason: UnbundledReason = reason
        self.detail = detail


# --- records --------------------------------------------------------------------------------

EdgeType = Literal["prod", "optional", "peer", "peerOptional"]


class RequiredBy(Record):
    """One edge a package satisfies: who requires it, with what spec."""

    requirer: str = Field(description='Location of the requiring package; "" is the package.')
    spec: str
    type: EdgeType


class PlacedPackage(Record):
    """A package the resolver ships, at `location` (relative to the package directory)."""

    location: str = Field(description="e.g. node_modules/a/node_modules/@s/b")
    name: str = Field(description="The folder name: the edge's name, which an alias renames.")
    package_name: str = Field(description="The registry name (an alias's target).")
    version: str
    tarball: str
    integrity: str | None
    shasum: str | None
    depth: int = Field(description="Dependency-chain depth; the package's own deps are 1.")
    optional: bool = Field(description="Reached only through optional edges.")
    engines_ok: bool = Field(description="False: npm only warns (engine-strict is off).")
    latest_after_as_of: bool = False
    deprecated: bool = False
    bundles: tuple[str, ...] = Field(
        default=(), description="Its own bundleDependencies: shipped by its tarball, not resolved."
    )
    declared_unpacked: int | None = Field(
        default=None, description="dist.unpackedSize; None when absent, negative or not an int."
    )
    has_shrinkwrap: bool = Field(
        default=False, description="The packument says it ships npm-shrinkwrap.json."
    )
    manifest_digests: dict[str, str] = Field(
        default_factory=dict, description="sha256 of each compared field of the registry manifest."
    )
    required_by: tuple[RequiredBy, ...] = ()


class SuppliedPackage(Record):
    """A folder the original tarball already ships under its own node_modules/: kept byte for
    byte, never overwritten, and its dependencies resolved like any bundled package's."""

    location: str
    name: str
    package_name: str | None
    version: str | None
    satisfies: bool = Field(
        default=True, description="False: an edge that reaches it wants another version."
    )


class SkippedPackage(Record):
    """An optional package or optional peer not shipped, with the failed check."""

    name: str
    spec: str
    requirer: str
    reason: Literal[
        "optional-peer",
        "platform",
        "engines",
        "optional-dependency-failed",
        "optional-unresolved",
    ]
    version: str | None = None


class UnresolvedSpec(Record):
    """An edge that couldn't be resolved. A required one makes the bundle incomplete."""

    name: str
    spec: str
    requirer: str
    type: EdgeType
    optional: bool
    reason: str = Field(description="A fixed code, e.g. git, not-on-registry, no-match.")
    version: str | None = None


class PeerConflict(Record):
    """A dependency's peer whose visible copy doesn't satisfy it and couldn't be replaced:
    npm keeps that copy and warns (`ERESOLVE overriding peer dependency`), and so does the
    bundle. `placed` is the copy kept (the same as `found`)."""

    name: str
    spec: str
    requirer: str
    found: str
    found_version: str | None
    placed: str


class PostCheckFailure(Record):
    """An edge Node's lookup from its requirer would not satisfy in the bundle."""

    name: str
    spec: str
    requirer: str
    found: str | None
    found_version: str | None


class Resolution(Record):
    """What `resolve` decided: a pure function of the package.json, `as_of`, the platform,
    the caps and the packuments."""

    package: str
    version: str
    manifest_digest: str = Field(description="sha256 of the package.json it resolved.")
    as_of: datetime
    assumes: dict[str, str]
    bundle_names: tuple[str, ...] = Field(
        description="The package's explicit, sorted bundleDependencies."
    )
    peers_copied: tuple[tuple[str, str], ...] = Field(
        default=(), description="Required peers copied into dependencies: (name, spec)."
    )
    packages: tuple[PlacedPackage, ...] = ()
    supplied: tuple[SuppliedPackage, ...] = ()
    skipped: tuple[SkippedPackage, ...] = ()
    unresolved: tuple[UnresolvedSpec, ...] = ()
    peer_conflicts: tuple[PeerConflict, ...] = ()
    post_check: tuple[PostCheckFailure, ...] = ()
    untimed_versions: int = Field(
        default=0, description="Versions excluded for having no publish time, over all picks."
    )
    passes: int = 1
    cap_exceeded: str | None = Field(default=None, description="The cap hit; then unbundled.")
    incomplete_reasons: tuple[str, ...] = ()

    @property
    def needs_bundle(self) -> bool:
        """False for a dependency-free package: export it unchanged, under its own key."""
        return bool(self.bundle_names)

    @property
    def complete(self) -> bool:
        return not self.incomplete_reasons and self.cap_exceeded is None


class PackageJsonChange(Record):
    field: str
    before: JsonValue = Field(
        description="The original value; None when absent, or too large or deep to record "
        "(then `before_sha256` is set)."
    )
    after: JsonValue
    before_sha256: str | None = Field(
        default=None, description="sha256 of the original value's canonical JSON, unrecorded."
    )


class PackageJsonRecord(Record):
    original_sha256: str
    rewritten_sha256: str
    changes: tuple[PackageJsonChange, ...]


class AddedPackage(Record):
    """One shipped package, as built."""

    location: str
    name: str
    package_name: str
    version: str
    integrity: str | None
    tarball_sha256: str
    tarball_bytes: int
    files: int
    unpacked_bytes: int
    required_by: tuple[RequiredBy, ...]
    optional: bool
    engines_ok: bool
    hooks: tuple[str, ...]
    binding_gyp: bool
    anomalies: tuple[str, ...] = ()


class PredictedNetwork(Record):
    """A package expected to need the network at install time ("Failure modes")."""

    location: str
    package_name: str | None
    reason: Literal["node-gyp", "install-tool", "known-downloader"]


class BundleRecord(Persisted):
    """`<key>.bundle.json`: everything about how a bundle was built."""

    SCHEMA_VERSION: ClassVar[int] = 1
    schema_version: int = 1

    format: str = BUNDLE_FORMAT
    package: str
    version: str
    status: Literal["complete", "incomplete"]
    incomplete_reasons: tuple[str, ...]
    assumes: dict[str, str]
    as_of: datetime
    original_sha256: str
    bundle_sha256: str
    tar_sha256: str = Field(description="sha256 of the uncompressed tar: the job key's input.")
    bundle_bytes: int
    package_json: PackageJsonRecord
    added: tuple[AddedPackage, ...]
    supplied_by_package: tuple[SuppliedPackage, ...]
    skipped: tuple[SkippedPackage, ...]
    unresolved: tuple[UnresolvedSpec, ...]
    peer_conflicts: tuple[PeerConflict, ...]
    post_check: tuple[PostCheckFailure, ...]
    predicted_network: tuple[PredictedNetwork, ...]
    normalized: tuple[str, ...] = Field(
        default=(),
        description="What was read the way npm reads it rather than byte for byte: "
        "link-entries-dropped, package-json-bom, package-json-duplicate-keys.",
    )
    files: dict[str, str] = Field(
        description='Every bundle path (without "package/") -> its origin: "package" or the '
        "added package's location."
    )

    def dependencies_sha256(self) -> str:
        """sha256 over the added packages, sorted by location: the dependency set a bundled
        job's key covers (with the tar's sha256)."""
        rows = sorted([p.location, p.package_name, p.version, p.tarball_sha256] for p in self.added)
        return sha256_hex(json.dumps(rows, separators=(",", ":")).encode())

    def job_bundle(self) -> JobBundle:
        """What `SandboxJob.bundle` carries for this bundle."""
        return JobBundle(
            format=self.format,
            tar_sha256=self.tar_sha256,
            dependencies_sha256=self.dependencies_sha256(),
            original_sha256=self.original_sha256,
            assumes=dict(self.assumes),
            added=len(self.added),
            dependencies=tuple(sorted({p.name for p in self.added})),
            top_level=tuple(
                sorted(p.name for p in self.added if p.location.count("node_modules/") == 1)
            ),
            package_json_changes=tuple(c.field for c in self.package_json.changes),
            supplied_by_package=len(self.supplied_by_package),
            skipped=len(self.skipped),
            predicted_network=len(self.predicted_network),
        )

    def summary(self) -> dict[str, JsonValue]:
        """The small summary `SandboxJob.bundle` carries in jobs.json."""
        return {
            "format": self.format,
            "status": self.status,
            "incomplete_reasons": list(self.incomplete_reasons),
            "tar_sha256": self.tar_sha256,
            "original_sha256": self.original_sha256,
            "assumes": dict(self.assumes),
            "added": len(self.added),
            "top_level": [
                name
                for name in sorted(
                    p.name for p in self.added if p.location.count("node_modules/") == 1
                )
            ],
            "supplied_by_package": len(self.supplied_by_package),
            "skipped": len(self.skipped),
            "unresolved": len(self.unresolved),
            "predicted_network": len(self.predicted_network),
            "package_json_changes": [c.field for c in self.package_json.changes],
            "normalized": list(self.normalized),
        }


@dataclass(frozen=True)
class BuiltBundle:
    data: bytes
    record: BundleRecord


# --- helpers --------------------------------------------------------------------------------


def _location(path: tuple[str, ...]) -> str:
    return "/".join(f"node_modules/{n}" for n in path)


def valid_name(name: object) -> bool:
    """A dependency name safe to use as a folder: npm's name grammar (one component, or
    `@scope/name`), no blacklisted names, within the component cap."""
    return (
        isinstance(name, str)
        and len(name.encode()) <= 214
        and NPM_NAME.fullmatch(name) is not None
        and name.lower() not in _BLACKLISTED_NAMES
        and name.rsplit("/", 1)[-1].lower() not in _BLACKLISTED_NAMES
    )


def registry_tarball_url(url: object) -> bool:
    """Only plain `https://registry.npmjs.org/...` tarball URLs are fetched. The prefix pins
    the authority (no user info, no port); a scoped package's path has an `@`, which is
    fine after it. No percent-escapes, queries, fragments, backslashes or `..` segments."""
    if not isinstance(url, str) or not url.startswith(REGISTRY_TARBALL_PREFIX):
        return False
    if not url.isascii() or any(c in url for c in "\\?# \t\r\n%"):
        return False
    parts = urlsplit(url)
    return (
        parts.scheme == "https"
        and parts.netloc == "registry.npmjs.org"
        and ".." not in parts.path.split("/")
    )


def _json_text(value: object) -> str:
    """Canonical JSON of untrusted data; a value nested past the encoder's recursion limit
    gets a fixed marker instead of crashing the export."""
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True)
    except RecursionError, TypeError, ValueError:
        return "<unencodable>"


def _digest(value: object) -> str:
    return sha256_hex(_json_text(value).encode())


def _js_truthy(value: object) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        return value != ""
    return True


def _check_list(value: str, wanted: object) -> bool:
    """npm-install-checks 8.0.0 `checkList` (`lib/index.js#L59-L83`). A value that isn't a
    string or a list of strings would throw in npm; here it fails."""
    entries = [wanted] if isinstance(wanted, str) else wanted
    if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
        return False
    if len(entries) == 1 and entries[0] == "any":
        return True
    negated = 0
    match = False
    for entry in entries:
        if entry.startswith("!"):
            negated += 1
            if value == entry[1:]:
                return False
        else:
            match = match or value == entry
    return match or negated == len(entries)


def platform_ok(manifest: Mapping[str, Any], platform: Platform = LINUX_X64_GLIBC) -> bool:
    """npm-install-checks 8.0.0 `checkPlatform` (`lib/index.js#L25-L57`) for `platform`."""
    for key, value in (("os", platform.os), ("cpu", platform.cpu), ("libc", platform.libc)):
        wanted = manifest.get(key)
        if _js_truthy(wanted) and not _check_list(value, wanted):
            return False
    return not (_js_truthy(manifest.get("libc")) and not platform.libc)


def _strings(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def bundle_list(manifest: Mapping[str, Any]) -> list[str]:
    """`bundleDependencies` as @npmcli/package-json normalizes it (`normalize.js#L211-L236`):
    the misspelling `bundledDependencies` when the right one is absent, `true` as the keys of
    `dependencies`, an object as its keys, a list as its strings."""
    raw = manifest.get("bundleDependencies")
    if raw is None and "bundleDependencies" not in manifest:
        raw = manifest.get("bundledDependencies")
    if raw is True:
        return list(_strings(manifest.get("dependencies")))
    if isinstance(raw, dict):
        return list(raw)
    if isinstance(raw, list):
        return [n for n in raw if isinstance(n, str)]
    return []


_FILE_SPEC: Final = re.compile(r"^(?:[.]|~/|/|[a-zA-Z]:)")
_URL_SPEC: Final = re.compile(r"^(?:git[+])?[a-z]+:", re.IGNORECASE)
_HOSTED: Final = re.compile(r"^(?:github|gitlab|bitbucket|gist):", re.IGNORECASE)
_SCP_GIT: Final = re.compile(r"^[^@/:\s]+@[^:./\s]+\.[^:\s]+:.+$")
_SHORTHAND: Final = re.compile(r"^[^/@:\s#][^/:\s#]*/[^/:\s#]+(?:#.*)?$")
_FILE_TYPE: Final = re.compile(r"[.](?:tgz|tar\.gz|tar)$", re.IGNORECASE)


@dataclass(frozen=True)
class SpecKind:
    """How npm-package-arg 13 classifies a dependency spec (`npa.js` `resolve`, #L76-L109)."""

    kind: Literal["registry", "alias", "git", "remote", "file", "protocol", "invalid"]
    package_name: str | None = None
    range: str = ""


def classify_spec(name: str, spec: str) -> SpecKind:
    """Registry specs (ranges, versions, tags) and `npm:` aliases can be resolved from a
    packument; git, hosted shorthands, URLs, `file:` and paths, and other protocols
    (`workspace:`, `link:`, `catalog:`) can't."""
    lowered = spec.lower()
    if lowered.startswith("file:") or _FILE_SPEC.match(spec):
        return SpecKind("file")
    if lowered.startswith("npm:"):
        rest = spec[4:]
        at = rest.find("@", 1)
        real, sub = (rest[:at], rest[at + 1 :]) if at > 0 else (rest, "")
        if not valid_name(real):
            return SpecKind("invalid")
        inner = classify_spec(real, sub or "*")
        if inner.kind != "registry":
            return SpecKind("invalid")  # npa: aliases only work for registry deps
        return SpecKind("alias", real, sub)
    if _HOSTED.match(spec) or _SCP_GIT.match(spec) or lowered.startswith(("git+", "git:")):
        return SpecKind("git")
    if _URL_SPEC.match(spec):
        return SpecKind("remote" if lowered.startswith(("http:", "https:")) else "protocol")
    if _SHORTHAND.match(spec):
        return SpecKind("git")  # hosted-git-info shorthand: user/repo
    if "/" in spec or _FILE_TYPE.search(spec):
        return SpecKind("file")
    return SpecKind("registry", name, spec)


def _manifest_edges(
    manifest: Mapping[str, Any], *, is_root: bool
) -> tuple[dict[str, tuple[object, EdgeType]], list[str]]:
    """A package's edges by name, in arborist's precedence (`node.js#L895-L945`): peers, then
    optional peers, then `dependencies`, then `optionalDependencies`, a later type replacing
    an earlier one. Never `devDependencies`. The package's own required peers become `prod`
    edges (they are copied into its dependencies). Returns the edges and the fields that were
    present but not objects."""
    bad: list[str] = []

    def section(key: str) -> dict[str, object]:
        value = manifest.get(key)
        if value is not None and not isinstance(value, dict):
            if _js_truthy(value):
                bad.append(key)
            return {}
        return dict(value) if isinstance(value, dict) else {}

    edges: dict[str, tuple[object, EdgeType]] = {}
    peers = section("peerDependencies")
    meta = _strings(manifest.get("peerDependenciesMeta"))
    for name, spec in peers.items():
        entry = meta.get(name)
        optional = isinstance(entry, dict) and _js_truthy(entry.get("optional"))
        if not optional:
            edges[name] = (spec, "prod" if is_root else "peer")
    for name, spec in peers.items():
        entry = meta.get(name)
        if isinstance(entry, dict) and _js_truthy(entry.get("optional")):
            edges[name] = (spec, "peerOptional")
    for name, spec in section("dependencies").items():
        edges[name] = (spec, "prod")
    for name, spec in section("optionalDependencies").items():
        edges[name] = (spec, "optional")
    return edges, bad


def _bundle_names(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    """The package's explicit `bundleDependencies` in a bundle: its own list, every name in
    `dependencies` and `optionalDependencies`, and every required peer, sorted."""
    names = set(bundle_list(manifest))
    names |= set(_strings(manifest.get("dependencies")))
    names |= set(_strings(manifest.get("optionalDependencies")))
    names |= set(required_peers(manifest))
    return tuple(sorted(names))


def wants_bundle(manifest: Mapping[str, Any]) -> bool:
    """Whether npm would need anything beyond the tarball for this package.json (the same test
    as `Resolution.needs_bundle`, without resolving): a dependency-free package is exported
    unchanged, under its own key."""
    return bool(_bundle_names(manifest))


def required_peers(manifest: Mapping[str, Any]) -> dict[str, object]:
    peers = _strings(manifest.get("peerDependencies"))
    meta = _strings(manifest.get("peerDependenciesMeta"))
    return {name: spec for name, spec in peers.items() if not _optional_meta(meta.get(name))}


def _optional_meta(entry: object) -> bool:
    return isinstance(entry, dict) and _js_truthy(entry.get("optional"))


# --- the resolver ---------------------------------------------------------------------------

PackumentSource = Callable[[str], Packument | None]
_JSON_ACCEPT: Final = {"Accept": "application/json"}  # the full document, as NpmEcosystem asks


class RegistryPackument(Packument):
    """A `Packument` that also exposes `dist-tags` (string values only), which the resolver's
    `latest` step needs. Until `ecosystems/npm/packument.py` exposes them itself (the design
    note's "Changes outside Stage 5"), Stage 5 reads them here from the same document.
    `body_bytes` is the response's size, which `resolve` counts against
    `BundleCaps.max_packument_bytes`."""

    def __init__(self, doc: object, *, expected_name: str, body_bytes: int = 0) -> None:
        super().__init__(doc, expected_name=expected_name)
        raw = doc.get("dist-tags") if isinstance(doc, dict) else None
        self.dist_tags: dict[str, str] = (
            {k: v for k, v in raw.items() if isinstance(k, str) and isinstance(v, str)}
            if isinstance(raw, dict)
            else {}
        )
        self.body_bytes = body_bytes


def registry_packuments(fetcher: HttpFetcher) -> PackumentSource:
    """Full packuments through `fetcher` (`Accept: application/json`, the request
    `NpmEcosystem.packument` makes, so a run's snapshot holds one response per name): None
    for a 404. Any other non-2xx status raises `FetchError` (the fetcher already retried 429
    and 5xx and raised `TransientFetchError`); a body that isn't a packument raises
    `PackumentError` or `ValueError`, which `resolve` records as `invalid-packument`."""

    def source(name: str) -> Packument | None:
        response = fetcher.get(packument_url(name), headers=_JSON_ACCEPT)
        if response.status == 404:
            return None
        if not response.ok:
            raise FetchError(f"packument: HTTP {response.status}")
        return RegistryPackument(response.json(), expected_name=name, body_bytes=len(response.body))

    return source


def _dist_tags(packument: Packument) -> dict[str, str]:
    """`dist-tags`, if the Packument exposes them (design note, "Changes outside Stage 5")."""
    raw = getattr(packument, "dist_tags", None)
    if not isinstance(raw, Mapping):
        return {}
    return {k: v for k, v in raw.items() if isinstance(k, str) and isinstance(v, str)}


def _registry_https(url: object) -> object:
    """An `http://registry.npmjs.org/` tarball URL in the https form npm fetches it in."""
    if isinstance(url, str) and url.startswith(_HTTP_REGISTRY_PREFIX):
        return REGISTRY_TARBALL_PREFIX + url.removeprefix(_HTTP_REGISTRY_PREFIX)
    return url


def _slim(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """A registry manifest cut to `_KEPT_FIELDS`, its tarball URL in the https form."""
    kept = {k: v for k, v in manifest.items() if k in _KEPT_FIELDS}
    dist = kept.get("dist")
    if isinstance(dist, dict):
        dist = {k: v for k, v in dist.items() if k in _KEPT_DIST}
        if "tarball" in dist:
            dist["tarball"] = _registry_https(dist["tarball"])
        kept["dist"] = dist
    return kept


@dataclass(frozen=True)
class _Versions:
    """What the resolver keeps of a packument: each version's manifest cut to the fields it
    reads, the publish times and the dist-tags. The document itself is dropped once read."""

    versions: dict[str, dict[str, Any]]
    publish_times: Mapping[str, datetime]
    dist_tags: dict[str, str]

    @classmethod
    def of(cls, doc: Packument) -> _Versions:
        versions = {v: _slim(m) for v, m in doc.versions.items()}
        return cls(versions, dict(doc.publish_times), _dist_tags(doc))


def _declared_unpacked(ref: ArtifactRef) -> int | None:
    """`dist.unpackedSize` when it is a size: a negative number (or a bool) is no size, never
    a credit against the unpacked cap."""
    size = ref.unpacked_size
    return size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None


@dataclass
class _Node:
    path: tuple[str, ...]
    package_name: str | None
    version: str | None
    manifest: dict[str, Any]
    depth: int
    opt_edge: tuple[str, str] | None  # the nearest optional edge on the chain that placed it
    supplied: bool = False
    tarball: str = ""
    integrity: str | None = None
    shasum: str | None = None
    engines_ok: bool = True
    latest_after_as_of: bool = False
    deprecated: bool = False
    declared_unpacked: int | None = None
    has_shrinkwrap: bool = False
    placed_by: tuple[str, ...] | None = None  # the requirer whose edge placed it
    required_by: list[RequiredBy] = field(default_factory=list)

    @property
    def ident(self) -> str:
        return "" if not self.path else f"{self.package_name}@{self.version}"

    def take(self, choice: _Choice) -> None:
        """Become the version `choice` picked (a placement, or npm's REPLACE)."""
        self.version = choice.version
        self.manifest = choice.manifest
        self.tarball = choice.ref.url if choice.ref is not None else ""
        self.integrity = choice.ref.integrity if choice.ref is not None else None
        self.shasum = choice.ref.shasum if choice.ref is not None else None
        self.engines_ok = choice.engines
        self.latest_after_as_of = choice.latest_after_as_of
        self.deprecated = _js_truthy(choice.manifest.get("deprecated"))
        self.declared_unpacked = None if choice.ref is None else _declared_unpacked(choice.ref)
        self.has_shrinkwrap = _js_truthy(choice.manifest.get("_hasShrinkwrap"))


@dataclass(frozen=True)
class _Edge:
    source: tuple[str, ...]
    name: str
    spec: str
    type: EdgeType
    target: tuple[str, ...]
    package_name: str
    range: str


@dataclass(frozen=True)
class _Pending:
    """A failure inside an optional chain: npm prunes the optional subtree, unless the
    requirer turns out to be required."""

    requirer: tuple[str, ...]
    node: tuple[str, ...] | None  # placed despite the failure (engines)
    opt_edge: tuple[str, str]
    unresolved: UnresolvedSpec | None


@dataclass(frozen=True)
class _Choice:
    """The version picked for an edge and its checks. `problem` is why it can't be fetched
    (`non-registry-tarball`, `no-digest`), checked after the platform, as npm fails a
    platform mismatch before it looks at the tarball."""

    version: str
    manifest: dict[str, Any]
    ref: ArtifactRef | None
    platform: bool
    engines: bool
    latest_after_as_of: bool
    problem: str | None


class _CapExceeded(Exception):
    def __init__(self, cap: str) -> None:
        super().__init__(cap)
        self.cap = cap


@dataclass
class _Context:
    packuments: PackumentSource
    as_of: datetime
    platform: Platform
    caps: BundleCaps
    cache: dict[str, _Versions | str | None] = field(default_factory=dict)
    picks: dict[tuple[str, str], ranges.Pick] = field(default_factory=dict)
    packument_bytes: int = 0

    def packument(self, name: str) -> _Versions | str:
        """The packument's versions, or a reason: not-on-registry, invalid-packument. Raises
        _CapExceeded past the packument caps, which count every name looked up and every
        body read, so a replay from the snapshot reaches the same cap."""
        if name not in self.cache:
            if len(self.cache) >= self.caps.max_packuments:
                raise _CapExceeded("packuments")
            try:
                doc = self.packuments(name)
            except PackumentError, ValueError, RecursionError:
                self.cache[name] = "invalid-packument"
            else:
                self.packument_bytes += getattr(doc, "body_bytes", 0)
                if self.packument_bytes > self.caps.max_packument_bytes:
                    raise _CapExceeded("packument-bytes")
                self.cache[name] = None if doc is None else _Versions.of(doc)
        found = self.cache[name]
        if found is None:
            return "not-on-registry"
        return found

    def pick(self, name: str, spec: str) -> ranges.Pick | str:
        doc = self.packument(name)
        if isinstance(doc, str):
            return doc
        key = (name, spec)
        if key not in self.picks:
            self.picks[key] = ranges.pick(
                doc.versions,
                doc.dist_tags,
                spec,
                published=doc.publish_times,
                as_of=self.as_of,
                node=self.platform.node,
                npm=self.platform.npm,
            )
        return self.picks[key]

    def choose(self, name: str, spec: str) -> _Choice | tuple[str, str | None]:
        """The version npm picks for `spec`, or (reason, version) when there is none."""
        picked = self.pick(name, spec)
        if isinstance(picked, str):
            return picked, None
        if picked.version is None:
            reason = picked.reason or "no-match"
            return _PICK_REASONS.get(reason, reason), None
        doc = self.packument(name)
        assert isinstance(doc, _Versions)  # noqa: S101 - pick() fetched it
        manifest = doc.versions.get(picked.version)
        if manifest is None:
            return "no-manifest", picked.version
        ref = artifact_ref(manifest)
        dist = manifest.get("dist")
        raw_url = dist.get("tarball") if isinstance(dist, dict) else None
        problem = None
        if not registry_tarball_url(raw_url) or ref is None:
            problem = "non-registry-tarball"
        elif not (ref.integrity or ref.shasum):
            problem = "no-digest"
        return _Choice(
            picked.version,
            manifest,
            ref,
            platform_ok(manifest, self.platform),
            ranges.engines_ok(manifest, node=self.platform.node, npm=self.platform.npm),
            picked.latest_after_as_of,
            problem,
        )


_PICK_REASONS: Final = {"tag-not-candidate": "tag-after-as-of"}

# ICU's root collation, which arborist's `localeCompare` ('en') uses to order its queue, for
# the characters npm paths hold: punctuation first, in this order, then digits, then letters
# case-blind, lowercase before uppercase only to break a tie; anything else after, by code
# point. An approximation of ICU, exact for lowercase ASCII names.
_PUNCTUATION_ORDER: Final = "_-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$"
_PUNCTUATION_RANK: Final = {c: i for i, c in enumerate(_PUNCTUATION_ORDER)}


def _collation_key(text: str) -> tuple[tuple[int, ...], tuple[int, ...]]:
    primary: list[int] = []
    tertiary: list[int] = []
    for char in text:
        low = char.lower()
        if low in _PUNCTUATION_RANK:
            primary.append(_PUNCTUATION_RANK[low])
        elif "0" <= low <= "9" or "a" <= low <= "z":
            primary.append(100 + ord(low))
        else:
            primary.append(1000 + ord(low))
        tertiary.append(int(char != low))
    return tuple(primary), tuple(tertiary)


def _accepts(version: str, spec: str) -> bool:
    """arborist's `depValid` for a registry copy of the right name (`dep-valid.js#L44-L68`):
    `*` takes anything, a version or range is `satisfies(loose)`, and a dist-tag takes any
    registry copy ("presumably, it came from the registry and was tagged at some point")."""
    trimmed = spec.strip()
    if trimmed in ("", "*"):
        return True
    if ranges.valid_range(trimmed, loose=True) is not None:
        return ranges.satisfies(version, trimmed, loose=True)
    return True


_QueueItem = tuple[int, tuple[tuple[int, ...], tuple[int, ...]], tuple[str, ...]]


class _Pass:
    """One resolution with a fixed set of excluded optional edges. Packages are processed in
    arborist's DepsQueue order (`build-ideal-tree.js#L51-L77`): shallower first, then by
    path."""

    def __init__(
        self,
        ctx: _Context,
        root: Mapping[str, Any],
        supplied: Mapping[str, Mapping[str, Any] | None],
        excluded: frozenset[tuple[str, str]],
    ) -> None:
        self.ctx = ctx
        self.root_manifest = root
        self.excluded = excluded
        self.nodes: dict[tuple[str, ...], _Node] = {}
        self.edges: list[_Edge] = []
        self.skipped: list[SkippedPackage] = []
        self.unresolved: list[UnresolvedSpec] = []
        self.conflicts: list[PeerConflict] = []
        self.pending: list[_Pending] = []
        self.bad_fields: list[str] = []
        self.declared_unpacked = 0
        self.edge_count = 0
        self.queue: list[_QueueItem] = []
        self.seen: set[tuple[str, ...]] = set()
        self.peers_placed: set[tuple[str, ...]] = set()
        self.peer_queue: list[_Node] = []
        self.placing_peers = False
        root_name, root_version = root.get("name"), root.get("version")
        self.nodes[()] = _Node(
            (),
            root_name if isinstance(root_name, str) else None,
            root_version if isinstance(root_version, str) else None,
            dict(root),
            0,
            None,
        )
        for location in sorted(supplied, key=lambda loc: (loc.count("/"), loc)):
            path = _path_of(location)
            if path is None:
                continue
            manifest = supplied[location]
            name = manifest.get("name") if manifest else None
            version = manifest.get("version") if manifest else None
            self.nodes[path] = _Node(
                path,
                name if isinstance(name, str) else None,
                version if isinstance(version, str) else None,
                dict(manifest or {}),
                len(path),
                None,
                supplied=True,
            )

    def run(self) -> None:
        """Process the package, then every package placed. A folder the original ships is
        never processed: npm takes a bundled package as it is and never resolves its own
        dependencies (`build-ideal-tree.js#L1135-L1155`)."""
        self._enqueue(())
        while self.queue:
            path = heapq.heappop(self.queue)[2]
            if path in self.seen:
                continue
            self.seen.add(path)
            self._process(self.nodes[path])

    def _enqueue(self, path: tuple[str, ...]) -> None:
        heapq.heappush(self.queue, (len(path), _collation_key(_location(path)), path))

    def _lookup(self, start: tuple[str, ...], name: str, *, skip_own: bool) -> _Node | None:
        """Node's module lookup from the package at `start`: its own node_modules, then each
        ancestor's, up to the package's. The first folder found wins, satisfying or not. Past
        the package's own node_modules is `/app/node_modules`, which holds the package
        itself, so a dependency that requires the package finds it there."""
        top = len(start) - 1 if skip_own else len(start)
        for i in range(top, -1, -1):
            found = self.nodes.get((*start[:i], name))
            if found is not None:
                return found
        root = self.nodes[()]
        return root if start and name == root.package_name else None

    def _satisfies(
        self, node: _Node, package_name: str, spec: str, source: tuple[str, ...]
    ) -> bool:
        """Whether the copy `node` satisfies an edge from `source`: arborist's `depValid`
        (`_accepts`) plus the real name. A folder the original ships satisfies the package's
        own edges whatever its version ("If it's included in a bundle, we take whatever is
        specified"); another requirer gets it only if it matches, and never for a dist-tag,
        which wants a registry copy. Neither does the package itself (a file: install)."""
        if node.supplied and not source:
            return True
        if node.package_name != package_name or node.version is None:
            return False
        trimmed = spec.strip()
        if trimmed in ("", "*") or ranges.valid_range(trimmed, loose=True) is not None:
            return _accepts(node.version, trimmed)
        if node.supplied or not node.path:
            return False
        picked = self.ctx.pick(package_name, spec)  # cached: the copy was placed from it
        return isinstance(picked, ranges.Pick) and picked.reason != "invalid-spec"

    def _parent_range(self, node: _Node, name: str, real: str) -> str | None:
        """The range the package that placed `node` has for `name`, when it names the same
        registry package: arborist's `parentEdge` for a peer set (`#loadPeerSet`)."""
        parent = self.nodes.get(node.placed_by) if node.placed_by is not None else None
        if parent is None:
            return None
        edges, _ = _manifest_edges(parent.manifest, is_root=not parent.path)
        raw = edges.get(name)
        if raw is None or not isinstance(raw[0], str) or not valid_name(name):
            return None
        kind = classify_spec(name, raw[0])
        if kind.kind not in ("registry", "alias") or kind.package_name != real:
            return None
        return kind.range

    def _choose_peer(
        self, real: str, spec: str, parent: str | None
    ) -> _Choice | tuple[str, str | None]:
        """A peer's version as `#loadPeerSet` and `#nodeFromEdge` pick it
        (`build-ideal-tree.js#L1052-L1100`, `#L1322-L1385`): the parent's pick if the peer
        accepts it, else the peer's own pick if the parent accepts that, else the parent's."""
        if parent is None:
            return self.ctx.choose(real, spec)
        first = self.ctx.choose(real, parent)
        if isinstance(first, _Choice) and _accepts(first.version, spec):
            return first
        second = self.ctx.choose(real, spec)
        if isinstance(second, _Choice) and _accepts(second.version, parent):
            return second
        return first if isinstance(first, _Choice) else second

    def _replace(self, found: _Node, real: str, choice: _Choice | tuple[str, str | None]) -> bool:
        """npm's REPLACE (`can-place-dep.js`, `Node.canReplace`): a peer's pick takes the place
        of the copy it found when that copy hasn't been processed yet (nothing was resolved
        under it) and the pick still satisfies every edge that reached the copy. A processed
        copy is kept, and the peer conflict recorded."""
        if (
            not isinstance(choice, _Choice)
            or not choice.platform
            or choice.problem is not None
            or not found.path
            or found.supplied
            or found.path in self.seen
            or found.package_name != real
            or choice.version == found.version
        ):
            return False
        incoming = [e for e in self.edges if e.target == found.path]
        if not all(e.package_name == real and _accepts(choice.version, e.range) for e in incoming):
            return False
        self.declared_unpacked -= found.declared_unpacked or 0
        found.take(choice)
        self.declared_unpacked += found.declared_unpacked or 0
        if self.declared_unpacked > self.ctx.caps.max_unpacked_bytes:
            raise _CapExceeded("unpacked-bytes")
        self.pending = [p for p in self.pending if p.node != found.path]
        if not choice.engines and found.opt_edge is not None:
            self.pending.append(_Pending(found.path[:-1], found.path, found.opt_edge, None))
        self.peers_placed.discard(found.path)  # the new version's peers, not the old one's
        self._placed(found)
        return True

    def _process(self, node: _Node) -> None:
        is_root = not node.path
        edges, bad = _manifest_edges(node.manifest, is_root=is_root)
        self._count_edges(len(edges))
        if is_root:
            self.bad_fields.extend(bad)
        own_bundle = set() if is_root else set(bundle_list(node.manifest))
        peers_placed = node.path in self.peers_placed
        for name in sorted(edges):
            raw_spec, etype = edges[name]
            if name in own_bundle or (etype == "peer" and peers_placed):
                continue
            self._edge(node, name, raw_spec, etype)

    def _place_peers(self, node: _Node) -> None:
        """A placed package's required peers, placed with it as its peer set
        (`#loadPeerSet`), before anything else is: so a peer's pick can still REPLACE a copy
        its requirer's other edges placed."""
        self.peers_placed.add(node.path)
        edges, _ = _manifest_edges(node.manifest, is_root=False)
        peers = sorted(n for n, (_, etype) in edges.items() if etype == "peer")
        self._count_edges(len(peers))
        own_bundle = set(bundle_list(node.manifest))
        for name in peers:
            if name not in own_bundle:
                self._edge(node, name, edges[name][0], "peer")

    def _count_edges(self, count: int) -> None:
        self.edge_count += count
        if self.edge_count > self.ctx.caps.max_edges:
            raise _CapExceeded("edges")

    def _edge(self, node: _Node, name: str, raw_spec: object, etype: EdgeType) -> None:
        """Resolve one edge of `node`: reuse what Node's lookup finds, REPLACE it, or place a
        new copy (at the top, else nested under the requirer)."""
        requirer = _location(node.path)
        spec = raw_spec if isinstance(raw_spec, str) else _json_text(raw_spec)
        opt_edge = (node.ident, name) if etype == "optional" else node.opt_edge

        def unresolved(reason: str, version: str | None = None) -> None:
            record = UnresolvedSpec(
                name=name,
                spec=spec,
                requirer=requirer,
                type=etype,
                optional=etype == "optional",
                reason=reason,
                version=version,
            )
            if etype == "optional" or opt_edge is None:
                self.unresolved.append(record)
            else:
                self.pending.append(_Pending(node.path, None, opt_edge, record))

        if etype == "optional" and (node.ident, name) in self.excluded:
            self.skipped.append(
                SkippedPackage(
                    name=name,
                    spec=spec,
                    requirer=requirer,
                    reason="optional-dependency-failed",
                )
            )
            return
        if etype == "peerOptional":
            if self._lookup(node.path, name, skip_own=True) is None:
                self.skipped.append(
                    SkippedPackage(name=name, spec=spec, requirer=requirer, reason="optional-peer")
                )
            return
        if not valid_name(name):
            unresolved("invalid-name")
            return
        if not isinstance(raw_spec, str):
            unresolved("invalid-spec")
            return
        kind = classify_spec(name, raw_spec)
        if kind.kind not in ("registry", "alias") or kind.package_name is None:
            unresolved(kind.kind)
            return
        real, rng = kind.package_name, kind.range
        peer = etype == "peer"
        parent_range = self._parent_range(node, name, real) if peer else None
        found = self._lookup(node.path, name, skip_own=peer)
        target: tuple[str, ...]
        choice: _Choice | tuple[str, str | None] | None = None
        if found is not None:
            if self._satisfies(found, real, rng, node.path):
                found.required_by.append(RequiredBy(requirer=requirer, spec=spec, type=etype))
                self.edges.append(_Edge(node.path, name, spec, etype, found.path, real, rng))
                return
            if peer:
                # npm keeps the copy it found (a peer is never nested under its requirer):
                # replaced by the peer's pick when it can be, else kept with a warning.
                choice = self._choose_peer(real, rng, parent_range)
                if self._replace(found, real, choice):
                    found.required_by.append(RequiredBy(requirer=requirer, spec=spec, type=etype))
                    self.edges.append(_Edge(node.path, name, spec, etype, found.path, real, rng))
                    return
                self.conflicts.append(
                    PeerConflict(
                        name=name,
                        spec=spec,
                        requirer=requirer,
                        found=_location(found.path),
                        found_version=found.version,
                        placed=_location(found.path),
                    )
                )
                return
            target = (*node.path, name)
            if target in self.nodes:
                unresolved("conflict", found.version)
                return
        else:
            target = (name,)
        if choice is None:
            choice = (
                self._choose_peer(real, rng, parent_range) if peer else self.ctx.choose(real, rng)
            )
        if isinstance(choice, tuple):
            unresolved(*choice)
            return
        if etype == "optional" and not (choice.platform and choice.engines):
            self.skipped.append(
                SkippedPackage(
                    name=name,
                    spec=spec,
                    requirer=requirer,
                    reason="platform" if not choice.platform else "engines",
                    version=choice.version,
                )
            )
            return
        if not choice.platform:
            unresolved("platform-mismatch", choice.version)
            return
        if choice.problem is not None:
            unresolved(choice.problem, choice.version)
            return
        assert choice.ref is not None  # noqa: S101 - no problem means a ref
        self._check_caps(target, node.depth + 1, _declared_unpacked(choice.ref))
        placed = _Node(target, real, None, {}, node.depth + 1, opt_edge, placed_by=node.path)
        placed.take(choice)
        placed.required_by.append(RequiredBy(requirer=requirer, spec=spec, type=etype))
        self.nodes[target] = placed
        self.edges.append(_Edge(node.path, name, spec, etype, target, real, rng))
        if not choice.engines and opt_edge is not None:
            self.pending.append(_Pending(node.path, target, opt_edge, None))
        self._enqueue(target)
        self._placed(placed)

    def _placed(self, node: _Node) -> None:
        """Place a new package's peer set now, and its peers' peers, without recursing (a
        chain of peers is as long as a package wants)."""
        self.peer_queue.append(node)
        if self.placing_peers:
            return
        self.placing_peers = True
        try:
            while self.peer_queue:
                self._place_peers(self.peer_queue.pop(0))
        finally:
            self.placing_peers = False

    def _check_caps(self, target: tuple[str, ...], depth: int, unpacked: int | None) -> None:
        caps = self.ctx.caps
        placed = sum(1 for n in self.nodes.values() if n.path and not n.supplied)
        if placed + 1 > caps.max_packages:
            raise _CapExceeded("packages")
        if depth > caps.max_depth:
            raise _CapExceeded("depth")
        if len(target) > caps.max_nesting:
            raise _CapExceeded("nesting")
        location = f"{PREFIX}/{_location(target)}"
        if len(location.encode()) > caps.max_path_bytes:
            raise _CapExceeded("path-length")
        if any(len(part.encode()) > caps.max_component_bytes for part in location.split("/")):
            raise _CapExceeded("path-length")
        self.declared_unpacked += unpacked or 0
        if self.declared_unpacked > caps.max_unpacked_bytes:
            raise _CapExceeded("unpacked-bytes")

    def required(self) -> set[tuple[str, ...]]:
        """Nodes reachable from the package through non-optional edges."""
        out: dict[tuple[str, ...], list[_Edge]] = {}
        for edge in self.edges:
            out.setdefault(edge.source, []).append(edge)
        reached: set[tuple[str, ...]] = {()}
        todo: list[tuple[str, ...]] = [()]
        while todo:
            path = todo.pop()
            for edge in out.get(path, ()):
                if edge.type in ("prod", "peer") and edge.target not in reached:
                    reached.add(edge.target)
                    todo.append(edge.target)
        return reached

    def post_check(self) -> list[PostCheckFailure]:
        """Every resolved edge, looked up as Node would from its requirer, must find a copy
        that satisfies it."""
        failures = []
        for edge in self.edges:
            found = self._lookup(edge.source, edge.name, skip_own=False)
            if found is None or not self._satisfies(
                found, edge.package_name, edge.range, edge.source
            ):
                failures.append(
                    PostCheckFailure(
                        name=edge.name,
                        spec=edge.spec,
                        requirer=_location(edge.source),
                        found=None if found is None else _location(found.path),
                        found_version=None if found is None else found.version,
                    )
                )
        return failures


def _path_of(location: str) -> tuple[str, ...] | None:
    """`node_modules/a/node_modules/@s/b` -> ("a", "@s/b"); None if it isn't that shape."""
    parts = location.split("/")
    path: list[str] = []
    i = 0
    while i < len(parts):
        if parts[i] != "node_modules" or i + 1 >= len(parts):
            return None
        if parts[i + 1].startswith("@"):
            if i + 2 >= len(parts):
                return None
            name = f"{parts[i + 1]}/{parts[i + 2]}"
            i += 3
        else:
            name = parts[i + 1]
            i += 2
        if not valid_name(name):
            return None
        path.append(name)
    return tuple(path) if path else None


def _package_folders(path: str) -> list[str]:
    """The package folders a file path lies in under node_modules/, outermost first:
    `node_modules/a/node_modules/@s/b/x.js` gives `node_modules/a` and
    `node_modules/a/node_modules/@s/b`.
    The walk stops at anything that isn't a valid package name (`.bin`, a stray file)."""
    return _folders_of(path.split("/")[:-1])


def _is_package_folder(path: str) -> bool:
    """Whether a path is itself where a package folder goes (`node_modules/a`): a regular
    file there is a conflict, which npm would try to read as a package."""
    folders = _folders_of(path.split("/"))
    return bool(folders) and folders[-1] == path


def _folders_of(parts: list[str]) -> list[str]:
    folders: list[str] = []
    i = 0
    while i + 1 < len(parts) and parts[i] == "node_modules":
        if parts[i + 1].startswith("@"):
            if i + 2 >= len(parts):
                break
            name, step = f"{parts[i + 1]}/{parts[i + 2]}", 3
        else:
            name, step = parts[i + 1], 2
        if not valid_name(name):
            break
        i += step
        folders.append("/".join(parts[:i]))
    return folders


def resolve(
    root_manifest: Mapping[str, Any],
    *,
    packuments: PackumentSource,
    as_of: datetime,
    platform: Platform = LINUX_X64_GLIBC,
    caps: BundleCaps = DEFAULT_CAPS,
    supplied: Mapping[str, Mapping[str, Any] | None] | None = None,
) -> Resolution:
    """Resolve the closure npm would install for the package whose own package.json is
    `root_manifest`, at `as_of`, on `platform`. `packuments` is the run's source (normally
    `NpmEcosystem(fetcher).packument`); `supplied` maps the locations of folders the original
    tarball already ships (`OriginalPackage.supplied`) to their package.json.

    Failed optional subtrees are pruned the way npm marks them inert: a failure on a
    non-optional edge inside an optional chain excludes the nearest optional edge of that
    chain, and resolution runs again (at most `MAX_PRUNING_PASSES` times)."""
    if as_of.tzinfo is None:
        raise ValueError("as_of must be timezone-aware")
    ctx = _Context(packuments, as_of, platform, caps)
    name = root_manifest.get("name")
    version = root_manifest.get("version")
    package = name if isinstance(name, str) else ""
    root_version = version if isinstance(version, str) else ""
    deps = _strings(root_manifest.get("dependencies"))
    optional = _strings(root_manifest.get("optionalDependencies"))
    peers_copied = tuple(
        (n, s)
        for n, s in sorted(required_peers(root_manifest).items())
        if isinstance(s, str) and n not in deps and n not in optional
    )
    bundle_names = _bundle_names(root_manifest)

    def finish(**outcome: Any) -> Resolution:
        return Resolution(
            package=package,
            version=root_version,
            manifest_digest=_digest(dict(root_manifest)),
            as_of=as_of,
            assumes=platform.assumes(),
            bundle_names=bundle_names,
            peers_copied=peers_copied,
            **outcome,
        )

    excluded: frozenset[tuple[str, str]] = frozenset()
    passes = 0
    while True:
        passes += 1
        current = _Pass(ctx, root_manifest, supplied or {}, excluded)
        try:
            current.run()
        except _CapExceeded as exc:
            return finish(
                passes=passes,
                cap_exceeded=exc.cap,
                incomplete_reasons=(f"cap:{exc.cap}",),
            )
        required = current.required()
        more: set[tuple[str, str]] = set()
        for pending in current.pending:
            node_required = pending.node is not None and pending.node in required
            requirer_required = pending.node is None and pending.requirer in required
            if node_required:
                continue  # engines only warns for a required package
            if requirer_required:
                assert pending.unresolved is not None  # noqa: S101 - set when node is None
                current.unresolved.append(pending.unresolved)
            else:
                more.add(pending.opt_edge)
        if not more - excluded or passes >= MAX_PRUNING_PASSES:
            break
        excluded = excluded | more
    reasons: set[str] = set()
    if more - excluded:
        reasons.add("optional-pruning-limit")
    for item in current.unresolved:
        if not item.optional:
            reasons.add("unresolved-required")
            if item.reason == "platform-mismatch":
                reasons.add("platform-mismatch")
    if current.bad_fields:
        reasons.add("invalid-manifest-field")
    if not platform_ok(root_manifest, platform):
        reasons.add("package-platform-mismatch")
    post = current.post_check()
    if post:
        reasons.add("post-check")
    placed = [n for p, n in current.nodes.items() if p and not n.supplied]
    if any(n.has_shrinkwrap for n in placed):
        # npm installs what that npm-shrinkwrap.json pins, not this resolution
        # (`build-ideal-tree.js#L794-L797`, `reify.js#L615-L646`)
        reasons.add("dependency-shrinkwrap")
    supplied_nodes = [n for p, n in current.nodes.items() if p and n.supplied]
    satisfied_supplied = {
        e.target
        for e in current.edges
        if (n := current.nodes[e.target]).supplied
        and n.package_name == e.package_name
        and n.version is not None
        and (e.range.strip() in ("", "*") or ranges.satisfies(n.version, e.range, loose=True))
    }
    reached_supplied = {e.target for e in current.edges if current.nodes[e.target].supplied}
    return finish(
        packages=tuple(
            _placed_record(n, n.path not in required)
            for n in sorted(placed, key=lambda n: _location(n.path))
        ),
        supplied=tuple(
            SuppliedPackage(
                location=_location(n.path),
                name=n.path[-1],
                package_name=n.package_name,
                version=n.version,
                satisfies=n.path not in reached_supplied or n.path in satisfied_supplied,
            )
            for n in sorted(supplied_nodes, key=lambda n: _location(n.path))
        ),
        skipped=tuple(sorted(set(current.skipped), key=_sort_key)),
        unresolved=tuple(sorted(set(current.unresolved), key=_sort_key)),
        peer_conflicts=tuple(current.conflicts),
        post_check=tuple(post),
        untimed_versions=sum(p.untimed for p in ctx.picks.values()),
        passes=passes,
        incomplete_reasons=tuple(sorted(reasons)),
    )


def _sort_key(item: SkippedPackage | UnresolvedSpec) -> tuple[str, str, str, str]:
    return (item.requirer, item.name, item.spec, item.reason)


def _placed_record(node: _Node, optional: bool) -> PlacedPackage:
    assert node.package_name is not None and node.version is not None  # noqa: S101
    return PlacedPackage(
        location=_location(node.path),
        name=node.path[-1],
        package_name=node.package_name,
        version=node.version,
        tarball=node.tarball,
        integrity=node.integrity,
        shasum=node.shasum,
        depth=node.depth,
        optional=optional,
        engines_ok=node.engines_ok,
        latest_after_as_of=node.latest_after_as_of,
        deprecated=node.deprecated,
        bundles=tuple(sorted(set(bundle_list(node.manifest)))),
        declared_unpacked=node.declared_unpacked,
        has_shrinkwrap=node.has_shrinkwrap,
        manifest_digests={
            k: _digest(node.manifest[k]) for k in _COMPARED_FIELDS if k in node.manifest
        },
        required_by=tuple(node.required_by),
    )


# --- the original tarball -------------------------------------------------------------------


@dataclass(frozen=True)
class OriginalPackage:
    """The package's own tarball as `extract_tar_gz` reads it, with the top directory
    stripped, checked to be repackable byte for byte. `normalized` lists what was read the
    way npm reads it rather than kept (`BundleRecord.normalized`)."""

    files: Mapping[str, bytes]
    executable: frozenset[str]
    manifest: dict[str, Any]
    sha256: str
    supplied: Mapping[str, Mapping[str, Any] | None]
    normalized: tuple[str, ...] = ()


class _Number(float):
    """A JSON number past a double's range (`1e400`), which JSON.parse reads as Infinity,
    keeping its source text so the rewritten package.json can write it back unchanged."""

    text: str

    def __new__(cls, value: float, text: str) -> _Number:
        number = super().__new__(cls, value)
        number.text = text
        return number


def _number(text: str) -> float:
    value = float(text)
    return value if math.isfinite(value) else _Number(value, text)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-JSON constant {name}")


def parse_manifest(raw: bytes, notes: list[str] | None = None) -> dict[str, Any] | None:
    """A package.json as npm reads it (json-parse-even-better-errors, then JSON.parse): UTF-8,
    a leading BOM stripped, a repeated key keeping its last value at its first position, an
    object at the top, no NaN/Infinity literals. A number past a double's range is ±Infinity,
    as in JavaScript, and keeps its text (`_Number`). The BOM and repeated keys are
    normalizations a byte-for-byte copy wouldn't make, so they are appended to `notes`
    (`package-json-bom`, `package-json-duplicate-keys`) for the record."""
    found: set[str] = set()

    def last_wins(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({k for k, _ in pairs}) != len(pairs):
            found.add("package-json-duplicate-keys")
        return dict(pairs)

    try:
        text = raw.decode("utf-8")
        if text.startswith("﻿"):
            text = text[1:]
            found.add("package-json-bom")
        doc = json.loads(
            text, object_pairs_hook=last_wins, parse_constant=_reject_constant, parse_float=_number
        )
    except UnicodeDecodeError, ValueError, RecursionError:
        return None
    if not isinstance(doc, dict):
        return None
    if notes is not None:
        notes.extend(sorted(found))
    return doc


def _executable(tree: ArtifactTree, path: str) -> bool:
    """Whether the entry had an execute bit (pacote keeps it: `(mode | 0o666) & ~umask`)."""
    mode = tree.modes.get(path)
    return mode is not None and bool(mode & 0o111)


def _is_link(entry: SkippedEntry) -> bool:
    return entry.reason.startswith(("symlink ->", "hardlink ->"))


def read_original(data: bytes, *, limits: ExtractLimits | None = None) -> OriginalPackage:
    """Read the package's own tarball, or raise BundleError(original-not-repackable). Link
    entries are dropped, as pacote drops them (`/Link$/` in its extract filter), and
    recorded; any other skipped entry refuses it."""
    try:
        tree = extract_tar_gz(data, limits=limits or DEFAULT_CAPS.extract_limits())
    except ArchiveError as exc:
        raise BundleError("original-not-repackable", "unreadable") from exc
    notes: list[str] = []
    if any(_is_link(s) for s in tree.skipped):
        notes.append("link-entries-dropped")
    if not all(_is_link(s) for s in tree.skipped):
        raise BundleError("original-not-repackable", "skipped-entries")
    if tree.duplicates:
        raise BundleError("original-not-repackable", "duplicates")
    if tree.anomalies:
        raise BundleError("original-not-repackable", "anomalies")
    tops = {p.split("/", 1)[0] for p in tree.files}
    if len(tops) != 1 or any("/" not in p for p in tree.files):
        raise BundleError("original-not-repackable", "top-level-prefix")
    files = {p.split("/", 1)[1]: b for p, b in tree.files.items()}
    executable = frozenset(p.split("/", 1)[1] for p in tree.files if _executable(tree, p))
    raw = files.get(MANIFEST)
    if raw is None:
        raise BundleError("original-not-repackable", "no-package-json")
    manifest = parse_manifest(raw, notes)
    if manifest is None:
        raise BundleError("original-not-repackable", "package-json-invalid")
    supplied: dict[str, Mapping[str, Any] | None] = {}
    for path in files:
        for folder in _package_folders(path):
            manifest_path = f"{folder}/{MANIFEST}"
            raw_folder_manifest = files.get(manifest_path)
            supplied[folder] = (
                None if raw_folder_manifest is None else parse_manifest(raw_folder_manifest)
            )
    return OriginalPackage(
        files=files,
        executable=executable,
        manifest=manifest,
        sha256=sha256_hex(data),
        supplied=dict(sorted(supplied.items())),
        normalized=tuple(sorted(set(notes))),
    )


# --- fetching -------------------------------------------------------------------------------


@dataclass(frozen=True)
class FetchedDependency:
    tree: ArtifactTree
    sha256: str
    size: int


@dataclass(frozen=True)
class DependencyFetch:
    """Each placed package's tarball by location, and the definite failures."""

    trees: Mapping[str, FetchedDependency]
    failures: Mapping[str, UnresolvedSpec] = field(default_factory=dict)


def _shipped(path: str) -> bool:
    """Whether a dependency's file goes into the bundle (its node_modules/.bin doesn't)."""
    parts = path.split("/")
    return not any(
        parts[i] == "node_modules" and parts[i + 1] == _BIN_DIR for i in range(len(parts) - 1)
    )


_OVER_CAP: Final = {"total": "unpacked-bytes", "files": "files", "compressed": "compressed-bytes"}


def fetch_dependencies(
    resolution: Resolution,
    fetcher: HttpFetcher,
    *,
    caps: BundleCaps = DEFAULT_CAPS,
    original: OriginalPackage | None = None,
) -> DependencyFetch:
    """Fetch and read every placed package's tarball (each tarball once). Each is read with
    what is left of the bundle's caps (the caps minus `original`'s files and the dependencies
    read so far), so no more than one bundle's worth is ever held, and BundleError(over-cap)
    is raised as soon as the compressed, unpacked or file cap is passed. Lets every
    FetchError (transient, replay miss) propagate (decision 0009)."""
    if resolution.cap_exceeded is not None:
        raise BundleError("over-cap", resolution.cap_exceeded)
    by_tarball: dict[tuple[str, str | None, str | None], FetchedDependency | str] = {}
    trees: dict[str, FetchedDependency] = {}
    failures: dict[str, UnresolvedSpec] = {}
    compressed = 0
    unpacked = sum(len(b) for b in original.files.values()) if original is not None else 0
    files = len(original.files) if original is not None else 0
    for package in resolution.packages:
        key = (package.tarball, package.integrity, package.shasum)
        if key not in by_tarball:
            remaining = ExtractLimits(
                max_compressed_bytes=caps.max_compressed_bytes - compressed,
                max_total_bytes=caps.max_unpacked_bytes - unpacked,
                max_file_bytes=caps.max_unpacked_bytes - unpacked,
                max_files=caps.max_files,
            )
            by_tarball[key] = _fetch_one(package, fetcher, remaining)
        got = by_tarball[key]
        if isinstance(got, str):
            first = package.required_by[0] if package.required_by else None
            failures[package.location] = UnresolvedSpec(
                name=package.name,
                spec=first.spec if first else "",
                requirer=first.requirer if first else "",
                type=first.type if first else "prod",
                optional=package.optional,
                reason=got,
                version=package.version,
            )
            continue
        compressed += got.size
        if compressed > caps.max_compressed_bytes:
            raise BundleError("over-cap", "compressed-bytes")
        kept = [data for path, data in got.tree.files.items() if _shipped(path)]
        unpacked += sum(len(data) for data in kept)
        files += len(kept)
        if unpacked > caps.max_unpacked_bytes:
            raise BundleError("over-cap", "unpacked-bytes")
        if files > caps.max_files:
            raise BundleError("over-cap", "files")
        trees[package.location] = got
    return DependencyFetch(trees=trees, failures=failures)


def _fetch_one(
    package: PlacedPackage, fetcher: HttpFetcher, limits: ExtractLimits
) -> FetchedDependency | str:
    """`NpmEcosystem.fetch_artifact`'s checks, keeping the bytes' size and sha256 for the
    record. A string is a definite failure. The tarball is read within `limits`, the bundle's
    remaining budget: past its compressed, unpacked or entry count it is BundleError(over-cap)
    (the unpacked budget covers the tar stream, headers included, and bounds one file too);
    past the compression ratio it is `unreadable`."""
    if not registry_tarball_url(package.tarball):
        return "non-registry-tarball"
    if not (package.integrity or package.shasum):
        return "no-digest"
    response = fetcher.get(package.tarball, immutable=True)
    if not response.ok:
        return "tarball-not-found" if response.status == 404 else "tarball-http-error"
    try:
        verify_integrity(response.body, integrity=package.integrity, shasum=package.shasum)
    except IntegrityError:
        return "integrity-mismatch"
    try:
        tree = extract_tar_gz(response.body, strip_components=1, limits=limits)
    except ArchiveLimitError as exc:
        if exc.limit in _OVER_CAP:
            raise BundleError("over-cap", _OVER_CAP[exc.limit]) from exc
        return "unreadable"
    except ArchiveError:
        return "unreadable"
    return FetchedDependency(tree=tree, sha256=sha256_hex(response.body), size=len(response.body))


# --- building -------------------------------------------------------------------------------


def _detect_style(raw: bytes) -> tuple[str, str, bool]:
    """The original package.json's indent, newline and trailing newline, kept on rewrite
    (as @npmcli/package-json does)."""
    text = raw.decode("utf-8").removeprefix("﻿")
    newline = "\r\n" if "\r\n" in text else "\n"
    match = re.match(r"\{\r?\n([ \t]+)", text)
    indent = match.group(1) if match else "  "
    return indent, newline, text.endswith(("\n", "\r\n"))


def _recordable(value: object) -> bool:
    """Small and shallow enough to record as is in a `PackageJsonChange`."""
    try:
        text = json.dumps(value, allow_nan=False)
    except RecursionError, TypeError, ValueError:
        return False
    if len(text) > _MAX_RECORDED_JSON:
        return False
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > _MAX_RECORDED_DEPTH:
            return False
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    return True


def _with_numbers(value: Any, numbers: list[_Number]) -> Any:
    """`value` with each `_Number` swapped for a placeholder string (`_number_marker`)."""
    if isinstance(value, _Number):
        numbers.append(value)
        return _number_marker(len(numbers) - 1)
    if isinstance(value, dict):
        return {k: _with_numbers(v, numbers) for k, v in value.items()}
    if isinstance(value, list):
        return [_with_numbers(v, numbers) for v in value]
    return value


def _number_marker(index: int) -> str:
    return f"kitsunox-number-{index}"


def _dump_manifest(doc: Mapping[str, Any], indent: str) -> str:
    """`json.dumps` for the rewrite. A number JSON.parse reads as ±Infinity is written back
    as its source text: it is dumped as a placeholder string, then the placeholder's JSON is
    replaced, which must occur exactly once (a package string equal to it refuses the
    rewrite with ValueError)."""

    def dumps(value: Any) -> str:
        return json.dumps(
            value, indent=indent, ensure_ascii=False, separators=(",", ": "), allow_nan=False
        )

    try:
        return dumps(doc)
    except ValueError:
        pass  # a non-finite number: write its text back
    numbers: list[_Number] = []
    text = dumps(_with_numbers(doc, numbers))
    for index, number in enumerate(numbers):
        placeholder = json.dumps(_number_marker(index), ensure_ascii=False)
        if text.count(placeholder) != 1:
            raise ValueError("number placeholder collides with package text")
        text = text.replace(placeholder, number.text)
    return text


def rewrite_manifest(
    raw: bytes, manifest: Mapping[str, Any], resolution: Resolution
) -> tuple[bytes, tuple[PackageJsonChange, ...]]:
    """The package.json with only the design's changes: an explicit sorted
    `bundleDependencies`, and each required peer not already a dependency copied into
    `dependencies` with its original spec. Key order is kept; a new key goes last. The
    original `bundleDependencies` is recorded as is when small, else by its sha256."""
    doc = dict(manifest)
    changes: list[PackageJsonChange] = []
    for name, spec in resolution.peers_copied:
        deps = doc.get("dependencies")
        if deps is not None and not isinstance(deps, dict):
            raise BundleError("original-not-repackable", "dependencies-not-object")
        updated = dict(deps or {})
        updated[name] = spec
        doc["dependencies"] = updated
        changes.append(PackageJsonChange(field=f"dependencies.{name}", before=None, after=spec))
    before = doc.get("bundleDependencies")
    after = list(resolution.bundle_names)
    if before != after:
        doc["bundleDependencies"] = after
        original = before if "bundleDependencies" in manifest else None
        recordable = _recordable(original)
        changes.append(
            PackageJsonChange(
                field="bundleDependencies",
                before=original if recordable else None,
                after=after,
                before_sha256=None if recordable else _digest(original),
            )
        )
    indent, newline, trailing = _detect_style(raw)
    try:
        text = _dump_manifest(doc, indent)
    except RecursionError, ValueError:
        raise BundleError("original-not-repackable", "package-json-invalid") from None
    text = text.replace("\n", newline) + (newline if trailing else "")
    try:
        return text.encode("utf-8"), tuple(changes)
    except UnicodeEncodeError as exc:  # a lone surrogate from a \ud800 escape
        raise BundleError("original-not-repackable", "package-json-invalid") from exc


def write_tar_gz(entries: Mapping[str, tuple[bytes, bool]]) -> tuple[bytes, bytes]:
    """A deterministic npm-pack-shaped tarball: regular files only, sorted by the UTF-8 bytes
    of the path, PAX format, npm pack's fixed mtime, uid/gid 0, empty user and group names,
    mode 0755 for executables and 0644 otherwise; gzip level 9 with mtime 0 and no file name.
    Returns (tar, tgz)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(entries, key=lambda p: p.encode("utf-8")):
            data, executable = entries[path]
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mtime = NPM_PACK_MTIME
            info.mode = 0o755 if executable else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))
    tar_bytes = raw.getvalue()
    out = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=out, compresslevel=GZIP_LEVEL, mtime=0
    ) as gz:
        gz.write(tar_bytes)
    return tar_bytes, out.getvalue()


def _network_reason(
    files: Mapping[str, bytes], manifest: Mapping[str, Any] | None, package_name: str | None
) -> Literal["node-gyp", "install-tool", "known-downloader"] | None:
    if manifest is None:
        return None
    hooks = manifest_hooks(dict(manifest), GYP_FILE in files)
    scripts = _strings(manifest.get("scripts"))
    declared = {h for h in ("preinstall", "install") if isinstance(scripts.get(h), str)}
    if "install" in hooks and GYP_FILE in files and not declared:
        return "node-gyp"
    for hook in hooks:
        command = scripts.get(hook)
        if isinstance(command, str) and _NETWORK_TOOLS.search(command):
            return "install-tool"
    if package_name in _KNOWN_DOWNLOADERS and any(isinstance(scripts.get(h), str) for h in hooks):
        return "known-downloader"
    return None


def _dependency_files(
    package: PlacedPackage, tree: ArtifactTree
) -> tuple[dict[str, bytes], set[str], list[str], dict[str, Any] | None]:
    """A dependency's files (minus node_modules/.bin), its executables, anomalies, and its
    tarball's own package.json."""
    anomalies = [f"skipped-entry:{s.reason.split(' ', 1)[0]}" for s in tree.skipped]
    anomalies += ["duplicate-entries"] * bool(tree.duplicates) + list(
        "archive-anomaly" for _ in tree.anomalies
    )
    files: dict[str, bytes] = {}
    executable: set[str] = set()
    for path in tree.files:
        if not _shipped(path):
            anomalies.append("bin-dir-dropped")
            continue
        files[path] = tree.files[path]
        if _executable(tree, path):
            executable.add(path)
    raw = files.get(MANIFEST)
    manifest = parse_manifest(raw, anomalies) if raw is not None else None
    if manifest is None:
        anomalies.append("package-json-unreadable")
    else:
        if manifest.get("name") != package.package_name:
            anomalies.append("package-json-name-differs")
        if manifest.get("version") != package.version:
            anomalies.append("package-json-version-differs")
        for key in _COMPARED_FIELDS:
            registry = package.manifest_digests.get(key)
            local = _digest(manifest[key]) if key in manifest else None
            if registry != local:
                anomalies.append(f"manifest-differs:{key}")
    if _SHRINKWRAP in files:
        anomalies.append("npm-shrinkwrap")
    return files, executable, sorted(set(anomalies)), manifest


_SHRINKWRAP: Final = "npm-shrinkwrap.json"


def _path_clashes(paths: Iterable[str]) -> set[str]:
    """Entries that can't be written as they are: a file that is also another entry's
    directory (`node_modules/a` and `node_modules/a/index.js`), or a file where a package
    folder goes (`node_modules/a`), which npm would read as a package."""
    entries = set(paths)
    directories = {p[:i] for p in entries for i, c in enumerate(p) if c == "/"}
    return {p for p in entries if p in directories or _is_package_folder(p)}


def build_bundle(
    original_tarball: bytes,
    resolution: Resolution,
    fetched: DependencyFetch,
    *,
    caps: BundleCaps = DEFAULT_CAPS,
) -> tuple[bytes, BundleRecord]:
    """Build the bundle `.tgz` and its record. Raises BundleError when the version must be
    exported unbundled (nothing to bundle, an original that can't be repacked, a cap, a
    resolution for another package.json, a failed self-check)."""
    if resolution.cap_exceeded is not None:
        raise BundleError("over-cap", resolution.cap_exceeded)
    if not resolution.needs_bundle:
        raise BundleError("nothing-to-bundle", "no-dependencies")
    original = read_original(original_tarball, limits=caps.extract_limits())
    if _digest(original.manifest) != resolution.manifest_digest:
        raise BundleError("resolution-mismatch", "package-json")
    raw_manifest = original.files[MANIFEST]
    rewritten, changes = rewrite_manifest(raw_manifest, original.manifest, resolution)

    entries: dict[str, tuple[bytes, bool]] = {}
    origins: dict[str, str] = {}
    for path, data in original.files.items():
        entries[path] = (rewritten if path == MANIFEST else data, path in original.executable)
        origins[path] = "package"
    reasons = set(resolution.incomplete_reasons)
    unresolved = list(resolution.unresolved)
    added: list[AddedPackage] = []
    predicted: list[PredictedNetwork] = []
    failed = set(fetched.failures)
    if fetched.failures:
        unresolved.extend(fetched.failures.values())
        reasons.add("fetch-failed")

    reason = _network_reason(original.files, original.manifest, resolution.package)
    if reason is not None:
        predicted.append(
            PredictedNetwork(location="", package_name=resolution.package, reason=reason)
        )
    for package in resolution.packages:
        if package.location in failed or any(package.location.startswith(f"{f}/") for f in failed):
            continue
        got = fetched.trees.get(package.location)
        if got is None:  # not fetched at all: as good as a failed fetch
            reasons.add("fetch-failed")
            failed.add(package.location)
            continue
        files, executable, anomalies, manifest = _dependency_files(package, got.tree)
        if manifest is None or not all(
            isinstance(manifest.get(k), str) and manifest.get(k) for k in ("name", "version")
        ):
            reasons.add("dependency-package-json")
        if "npm-shrinkwrap" in anomalies:
            reasons.add("dependency-shrinkwrap")
        for bundled in package.bundles:
            # npm records a bundled dependency the tarball doesn't ship and carries on
            # (`reify.js#L987-L1006`): an anomaly, not an incomplete bundle
            if f"node_modules/{bundled}/{MANIFEST}" not in files:
                anomalies = sorted({*anomalies, "bundled-dependency-missing"})
        for path, data in files.items():
            target = f"{package.location}/{path}"
            if target in entries:
                anomalies = sorted({*anomalies, "path-collision"})
                reasons.add("path-collision")
                continue
            entries[target] = (data, path in executable)
            origins[target] = package.location
        reason = _network_reason(files, manifest, package.package_name)
        if reason is not None:
            predicted.append(
                PredictedNetwork(
                    location=package.location, package_name=package.package_name, reason=reason
                )
            )
        added.append(
            AddedPackage(
                location=package.location,
                name=package.name,
                package_name=package.package_name,
                version=package.version,
                integrity=package.integrity,
                tarball_sha256=got.sha256,
                tarball_bytes=got.size,
                files=len(files),
                unpacked_bytes=sum(len(b) for b in files.values()),
                required_by=package.required_by,
                optional=package.optional,
                engines_ok=package.engines_ok,
                hooks=manifest_hooks(manifest, GYP_FILE in files) if manifest else (),
                binding_gyp=GYP_FILE in files,
                anomalies=tuple(anomalies),
            )
        )

    clashes = _path_clashes(entries)
    if clashes:
        reasons.add("path-collision")
        owners = {origins[p] for p in entries if p in clashes or _under(p, clashes)}
        added = [
            a.model_copy(update={"anomalies": tuple(sorted({*a.anomalies, "path-collision"}))})
            if a.location in owners
            else a
            for a in added
        ]
    _check_entries(entries, caps)
    tar_bytes, tgz = write_tar_gz({f"{PREFIX}/{p}": e for p, e in entries.items()})
    if len(tgz) > caps.max_compressed_bytes:
        raise BundleError("over-cap", "compressed-bytes")
    _self_check(tgz, entries, caps)
    record = BundleRecord(
        package=resolution.package,
        version=resolution.version,
        status="incomplete" if reasons else "complete",
        incomplete_reasons=tuple(sorted(reasons)),
        assumes=dict(resolution.assumes),
        as_of=resolution.as_of,
        original_sha256=original.sha256,
        bundle_sha256=sha256_hex(tgz),
        tar_sha256=sha256_hex(tar_bytes),
        bundle_bytes=len(tgz),
        package_json=PackageJsonRecord(
            original_sha256=sha256_hex(raw_manifest),
            rewritten_sha256=sha256_hex(rewritten),
            changes=changes,
        ),
        added=tuple(added),
        supplied_by_package=resolution.supplied,
        skipped=resolution.skipped,
        unresolved=tuple(sorted(set(unresolved), key=_sort_key)),
        peer_conflicts=resolution.peer_conflicts,
        post_check=resolution.post_check,
        predicted_network=tuple(predicted),
        normalized=original.normalized,
        files=dict(sorted(origins.items(), key=lambda kv: kv[0].encode("utf-8"))),
    )
    return tgz, record


def _under(path: str, directories: set[str]) -> bool:
    return any(path.startswith(f"{d}/") for d in _parents(path) if d in directories)


def _parents(path: str) -> list[str]:
    return [path[:i] for i, c in enumerate(path) if c == "/"]


def _check_entries(entries: Mapping[str, tuple[bytes, bool]], caps: BundleCaps) -> None:
    if len(entries) > caps.max_files:
        raise BundleError("over-cap", "files")
    if sum(len(data) for data, _ in entries.values()) > caps.max_unpacked_bytes:
        raise BundleError("over-cap", "unpacked-bytes")
    for path in entries:
        full = f"{PREFIX}/{path}"
        if len(full.encode()) > caps.max_path_bytes or any(
            len(part.encode()) > caps.max_component_bytes for part in full.split("/")
        ):
            raise BundleError("over-cap", "path-length")


def _self_check(tgz: bytes, entries: Mapping[str, tuple[bytes, bool]], caps: BundleCaps) -> None:
    """Read the written bundle back with `extract_tar_gz` and the export's limits: the same
    files, the same bytes, the same execute bits, nothing skipped, no anomalies, and a
    package.json that JSON.parse reads as written (no BOM, no repeated keys)."""
    try:
        tree = extract_tar_gz(tgz, strip_components=1, limits=caps.extract_limits())
    except ArchiveError as exc:
        raise BundleError("self-check-failed", "unreadable") from exc
    if tree.skipped or tree.duplicates or tree.anomalies:
        raise BundleError("self-check-failed", "entries")
    if dict(tree.files) != {p: data for p, (data, _) in entries.items()}:
        raise BundleError("self-check-failed", "contents")
    for path, (_, executable) in entries.items():
        if _executable(tree, path) != executable:
            raise BundleError("self-check-failed", "modes")
    notes: list[str] = []
    if MANIFEST in tree.files and (parse_manifest(tree.files[MANIFEST], notes) is None or notes):
        raise BundleError("self-check-failed", "package-json")


def make_bundle(
    original_tarball: bytes,
    *,
    packuments: PackumentSource,
    fetcher: HttpFetcher,
    as_of: datetime,
    platform: Platform = LINUX_X64_GLIBC,
    caps: BundleCaps = DEFAULT_CAPS,
) -> BuiltBundle:
    """Read, resolve, fetch and build in one call, for the export. Raises BundleError for an
    unbundled export (`reason` is `unbundled_reason`; `nothing-to-bundle` means export the
    original unchanged under its own key) and FetchError to leave the job pending."""
    original = read_original(original_tarball, limits=caps.extract_limits())
    resolution = resolve(
        original.manifest,
        packuments=packuments,
        as_of=as_of,
        platform=platform,
        caps=caps,
        supplied=original.supplied,
    )
    if not resolution.needs_bundle:
        raise BundleError("nothing-to-bundle", "no-dependencies")
    fetched = fetch_dependencies(resolution, fetcher, caps=caps, original=original)
    data, record = build_bundle(original_tarball, resolution, fetched, caps=caps)
    return BuiltBundle(data, record)
