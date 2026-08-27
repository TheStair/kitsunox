"""HTTP client for the npm registry and adjacent metadata services.

Endpoints (all verified 2026-08):
- packument (full):   GET  {registry}/{name}
- packument (abbrev): GET  {registry}/{name}   Accept: application/vnd.npm.install-v1+json
- tarball:            GET  {dist.tarball}       (absolute URL from the packument)
- weekly downloads:   GET  {downloads}/downloads/point/last-week/{name}
- dependents + times: GET  {deps_dev}/v3/systems/npm/packages/{name}

``include_docs`` on the ``_changes`` feed was removed in the May 2025 replication-API
migration, so version metadata must be fetched here, separately from the feed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from kitsunox.config import Settings, get_settings
from kitsunox.ir import Ecosystem, PackageRef, VersionMeta

log = structlog.get_logger(__name__)

ABBREVIATED_ACCEPT = "application/vnd.npm.install-v1+json"
_INSTALL_SCRIPT_KEYS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


class RegistryError(RuntimeError):
    """Non-retryable registry problem (404, malformed payload, ...)."""


class TarballUnavailable(RegistryError):
    """The version has no downloadable tarball — typically an unpublished malicious version.

    Backfill treats these as 'could not evaluate' rather than a hit or a miss.
    """


class PackageNotFound(RegistryError):
    pass


def _retryable():
    return retry(
        retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        stop=stop_after_attempt(5),
        reraise=True,
    )


@dataclass
class DepsDevVersion:
    version: str
    published_at: datetime | None
    is_default: bool = False
    is_deprecated: bool = False


@dataclass
class DepsDevInfo:
    dependents_count: int | None
    versions: list[DepsDevVersion] = field(default_factory=list)

    def published_at(self, version: str) -> datetime | None:
        for v in self.versions:
            if v.version == version:
                return v.published_at
        return None


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


class RegistryClient:
    def __init__(self, settings: Settings | None = None, client: httpx.Client | None = None):
        self.settings = settings or get_settings()
        self.settings.ensure_dirs()
        self._client = client or httpx.Client(
            timeout=self.settings.http_timeout_seconds,
            headers={"User-Agent": self.settings.user_agent},
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> RegistryClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --------------------------------------------------------------- packument
    @_retryable()
    def _get_json(self, url: str, *, headers: dict | None = None) -> dict:
        resp = self._client.get(url, headers=headers)
        if resp.status_code == 404:
            raise PackageNotFound(url)
        resp.raise_for_status()
        return resp.json()

    def packument(self, name: str, *, abbreviated: bool = False) -> dict:
        url = f"{self.settings.registry_base_url}/{_registry_path(name)}"
        headers = {"Accept": ABBREVIATED_ACCEPT} if abbreviated else None
        return self._get_json(url, headers=headers)

    def version_meta(
        self, name: str, version: str, *, packument: dict | None = None
    ) -> VersionMeta:
        doc = packument or self.packument(name)
        versions = doc.get("versions", {})
        v = versions.get(version)
        if v is None:
            raise RegistryError(f"{name}@{version} not present in packument")

        times = doc.get("time", {}) or {}
        dist = v.get("dist", {}) or {}
        npm_user = v.get("_npmUser", {}) or {}
        scripts = v.get("scripts", {}) or {}

        return VersionMeta(
            ref=PackageRef(ecosystem=Ecosystem.NPM, name=name),
            version=version,
            published_at=_parse_ts(times.get(version)),
            publisher=npm_user.get("name"),
            maintainers=[m.get("name", "") for m in (v.get("maintainers") or []) if m.get("name")],
            dependencies=dict(v.get("dependencies", {}) or {}),
            install_scripts={k: scripts[k] for k in _INSTALL_SCRIPT_KEYS if k in scripts},
            dist_tarball_url=dist.get("tarball"),
            dist_shasum=dist.get("shasum"),
            dist_integrity=dist.get("integrity"),
            unpacked_size=dist.get("unpackedSize"),
        )

    def version_timeline(
        self, name: str, *, packument: dict | None = None
    ) -> list[tuple[str, datetime | None]]:
        """(version, published_at) pairs in chronological order, from packument ``time``."""
        doc = packument or self.packument(name)
        times = doc.get("time", {}) or {}
        versions = [k for k in doc.get("versions", {})]
        pairs = [(ver, _parse_ts(times.get(ver))) for ver in versions]
        pairs.sort(key=lambda p: (p[1] is None, p[1] or datetime.min))
        return pairs

    # ----------------------------------------------------------------- tarball
    def download_tarball(self, name: str, version: str, *, tarball_url: str | None = None) -> Path:
        if tarball_url is None:
            try:
                meta = self.version_meta(name, version)
            except RegistryError as exc:
                # version entry absent from the packument — typically an unpublished
                # malicious version (e.g. event-stream@3.3.6).
                raise TarballUnavailable(f"{name}@{version}: {exc}") from exc
            tarball_url = meta.dist_tarball_url
        if not tarball_url:
            raise TarballUnavailable(f"{name}@{version} has no dist.tarball")

        cache_key = hashlib.sha256(f"{name}@{version}".encode()).hexdigest()[:16]
        safe = name.replace("/", "__").replace("@", "")
        dest = self.settings.tarball_cache_dir / f"{safe}-{version}-{cache_key}.tgz"
        if dest.exists() and dest.stat().st_size > 0:
            return dest

        try:
            resp = self._client.get(tarball_url)
            if resp.status_code == 404:
                raise TarballUnavailable(f"{name}@{version} tarball 404 ({tarball_url})")
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:  # noqa: BLE001
            raise TarballUnavailable(f"{name}@{version}: {exc}") from exc

        tmp = dest.with_suffix(".tmp")
        tmp.write_bytes(resp.content)
        tmp.replace(dest)
        return dest

    # --------------------------------------------------------------- downloads
    def weekly_downloads(self, name: str) -> int | None:
        url = f"{self.settings.downloads_base_url}/downloads/point/last-week/{_registry_path(name)}"
        try:
            data = self._get_json(url)
        except PackageNotFound:
            return None
        value = data.get("downloads")
        return int(value) if isinstance(value, int) else None

    # ----------------------------------------------------------------- deps.dev
    def deps_dev(self, name: str) -> DepsDevInfo:
        enc = quote(name, safe="")
        base = f"{self.settings.deps_dev_base_url}/v3/systems/npm/packages/{enc}"
        try:
            data = self._get_json(base)
        except PackageNotFound:
            return DepsDevInfo(dependents_count=None)

        versions = [
            DepsDevVersion(
                version=v["versionKey"]["version"],
                published_at=_parse_ts(v.get("publishedAt")),
                is_default=v.get("isDefault", False),
                is_deprecated=v.get("isDeprecated", False),
            )
            for v in data.get("versions", [])
            if v.get("versionKey", {}).get("version")
        ]

        dependents = None
        default_v = next((v.version for v in versions if v.is_default), None)
        if default_v:
            try:
                dep_data = self._get_json(f"{base}/versions/{quote(default_v, safe='')}:dependents")
                dependents = dep_data.get("dependentCount")
            except (PackageNotFound, RegistryError):
                dependents = None

        return DepsDevInfo(dependents_count=dependents, versions=versions)


def _registry_path(name: str) -> str:
    """npm registry accepts an unencoded slash in scoped names for GET packument, but
    encode everything else defensively."""
    if name.startswith("@") and "/" in name:
        scope, pkg = name.split("/", 1)
        return f"{scope}/{quote(pkg, safe='')}"
    return quote(name, safe="")
