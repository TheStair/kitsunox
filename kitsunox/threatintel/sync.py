"""Refresh and read the local threat-intel mirror of known-malicious npm packages.

Two sources, both streamed straight into one compact ``index.json`` (no exploded
per-advisory files — the combined corpus is ~450k records):

- **OSV npm export** — ``https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip``
  (all npm advisories; we keep only the malware ones — ``MAL-*`` ids or the CWE-506
  "embedded malicious code" family).
- **OpenSSF Malicious Packages** — ``github.com/ossf/malicious-packages``, pulled as a
  GitHub tarball (not ``git clone``: the repo has paths invalid on Windows, e.g.
  ``osv/malicious/vscode:open-vsx.org/...``). We read only ``osv/malicious/npm/**/*.json``.

Everything is optional: with no network and no prior ``index.json``, ``load_index``
returns an empty index and callers fall back to a live OSV query.
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from dataclasses import dataclass, field

import httpx
import structlog

from kitsunox.config import Settings, get_settings

log = structlog.get_logger(__name__)

OSV_NPM_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
MALICIOUS_PACKAGES_TARBALL = "https://codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main"

# CWE family for planted/embedded malicious code — the reliable "this is malware" signal
# on GitHub-reviewed advisories that carry no explicit malware flag.
_MALWARE_CWES = {"CWE-506", "CWE-507", "CWE-509", "CWE-510", "CWE-511", "CWE-912"}


@dataclass
class LabelHit:
    package_name: str
    versions: list[str]  # affected versions; empty => whole package / range unresolved
    advisory_id: str
    source: str  # "osv" | "openssf"
    summary: str = ""
    is_malware: bool = True  # False => ordinary vuln advisory, not a malicious-package report

    def matches_version(self, version: str | None) -> bool:
        if version is None or not self.versions:
            return True
        return version in self.versions


# ---------------------------------------------------------------- OSV doc parsing
def _npm_affected(osv_doc: dict) -> list[tuple[str, list[str]]]:
    """[(package_name, affected_versions)] for npm entries in an OSV document."""
    out: list[tuple[str, list[str]]] = []
    for aff in osv_doc.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").lower() != "npm" or not pkg.get("name"):
            continue
        out.append((pkg["name"], sorted(set(aff.get("versions", []) or []))))
    return out


def _is_malware_advisory(osv_doc: dict) -> bool:
    if str(osv_doc.get("id", "")).startswith("MAL-"):
        return True
    ds = osv_doc.get("database_specific", {}) or {}
    if ds.get("type") == "malware" or "malicious" in json.dumps(ds).lower():
        return True
    return bool(set(ds.get("cwe_ids", []) or []) & _MALWARE_CWES)


def _hits_from_doc(osv_doc: dict, source: str, *, malware_only: bool):
    is_mal = _is_malware_advisory(osv_doc)
    if malware_only and not is_mal:
        return
    advisory_id = osv_doc.get("id", "")
    summary = (osv_doc.get("summary") or "")[:200]
    for name, versions in _npm_affected(osv_doc):
        yield LabelHit(
            package_name=name,
            versions=versions,
            advisory_id=advisory_id,
            source=source,
            summary=summary,
            is_malware=True if malware_only else is_mal,
        )


# ------------------------------------------------------------------------- index
@dataclass
class MaliciousIndex:
    """In-memory index of known-malicious npm packages."""

    by_package: dict[str, list[LabelHit]] = field(default_factory=dict)

    def is_known_malicious(self, package_name: str) -> bool:
        return package_name in self.by_package

    def lookup(self, package_name: str, version: str | None = None) -> list[LabelHit]:
        hits = self.by_package.get(package_name, [])
        if version is None:
            return list(hits)
        return [h for h in hits if h.matches_version(version)]

    def add(self, hit: LabelHit) -> None:
        self.by_package.setdefault(hit.package_name, []).append(hit)

    def __len__(self) -> int:
        return sum(len(v) for v in self.by_package.values())

    # ---- serialization (compact index.json) ----
    def to_payload(self) -> dict:
        return {
            pkg: [
                {"v": h.versions, "id": h.advisory_id, "src": h.source, "mal": h.is_malware, "s": h.summary}
                for h in hits
            ]
            for pkg, hits in self.by_package.items()
        }

    @classmethod
    def from_payload(cls, payload: dict) -> MaliciousIndex:
        idx = cls()
        for pkg, hits in payload.items():
            for h in hits:
                idx.add(
                    LabelHit(
                        package_name=pkg,
                        versions=h.get("v", []),
                        advisory_id=h.get("id", ""),
                        source=h.get("src", "osv"),
                        summary=h.get("s", ""),
                        is_malware=h.get("mal", True),
                    )
                )
        return idx


def _index_path(settings: Settings):
    return settings.intel_mirror_dir / "index.json"


# ------------------------------------------------------------------------- sync
def _download(url: str, settings: Settings, *, min_timeout: float = 0.0) -> bytes | None:
    try:
        resp = httpx.get(
            url,
            timeout=max(settings.http_timeout_seconds, min_timeout),
            follow_redirects=True,
        )
        resp.raise_for_status()
        return resp.content
    except httpx.HTTPError as exc:  # noqa: BLE001
        log.warning("threat-intel download failed", url=url, error=str(exc))
        return None


def _ingest_osv_export(raw: bytes, index: MaliciousIndex) -> int:
    seen = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for member in zf.namelist():
            if not member.endswith(".json"):
                continue
            try:
                doc = json.loads(zf.read(member))
            except (json.JSONDecodeError, KeyError):
                continue
            for hit in _hits_from_doc(doc, source="osv", malware_only=True):
                index.add(hit)
                seen += 1
    return seen


def _ingest_malicious_packages(raw: bytes, index: MaliciousIndex) -> int:
    seen = 0
    marker = "/osv/malicious/npm/"
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        for member in tf:
            if not member.isfile() or marker not in member.name or not member.name.endswith(".json"):
                continue
            fobj = tf.extractfile(member)
            if fobj is None:
                continue
            try:
                doc = json.loads(fobj.read())
            except json.JSONDecodeError:
                continue
            for hit in _hits_from_doc(doc, source="openssf", malware_only=False):
                index.add(hit)
                seen += 1
    return seen


def sync_all(settings: Settings | None = None) -> dict[str, int]:
    """Rebuild ``index.json`` from both upstream sources. Returns per-source hit counts."""
    settings = settings or get_settings()
    settings.ensure_dirs()
    index = MaliciousIndex()

    result = {"osv_npm": 0, "openssf": 0}

    osv_raw = _download(OSV_NPM_EXPORT_URL, settings, min_timeout=120.0)
    if osv_raw:
        result["osv_npm"] = _ingest_osv_export(osv_raw, index)

    mp_raw = _download(MALICIOUS_PACKAGES_TARBALL, settings, min_timeout=180.0)
    if mp_raw:
        result["openssf"] = _ingest_malicious_packages(mp_raw, index)

    if index.by_package:
        _index_path(settings).write_text(json.dumps(index.to_payload()), encoding="utf-8")
        log.info(
            "threat-intel index rebuilt",
            packages=len(index.by_package),
            hits=len(index),
            **result,
        )
    else:
        log.warning("threat-intel sync produced no records; keeping any existing index.json")

    result["packages"] = len(index.by_package)
    return result


def load_index(settings: Settings | None = None) -> MaliciousIndex:
    settings = settings or get_settings()
    path = _index_path(settings)
    if not path.exists():
        log.warning("no threat-intel index.json — run `kitsunox intel-sync`")
        return MaliciousIndex()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:  # noqa: BLE001
        log.warning("threat-intel index.json unreadable", error=str(exc))
        return MaliciousIndex()
    index = MaliciousIndex.from_payload(payload)
    log.info("threat-intel index loaded", hits=len(index), packages=len(index.by_package))
    return index


def osv_query_live(
    package_name: str, version: str | None = None, *, settings: Settings | None = None
) -> list[LabelHit]:
    """Live OSV.dev query — fallback when the mirror is stale or missing a package."""
    settings = settings or get_settings()
    body: dict = {"package": {"ecosystem": "npm", "name": package_name}}
    if version:
        body["version"] = version
    try:
        resp = httpx.post(settings.osv_query_url, json=body, timeout=settings.http_timeout_seconds)
        resp.raise_for_status()
    except httpx.HTTPError as exc:  # noqa: BLE001
        log.warning("osv live query failed", package=package_name, error=str(exc))
        return []

    hits: list[LabelHit] = []
    for vuln in resp.json().get("vulns", []):
        is_mal = _is_malware_advisory(vuln)
        versions: list[str] = []
        for name, vers in _npm_affected(vuln):
            if name == package_name:
                versions = vers
        hits.append(
            LabelHit(
                package_name=package_name,
                versions=versions,
                advisory_id=vuln.get("id", ""),
                source="osv",
                summary=(vuln.get("summary") or "")[:200],
                is_malware=is_mal,
            )
        )
    return hits
