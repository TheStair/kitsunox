"""Tier 0 orchestration.   [USER-OWNED body — Claude provides the wiring skeleton]

``run_tier0`` ties together: resolve previous version -> diff tarballs -> run
``iocs`` + ``patterns`` + ``heuristics`` -> dedupe -> persist -> set event status.

Claude has wired the happy path and the helpers (``resolve_prev_version``,
``dedupe_findings``, ``persist_findings``). What's left for the USER:
  - the severity/þreshold policy that decides ``clean`` vs ``flagged``
  - how aggressively to resolve ``prev_version`` (nearest chronological? highest stable?)
  - whether an IOC-only hit should short-circuit the (expensive) tarball diff
  - dependency extraction nuance (optionalDependencies, workspace specs, ...)

Until ``patterns.scan`` / ``heuristics.check`` are implemented they raise
``NotImplementedError``; this skeleton catches that and records a partial scan so the
IOC path (and the event-stream evaluation gate) still works.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import structlog

from kitsunox.analysis import tarball
from kitsunox.analysis.tier0 import heuristics, patterns
from kitsunox.analysis.tier0.iocs import IOCChecker
from kitsunox.ingest.registry_client import RegistryClient, RegistryError, TarballUnavailable
from kitsunox.ir import Finding, PublishEvent, Severity, VersionMeta

log = structlog.get_logger(__name__)

_FLAGGING_SEVERITIES = {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


@dataclass
class Tier0Result:
    event: PublishEvent
    findings: list[Finding] = field(default_factory=list)
    status: str = "pending"  # clean | flagged | error
    tarball_available: bool = True
    partial: bool = False  # a sub-scanner was not implemented / errored
    notes: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.status == "flagged"


def resolve_prev_version(
    name: str, cur_version: str, *, client: RegistryClient, packument: dict | None = None
) -> str | None:
    """Nearest chronological predecessor of ``cur_version`` from the packument timeline."""
    timeline = client.version_timeline(name, packument=packument)
    ordered = [v for v, _ in timeline]
    if cur_version not in ordered:
        return ordered[-1] if ordered else None
    idx = ordered.index(cur_version)
    return ordered[idx - 1] if idx > 0 else None


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple, Finding] = {}
    for f in findings:
        cur = seen.get(f.key())
        if cur is None or _severity_rank(f.severity) > _severity_rank(cur.severity):
            seen[f.key()] = f
    return sorted(seen.values(), key=lambda f: (-_severity_rank(f.severity), f.rule_id))


def _severity_rank(sev: Severity) -> int:
    return list(Severity).index(sev)


def persist_findings(repo, event_id: int, findings: list[Finding], status: str) -> None:
    repo.add_findings(event_id, findings)
    repo.set_event_tier0(event_id, status)


def run_tier0(
    event: PublishEvent,
    *,
    client: RegistryClient,
    ioc_checker: IOCChecker | None = None,
    workdir: Path | None = None,
    packument: dict | None = None,
) -> Tier0Result:
    result = Tier0Result(event=event)
    name = event.ref.name
    version = event.version
    ioc_checker = ioc_checker or IOCChecker(settings=client.settings)

    if version is None:  # whole-package delete — nothing to diff
        result.status = "clean"
        result.notes.append("no version (delete event)")
        return result

    packument = packument or _safe_packument(client, name)
    prev_version = event.prev_version or (
        resolve_prev_version(name, version, client=client, packument=packument)
        if packument
        else None
    )
    event.prev_version = prev_version

    cur_meta: VersionMeta | None = None
    file_diffs = []
    owns_tmp = workdir is None
    tmp_root = workdir or Path(tempfile.mkdtemp(prefix="kitsunox-t0-"))
    try:
        try:
            file_diffs, cur_unpacked, _prev_unpacked = tarball.diff_versions(
                name, prev_version, version, client=client, workdir=tmp_root
            )
            cur_meta = _safe_version_meta(client, name, version, packument)
        except (TarballUnavailable, RegistryError) as exc:
            result.tarball_available = False
            result.notes.append(f"tarball unavailable: {exc}")
            cur_meta = _safe_version_meta(client, name, version, packument)

        deps = dict(cur_meta.dependencies) if cur_meta else {}

        all_findings: list[Finding] = []
        all_findings += ioc_checker.check(name, version, dependencies=deps)

        if cur_meta is not None and file_diffs:
            prev_meta = (
                _safe_version_meta(client, name, prev_version, packument) if prev_version else None
            )
            for label, fn in (
                ("patterns", lambda: patterns.scan(file_diffs, cur_meta)),
                ("heuristics", lambda: heuristics.check(file_diffs, prev_meta, cur_meta)),
            ):
                try:
                    all_findings += fn()
                except NotImplementedError:
                    result.partial = True
                    result.notes.append(f"{label} not implemented")
                except Exception as exc:  # noqa: BLE001 - a buggy rule shouldn't kill the scan
                    result.partial = True
                    result.notes.append(f"{label} errored: {exc}")
                    log.warning("tier0 sub-scanner error", scanner=label, error=str(exc))

        result.findings = dedupe_findings(all_findings)
        result.status = _decide_status(result)
        return result
    finally:
        if owns_tmp:
            shutil.rmtree(tmp_root, ignore_errors=True)


def _decide_status(result: Tier0Result) -> str:
    # USER: refine this policy (e.g. feed severity into a Tier 1 score instead of a
    # hard flag; decide how LOW/INFO findings surface).
    if any(f.severity in _FLAGGING_SEVERITIES for f in result.findings):
        return "flagged"
    if not result.tarball_available and result.partial and not result.findings:
        return "error"
    return "clean"


def _safe_packument(client: RegistryClient, name: str) -> dict | None:
    try:
        return client.packument(name)
    except Exception as exc:  # noqa: BLE001
        log.warning("packument fetch failed", name=name, error=str(exc))
        return None


def _safe_version_meta(
    client: RegistryClient, name: str, version: str | None, packument: dict | None
) -> VersionMeta | None:
    if version is None:
        return None
    try:
        return client.version_meta(name, version, packument=packument)
    except Exception as exc:  # noqa: BLE001
        log.warning("version_meta failed", name=name, version=version, error=str(exc))
        return None
