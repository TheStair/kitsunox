"""Glue: one ``_changes`` row -> pre-score -> (routed) Tier 0 -> persist.

This module owns orchestration and baseline bookkeeping. ``ingest.prescore.route`` is
consulted for the routing decision; until it's implemented, ``_fallback_route`` keeps the
listener working end-to-end (new packages, version bumps, and unpublishes go to TIER01;
everything else is ignored).
"""

from __future__ import annotations

import structlog

from kitsunox.analysis.scanner import run_tier0
from kitsunox.db.repo import Repository, open_repo
from kitsunox.ingest.changes_feed import ChangeRow
from kitsunox.ingest.registry_client import PackageNotFound, RegistryClient, RegistryError
from kitsunox.ir import Ecosystem, PackageRef, PublishEvent, Route

log = structlog.get_logger(__name__)


def _fallback_route(row: ChangeRow, baseline_known: bool) -> tuple[Route, list[str]]:
    reasons: list[str] = []
    if row.deleted:
        return Route.TIER01, ["unpublish/delete event"]
    if row.looks_new_package or not baseline_known:
        reasons.append("new or previously-unseen package")
    reasons.append("fallback router (prescore.route not implemented)")
    return (Route.TIER01 if reasons else Route.IGNORE), reasons


def _resolve_versions(
    client: RegistryClient, name: str, baseline_last_version: str | None
) -> tuple[str | None, str | None, dict | None]:
    """Best-effort (current_version, prev_version, packument) from registry metadata."""
    try:
        doc = client.packument(name)
    except (PackageNotFound, RegistryError):
        return None, None, None
    latest = (doc.get("dist-tags") or {}).get("latest")
    timeline = [v for v, _ in _sorted_versions(doc)]
    prev = None
    if latest and latest in timeline:
        idx = timeline.index(latest)
        prev = timeline[idx - 1] if idx > 0 else None
    prev = prev or baseline_last_version
    return latest, prev, doc


def _sorted_versions(doc: dict) -> list[tuple[str, object]]:
    times = doc.get("time", {}) or {}
    pairs = [(v, times.get(v)) for v in doc.get("versions", {})]
    pairs.sort(key=lambda p: (p[1] is None, p[1] or ""))
    return pairs


def handle_change(
    row: ChangeRow,
    *,
    registry: RegistryClient,
    repo: Repository | None = None,
    ioc_checker=None,
) -> int:
    """Process a single change row. Returns the ``publish_event`` id."""
    if repo is not None:
        return _handle(row, registry, repo, ioc_checker)
    with open_repo() as r:
        return _handle(row, registry, r, ioc_checker)


def _handle(row: ChangeRow, registry: RegistryClient, repo: Repository, ioc_checker=None) -> int:
    name = row.package_name
    ref = PackageRef(ecosystem=Ecosystem.NPM, name=name)
    baseline = repo.get_baseline(name)

    # Routing decision (real router if available, else fallback).
    route: Route
    reasons: list[str]
    version: str | None = None
    prev_version: str | None = None
    try:
        from kitsunox.ingest.prescore import PrescoreContext
        from kitsunox.ingest.prescore import route as prescore_route

        res = prescore_route(row, PrescoreContext(repo=repo, client=registry))
        route, reasons = res.route, res.reasons
        version, prev_version = res.version, res.prev_version
    except NotImplementedError:
        route, reasons = _fallback_route(row, baseline_known=baseline is not None)

    packument: dict | None = None
    if route != Route.IGNORE and version is None and not row.deleted:
        version, prev_version, packument = _resolve_versions(
            registry, name, baseline.last_version if baseline else None
        )

    event = PublishEvent(
        seq=row.seq,
        ref=ref,
        version=version,
        prev_version=prev_version,
        rev=row.rev,
        is_delete=row.deleted,
        route=route,
        route_reasons=reasons,
    )
    event_id = repo.record_publish_event(event, source="live")
    repo.set_event_route(event_id, route, reasons)

    # Fold into the running baseline (pipeline owns this, not the router).
    if not row.deleted:
        repo.observe_publish_for_baseline(
            name,
            version=version,
            maintainers=(
                [m.get("name") for m in (packument.get("maintainers") or []) if m.get("name")]
                if packument
                else None
            ),
        )

    if route == Route.IGNORE:
        repo.set_event_tier0(event_id, "clean")
        return event_id

    if row.deleted or version is None:
        repo.set_event_tier0(event_id, "clean")
        log.info("routed but nothing to scan", package=name, route=route.value, deleted=row.deleted)
        return event_id

    try:
        result = run_tier0(event, client=registry, packument=packument, ioc_checker=ioc_checker)
    except Exception as exc:  # noqa: BLE001 - keep the listener alive
        log.warning("tier0 failed", package=name, version=version, error=str(exc))
        repo.set_event_tier0(event_id, "error")
        return event_id

    repo.add_findings(event_id, result.findings)
    repo.set_event_tier0(event_id, result.status)
    if result.findings:
        log.info(
            "tier0 findings",
            package=name,
            version=version,
            status=result.status,
            rules=[f.rule_id for f in result.findings],
        )
    return event_id
