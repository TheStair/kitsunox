"""Repository — the only module outside ``kitsunox.db`` that anything should import for
persistence.

It returns plain dataclasses (never ORM instances) so callers never hold a session-bound
object and the SQLite->Postgres swap stays contained here.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kitsunox.db.engine import session_scope
from kitsunox.db.models import (
    FeedCursor,
    FindingRecord,
    IncidentLabel,
    PackageBaseline,
    PublishEventRecord,
)
from kitsunox.ir import Finding, PublishEvent, Route, Severity


def _utcnow() -> datetime:
    """Naive UTC 'now' — the whole codebase stores naive UTC."""
    return datetime.now(UTC).replace(tzinfo=None)


@dataclass
class BaselineView:
    name: str
    ecosystem: str
    first_seen_at: datetime | None
    last_publish_at: datetime | None
    known_maintainers: list[str]
    publish_count: int
    publish_cadence_days_median: float | None
    last_version: str | None
    last_tarball_sha256: str | None
    weekly_downloads: int | None
    dependents_count: int | None


@dataclass
class LabelView:
    package_name: str
    version: str | None
    label: str
    source: str
    ref: str | None
    incident_date: datetime | None


@dataclass
class EventView:
    id: int
    seq: int | None
    package_name: str
    version: str | None
    prev_version: str | None
    route: str | None
    tier0_status: str
    source: str
    route_reasons: list[str] = field(default_factory=list)


class Repository:
    def __init__(self, session: Session) -> None:
        self.s = session

    # ------------------------------------------------------------------ cursor
    def get_cursor(self) -> int:
        row = self.s.get(FeedCursor, 1)
        return row.last_seq if row else 0

    def set_cursor(self, seq: int) -> None:
        row = self.s.get(FeedCursor, 1)
        if row is None:
            row = FeedCursor(id=1, last_seq=seq)
            self.s.add(row)
        else:
            row.last_seq = seq

    # --------------------------------------------------------------- baselines
    def get_baseline(self, name: str, ecosystem: str = "npm") -> BaselineView | None:
        row = self.s.scalar(
            select(PackageBaseline).where(
                PackageBaseline.ecosystem == ecosystem, PackageBaseline.name == name
            )
        )
        if row is None:
            return None
        return BaselineView(
            name=row.name,
            ecosystem=row.ecosystem,
            first_seen_at=row.first_seen_at,
            last_publish_at=row.last_publish_at,
            known_maintainers=list(row.known_maintainers or []),
            publish_count=row.publish_count,
            publish_cadence_days_median=row.publish_cadence_days_median,
            last_version=row.last_version,
            last_tarball_sha256=row.last_tarball_sha256,
            weekly_downloads=row.weekly_downloads,
            dependents_count=row.dependents_count,
        )

    def _get_or_create_baseline(self, name: str, ecosystem: str) -> PackageBaseline:
        row = self.s.scalar(
            select(PackageBaseline).where(
                PackageBaseline.ecosystem == ecosystem, PackageBaseline.name == name
            )
        )
        if row is None:
            row = PackageBaseline(ecosystem=ecosystem, name=name, known_maintainers=[])
            self.s.add(row)
            self.s.flush()
        return row

    def observe_publish_for_baseline(
        self,
        name: str,
        *,
        ecosystem: str = "npm",
        published_at: datetime | None = None,
        maintainers: Sequence[str] | None = None,
        version: str | None = None,
        tarball_sha256: str | None = None,
        weekly_downloads: int | None = None,
        dependents_count: int | None = None,
    ) -> None:
        """Fold one publish into the running baseline (cadence, maintainer set, ...).

        Cadence median is recomputed from the gap between the previous and current
        ``last_publish_at``; it is a rough running estimate, not a full history replay.
        """
        row = self._get_or_create_baseline(name, ecosystem)
        now = published_at or _utcnow()

        if row.first_seen_at is None:
            row.first_seen_at = now

        if row.last_publish_at is not None and now > row.last_publish_at:
            gap_days = (now - row.last_publish_at).total_seconds() / 86400.0
            prior = row.publish_cadence_days_median
            row.publish_cadence_days_median = (
                gap_days if prior is None else statistics.fmean([prior, gap_days])
            )

        row.last_publish_at = now
        row.publish_count = (row.publish_count or 0) + 1
        if maintainers is not None:
            row.known_maintainers = sorted(set(maintainers))
        if version is not None:
            row.last_version = version
        if tarball_sha256 is not None:
            row.last_tarball_sha256 = tarball_sha256
        if weekly_downloads is not None:
            row.weekly_downloads = weekly_downloads
        if dependents_count is not None:
            row.dependents_count = dependents_count

    def set_baseline_popularity(
        self,
        name: str,
        *,
        ecosystem: str = "npm",
        weekly_downloads: int | None = None,
        dependents_count: int | None = None,
    ) -> None:
        row = self._get_or_create_baseline(name, ecosystem)
        if weekly_downloads is not None:
            row.weekly_downloads = weekly_downloads
        if dependents_count is not None:
            row.dependents_count = dependents_count

    # ----------------------------------------------------------- publish events
    def record_publish_event(self, event: PublishEvent, *, source: str = "live") -> int:
        rec = PublishEventRecord(
            seq=event.seq,
            ecosystem=event.ref.ecosystem.value,
            package_name=event.ref.name,
            version=event.version,
            prev_version=event.prev_version,
            rev=event.rev,
            is_delete=event.is_delete,
            observed_at=event.observed_at,
            published_at=event.published_at,
            route=event.route.value if event.route else None,
            route_reasons=list(event.route_reasons),
            source=source,
        )
        self.s.add(rec)
        self.s.flush()
        return rec.id

    def set_event_route(self, event_id: int, route: Route, reasons: Sequence[str]) -> None:
        rec = self.s.get(PublishEventRecord, event_id)
        if rec is None:
            raise KeyError(f"publish_event {event_id} not found")
        rec.route = route.value
        rec.route_reasons = list(reasons)

    def set_event_tier0(self, event_id: int, status: str) -> None:
        rec = self.s.get(PublishEventRecord, event_id)
        if rec is None:
            raise KeyError(f"publish_event {event_id} not found")
        if status not in {"pending", "clean", "flagged", "error"}:
            raise ValueError(f"bad tier0 status {status!r}")
        rec.tier0_status = status
        rec.processed_at = _utcnow()

    def iter_events(
        self,
        *,
        source: str | None = None,
        route: str | None = None,
        package_name: str | None = None,
    ) -> Iterator[EventView]:
        stmt = select(PublishEventRecord)
        if source is not None:
            stmt = stmt.where(PublishEventRecord.source == source)
        if route is not None:
            stmt = stmt.where(PublishEventRecord.route == route)
        if package_name is not None:
            stmt = stmt.where(PublishEventRecord.package_name == package_name)
        stmt = stmt.order_by(PublishEventRecord.id)
        for rec in self.s.scalars(stmt):
            yield EventView(
                id=rec.id,
                seq=rec.seq,
                package_name=rec.package_name,
                version=rec.version,
                prev_version=rec.prev_version,
                route=rec.route,
                tier0_status=rec.tier0_status,
                source=rec.source,
                route_reasons=list(rec.route_reasons or []),
            )

    # ----------------------------------------------------------------- findings
    def add_finding(self, event_id: int, finding: Finding) -> int:
        rec = FindingRecord(
            publish_event_id=event_id,
            tier=finding.tier,
            rule_id=finding.rule_id,
            severity=finding.severity.value
            if isinstance(finding.severity, Severity)
            else str(finding.severity),
            rationale=finding.rationale,
            file_path=finding.file_path,
            line=finding.line,
            evidence=finding.evidence,
        )
        self.s.add(rec)
        self.s.flush()
        return rec.id

    def add_findings(self, event_id: int, findings: Sequence[Finding]) -> list[int]:
        return [self.add_finding(event_id, f) for f in findings]

    def findings_for_event(self, event_id: int) -> list[Finding]:
        rows = self.s.scalars(
            select(FindingRecord).where(FindingRecord.publish_event_id == event_id)
        )
        return [
            Finding(
                tier=r.tier,
                rule_id=r.rule_id,
                severity=Severity(r.severity),
                rationale=r.rationale,
                file_path=r.file_path,
                line=r.line,
                evidence=r.evidence,
            )
            for r in rows
        ]

    # --------------------------------------------------------- incident labels
    def add_incident_label(
        self,
        package_name: str,
        version: str | None,
        label: str,
        *,
        source: str,
        ref: str | None = None,
        incident_date: datetime | None = None,
        ecosystem: str = "npm",
    ) -> None:
        existing = self.s.scalar(
            select(IncidentLabel).where(
                IncidentLabel.ecosystem == ecosystem,
                IncidentLabel.package_name == package_name,
                IncidentLabel.version.is_(version) if version is None else IncidentLabel.version == version,
                IncidentLabel.source == source,
            )
        )
        if existing is not None:
            existing.label = label
            existing.ref = ref
            existing.incident_date = incident_date
            return
        self.s.add(
            IncidentLabel(
                ecosystem=ecosystem,
                package_name=package_name,
                version=version,
                label=label,
                source=source,
                ref=ref,
                incident_date=incident_date,
            )
        )

    def label_lookup(
        self, package_name: str, version: str | None = None, *, ecosystem: str = "npm"
    ) -> list[LabelView]:
        stmt = select(IncidentLabel).where(
            IncidentLabel.ecosystem == ecosystem,
            IncidentLabel.package_name == package_name,
        )
        if version is not None:
            # Match exact-version labels and whole-package labels (version IS NULL).
            stmt = stmt.where(
                (IncidentLabel.version == version) | (IncidentLabel.version.is_(None))
            )
        rows = self.s.scalars(stmt)
        return [
            LabelView(
                package_name=r.package_name,
                version=r.version,
                label=r.label,
                source=r.source,
                ref=r.ref,
                incident_date=r.incident_date,
            )
            for r in rows
        ]


@contextmanager
def open_repo():
    """Convenience: ``with open_repo() as repo:`` — commits on clean exit."""
    with session_scope() as session:
        yield Repository(session)
