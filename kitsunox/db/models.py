"""SQLAlchemy ORM models.

Design notes:
- JSON columns are used for small lists/dicts (maintainer lists, route reasons). SQLite
  stores these as TEXT; Postgres would use native JSONB. The repository layer hides the
  difference.
- ``created_at`` / ``updated_at`` are naive UTC timestamps (``datetime.utcnow``); keep the
  whole codebase in UTC.
- Enum-like fields are stored as plain strings validated against the IR enums at the
  repository boundary, not as DB-native enums (cheaper to migrate).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class FeedCursor(Base):
    """Singleton row (id == 1): the resumable ``_changes`` position."""

    __tablename__ = "feed_cursor"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    last_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )


class PackageBaseline(Base):
    """Per-package threat-intel record the system accretes over time."""

    __tablename__ = "package_baseline"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(16), nullable=False, default="npm")
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_publish_at: Mapped[datetime | None] = mapped_column(DateTime)
    known_maintainers: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    publish_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    publish_cadence_days_median: Mapped[float | None] = mapped_column()
    last_version: Mapped[str | None] = mapped_column(String(128))
    last_tarball_sha256: Mapped[str | None] = mapped_column(String(64))
    weekly_downloads: Mapped[int | None] = mapped_column(Integer)
    dependents_count: Mapped[int | None] = mapped_column(Integer)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("ecosystem", "name", name="uq_baseline_pkg"),)


class PublishEventRecord(Base):
    __tablename__ = "publish_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int | None] = mapped_column(Integer, index=True)
    ecosystem: Mapped[str] = mapped_column(String(16), nullable=False, default="npm")
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(128))
    prev_version: Mapped[str | None] = mapped_column(String(128))
    rev: Mapped[str | None] = mapped_column(String(80))
    is_delete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    observed_at: Mapped[datetime | None] = mapped_column(DateTime)
    published_at: Mapped[datetime | None] = mapped_column(DateTime)

    route: Mapped[str | None] = mapped_column(String(16))  # ignore | tier01 | tier2
    route_reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    tier0_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending"
    )  # pending | clean | flagged | error
    # Marks rows created by `kitsunox backfill` so they don't pollute live statistics.
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="live")
    processed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "ecosystem", "package_name", "version", "rev", "source", name="uq_publish_event"
        ),
    )


class FindingRecord(Base):
    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    publish_event_id: Mapped[int] = mapped_column(
        ForeignKey("publish_event.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tier: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    event: Mapped[PublishEventRecord] = relationship(back_populates="findings")


class IncidentLabel(Base):
    """Ground truth for evaluation: which (package, version) pairs are known malicious."""

    __tablename__ = "incident_label"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(16), nullable=False, default="npm")
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(128))
    label: Mapped[str] = mapped_column(String(24), nullable=False)  # malicious | benign_control
    source: Mapped[str] = mapped_column(String(24), nullable=False)  # osv | openssf | manual
    ref: Mapped[str | None] = mapped_column(String(256))  # GHSA id / advisory URL
    incident_date: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "ecosystem", "package_name", "version", "source", name="uq_incident_label"
        ),
    )
