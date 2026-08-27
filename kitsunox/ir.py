"""Ecosystem-neutral intermediate representation.

Everything downstream of ``ingest/`` speaks this vocabulary, not raw registry JSON. npm
concepts are mapped *in* here (see ``ingest/registry_client.py``); they must not leak out.
When PyPI / crates.io are added later, only the mapping layer changes.
"""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, Field


class Ecosystem(enum.StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    CRATES = "crates"


class ChangeType(enum.StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Route(enum.StrEnum):
    """Pre-score routing decision for a publish event."""

    IGNORE = "ignore"
    TIER01 = "tier01"
    TIER2 = "tier2"


class PackageRef(BaseModel):
    ecosystem: Ecosystem = Ecosystem.NPM
    name: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.ecosystem.value}:{self.name}"


class VersionMeta(BaseModel):
    """Normalized per-version metadata, sourced from the registry packument."""

    ref: PackageRef
    version: str
    published_at: datetime | None = None
    publisher: str | None = None  # npm: _npmUser.name
    maintainers: list[str] = Field(default_factory=list)
    dependencies: dict[str, str] = Field(default_factory=dict)
    # scripts.preinstall / install / postinstall (and prepare) — the install-time surface.
    install_scripts: dict[str, str] = Field(default_factory=dict)
    dist_tarball_url: str | None = None
    dist_shasum: str | None = None
    dist_integrity: str | None = None
    unpacked_size: int | None = None

    @property
    def has_install_script(self) -> bool:
        return any(k in self.install_scripts for k in ("preinstall", "install", "postinstall"))


class FileEntry(BaseModel):
    path: str
    size: int
    is_binary: bool
    sha256: str


class FileDiff(BaseModel):
    path: str
    change_type: ChangeType
    is_binary: bool
    size_before: int | None = None
    size_after: int | None = None
    # Unified-diff text for text files; empty for binary or when suppressed for size.
    hunks: str = ""


class MaintainerDelta(BaseModel):
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


class PublishEvent(BaseModel):
    """One observed publish or unpublish, normalized.

    Produced both by the live feed consumer and by the historical backfill (which
    synthesizes events from packument history).
    """

    seq: int | None = None  # _changes sequence; None for synthesized backfill events
    ref: PackageRef
    version: str | None = None  # None for whole-package deletes
    prev_version: str | None = None
    rev: str | None = None
    is_delete: bool = False
    observed_at: datetime | None = None
    published_at: datetime | None = None
    maintainer_delta: MaintainerDelta = Field(default_factory=MaintainerDelta)
    # Filled in as the event moves through the funnel.
    route: Route | None = None
    route_reasons: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A single detection hit. Evidence is always a bounded snippet, never a whole file."""

    tier: int
    rule_id: str  # e.g. "tier0.pattern.child_process_exec"
    severity: Severity
    rationale: str
    file_path: str | None = None
    line: int | None = None
    evidence: str = ""

    def key(self) -> tuple:
        """Dedupe key for merging findings from multiple Tier 0 modules."""
        return (self.rule_id, self.file_path, self.line)
