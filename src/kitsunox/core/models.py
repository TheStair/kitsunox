"""Records passed between pipeline stages.

All models are frozen: a stage that wants to add information returns a new instance. Fields that
hold fetched content (manifests, snippets) are untrusted data and must never be interpreted.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Record(BaseModel):
    """Base for all inter-stage records: immutable, and strict about unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class PackageVersionRef(Record):
    """Identifies one published release."""

    ecosystem: str
    name: str
    version: str

    def __str__(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


class Window(Record):
    """Half-open publish-time window `(start, end]` that defines "recent" for a run."""

    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _check_order(self) -> Window:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("window bounds must be timezone-aware")
        if self.start >= self.end:
            raise ValueError("window start must be before end")
        return self

    def contains(self, moment: datetime) -> bool:
        return self.start < moment <= self.end


class PublishInfo(Record):
    """How a version reached the registry. Used for publish-method and account signals."""

    published_at: datetime | None = None
    publisher: str | None = None
    trusted_publisher: str | None = Field(
        default=None, description="Trusted-publishing (OIDC) provider id, if used."
    )
    approver: str | None = Field(default=None, description="Staged-publish approver, if any.")
    has_provenance: bool = False
    git_head: str | None = None
    maintainers: tuple[str, ...] = ()


class ArtifactRef(Record):
    """Where to download a version's published artifact, and how to verify it."""

    url: str
    integrity: str | None = Field(default=None, description="SRI string, e.g. 'sha512-...'.")
    shasum: str | None = Field(default=None, description="Legacy SHA-1 hex digest.")
    file_count: int | None = None
    unpacked_size: int | None = None


class VersionSnapshot(Record):
    """Everything Stage 0 knows about one version, without downloading its artifact."""

    ref: PackageVersionRef
    publish: PublishInfo
    manifest: dict[str, Any] = Field(description="Version manifest as published (untrusted).")
    artifact: ArtifactRef | None = None


class Change(Record):
    """Unit of work produced by Stage 0: one new version, plus the version it should be diffed
    against. `previous is None` means a brand-new package (threat-model shape B)."""

    new: VersionSnapshot
    previous: VersionSnapshot | None = None
    repository_url: str | None = None
    feed_seq: int | None = Field(default=None, description="Change-feed sequence it came from.")

    @property
    def is_new_package(self) -> bool:
        return self.previous is None

    @property
    def sort_key(self) -> tuple[str, str, str]:
        ref = self.new.ref
        return (ref.ecosystem, ref.name, ref.version)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceKind(StrEnum):
    FILE_SPAN = "file-span"
    MANIFEST_FIELD = "manifest-field"
    METADATA = "metadata"


class Evidence(Record):
    """Proof for a finding. `snippet`, `before` and `after` are untrusted and must be escaped
    by any renderer."""

    kind: EvidenceKind
    path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet: str | None = None
    before: str | None = None
    after: str | None = None


class Finding(Record):
    """One rule firing on one change."""

    rule_id: str
    rule_version: int
    severity: Severity
    weight: float
    title: str
    explanation: str
    evidence: tuple[Evidence, ...] = ()


class StageDecision(Record):
    """What one stage decided about a candidate, kept so per-stage metrics can be computed."""

    stage: str
    forwarded: bool
    reason: str


class Candidate(Record):
    """A change moving through the pipeline with the findings accumulated so far."""

    change: Change
    findings: tuple[Finding, ...] = ()
    history: tuple[StageDecision, ...] = ()

    @property
    def score(self) -> float:
        return sum(f.weight for f in self.findings)
