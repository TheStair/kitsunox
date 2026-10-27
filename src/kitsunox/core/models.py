"""Records passed between pipeline stages.

All models are frozen: a stage that wants to add information returns a new instance. Fields that
hold fetched content (manifests, snippets) are untrusted data and must never be interpreted.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kitsunox.util.schema import require_schema_version


class Record(BaseModel):
    """Base for all inter-stage records: immutable, and strict about unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class Persisted(Record):
    """A record written to disk on its own (one file, or one JSON line). `load_json` refuses
    data written with another schema version. On an incompatible change, bump both
    `SCHEMA_VERSION` and the `schema_version` default in the subclass."""

    SCHEMA_VERSION: ClassVar[int] = 1
    schema_version: int = 1

    @model_validator(mode="after")
    def _check_schema_version(self) -> Self:
        if self.schema_version != self.SCHEMA_VERSION:
            raise ValueError(
                f"schema_version {self.schema_version} != {self.SCHEMA_VERSION} for "
                f"{type(self).__name__}"
            )
        return self

    @classmethod
    def load_json(cls, data: str | bytes) -> Self:
        require_schema_version(data, cls.SCHEMA_VERSION, cls.__name__)
        return cls.model_validate_json(data)


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


class Popularity(Record):
    """How widely used a package is, and whether it clears the run's popularity cutoff."""

    source: str = Field(description="Where the numbers came from, e.g. 'watchlist:<id>'.")
    downloads: int | None = Field(description="Downloads over `period_days`; None if unknown.")
    period_days: int
    watched: bool = Field(
        description="Meets the popularity cutoff: tarball stages see this change even when "
        "Stage 1 finds nothing."
    )


class Change(Persisted):
    """Unit of work produced by Stage 0: one new version, plus the version it should be diffed
    against. `previous is None` means a brand-new package (threat-model shape B)."""

    new: VersionSnapshot
    previous: VersionSnapshot | None = None
    repository_url: str | None = None
    feed_seq: int | None = Field(default=None, description="Change-feed sequence it came from.")
    popularity: Popularity | None = Field(
        default=None, description="None when not fetched (new packages, or the lookup failed)."
    )

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


class PackageBatch(Persisted):
    """Stage 1 → Stage 2 handoff: every version of one package from one run, analysed together.

    Bursty packages publish dozens of versions an hour (233 in a day for one package on
    2026-10-27). Analysing only the newest version would hide a malicious version that is
    reverted within the burst, so Stage 2 instead analyses every *distinct file content* that
    appears in any version here but not in `base`, once, and attributes each finding to the
    first version that contained it. Cost scales with distinct contents, not with versions.
    """

    ecosystem: str
    name: str
    base: VersionSnapshot | None = Field(
        description="What the earliest version was diffed against; None for a new package."
    )
    versions: tuple[Candidate, ...] = Field(description="Oldest first, by publish time.")

    @property
    def forwarded(self) -> bool:
        return any(c.history and c.history[-1].forwarded for c in self.versions)
