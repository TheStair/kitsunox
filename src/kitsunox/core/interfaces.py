"""Contracts between the pipeline core and pluggable parts.

Only the ecosystem contract exists so far. Rule and Stage contracts land with Stage 1 (roadmap
Phase 4), when there is a real consumer to shape them.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from pydantic import Field

from kitsunox.core.models import ArtifactRef, Change, Record, Window
from kitsunox.util.archive import ArtifactTree


class ChangeStub(Record):
    """A package the ecosystem's change feed says was modified, before any metadata is fetched.
    `cursor` is the feed position (npm: `_changes` sequence number)."""

    name: str
    cursor: int


class PackageChanges(Record):
    """What `build_changes` found for one feed entry."""

    changes: tuple[Change, ...] = ()
    modified_at: datetime | None = Field(
        default=None,
        description="When the package last changed. Because the feed lists a package at its "
        "latest change, a low percentile of these over a run estimates the feed range's start "
        "time, which is how Stage 0 checks that the range covers the window.",
    )


class DownloadCounts(Record):
    source: str = Field(description="Source and exact period, e.g. 'npm-downloads:<a>..<b>'.")
    period_days: int
    counts: dict[str, int | None]


class Ecosystem(Protocol):
    """Everything ecosystem-specific that Stage 0 and artifact-reading stages need."""

    name: str

    def feed_head(self) -> int:
        """Current position of the change feed."""
        ...

    def list_changes(self, since: int, until: int) -> list[ChangeStub]:
        """Packages changed in feed positions `(since, until]`, one stub per package, sorted by
        name."""
        ...

    def build_changes(self, stub: ChangeStub, window: Window) -> PackageChanges:
        """One Change per version of `stub.name` published inside `window`, each paired with the
        version it should be diffed against."""
        ...

    def download_counts(self, names: Sequence[str], as_of: datetime) -> DownloadCounts:
        """Per-package download counts for a fixed period ending before `as_of`. Names whose
        lookup failed are absent from `counts`; None means the registry has no stats."""
        ...

    def fetch_artifact(self, artifact: ArtifactRef) -> ArtifactTree:
        """Download, integrity-check and safely extract a published artifact. Never executes."""
        ...
