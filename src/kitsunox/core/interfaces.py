"""Contracts between the pipeline core and pluggable parts.

Only the ecosystem contract exists so far. Rule and Stage contracts land with Stage 1 (roadmap
Phase 4), when there is a real consumer to shape them.
"""

from __future__ import annotations

from typing import Protocol

from kitsunox.core.models import ArtifactRef, Change, Record, Window
from kitsunox.util.archive import ArtifactTree


class ChangeStub(Record):
    """A package the ecosystem's change feed says was modified, before any metadata is fetched.
    `cursor` is the feed position (npm: `_changes` sequence number)."""

    name: str
    cursor: int


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

    def build_changes(self, stub: ChangeStub, window: Window) -> list[Change]:
        """One Change per version of `stub.name` published inside `window`, each paired with the
        version it should be diffed against."""
        ...

    def fetch_artifact(self, artifact: ArtifactRef) -> ArtifactTree:
        """Download, integrity-check and safely extract a published artifact. Never executes."""
        ...
