"""Versioned, hash-pinned storage for reference data that runs depend on (watchlists, label sets,
evaluation datasets).

Files live at `<root>/<ecosystem>/<id>.json`. Ids are UTC timestamps (`YYYYMMDDTHHMMSSZ`) or
names; timestamp ids sort chronologically, which `latest_id` relies on. Anything that uses a
stored record records its id and SHA-256, and loads it back with `sha256=` so a changed file is
detected instead of silently giving different results.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kitsunox.core.models import Persisted
from kitsunox.util.hashing import sha256_hex


def timestamp_id(moment: datetime) -> str:
    return f"{moment.astimezone(UTC):%Y%m%dT%H%M%SZ}"


class RecordStore[T: Persisted]:
    def __init__(self, root: Path, model: type[T]) -> None:
        self.root = root
        self.model = model

    def path(self, ecosystem: str, record_id: str) -> Path:
        return self.root / ecosystem / f"{record_id}.json"

    def save(self, ecosystem: str, record_id: str, record: T) -> tuple[Path, str]:
        path = self.path(ecosystem, record_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = record.model_dump_json().encode()
        path.write_bytes(data)
        return path, sha256_hex(data)

    def load(self, ecosystem: str, record_id: str, *, sha256: str | None = None) -> T:
        data = self.path(ecosystem, record_id).read_bytes()
        if sha256 is not None and sha256_hex(data) != sha256:
            raise ValueError(f"{self.model.__name__} {record_id} changed since it was recorded")
        return self.model.load_json(data)

    def sha256(self, ecosystem: str, record_id: str) -> str:
        return sha256_hex(self.path(ecosystem, record_id).read_bytes())

    def latest_id(self, ecosystem: str, *, not_after: datetime | None = None) -> str | None:
        """Newest timestamp-id record no later than `not_after`."""
        directory = self.root / ecosystem
        ids = sorted(p.stem for p in directory.glob("*.json")) if directory.exists() else []
        if not_after is not None:
            cutoff = timestamp_id(not_after)
            ids = [i for i in ids if i <= cutoff]
        return ids[-1] if ids else None
