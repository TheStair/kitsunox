from datetime import UTC, datetime
from pathlib import Path

import pytest

from kitsunox.core.interfaces import ChangeStub
from kitsunox.core.models import (
    ArtifactRef,
    Change,
    PackageVersionRef,
    PublishInfo,
    VersionSnapshot,
    Window,
)
from kitsunox.stages.ingest import read_changes, run_ingest, write_jsonl
from kitsunox.util.archive import ArtifactTree
from kitsunox.util.http import FetchError

WINDOW = Window(start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC))


def change(name: str, version: str) -> Change:
    return Change(
        new=VersionSnapshot(
            ref=PackageVersionRef(ecosystem="fake", name=name, version=version),
            publish=PublishInfo(),
            manifest={"name": name, "version": version},
        )
    )


class FakeEcosystem:
    name = "fake"

    def __init__(self, behavior: dict[str, list[Change] | Exception]) -> None:
        self.behavior = behavior

    def feed_head(self) -> int:
        return 0

    def list_changes(self, since: int, until: int) -> list[ChangeStub]:
        return [ChangeStub(name=n, cursor=i) for i, n in enumerate(sorted(self.behavior))]

    def build_changes(self, stub: ChangeStub, window: Window) -> list[Change]:
        outcome = self.behavior[stub.name]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def fetch_artifact(self, artifact: ArtifactRef) -> ArtifactTree:
        raise NotImplementedError


def test_failures_are_recorded_not_dropped() -> None:
    eco = FakeEcosystem(
        {
            "ok": [change("ok", "1.0.0")],
            "net": FetchError("timeout"),
            "bad": ValueError("malformed\nsecond line"),
            "quiet": [],
        }
    )
    result = run_ingest(eco, WINDOW, since=0, until=10)
    assert [str(c.new.ref) for c in result.changes] == ["fake:ok@1.0.0"]
    assert [(s.name, s.reason) for s in result.skipped] == [
        ("bad", "ValueError: malformed"),
        ("net", "FetchError: timeout"),
    ]
    assert result.packages_seen == 4


@pytest.mark.parametrize("workers", [1, 8])
def test_output_order_is_independent_of_workers(workers: int) -> None:
    eco = FakeEcosystem({n: [change(n, "2.0.0"), change(n, "1.0.0")] for n in "zyxwvu"})
    result = run_ingest(eco, WINDOW, since=0, until=10, workers=workers)
    keys = [c.sort_key for c in result.changes]
    assert keys == sorted(keys)


def test_jsonl_round_trip(tmp_path: Path) -> None:
    changes = [change("a", "1.0.0"), change("b", "1.0.0")]
    write_jsonl(tmp_path / "c.jsonl", changes)
    assert list(read_changes(tmp_path / "c.jsonl")) == changes
