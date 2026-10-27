"""Stage 2 engine: new contents, attribution across a burst, and the content cache."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from kitsunox.core.models import (
    Candidate,
    Change,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    VersionSnapshot,
)
from kitsunox.rules.static import RULES
from kitsunox.stages.static import ContentCache, analyse_batch, new_contents

T0 = datetime(2026, 10, 1, tzinfo=UTC)
BASE = {"index.js": b"module.exports = 1", "README.md": b"hi"}
BAD = {"index.js": b"module.exports = 1", "lib/x.js": b"eval(atob(p))", "README.md": b"hi"}
CLEAN = {"index.js": b"module.exports = 2", "README.md": b"hi"}


def candidate(version: str, minutes: int) -> Candidate:
    snap = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(published_at=T0 + timedelta(minutes=minutes)),
        manifest={},
    )
    return Candidate(change=Change(new=snap))


def test_new_contents_dedupes_and_keeps_first_version() -> None:
    items = new_contents(BASE, [("1.0.1", BAD), ("1.0.2", BAD | CLEAN)])
    assert [(i.path, i.first_version) for i, _ in items] == [
        ("lib/x.js", "1.0.1"),
        ("index.js", "1.0.2"),
    ]
    assert len(new_contents(None, [("1", BASE)])) == 2  # new package: everything is new


def test_reverted_payload_is_attributed_to_the_version_that_had_it(tmp_path: Path) -> None:
    batch = PackageBatch(
        ecosystem="npm",
        name="kx",
        base=None,
        versions=(candidate("1.0.1", 5), candidate("1.0.2", 10)),
    )
    trees = {"1.0.1": BAD, "1.0.2": CLEAN}
    result = analyse_batch(
        batch, lambda c: trees[c.change.new.ref.version], BASE, ContentCache(tmp_path, RULES)
    )
    bad, clean = result.versions
    assert bad.history[-1].forwarded and bad.findings[0].evidence[0].path == "lib/x.js"
    assert not clean.history[-1].forwarded and clean.findings == ()


def test_cache_is_reused_and_keyed_by_rule_versions(tmp_path: Path) -> None:
    cache = ContentCache(tmp_path, RULES)
    first = cache.matches("ab" * 32, b"eval(x)")
    files = list(tmp_path.rglob("*.json"))
    assert len(files) == 1
    assert (
        cache.matches("ab" * 32, b"different bytes, same claimed hash") == first
    )  # served from disk
    assert ContentCache(tmp_path, RULES[:1]).dir != cache.dir
