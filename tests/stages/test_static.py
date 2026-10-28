"""Stage 2 engine: new contents, attribution across a burst, and the content cache."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conftest import Router, TarEntry, make_tar_gz, sri_sha512
from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    VersionSnapshot,
)
from kitsunox.core.run import DataDir
from kitsunox.ecosystems.npm.registry import NpmEcosystem
from kitsunox.rules.static import RULES
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.static import (
    ArtifactFiles,
    ContentCache,
    Unavailable,
    analyse_batch,
    new_contents,
    record_static,
    static_run,
)
from kitsunox.util.http import FetchError

T0 = datetime(2026, 10, 1, tzinfo=UTC)
BASE = {"index.js": b"module.exports = 1", "README.md": b"hi"}
BAD = {
    "index.js": b"module.exports = 1",
    "lib/x.js": b"post('https://discord.com/api/webhooks/1/x')",
    "README.md": b"hi",
}
CLEAN = {"index.js": b"module.exports = 2", "README.md": b"hi"}


def snapshot(version: str, minutes: int = 0, size: int | None = 100) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(published_at=T0 + timedelta(minutes=minutes)),
        manifest={},
        artifact=ArtifactRef(
            url=f"https://r.test/kx-{version}.tgz", integrity="sha512-x", unpacked_size=size
        ),
    )


def candidate(version: str, minutes: int) -> Candidate:
    return Candidate(change=Change(new=snapshot(version, minutes)))


TREES = {"1.0.0": BASE, "1.0.1": BAD, "1.0.2": CLEAN}


def batch(base: VersionSnapshot | None = None) -> PackageBatch:
    return PackageBatch(
        ecosystem="npm",
        name="kx",
        base=base,
        versions=(candidate("1.0.1", 5), candidate("1.0.2", 10)),
    )


def test_new_contents_dedupes_and_keeps_first_version() -> None:
    items = list(new_contents(BASE, [("1.0.1", BAD), ("1.0.2", BAD | CLEAN)]))
    assert [(i.path, i.first_version) for i, _ in items] == [
        ("lib/x.js", "1.0.1"),
        ("index.js", "1.0.2"),
    ]
    assert len(list(new_contents(None, [("1", BASE)]))) == 2  # new package: everything is new


def test_reverted_payload_is_attributed_to_the_version_that_had_it(tmp_path: Path) -> None:
    result = analyse_batch(
        batch(snapshot("1.0.0")), lambda s: TREES[s.ref.version], ContentCache(tmp_path, RULES)
    )
    bad, clean = result.versions
    assert bad.history[-1].forwarded and bad.findings[0].evidence[0].path == "lib/x.js"
    assert not clean.history[-1].forwarded and clean.findings == ()
    assert clean.history[-1].reason == "no signal"


def test_unavailable_versions_and_base_are_explained(tmp_path: Path) -> None:
    def files(s: VersionSnapshot) -> dict[str, bytes] | Unavailable:
        return Unavailable(reason="gone") if s.ref.version != "1.0.2" else CLEAN

    result = analyse_batch(batch(snapshot("1.0.0")), files, ContentCache(None, RULES))
    bad, clean = result.versions
    assert bad.history[-1].reason == "files unavailable: gone; base unavailable: gone"
    assert not bad.history[-1].forwarded
    assert clean.history[-1].reason == "no signal; base unavailable: gone"


class FakeEcosystem:
    def __init__(self) -> None:
        self.fetched: list[str] = []

    def fetch_artifact(self, artifact: ArtifactRef) -> dict[str, bytes]:
        self.fetched.append(artifact.url)
        if "1.0.2" in artifact.url:
            raise FetchError("HTTP 404")
        return BAD


def test_artifact_files_skips_oversize_and_reports_fetch_errors() -> None:
    ecosystem = FakeEcosystem()
    files = ArtifactFiles(ecosystem, max_bytes=1000)  # type: ignore[arg-type]
    assert files(snapshot("1.0.1")) == BAD
    assert files(snapshot("1.0.1", size=1001)) == Unavailable(
        reason="declared unpacked size 1001 bytes"
    )
    assert files(snapshot("1.0.2")) == Unavailable(reason="FetchError: HTTP 404")
    no_artifact = snapshot("1.0.1").model_copy(update={"artifact": None})
    assert files(no_artifact) == Unavailable(reason="no artifact")
    assert len(ecosystem.fetched) == 2  # the oversize one was never downloaded


@pytest.mark.parametrize("base", [None, "1.0.0"])
def test_static_run_reads_batches_and_writes_results(tmp_path: Path, base: str | None) -> None:
    write_jsonl(tmp_path / "batches.jsonl", [batch(snapshot(base) if base else None)])
    (result,) = static_run(
        tmp_path, lambda s: TREES[s.ref.version], ContentCache(tmp_path / "cache", RULES)
    )
    assert [c.history[-1].forwarded for c in result.versions] == [True, False]
    assert PackageBatch.load_json((tmp_path / "static.jsonl").read_bytes()) == result


def test_cache_is_reused_and_keyed_by_rule_versions(tmp_path: Path) -> None:
    cache = ContentCache(tmp_path, RULES)
    first = cache.matches("ab" * 32, b"eval(x)")
    files = list(tmp_path.rglob("*.json"))
    assert len(files) == 1
    assert (
        cache.matches("ab" * 32, b"different bytes, same claimed hash") == first
    )  # served from disk
    assert ContentCache(tmp_path, RULES[:1]).dir != cache.dir


def test_record_static_fetches_verifies_and_records(tmp_path: Path, router: Router) -> None:
    data = DataDir(tmp_path)
    tarball = make_tar_gz([TarEntry(f"package/{path}", content) for path, content in BAD.items()])
    good = snapshot("1.0.1").model_copy(
        update={
            "artifact": ArtifactRef(
                url="https://r.test/kx-1.0.1.tgz", integrity=sri_sha512(tarball)
            )
        }
    )
    router.add_bytes("https://r.test/kx-1.0.1.tgz", tarball)
    run_dir = data.run_dir("r1")
    write_jsonl(
        run_dir / "batches.jsonl",
        [
            PackageBatch(
                ecosystem="npm",
                name="kx",
                base=None,
                versions=(Candidate(change=Change(new=good)),),
            )
        ],
    )
    (result,) = record_static(data, "r1", NpmEcosystem, client=router.client())
    (version,) = result.versions
    assert version.history[-1].forwarded
    assert (run_dir / "static-snapshot.json").exists()
    assert (run_dir / "static.jsonl").exists()
    # A second pass is served from the immutable blob store, not the network.
    record_static(data, "r1", NpmEcosystem, client=router.client())
    assert router.requests == ["https://r.test/kx-1.0.1.tgz"]
