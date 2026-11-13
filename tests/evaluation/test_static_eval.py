"""The evaluation reads a version as the pipeline does (decision 0021: partial reads)."""

from kitsunox.core.models import ArtifactRef, PackageVersionRef, PublishInfo, VersionSnapshot
from kitsunox.evaluation.static_eval import as_read
from kitsunox.stages.static import MAX_HOOK_ARTIFACT_BYTES
from kitsunox.util.archive import ArtifactTree


def snapshot(size: int, hook: bool) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.0"),
        publish=PublishInfo(),
        manifest={"scripts": {"postinstall": "node i.js"}} if hook else {},
        artifact=ArtifactRef(url="https://r.test/kx.tgz", unpacked_size=size),
    )


TREE = ArtifactTree(files={"i.js": b"require('https')", "x.node": b"\x7fELF\x00\x01"})


def test_a_version_read_partially_is_evaluated_on_what_a_partial_read_keeps() -> None:
    large = MAX_HOOK_ARTIFACT_BYTES + 1
    partial = as_read(snapshot(large, hook=True), TREE)
    assert list(partial) == ["i.js"]
    assert [o.path for o in partial.omitted] == ["x.node"]
    assert as_read(snapshot(large, hook=False), TREE) is TREE  # not read: the caller's routing
    assert as_read(snapshot(100, hook=True), TREE) is TREE
