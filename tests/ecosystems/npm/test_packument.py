from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from kitsunox.core.models import PackageVersionRef, PublishInfo, VersionSnapshot, Window
from kitsunox.ecosystems.npm.packument import (
    Packument,
    PackumentError,
    is_registry_placeholder,
    normalize_repository_url,
)

WINDOW = Window(
    start=datetime(2026, 10, 27, 0, tzinfo=UTC), end=datetime(2026, 10, 27, 12, tzinfo=UTC)
)


@pytest.fixture
def packument(load_fixture: Callable[[str], object]) -> Packument:
    return Packument(load_fixture("npm/packument_basic.json"), expected_name="kx-fixture")


def test_versions_in_window_oldest_first(packument: Packument) -> None:
    assert packument.versions_in(WINDOW) == ["1.1.1", "2.0.1", "9.9.9", "3.0.0-beta.1"]


@pytest.mark.parametrize(
    ("version", "previous"),
    [
        ("1.0.0", None),  # first release: shape B
        ("1.1.1", "1.1.0"),  # backport stays on its release line, not 2.0.0
        ("2.0.1", "2.0.0"),
        ("9.9.9", "2.0.1"),  # big jump diffs against the highest earlier version
        ("3.0.0-beta.1", "2.0.1"),
    ],
)
def test_previous_version(packument: Packument, version: str, previous: str | None) -> None:
    assert packument.previous_version(version) == previous


def test_publish_info_and_artifact(packument: Packument) -> None:
    trusted = packument.snapshot("2.0.0")
    assert trusted.publish.trusted_publisher == "github"
    assert trusted.publish.approver == "alice"
    assert trusted.publish.has_provenance
    assert trusted.publish.git_head == "0123456789abcdef0123456789abcdef01234567"

    manual = packument.snapshot("2.0.1")
    assert manual.publish.publisher == "mallory"
    assert manual.publish.trusted_publisher is None
    assert not manual.publish.has_provenance
    assert manual.publish.maintainers == ("alice", "mallory")  # malformed entry ignored
    assert manual.manifest["scripts"] == {"postinstall": "node setup.js"}
    assert manual.artifact is not None
    assert manual.artifact.file_count is None  # wrong type ignored


def test_hostile_field_types_are_ignored(packument: Packument) -> None:
    odd = packument.snapshot("9.9.9")
    assert odd.publish.publisher is None
    assert odd.artifact is None
    assert packument.snapshot("3.0.0-beta.1").artifact is None  # non-https tarball refused


def test_readme_is_dropped_from_manifest(packument: Packument) -> None:
    assert "readme" not in packument.snapshot("1.1.1").manifest


def test_changes_in_window(packument: Packument) -> None:
    changes = packument.changes_in(WINDOW, feed_seq=42)
    assert [c.new.ref.version for c in changes] == ["1.1.1", "2.0.1", "9.9.9", "3.0.0-beta.1"]
    assert changes[0].previous is not None and changes[0].previous.ref.version == "1.1.0"
    assert all(c.feed_seq == 42 for c in changes)
    assert changes[0].repository_url == "https://github.com/example/kx-fixture"


def test_name_mismatch_rejected(load_fixture: Callable[[str], object]) -> None:
    with pytest.raises(PackumentError):
        Packument(load_fixture("npm/packument_basic.json"), expected_name="other")


def test_unpublished_package() -> None:
    doc = {"name": "gone", "time": {"unpublished": {"time": "2026-10-27T00:00:00Z"}}}
    packument = Packument(doc, expected_name="gone")
    assert packument.unpublished
    assert packument.changes_in(WINDOW) == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("git+https://github.com/Owner/Repo.git", "https://github.com/Owner/Repo"),
        ("https://github.com/owner/repo", "https://github.com/owner/repo"),
        ("git://github.com/owner/repo.git", "https://github.com/owner/repo"),
        ("git+ssh://git@github.com/owner/repo.git", "https://github.com/owner/repo"),
        ("git@github.com:owner/repo.git", "https://github.com/owner/repo"),
        ("github:owner/repo", "https://github.com/owner/repo"),
        ("owner/repo", "https://github.com/owner/repo"),
        ("git+https://github.com/o/mono/packages/sub.git", "https://github.com/o/mono"),
        ("https://github.com/o/r#main", "https://github.com/o/r"),
        ("https://gitlab.com/o/r", "https://gitlab.com/o/r"),
        ("   ", None),
    ],
)
def test_normalize_repository_url(raw: str, expected: str | None) -> None:
    assert normalize_repository_url(raw) == expected


@pytest.mark.parametrize("maintainers", [1.0, "alice", {"name": "alice"}, None, [None, 3]])
def test_non_list_maintainers_are_ignored(maintainers: object) -> None:
    # Regression: a float here crashed the whole ingest run (found by fuzzing, 2026-10-27).
    doc = {
        "name": "p",
        "time": {"1.0.0": "2026-10-27T06:00:00Z"},
        "versions": {"1.0.0": {"maintainers": maintainers}},
    }
    (change,) = Packument(doc, expected_name="p").changes_in(WINDOW)
    assert change.new.publish.maintainers == ()


@pytest.mark.parametrize(
    ("publisher", "version", "manifest", "expected"),
    [
        ("npm", "0.0.1-security", {}, True),
        ("npm", "0.0.0-stage", {"stub": True}, True),
        ("npm", "1.2.3", {}, False),  # npm's account publishing a real release
        ("mallory", "0.0.1-security", {"stub": True}, False),  # anyone can pick the version
        (None, "0.0.1-security", {}, False),
        ("alice", "0.0.0-stage", {"stub": True}, True),  # staged-publishing placeholder
        ("alice", "0.0.0-stage", {"stub": True, "scripts": {"postinstall": "x"}}, False),
        ("alice", "1.0.0", {"stub": True}, False),
    ],
)
def test_registry_placeholder(
    publisher: str | None, version: str, manifest: dict[str, object], expected: bool
) -> None:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="x", version=version),
        publish=PublishInfo(publisher=publisher),
        manifest=manifest,
    )
    assert is_registry_placeholder(snapshot) is expected


def test_stub_is_never_a_diff_base() -> None:
    doc = {
        "name": "kx",
        "versions": {
            "0.0.0-stage": {"version": "0.0.0-stage", "stub": True},
            "1.0.0": {"version": "1.0.0"},
            "1.0.1": {"version": "1.0.1"},
            "1.0.2": {"version": "1.0.2", "stub": True},  # publisher-set flag
            "1.0.3": {"version": "1.0.3"},
        },
        "time": {
            "0.0.0-stage": "2026-10-27T00:00:00Z",
            "1.0.0": "2026-10-27T01:00:00Z",
            "1.0.1": "2026-10-27T02:00:00Z",
            "1.0.2": "2026-10-27T03:00:00Z",
            "1.0.3": "2026-10-27T04:00:00Z",
        },
    }
    packument = Packument(doc, expected_name="kx")
    assert packument.previous_version("1.0.0") is None  # first real release: a new package
    assert packument.previous_version("1.0.1") == "1.0.0"
    assert packument.previous_version("1.0.3") == "1.0.1"  # the "stub" is skipped as a base...
    window = Window(
        start=datetime(2026, 10, 27, tzinfo=UTC), end=datetime(2026, 10, 28, tzinfo=UTC)
    )
    assert "1.0.2" in packument.versions_in(window)  # ...but still emitted and analysed


def releases(*rows: tuple[str, int | None, int | None]) -> Packument:
    """A packument of `(version, dist.fileCount, dist.unpackedSize)`, published an hour apart
    in the order given."""
    versions: dict[str, Any] = {}
    times: dict[str, str] = {}
    for hour, (version, files, size) in enumerate(rows):
        dist: dict[str, Any] = {}
        if files is not None:
            dist["fileCount"] = files
        if size is not None:
            dist["unpackedSize"] = size
        versions[version] = {"version": version, "dist": dist}
        times[version] = f"2026-10-29T{hour:02d}:00:00Z"
    return Packument({"name": "kx", "versions": versions, "time": times}, expected_name="kx")


def test_a_partial_publish_is_not_a_diff_base() -> None:
    """`@nutui/nutui-react-taro`: beta.3 shipped 166 of 5,215 files, so beta.4 looked as if it
    had added the build and the postinstall that beta.2 already had."""
    nutui = releases(
        ("3.0.24-beta.2", 5215, None), ("3.0.24-beta.3", 166, None), ("3.0.24-beta.4", 5215, None)
    )
    assert nutui.previous_version("3.0.24-beta.4") == "3.0.24-beta.2"
    assert nutui.previous_version("3.0.24-beta.4", diff_base=1) == "3.0.24-beta.3"  # old runs
    assert nutui.previous_version("3.0.24-beta.3") == "3.0.24-beta.2"  # still analysed itself
    # By unpacked size when a count is missing:
    sized = releases(("1.0.0", None, 900_000), ("1.0.1", None, 80_000), ("1.0.2", None, 900_000))
    assert sized.previous_version("1.0.2") == "1.0.0"


def test_a_large_release_cannot_push_its_diff_base_back() -> None:
    """A release only smaller than the new one is kept: otherwise an attacker could bloat a
    release to skip back to an older version that already had its install script."""
    grown = releases(("1.0.0", 30, None), ("1.1.0", 30, None), ("2.0.0", 4000, None))
    assert grown.previous_version("2.0.0") == "1.1.0"
    tiny = releases(("1.0.0", 12, None), ("1.0.1", 2, None), ("1.0.2", 12, None))
    assert tiny.previous_version("1.0.2") == "1.0.1"  # too small to call anything partial
    flags = releases(("1.0.0", True, None), ("1.0.1", 1, None), ("1.0.2", 500, None))
    assert flags.previous_version("1.0.2") == "1.0.1"  # `true` is not a file count


def test_at_most_a_few_partial_publishes_are_passed_over() -> None:
    rows = [
        ("1.0.0", 500, None),
        *((f"1.0.{i}", 5, None) for i in range(1, 6)),
        ("1.0.6", 500, None),
    ]
    many = releases(*rows)
    # 1.0.5 .. 1.0.1 are partial next to 1.0.6, but each is the size of the one before it
    assert many.previous_version("1.0.6") == "1.0.5"
    rows = [("1.0.0", 500, None), ("1.0.1", 500, None), ("1.0.2", 5, None), ("1.0.3", 500, None)]
    assert releases(*rows).previous_version("1.0.3") == "1.0.1"


def test_a_chain_of_shrinking_releases_keeps_the_usual_diff_base() -> None:
    """Each a quarter of the one before: passing over all of them would reach far back, so
    after `MAX_PARTIAL_SKIPS` the usual choice stands."""
    sizes = (8530, 2130, 530, 130, 30, 9000)
    chain = releases(*((f"1.0.{i}", n, None) for i, n in enumerate(sizes)))
    assert chain.previous_version("1.0.5") == "1.0.4"
    assert chain.previous_version("9.9.9") is None  # no publish time: not in the packument
