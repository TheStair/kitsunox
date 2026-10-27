from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from kitsunox.core.models import Window
from kitsunox.ecosystems.npm.packument import (
    Packument,
    PackumentError,
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
