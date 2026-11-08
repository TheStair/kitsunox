from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from kitsunox.core.models import PackageVersionRef, PublishInfo, VersionSnapshot, Window
from kitsunox.ecosystems.npm.packument import (
    Packument,
    PackumentError,
    commit_line,
    is_registry_placeholder,
    is_security_holder,
    normalize_repository_url,
    platform_build,
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


@pytest.mark.parametrize(
    ("publisher", "version", "expected"),
    [
        ("npm", "0.0.1-security", True),
        ("npm", "0.0.0-stage", False),  # staged publishing, not a takedown
        ("mallory", "0.0.1-security", False),  # anyone can pick the version string
        (None, "0.0.1-security", False),
    ],
)
def test_security_holder(publisher: str | None, version: str, expected: bool) -> None:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="x", version=version),
        publish=PublishInfo(publisher=publisher),
        manifest={},
    )
    assert is_security_holder(snapshot) is expected


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


def test_a_platform_build_is_not_a_release_s_diff_base() -> None:
    """`@ozyman42/ozy-cli@0.5.4` was diffed against `0.5.4-latest-windows-x64`, published just
    before it with one platform's binary and no postinstall."""
    ozy = releases(("0.5.3", 40, None), ("0.5.4-latest-windows-x64", 30, None), ("0.5.4", 40, None))
    assert ozy.previous_version("0.5.4") == "0.5.3"
    assert ozy.previous_version("0.5.4", diff_base=2) == "0.5.4-latest-windows-x64"  # old runs
    assert ozy.previous_version("0.5.4-latest-windows-x64") == "0.5.3"  # still analysed itself
    daily = releases(
        ("0.2.19-daily.20261029", 9, None),
        ("0.2.19-daily.20261029.win32-x64", 9, None),
        ("0.2.19-daily.20261030", 9, None),
    )
    assert daily.previous_version("0.2.19-daily.20261030") == "0.2.19-daily.20261029"
    ohos = releases(
        ("0.2.19-daily.20261030", 9, None),
        ("0.2.19-daily.20261030.ohos-arm64", 9, None),
        ("0.2.19-daily.20261031", 9, None),
    )
    assert ohos.previous_version("0.2.19-daily.20261031") == "0.2.19-daily.20261030"
    assert (  # diff base 3 runs replay as recorded
        ohos.previous_version("0.2.19-daily.20261031", diff_base=3)
        == "0.2.19-daily.20261030.ohos-arm64"
    )
    only = releases(("0.1.0-linux-x64", 30, None), ("0.1.0", 40, None))
    assert only.previous_version("0.1.0") == "0.1.0-linux-x64"  # nothing else to diff against


@pytest.mark.parametrize(
    ("version", "build"),
    [
        ("0.1.19-linux-x64", True),
        ("0.3.8-darwin-x64", True),
        ("0.2.19-daily.20261029.win32-x64", True),
        ("1.0.0-macos-arm64.2", True),
        ("0.2.19-daily.20261030.ohos-arm64", True),
        ("1.0.0", False),
        ("1.0.0-beta.1", False),
        ("1.0.0-linux", False),  # an OS alone: a release line, not a build
        ("1.0.0+linux-x64", False),  # build metadata isn't a prerelease
    ],
)
def test_platform_build(version: str, build: bool) -> None:
    assert platform_build(version) is build


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


def published(*versions: str, manifests: dict[str, dict[str, Any]] | None = None) -> Packument:
    """A packument of `versions`, published an hour apart in the order given."""
    extra = manifests or {}
    doc = {
        "name": "kx",
        "versions": {v: {"version": v, **extra.get(v, {})} for v in versions},
        "time": {v: f"2026-10-29T{hour:02d}:00:00Z" for hour, v in enumerate(versions)},
    }
    return Packument(doc, expected_name="kx")


def test_a_commit_named_canary_is_diffed_against_the_canary_before_it() -> None:
    """`@astryxdesign/cli@0.7.6-canary.2936b07` was diffed against `0.7.6-canary.2782f99`, the
    canary whose hash sorts just below it, not the one published before it."""
    canaries = published(
        "0.7.5",
        "0.7.6-canary.2782f99",
        "0.7.6-canary.f29e90e",
        "0.7.6-canary.0bd3b37",
        "0.7.6-canary.2936b07",
    )
    assert canaries.previous_version("0.7.6-canary.2936b07") == "0.7.6-canary.0bd3b37"
    assert canaries.previous_version("0.7.6-canary.0bd3b37") == "0.7.6-canary.f29e90e"
    assert canaries.previous_version("0.7.6-canary.2782f99") == "0.7.5"  # first on its line
    # Runs recorded with diff base 4 replay with the base they had:
    assert canaries.previous_version("0.7.6-canary.2936b07", diff_base=4) == "0.7.6-canary.2782f99"
    assert canaries.previous_version("0.7.6-canary.0bd3b37", diff_base=4) == "0.7.5"


def test_each_channel_is_its_own_line() -> None:
    """`create-strapi-app` publishes `0.0.0-experimental.<sha>` and `0.0.0-next.<sha>`."""
    sha = "7150f4afc4d03e57c3b9e774a308edb31990ee70"
    channels = published(
        f"0.0.0-experimental.{sha}",
        "0.0.0-next.7ad8a01310d1599e990489b87a37503e766d4c54",
        "0.0.0-experimental.1e43302fbe9572b7275aedb547333dbf5c71d599",
        "0.0.0-next.a38539834b739bad1b681f690f384a9e6068d727",
    )
    assert (
        channels.previous_version("0.0.0-experimental.1e43302fbe9572b7275aedb547333dbf5c71d599")
        == f"0.0.0-experimental.{sha}"
    )
    assert (
        channels.previous_version("0.0.0-next.a38539834b739bad1b681f690f384a9e6068d727")
        == "0.0.0-next.7ad8a01310d1599e990489b87a37503e766d4c54"
    )


def test_stable_releases_and_other_cores_keep_the_usual_base() -> None:
    mixed = published(
        "1.1.8",
        "1.1.9-canary.e098c93",
        "1.1.9",
        "1.2.0-canary.8915c17",
        "1.1.9-canary.2911f40",  # a late canary of 1.1.9, after 1.1.9 itself
        "1.2.0",
        "1.2.0-canary.11f9079",
    )
    assert mixed.previous_version("1.1.9") == "1.1.9-canary.e098c93"  # not a commit line
    assert mixed.previous_version("1.2.0-canary.8915c17") == "1.1.9"  # first of 1.2.0's line
    assert mixed.previous_version("1.1.9-canary.2911f40") == "1.1.9-canary.e098c93"
    assert mixed.previous_version("1.2.0") == "1.2.0-canary.8915c17"
    # The stable release isn't on the line (it isn't a prerelease of 1.2.0):
    assert mixed.previous_version("1.2.0-canary.11f9079") == "1.2.0-canary.8915c17"


def test_a_numbered_part_before_the_commit_stays_in_the_line() -> None:
    """`@jonaskahn/relo@0.2.1-beta.60.90c6f7c6`: the build number already sorts."""
    numbered = published("0.2.1-beta.59.2f8fb615", "0.2.1-beta.60.90c6f7c6")
    assert numbered.previous_version("0.2.1-beta.60.90c6f7c6") == "0.2.1-beta.59.2f8fb615"
    hyphen = published(
        "0.14.3-dev-0105e1a.0", "0.14.3-dev-d4b32f1.0", "0.14.3-dev-0110e2a.0.0110e2a"
    )  # `@agoric/xsnap`: the commit id inside a hyphenated part
    assert hyphen.previous_version("0.14.3-dev-0110e2a.0.0110e2a") == "0.14.3-dev-d4b32f1.0"
    assert hyphen.previous_version("0.14.3-dev-0110e2a.0.0110e2a", diff_base=4) == (
        "0.14.3-dev-0105e1a.0"
    )


def test_a_malicious_canary_still_shows_what_it_added() -> None:
    """A canary that adds a postinstall is diffed against the clean canary published before
    it, so the hook reads as added; under diff base 4 its hash sorted lowest and it was
    diffed against the stable release (also clean). A second malicious canary is diffed
    against the first, as any release is against the one before it: the first is the one
    reported, and install-hook rules that read the new version alone still fire on both."""
    hook = {"scripts": {"postinstall": "node x.js"}}
    line = published(
        "2.0.0",
        "2.0.1-canary.fa3f760",
        "2.0.1-canary.1010d4c",
        "2.0.1-canary.c39a5b1",
        manifests={"2.0.1-canary.1010d4c": hook, "2.0.1-canary.c39a5b1": hook},
    )
    base = line.previous_version("2.0.1-canary.1010d4c")
    assert base == "2.0.1-canary.fa3f760"
    assert "scripts" not in line.versions[base]
    assert line.previous_version("2.0.1-canary.1010d4c", diff_base=4) == "2.0.0"
    assert line.previous_version("2.0.1-canary.c39a5b1") == "2.0.1-canary.1010d4c"


def test_the_line_passes_over_stubs_platform_builds_and_partial_publishes() -> None:
    line = published(
        "3.0.0-dev.aaaa111",
        "3.0.0-dev.bbbb222",
        "3.0.0-dev.cccc333.linux-x64",
        "3.0.0-dev.dddd444",
        "3.0.0-dev.eeee555",
        manifests={
            "3.0.0-dev.aaaa111": {"dist": {"fileCount": 400}},
            "3.0.0-dev.bbbb222": {"dist": {"fileCount": 400}},
            "3.0.0-dev.dddd444": {"stub": True},
            "3.0.0-dev.eeee555": {"dist": {"fileCount": 400}},
        },
    )
    assert line.previous_version("3.0.0-dev.eeee555") == "3.0.0-dev.bbbb222"
    small = published(
        "3.0.0-dev.aaaa111",
        "3.0.0-dev.bbbb222",
        "3.0.0-dev.cccc333",
        manifests={
            "3.0.0-dev.aaaa111": {"dist": {"fileCount": 400}},
            "3.0.0-dev.bbbb222": {"dist": {"fileCount": 9}},
            "3.0.0-dev.cccc333": {"dist": {"fileCount": 400}},
        },
    )
    assert small.previous_version("3.0.0-dev.cccc333") == "3.0.0-dev.aaaa111"


@pytest.mark.parametrize(
    ("version", "line"),
    [
        ("0.7.6-canary.2936b07", ((0, 7, 6), "canary.")),
        ("1.0.0-741727bc1", ((1, 0, 0), "")),
        ("0.14.3-dev-12a46af.0.12a46af", ((0, 14, 3), "dev-")),
        ("0.2.1-beta.60.90c6f7c6", ((0, 2, 1), "beta.60.")),
        ("1.0.0-nightly-2e4cf78-20261030", ((1, 0, 0), "nightly-")),
        ("1.0.0-x." + "ab12" * 10, ((1, 0, 0), "x.")),  # 40 hex digits: a full SHA-1
        ("1.0.0-x." + "ab12" * 10 + "a", None),  # 41: not a commit id
        ("1.0.0-canary.abc123", None),  # 6 digits: too short
        ("1.0.0-nightly.20261031", None),  # all digits: a build number or a date
        ("1.0.0-nightly-8627589-20261104", None),  # an all-digit hash can't be told apart
        ("1.0.0-canary.deadbee", None),  # letters only
        ("1.0.0-canary.ABC1234", None),  # git prints commit ids in lowercase
        ("1.0.0-nightly.gdba95ce", None),  # `git describe`'s g prefix: not a bare id
        ("1.0.0+2936b07", None),  # build metadata isn't a prerelease
        ("1.0.0", None),
        ("not-a-version", None),
    ],
)
def test_commit_line(version: str, line: tuple[tuple[int, int, int], str] | None) -> None:
    assert commit_line(version) == line
