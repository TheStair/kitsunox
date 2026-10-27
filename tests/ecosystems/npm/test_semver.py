import pytest

from kitsunox.ecosystems.npm.semver import SemVer, parse


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1.2.3", SemVer(1, 2, 3)),
        ("v1.2.3", SemVer(1, 2, 3)),
        ("1.0.0-alpha.1", SemVer(1, 0, 0, ("alpha", 1))),
        ("1.0.0+build.5", SemVer(1, 0, 0)),
        ("01.2.3", None),
        ("1.2", None),
        ("1.2.3-", None),
        ("latest", None),
    ],
)
def test_parse(text: str, expected: SemVer | None) -> None:
    assert parse(text) == expected


def test_precedence_follows_semver_spec() -> None:
    # Ordering example from semver.org section 11.
    ordered = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.1.0",
        "2.0.0",
    ]
    parsed = [parse(v) for v in ordered]
    assert all(p is not None for p in parsed)
    assert sorted(parsed, key=lambda p: p or SemVer(0, 0, 0)) == parsed
