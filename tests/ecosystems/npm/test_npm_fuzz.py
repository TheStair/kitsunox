"""Property tests for npm parsing: hostile packuments, semver ordering vs. a reference
implementation, and repository URL normalization."""

import contextlib
import re
from datetime import UTC, datetime, timedelta

import semver as reference
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from kitsunox.core.models import Window
from kitsunox.ecosystems.npm import semver
from kitsunox.ecosystems.npm.packument import (
    Packument,
    PackumentError,
    normalize_repository_url,
)

JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=20,
)
BASE = datetime(2026, 10, 27, tzinfo=UTC)
TIMES = st.integers(min_value=-72, max_value=72).map(
    lambda h: (BASE + timedelta(hours=h)).isoformat().replace("+00:00", "Z")
)
VERSIONS = st.sampled_from(
    ["1.0.0", "1.0.1", "1.1.0", "2.0.0", "2.0.0-rc.1", "0.0.1-security", "10.0.0", "bogus", ""]
)
MANIFEST = st.fixed_dictionaries(
    {},
    optional={
        "_npmUser": JSON,
        "maintainers": JSON,
        "dist": st.fixed_dictionaries(
            {},
            optional={
                "tarball": st.text(max_size=30) | st.just("https://r/x.tgz"),
                "integrity": JSON,
                "fileCount": JSON,
                "attestations": JSON,
            },
        )
        | JSON,
        "gitHead": JSON,
        "repository": JSON,
        "scripts": JSON,
        "readme": JSON,
    },
)
PACKUMENT = st.fixed_dictionaries(
    {"name": st.just("pkg")},
    optional={
        "versions": st.dictionaries(VERSIONS, MANIFEST | JSON, max_size=6) | JSON,
        "time": st.dictionaries(VERSIONS | st.text(max_size=8), TIMES | JSON, max_size=8) | JSON,
        "repository": JSON,
    },
)
WINDOW = Window(start=BASE - timedelta(hours=24), end=BASE)


@given(PACKUMENT)
def test_hostile_packuments_never_crash(doc: dict[str, object]) -> None:
    try:
        packument = Packument(doc, expected_name="pkg")
        changes = packument.changes_in(WINDOW)
    except PackumentError:
        return
    except ValidationError as exc:  # pragma: no cover - this is the failure we hunt for
        raise AssertionError(f"model rejected parsed data: {exc}") from exc
    for change in changes:
        published = change.new.publish.published_at
        assert published is not None and WINDOW.contains(published)
        if change.previous is not None:
            before = change.previous.publish.published_at
            assert before is not None and before <= published
            assert change.previous.ref.version != change.new.ref.version
        if change.new.artifact is not None:
            assert change.new.artifact.url.startswith("https://")


@given(JSON)
def test_arbitrary_json_documents_never_crash(doc: object) -> None:
    with contextlib.suppress(PackumentError):
        Packument(doc, expected_name="pkg").changes_in(WINDOW)


SEMVERS = st.builds(
    lambda ma, mi, pa, pre: f"{ma}.{mi}.{pa}" + (f"-{pre}" if pre else ""),
    st.integers(0, 30),
    st.integers(0, 30),
    st.integers(0, 30),
    st.none()
    | st.lists(
        st.integers(0, 20).map(str) | st.sampled_from(["alpha", "beta", "rc", "x-y", "a1"]),
        min_size=1,
        max_size=3,
    ).map(".".join),
)


@given(SEMVERS, SEMVERS)
def test_precedence_matches_reference_implementation(a: str, b: str) -> None:
    ours_a, ours_b = semver.parse(a), semver.parse(b)
    assert ours_a is not None and ours_b is not None
    expected = reference.Version.parse(a).compare(b)
    actual = (ours_a > ours_b) - (ours_a < ours_b)
    assert actual == expected


@given(st.text(max_size=40))
def test_parse_agrees_with_reference_on_validity(text: str) -> None:
    candidate = text.strip().removeprefix("v")
    ours = semver.parse(text)
    try:
        reference.Version.parse(candidate)
        valid = True
    except ValueError, TypeError:
        valid = False
    if ours is not None:
        assert valid, f"we accepted {text!r} but the reference rejects it"


CANONICAL = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@given(st.text(max_size=80))
def test_repository_normalization_never_crashes(raw: str) -> None:
    result = normalize_repository_url(raw)
    if result is not None and result.startswith("https://github.com/") and raw.strip() != result:
        assert CANONICAL.match(result), result


@given(
    st.from_regex(r"[A-Za-z0-9_-]{1,20}", fullmatch=True),
    st.from_regex(r"[A-Za-z0-9_-]{1,20}", fullmatch=True),
    st.sampled_from(
        [
            "git+https://github.com/{o}/{r}.git",
            "https://github.com/{o}/{r}",
            "git://github.com/{o}/{r}.git",
            "git+ssh://git@github.com/{o}/{r}.git",
            "git@github.com:{o}/{r}.git",
            "github:{o}/{r}",
            "{o}/{r}",
            "https://github.com/{o}/{r}/tree/main/packages/x",
        ]
    ),
)
def test_known_github_forms_normalize(owner: str, repo: str, template: str) -> None:
    raw = template.format(o=owner, r=repo)
    assert normalize_repository_url(raw) == f"https://github.com/{owner}/{repo}"
