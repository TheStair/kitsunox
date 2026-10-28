from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from conftest import PUBLISHED, Router, mal, osv_zip
from kitsunox.core.run import DataDir
from kitsunox.evaluation.harness import sync_labels
from kitsunox.evaluation.labels import (
    OSV_EXPORT_URL,
    AffectedRange,
    LabelSet,
    MalwareLabel,
    label_store,
    parse_osv_export,
)

ALL_VERSIONS = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}


@pytest.mark.parametrize(
    ("label", "version", "expected"),
    [
        (MalwareLabel(id="M", published=datetime.now(UTC), versions=("1.0.0",)), "1.0.0", True),
        (MalwareLabel(id="M", published=datetime.now(UTC), versions=("1.0.0",)), "1.0.1", False),
        (
            MalwareLabel(
                id="M",
                published=datetime.now(UTC),
                ranges=(AffectedRange(introduced="2.0.0", fixed="2.0.3"),),
            ),
            "2.0.2",
            True,
        ),
        (
            MalwareLabel(
                id="M",
                published=datetime.now(UTC),
                ranges=(AffectedRange(introduced="2.0.0", fixed="2.0.3"),),
            ),
            "2.0.3",
            False,
        ),
        (
            MalwareLabel(
                id="M",
                published=datetime.now(UTC),
                ranges=(AffectedRange(introduced="1.0.0", last_affected="1.2.0"),),
            ),
            "1.2.0",
            True,
        ),
        (
            MalwareLabel(
                id="M", published=datetime.now(UTC), ranges=(AffectedRange(introduced="0"),)
            ),
            "not-semver",
            False,  # ranges need a parseable version; explicit lists don't
        ),
    ],
)
def test_affects(label: MalwareLabel, version: str, expected: bool) -> None:
    assert label.affects(version) is expected


def test_parse_osv_export_keeps_only_valid_npm_malware() -> None:
    data = osv_zip(
        {
            "MAL-2026-1.json": mal("MAL-2026-1", "evil-pkg", **ALL_VERSIONS),
            "MAL-2026-2.json": mal("MAL-2026-2", "hijacked", versions=["4.2.1", 7]),
            "MAL-2026-3.json": {**mal("MAL-2026-3", "oops", **ALL_VERSIONS), "withdrawn": "x"},
            "MAL-2026-4.json": mal("MAL-2026-4", "pypi-thing", **ALL_VERSIONS)
            | {"affected": [{"package": {"name": "p", "ecosystem": "PyPI"}, **ALL_VERSIONS}]},
            "MAL-2026-5.json": "{not json",
            "MAL-2026-6.json": {"id": 5, "published": PUBLISHED},
            "GHSA-xxxx.json": mal("GHSA-xxxx", "vuln-only", **ALL_VERSIONS),
            "MAL-2026-7.json": mal(
                "MAL-2026-7",
                "ranged",
                ranges=[
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.0.2"},
                            {"introduced": "3.0.0"},
                        ],
                    }
                ],
            ),
        }
    )
    labels = parse_osv_export(data, ecosystem="npm")
    assert list(labels) == ["evil-pkg", "hijacked", "ranged"]
    assert labels["evil-pkg"][0].all_versions
    assert labels["hijacked"][0].versions == ("4.2.1",)  # non-string version dropped
    ranged = labels["ranged"][0]
    assert ranged.affects("1.0.1") and not ranged.affects("1.0.2")
    assert ranged.affects("3.5.0") and not ranged.affects("2.0.0")


def test_sync_labels_saves_hash_pinned_set(tmp_path, router: Router) -> None:  # type: ignore[no-untyped-def]
    router.add_bytes(
        OSV_EXPORT_URL.format(ecosystem="npm"),
        osv_zip({"MAL-2026-1.json": mal("MAL-2026-1", "evil-pkg", **ALL_VERSIONS)}),
    )
    data = DataDir(tmp_path)
    fetched = datetime(2026, 10, 27, 21, tzinfo=UTC)
    labels, _path, sha = sync_labels(
        data, ecosystem="npm", fetched_at=fetched, client=router.client()
    )
    assert labels.id == "20261027T210000Z"
    assert labels.match("evil-pkg", "9.9.9") == ("MAL-2026-1",)
    assert labels.match("evil-pkg-not", "1.0.0") == ()
    assert label_store(data).load("npm", labels.id, sha256=sha) == labels
    assert not (tmp_path / "blobs").exists()


JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=12),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=10), children, max_size=4)
    ),
    max_leaves=25,
)
EVENTS = st.lists(
    st.dictionaries(
        st.sampled_from(["introduced", "fixed", "last_affected", "limit"]),
        st.sampled_from(["0", "1.0.0", "2.0.0", "x"]) | JSON,
        max_size=2,
    ),
    max_size=4,
)
RECORDS = st.fixed_dictionaries(
    {"id": st.just("MAL-1") | JSON, "published": st.just(PUBLISHED) | JSON},
    optional={
        "withdrawn": JSON,
        "affected": st.lists(
            st.fixed_dictionaries(
                {"package": st.just({"name": "p", "ecosystem": "npm"}) | JSON},
                optional={
                    "versions": JSON | st.lists(st.text(max_size=8)),
                    "ranges": st.lists(
                        st.fixed_dictionaries(
                            {"type": st.sampled_from(["SEMVER", "ECOSYSTEM", "GIT"]) | JSON},
                            optional={"events": EVENTS | JSON},
                        )
                    )
                    | JSON,
                },
            )
            | JSON,
            max_size=3,
        )
        | JSON,
    },
)


@given(st.lists(RECORDS | JSON, max_size=4), st.text(max_size=10))
def test_hostile_osv_records_never_crash(records: list[object], version: str) -> None:
    data = osv_zip({f"MAL-{i}.json": r for i, r in enumerate(records)})
    labels = parse_osv_export(data, ecosystem="npm")
    for name, entries in labels.items():
        assert isinstance(name, str)
        for label in entries:
            label.affects(version)  # must not raise for any version string


RECORD = datetime(2026, 10, 1, tzinfo=UTC)
BEFORE, AFTER = datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 10, 20, tzinfo=UTC)


@pytest.mark.parametrize(
    ("label", "published_at", "observed"),
    [
        (
            MalwareLabel(id="M", published=RECORD, ranges=(AffectedRange(introduced="0"),)),
            BEFORE,
            True,
        ),
        (
            MalwareLabel(id="M", published=RECORD, ranges=(AffectedRange(introduced="0"),)),
            AFTER,
            False,
        ),
        (
            MalwareLabel(id="M", published=RECORD, ranges=(AffectedRange(introduced="0"),)),
            None,
            False,
        ),
        (MalwareLabel(id="M", published=RECORD, versions=("1.0.0",)), AFTER, True),
        (
            MalwareLabel(
                id="M", published=RECORD, ranges=(AffectedRange(introduced="0", fixed="2.0.0"),)
            ),
            AFTER,
            True,
        ),
        (MalwareLabel(id="M", published=RECORD, versions=("9.9.9",)), BEFORE, False),
    ],
)
def test_open_ranges_only_observe_earlier_releases(
    label: MalwareLabel, published_at: datetime | None, observed: bool
) -> None:
    assert label.observes("1.0.0", published_at) is observed


def test_classify_splits_observed_and_projected() -> None:
    labels = LabelSet(
        ecosystem="npm",
        source="t",
        fetched_at=AFTER,
        source_sha256="0" * 64,
        labels={
            "pkg": (
                MalwareLabel(id="MAL-A", published=RECORD, ranges=(AffectedRange(introduced="0"),)),
                MalwareLabel(id="MAL-B", published=RECORD, versions=("1.0.0",)),
            )
        },
    )
    assert labels.classify("pkg", "1.0.0", AFTER) == (("MAL-B",), ("MAL-A",))
    assert labels.classify("pkg", "1.0.1", AFTER) == ((), ("MAL-A",))
    assert labels.classify("pkg", "1.0.1", BEFORE) == (("MAL-A",), ())
