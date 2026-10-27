from datetime import UTC, datetime, timedelta

from kitsunox.core.models import (
    Change,
    PackageVersionRef,
    Popularity,
    PublishInfo,
    VersionSnapshot,
)
from kitsunox.evaluation.dataset import Label, Shape, build_dataset
from kitsunox.evaluation.labels import AffectedRange, LabelSet, MalwareLabel
from kitsunox.evaluation.metrics import ForwardAll, PopularityOnly, evaluate, render_markdown

FETCHED = datetime(2026, 12, 1, tzinfo=UTC)
OLD = FETCHED - timedelta(days=40)
RECENT = FETCHED - timedelta(days=2)


def snap(name: str, version: str, when: datetime) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
        publish=PublishInfo(published_at=when),
        manifest={},
    )


def change(name: str, version: str, when: datetime, *, new: bool, watched: bool) -> Change:
    popularity = Popularity(source="t", downloads=None, period_days=30, watched=watched)
    return Change(
        new=snap(name, version, when),
        previous=None if new else snap(name, "0.0.1", when - timedelta(days=9)),
        popularity=None if new else popularity,
    )


LABELS = LabelSet(
    ecosystem="npm",
    source="test",
    fetched_at=FETCHED,
    source_sha256="0" * 64,
    labels={
        "typosquat": (
            MalwareLabel(id="MAL-1", published=OLD, ranges=(AffectedRange(introduced="0"),)),
        ),
        "popular-lib": (MalwareLabel(id="MAL-2", published=OLD, versions=("2.0.1",)),),
    },
)


def sample_changes() -> list[tuple[str, Change]]:
    benign = [
        ("run-1", change(f"lib{i}", "1.0.0", OLD, new=False, watched=i % 2 == 0)) for i in range(10)
    ]
    return [
        ("run-1", change("typosquat", "1.0.0", OLD, new=True, watched=False)),
        ("run-1", change("popular-lib", "2.0.1", OLD, new=False, watched=True)),
        ("run-2", change("popular-lib", "2.0.1", OLD, new=False, watched=True)),  # re-emitted
        ("run-1", change("popular-lib", "2.0.0", OLD, new=False, watched=True)),
        ("run-2", change("fresh", "1.0.0", RECENT, new=True, watched=False)),
        *benign,
    ]


def build(per_stratum: int = 3, name: str = "ds") -> object:
    return build_dataset(
        sample_changes(),
        LABELS,
        name=name,
        label_set_sha256="a" * 64,
        built_at=FETCHED,
        benign_per_stratum=per_stratum,
    )


def test_labels_shapes_and_settling() -> None:
    dataset = build()
    malicious = {s.key: s for s in dataset.samples if s.label is Label.MALICIOUS}  # type: ignore[attr-defined]
    assert set(malicious) == {"npm:typosquat@1.0.0", "npm:popular-lib@2.0.1"}
    assert malicious["npm:typosquat@1.0.0"].shape is Shape.B
    assert malicious["npm:popular-lib@2.0.1"].shape is Shape.A
    assert malicious["npm:popular-lib@2.0.1"].run_id == "run-1"  # earliest run wins
    fresh = [s for s in dataset.samples if s.key == "npm:fresh@1.0.0"]  # type: ignore[attr-defined]
    assert fresh and not fresh[0].settled and fresh[0].label is Label.BENIGN


def test_benign_sampling_is_stratified_and_deterministic() -> None:
    first, again = build(per_stratum=2), build(per_stratum=2)
    assert first == again
    benign_a = [s for s in first.samples if s.label is Label.BENIGN and s.shape is Shape.A]  # type: ignore[attr-defined]
    assert sum(s.watched for s in benign_a) == 2 and sum(not s.watched for s in benign_a) == 2
    assert build(per_stratum=2, name="other").samples != first.samples  # type: ignore[attr-defined]


def test_metrics_report_recall_and_pass_through() -> None:
    dataset = build(per_stratum=100)
    changes = {str(c.new.ref): c for _, c in sample_changes()}
    report = evaluate(dataset, "b" * 64, changes, PopularityOnly())  # type: ignore[arg-type]
    cells = {k: (c.total, c.forwarded) for k, c in report.cells.items()}
    assert cells["malicious/A"] == (1, 1)  # popular package hijack: forwarded
    assert cells["malicious/B"] == (1, 0)  # typosquat: popularity alone misses it
    assert cells["benign/all"] == (11, 6)  # 10 lib + popular-lib@2.0.0, 6 watched
    assert cells["benign/B/provisional"] == (1, 0)
    assert "benign/all" in render_markdown(report)
    everything = evaluate(dataset, "b" * 64, changes, ForwardAll())  # type: ignore[arg-type]
    assert everything.cells["malicious/all"].rate == 1.0


def placeholder(name: str, version: str, when: datetime) -> Change:
    return Change(
        new=VersionSnapshot(
            ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
            publish=PublishInfo(published_at=when, publisher="npm", maintainers=("npm",)),
            manifest={"stub": True},
        )
    )


def test_placeholders_and_projected_labels_are_excluded() -> None:
    # The first live run: npm takedown stubs and a legitimate later build both matched
    # open-ended "all versions" ranges and were counted as malware.
    extra = [
        ("run-1", placeholder("typosquat", "0.0.1-security", RECENT)),
        ("run-1", placeholder("typosquat", "0.0.0-stage", RECENT)),
        ("run-1", change("typosquat", "1.0.1", RECENT, new=False, watched=False)),
    ]
    dataset = build_dataset(
        sample_changes() + extra,
        LABELS,
        name="ds",
        label_set_sha256="a" * 64,
        built_at=FETCHED,
    )
    keys = {s.key for s in dataset.samples}
    assert "npm:typosquat@1.0.0" in keys  # published no later than MAL-1: observed
    assert not keys & {f"npm:typosquat@{v}" for v in ("0.0.1-security", "0.0.0-stage", "1.0.1")}
    assert dataset.excluded == {"label-projected": 1, "registry-placeholder": 2}


def test_population_counts_every_benign_candidate() -> None:
    dataset = build(per_stratum=1)
    assert dataset.population == {"A/unwatched": 5, "A/watched": 6, "B/unwatched": 1}  # type: ignore[attr-defined]


def test_pass_through_is_reweighted_to_population() -> None:
    # 1 watched + 1 unwatched sampled per stratum, but 6 watched vs 5 unwatched A in population.
    dataset = build(per_stratum=1)
    changes = {str(c.new.ref): c for _, c in sample_changes()}
    report = evaluate(dataset, "b" * 64, changes, PopularityOnly())  # type: ignore[arg-type]
    assert report.cells["benign/all"].rate == 0.5  # raw sample rate: 1 of 2
    assert report.weighted_pass_through["A"] == 6 / 11
    assert report.weighted_pass_through["all"] == 6 / 12
    assert "re-weighted" in render_markdown(report)
