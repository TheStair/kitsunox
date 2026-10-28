"""DataDog importer against a mocked GitHub, with an inert encrypted fixture."""

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from conftest import FIXTURES, Router
from kitsunox.core.run import DataDir
from kitsunox.evaluation.datadog import API_URL, RAW_URL, parse_sample_path
from kitsunox.evaluation.dataset import Label, Shape
from kitsunox.evaluation.harness import (
    external_store,
    label_store,
    make_dataset,
    make_predictor,
    run_eval,
    sync_datadog,
)
from kitsunox.evaluation.labels import LabelSet
from kitsunox.evaluation.metrics import ForwardAll
from kitsunox.evaluation.static_eval import strip_to_package

COMMIT = "c0ffee" + "0" * 34
GOOD = "compromised_lib/kx-fixture/1.1.0/2026-03-02-kx-fixture-v1.1.0.zip"
BROKEN = "compromised_lib/@kx@broken/1.0.0/2026-03-02-@kx_broken-v1.0.0.zip"
INTENT = "malicious_intent/kx-other/9.9.9/2025-01-01-kx-other-v9.9.9.zip"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (GOOD, (Shape.A, "kx-fixture", "1.1.0", date(2026, 3, 2))),
        (BROKEN, (Shape.A, "@kx/broken", "1.0.0", date(2026, 3, 2))),
        ("malicious_intent/x/1.0.0/undated.zip", (Shape.B, "x", "1.0.0", None)),
    ],
)
def test_parse_sample_path(path: str, expected: tuple[object, ...]) -> None:
    assert parse_sample_path(path) == expected


@pytest.fixture
def github(router: Router) -> Router:
    router.add_json(f"{API_URL}/commits/main", {"sha": COMMIT})
    router.add_json(
        f"{API_URL}/contents/samples/npm?ref={COMMIT}",
        [
            {"name": "compromised_lib", "type": "dir", "sha": "t-a"},
            {"name": "malicious_intent", "type": "dir", "sha": "t-b"},
            {"name": "manifest.json", "type": "file", "sha": "m"},
        ],
    )
    tree_a = [
        {"type": "tree", "path": "kx-fixture"},
        {"type": "blob", "path": GOOD.split("/", 1)[1]},
        {"type": "blob", "path": BROKEN.split("/", 1)[1]},
    ]
    router.add_json(f"{API_URL}/git/trees/t-a?recursive=1", {"tree": tree_a, "truncated": False})
    tree_b = [{"type": "blob", "path": INTENT.split("/", 1)[1]}]
    router.add_json(f"{API_URL}/git/trees/t-b?recursive=1", {"tree": tree_b, "truncated": False})
    router.add_json(f"{RAW_URL}/{COMMIT}/samples/npm/manifest.json", {"kx-fixture": ["1.1.0"]})
    sample = (FIXTURES / "datadog_sample_kx_fixture.zip").read_bytes()
    router.add_bytes(f"{RAW_URL}/{COMMIT}/samples/npm/{GOOD}", sample)
    router.add_bytes(f"{RAW_URL}/{COMMIT}/samples/npm/{BROKEN}", b"not a zip")
    return router


def test_import_builds_changes_and_records_failures(tmp_path: Path, github: Router) -> None:
    data = DataDir(tmp_path)
    limits: dict[str, int | None] = {"compromised_lib": None, "malicious_intent": 0}
    sample_set, path, _ = sync_datadog(
        data, fetched_at=datetime(2026, 10, 27, tzinfo=UTC), limits=limits, client=github.client()
    )
    assert sample_set.id == f"datadog-{COMMIT[:12]}"
    (sample,) = sample_set.samples
    assert sample.shape is Shape.A and sample.discovered == date(2026, 3, 2)
    assert str(sample.change.new.ref) == "npm:kx-fixture@1.1.0"
    assert sample.change.previous is not None
    assert sample.change.previous.ref.version == "1.0.0"
    assert sample.previous_malicious is False  # 1.0.0 is not in the manifest
    assert set(sample_set.failures) == {BROKEN}
    assert "ArchiveError" in sample_set.failures[BROKEN]
    assert not any(INTENT in url for url in github.requests)  # limit 0: never downloaded
    # Zips are kept encrypted, as distributed, in their own store.
    stored = list((tmp_path / "eval" / "malware" / "blobs").glob("??/*.zst"))
    assert stored and not (tmp_path / "blobs").exists()
    assert (path.parent / "snapshots" / f"{sample_set.id}.json").exists()
    assert external_store(data).load("npm", sample_set.id) == sample_set


def test_external_samples_join_datasets_under_their_own_cells(
    tmp_path: Path, github: Router
) -> None:
    data = DataDir(tmp_path)
    limits: dict[str, int | None] = {"compromised_lib": None, "malicious_intent": 0}
    sync_datadog(
        data, fetched_at=datetime(2026, 10, 27, tzinfo=UTC), limits=limits, client=github.client()
    )
    labels = LabelSet(
        ecosystem="npm",
        source="t",
        fetched_at=datetime(2026, 10, 27, tzinfo=UTC),
        source_sha256="0" * 64,
        labels={},
    )
    label_store(data).save("npm", labels.id, labels)
    dataset, _, _ = make_dataset(
        data, ecosystem="npm", name="ext", built_at=datetime(2026, 10, 27, tzinfo=UTC)
    )
    (sample,) = dataset.samples
    assert sample.label is Label.MALICIOUS and sample.source == "datadog"
    assert sample.key == "datadog:npm:kx-fixture@1.1.0"
    report = run_eval(data, ecosystem="npm", dataset_name="ext", predictor=ForwardAll())
    assert set(report.cells) == {"malicious/A/datadog", "malicious/all/datadog"}
    assert json.loads(report.model_dump_json())["cells"]["malicious/A/datadog"]["forwarded"] == 1


@pytest.mark.parametrize(
    ("listed", "follow_on"), [(["1.1.0", "1.0.0"], True), (None, True), (["1.1.0"], False)]
)
def test_follow_on_releases_get_their_own_cell(
    tmp_path: Path, github: Router, listed: list[str] | None, follow_on: bool
) -> None:
    github.add_json(f"{RAW_URL}/{COMMIT}/samples/npm/manifest.json", {"kx-fixture": listed})
    data = DataDir(tmp_path)
    when = datetime(2026, 10, 27, tzinfo=UTC)
    limits: dict[str, int | None] = {"compromised_lib": None, "malicious_intent": 0}
    sample_set, _, _ = sync_datadog(data, fetched_at=when, limits=limits, client=github.client())
    assert [s.previous_malicious for s in sample_set.samples] == [follow_on]
    labels = LabelSet(
        ecosystem="npm", source="t", fetched_at=when, source_sha256="0" * 64, labels={}
    )
    label_store(data).save("npm", labels.id, labels)
    make_dataset(data, ecosystem="npm", name="ext", built_at=when)
    report = run_eval(data, ecosystem="npm", dataset_name="ext", predictor=ForwardAll())
    assert ("malicious/A/datadog/follow-on" in report.cells) is follow_on


def test_strip_to_package() -> None:
    tree = {
        "tmp/x/kx/package/index.js": b"1",
        "tmp/x/kx/package_info-kx.json": b"{}",
        "tmp/x/kx/package/lib/package/a.js": b"2",
    }
    assert strip_to_package(tree) == {"index.js": b"1", "lib/package/a.js": b"2"}


@pytest.mark.parametrize(
    "name", ["stage2-rules", "stage1+2-rules", "pipeline", "stage3-rules", "pipeline+3"]
)
def test_stage2_predictor_reads_files_from_the_encrypted_zip(
    tmp_path: Path, github: Router, name: str
) -> None:
    data = DataDir(tmp_path)
    when = datetime(2026, 10, 27, tzinfo=UTC)
    limits: dict[str, int | None] = {"compromised_lib": None, "malicious_intent": 0}
    sync_datadog(data, fetched_at=when, limits=limits, client=github.client())
    labels = LabelSet(
        ecosystem="npm", source="t", fetched_at=when, source_sha256="0" * 64, labels={}
    )
    label_store(data).save("npm", labels.id, labels)
    make_dataset(data, ecosystem="npm", name="ext", built_at=when)
    predictor = make_predictor(data, "npm", name)
    report = run_eval(data, ecosystem="npm", dataset_name="ext", predictor=predictor)
    # The fixture zip holds only an inert package.json, so nothing fires; the previous
    # version's tarball isn't served by the mock, so the base counts as unavailable.
    assert report.cells["malicious/A/datadog"].forwarded == 0
    notes = predictor.notes  # type: ignore[attr-defined]
    assert notes == {"base unavailable (all files treated as new)": 1} or (
        name.startswith("pipeline") and not notes  # not routed to Stage 2 at all
    )
