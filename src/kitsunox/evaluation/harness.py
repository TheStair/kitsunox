"""Glue between the evaluation pieces and the data directory.

labels/<ecosystem>/<id>.json        LabelSet, one per `labels sync`
eval/external/<ecosystem>/<id>.json ExternalSampleSet (e.g. datadog-<commit>); its HTTP
                                    snapshot is in snapshots/<id>.json beside it
eval/malware/                       encrypted sample zips as distributed (own blob store)
eval/datasets/<ecosystem>/<name>.json
eval/reports/<ecosystem>/<dataset>--<predictor>.json
"""

from __future__ import annotations

import re
import tempfile
from datetime import datetime
from pathlib import Path

import httpx

from kitsunox.core.run import DataDir
from kitsunox.core.store import RecordStore
from kitsunox.core.watchlist import Watchlist
from kitsunox.evaluation.datadog import fetch_datadog
from kitsunox.evaluation.dataset import (
    EvalDataset,
    ExternalSampleSet,
    build_dataset,
    iter_run_changes,
    load_sample_changes,
)
from kitsunox.evaluation.labels import OSV_MAX_DOWNLOAD, LabelSet, fetch_label_set, label_store
from kitsunox.evaluation.metrics import PREDICTORS, EvalReport, Predictor, evaluate
from kitsunox.evaluation.static_eval import (
    CodeRules,
    Correlated,
    Pipeline,
    PipelineWithCode,
    StaticAndMetadataRules,
    StaticRules,
)
from kitsunox.stages.ingest import changes_file
from kitsunox.util.http import BlobStore, FetchMode, HttpFetcher, Snapshot

_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def dataset_store(data: DataDir) -> RecordStore[EvalDataset]:
    return RecordStore(data.root / "eval" / "datasets", EvalDataset)


def report_store(data: DataDir) -> RecordStore[EvalReport]:
    return RecordStore(data.root / "eval" / "reports", EvalReport)


def external_store(data: DataDir) -> RecordStore[ExternalSampleSet]:
    return RecordStore(data.root / "eval" / "external", ExternalSampleSet)


def sync_datadog(
    data: DataDir,
    *,
    fetched_at: datetime,
    limits: dict[str, int | None],
    client: httpx.Client | None = None,
) -> tuple[ExternalSampleSet, Path, str]:
    """Import DataDog npm samples. Zips go to `eval/malware/` (still encrypted); the snapshot is
    saved next to the set so it can be rebuilt offline."""
    malware = data.root / "eval" / "malware"
    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=BlobStore(malware / "blobs"),
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=malware / "http-immutable",
        client=client,
    )
    watchlist = _latest_watchlist(data, "npm")
    try:
        sample_set = fetch_datadog(
            fetcher, fetched_at=fetched_at, limits=limits, watchlist=watchlist
        )
    finally:
        fetcher.close()
    store = external_store(data)
    path, sha = store.save(sample_set.ecosystem, sample_set.id, sample_set)
    snapshot.save(path.parent / "snapshots" / f"{sample_set.id}.json")
    return sample_set, path, sha


def _latest_watchlist(data: DataDir, ecosystem: str) -> Watchlist | None:
    watchlist_id = data.watchlists.latest_id(ecosystem)
    return data.watchlists.load(ecosystem, watchlist_id) if watchlist_id else None


def _external_sets(data: DataDir, ecosystem: str) -> list[ExternalSampleSet]:
    directory = external_store(data).root / ecosystem
    if not directory.exists():
        return []
    ids = sorted(p.stem for p in directory.glob("*.json"))
    return [external_store(data).load(ecosystem, i) for i in ids]


def sync_labels(
    data: DataDir, *, ecosystem: str, fetched_at: datetime, client: httpx.Client | None = None
) -> tuple[LabelSet, Path, str]:
    """Download the OSV export and save the malware labels. The raw zip is discarded."""
    with tempfile.TemporaryDirectory(prefix="kitsunox-labels-") as tmp:
        fetcher = HttpFetcher(
            store=BlobStore(Path(tmp)),
            snapshot=Snapshot(),
            mode=FetchMode.RECORD,
            client=client,
            max_bytes=OSV_MAX_DOWNLOAD,
        )
        try:
            labels = fetch_label_set(fetcher, ecosystem=ecosystem, fetched_at=fetched_at)
        finally:
            fetcher.close()
    path, sha = label_store(data).save(ecosystem, labels.id, labels)
    return labels, path, sha


def make_dataset(
    data: DataDir,
    *,
    ecosystem: str,
    name: str,
    built_at: datetime,
    label_set_id: str | None = None,
    runs: list[str] | None = None,
    benign_per_stratum: int = 500,
    min_benign_age_days: int = 30,
) -> tuple[EvalDataset, Path, str]:
    """Join recorded runs (default: all of this ecosystem's runs) against a label set (default:
    the newest) and save the dataset."""
    if not _SAFE_NAME.fullmatch(name):
        raise ValueError(f"dataset name {name!r} must match {_SAFE_NAME.pattern}")
    labels_id = label_set_id or label_store(data).latest_id(ecosystem)
    if labels_id is None:
        raise LookupError(f"no {ecosystem} label set; run `kitsunox labels sync` first")
    labels_sha = label_store(data).sha256(ecosystem, labels_id)
    labels = label_store(data).load(ecosystem, labels_id, sha256=labels_sha)
    runs_root = data.root / "runs"
    run_ids = runs if runs is not None else _runs_for(runs_root, ecosystem)
    dataset = build_dataset(
        iter_run_changes(runs_root, run_ids),
        labels,
        name=name,
        label_set_sha256=labels_sha,
        built_at=built_at,
        benign_per_stratum=benign_per_stratum,
        min_benign_age_days=min_benign_age_days,
        external=_external_sets(data, ecosystem),
    )
    path, sha = dataset_store(data).save(ecosystem, name, dataset)
    return dataset, path, sha


FILE_PREDICTORS = (
    StaticRules,
    StaticAndMetadataRules,
    Pipeline,
    CodeRules,
    PipelineWithCode,
    Correlated,
)
PREDICTOR_NAMES = (*PREDICTORS, *(p.name for p in FILE_PREDICTORS))


def make_predictor(data: DataDir, ecosystem: str, name: str) -> Predictor:
    """Predictors by name. Stage 2 ones need the data directory to find package files."""
    if name in PREDICTORS:
        return PREDICTORS[name]()
    for cls in FILE_PREDICTORS:
        if cls.name == name:
            return cls(data, _external_sets(data, ecosystem))
    raise KeyError(name)


def run_eval(
    data: DataDir, *, ecosystem: str, dataset_name: str, predictor: Predictor
) -> EvalReport:
    store = dataset_store(data)
    sha = store.sha256(ecosystem, dataset_name)
    dataset = store.load(ecosystem, dataset_name, sha256=sha)
    changes = load_sample_changes(data.root / "runs", dataset, _external_sets(data, ecosystem))
    report = evaluate(dataset, sha, changes, predictor)
    report_store(data).save(ecosystem, f"{dataset_name}--{predictor.name}", report)
    return report


def _runs_for(runs_root: Path, ecosystem: str) -> list[str]:
    if not runs_root.exists():
        return []
    return sorted(
        p.name
        for p in runs_root.iterdir()
        if p.name.endswith(f"-{ecosystem}") and changes_file(p).exists()
    )
