"""Evaluation datasets built from our own ingest runs.

A sample is a `Change` we recorded, labeled by joining it against a `LabelSet`:

- **malicious**: an OSV MAL record covers the exact release. Because npm removes malicious
  versions quickly, these only exist for releases an ingest run captured before the takedown
  ("prospective labeling"), so the set grows as ingest runs regularly.
- **benign**: no record covers it. Only *settled* once the label set was fetched at least
  `min_benign_age_days` after the release (a malicious release may not be reported yet);
  younger ones are kept but marked provisional, and metrics report them separately.

Some releases are neither, and are left out (counted in `EvalDataset.excluded`):

- **registry-placeholder**: the registry's own stand-in for a removed package (npm's
  `0.0.1-security` stubs). OSV's "all versions" ranges match them, but they hold no attacker code.
- **label-projected**: matched only by an open-ended OSV range from a record published before the
  release (see `MalwareLabel.observes`). The record is a guess about this release, not evidence.

Benign samples are a deterministic stratified sample: within each (shape, watched) stratum,
candidates are ordered by a hash of (dataset name, release) and the first N are taken. Strata
are sampled equally, not in proportion, so `population` records each stratum's real size and
metrics re-weight by it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path

from pydantic import Field

from kitsunox.core.models import Change, PackageVersionRef, Persisted, Record, VersionSnapshot
from kitsunox.ecosystems.npm.packument import is_security_placeholder
from kitsunox.evaluation.labels import LabelSet
from kitsunox.stages.ingest import changes_file, read_changes
from kitsunox.util.hashing import sha256_hex


class Label(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"


class Shape(StrEnum):
    """Threat-model attack shapes: A = new version of an existing package, B = new package."""

    A = "A"
    B = "B"


REGISTRY_PLACEHOLDER: dict[str, Callable[[VersionSnapshot], bool]] = {
    "npm": is_security_placeholder
}


def _never(_: VersionSnapshot) -> bool:
    return False


def stratum(shape: Shape, watched: bool) -> str:
    return f"{shape}/{'watched' if watched else 'unwatched'}"


class EvalSample(Record):
    ref: PackageVersionRef
    run_id: str
    label: Label
    shape: Shape
    watched: bool
    settled: bool
    label_ids: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return str(self.ref)

    @property
    def stratum(self) -> str:
        return stratum(self.shape, self.watched)


class EvalDataset(Persisted):
    SCHEMA_VERSION = 2
    schema_version: int = 2

    name: str
    ecosystem: str
    built_at: datetime
    label_set_id: str
    label_set_sha256: str
    runs: tuple[str, ...]
    min_benign_age_days: int
    benign_per_stratum: int
    samples: tuple[EvalSample, ...]
    population: dict[str, int] = Field(
        description="Benign candidates per stratum before sampling, for re-weighting."
    )
    excluded: dict[str, int] = Field(description="Releases left out, by reason.")

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for s in self.samples:
            key = f"{s.label}/{s.shape}" + ("" if s.settled else "/provisional")
            result[key] = result.get(key, 0) + 1
        return dict(sorted(result.items()))


def iter_run_changes(runs_root: Path, run_ids: Iterable[str]) -> Iterable[tuple[str, Change]]:
    for run_id in sorted(run_ids):
        for change in read_changes(changes_file(runs_root / run_id)):
            yield run_id, change


def build_dataset(
    changes: Iterable[tuple[str, Change]],
    labels: LabelSet,
    *,
    name: str,
    label_set_sha256: str,
    built_at: datetime,
    benign_per_stratum: int = 500,
    min_benign_age_days: int = 30,
) -> EvalDataset:
    first_seen: dict[str, tuple[str, Change]] = {}
    for run_id, change in changes:
        first_seen.setdefault(str(change.new.ref), (run_id, change))  # earliest run wins

    malicious: list[EvalSample] = []
    benign_by_stratum: dict[tuple[Shape, bool], list[EvalSample]] = {}
    excluded: dict[str, int] = {}
    settle_by = labels.fetched_at - timedelta(days=min_benign_age_days)
    is_placeholder = REGISTRY_PLACEHOLDER.get(labels.ecosystem, _never)
    for run_id, change in first_seen.values():
        ref = change.new.ref
        shape = Shape.B if change.is_new_package else Shape.A
        watched = bool(change.popularity and change.popularity.watched)
        published = change.new.publish.published_at
        label_ids, projected = labels.classify(ref.name, ref.version, published)
        reason = (
            "registry-placeholder"
            if is_placeholder(change.new)
            else "label-projected"
            if projected and not label_ids
            else None
        )
        if reason:
            excluded[reason] = excluded.get(reason, 0) + 1
            continue
        if label_ids:
            malicious.append(
                EvalSample(
                    ref=ref,
                    run_id=run_id,
                    label=Label.MALICIOUS,
                    shape=shape,
                    watched=watched,
                    settled=True,
                    label_ids=label_ids,
                )
            )
            continue
        settled = published is not None and published <= settle_by
        sample = EvalSample(
            ref=ref,
            run_id=run_id,
            label=Label.BENIGN,
            shape=shape,
            watched=watched,
            settled=settled,
        )
        benign_by_stratum.setdefault((shape, watched), []).append(sample)

    benign: list[EvalSample] = []
    for _, candidates in sorted(benign_by_stratum.items()):
        ordered = sorted(candidates, key=lambda s: sha256_hex(f"{name}\n{s.key}".encode()))
        benign.extend(ordered[:benign_per_stratum])

    samples = sorted(malicious + benign, key=lambda s: (s.label, s.key))
    return EvalDataset(
        name=name,
        ecosystem=labels.ecosystem,
        built_at=built_at,
        label_set_id=labels.id,
        label_set_sha256=label_set_sha256,
        runs=tuple(sorted({s.run_id for s in samples} | {r for r, _ in first_seen.values()})),
        min_benign_age_days=min_benign_age_days,
        benign_per_stratum=benign_per_stratum,
        samples=tuple(samples),
        population={stratum(*k): len(v) for k, v in sorted(benign_by_stratum.items())},
        excluded=dict(sorted(excluded.items())),
    )


def load_sample_changes(runs_root: Path, dataset: EvalDataset) -> Mapping[str, Change]:
    """The recorded Change for every sample, keyed by `EvalSample.key`."""
    wanted: dict[str, set[str]] = {}
    for sample in dataset.samples:
        wanted.setdefault(sample.run_id, set()).add(sample.key)
    found: dict[str, Change] = {}
    for run_id, keys in wanted.items():
        for change in read_changes(changes_file(runs_root / run_id)):
            key = str(change.new.ref)
            if key in keys:
                found.setdefault(key, change)
    missing = {s.key for s in dataset.samples} - found.keys()
    if missing:
        raise LookupError(f"{len(missing)} samples missing from their runs, e.g. {min(missing)}")
    return found
