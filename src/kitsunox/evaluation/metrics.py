"""Score a forwarding decision against an evaluation dataset.

A `Predictor` answers the one question every stage answers: forward this change to the next,
more expensive stage, or clear it? Stage 1 will plug in as a predictor; until then, baselines
show what the pipeline's policy does with no detection at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from pydantic import Field

from kitsunox.core.models import Change, Persisted, Record
from kitsunox.evaluation.dataset import EvalDataset, Label


class Predictor(Protocol):
    name: str

    def forward(self, change: Change) -> bool: ...


class ForwardAll:
    """Upper bound on recall and worst case for cost: every change goes on."""

    name = "forward-all"

    def forward(self, change: Change) -> bool:
        return True


class PopularityOnly:
    """The watchlist half of the forward policy (roadmap decision 3) with no Stage 1 signals:
    what popularity alone would send to the tarball stages."""

    name = "popularity-only"

    def forward(self, change: Change) -> bool:
        return bool(change.popularity and change.popularity.watched)


PREDICTORS: dict[str, type[ForwardAll] | type[PopularityOnly]] = {
    ForwardAll.name: ForwardAll,
    PopularityOnly.name: PopularityOnly,
}


class Cell(Record):
    total: int = 0
    forwarded: int = 0

    @property
    def rate(self) -> float | None:
        return self.forwarded / self.total if self.total else None


class EvalReport(Persisted):
    SCHEMA_VERSION = 2
    schema_version: int = 2

    dataset: str
    dataset_sha256: str
    predictor: str
    cells: dict[str, Cell]
    weighted_pass_through: dict[str, float] = Field(
        description="Benign pass-through re-weighted to the real stratum sizes, by shape and "
        "'all'. Counts provisional samples too."
    )
    forwarded: tuple[str, ...]


def evaluate(
    dataset: EvalDataset,
    dataset_sha256: str,
    changes: Mapping[str, Change],
    predictor: Predictor,
) -> EvalReport:
    """Cells are keyed `<label>/<shape>[/provisional]`, plus `<label>/all` rollups (settled
    samples only for benign, since provisional benign labels may still flip)."""
    tallies: dict[str, list[int]] = {}
    strata: dict[str, list[int]] = {}
    forwarded: list[str] = []

    def add(key: str, hit: bool) -> None:
        cell = tallies.setdefault(key, [0, 0])
        cell[0] += 1
        cell[1] += hit

    for sample in dataset.samples:
        hit = predictor.forward(changes[sample.key])
        if hit:
            forwarded.append(sample.key)
        suffix = "" if sample.settled else "/provisional"
        add(f"{sample.label}/{sample.shape}{suffix}", hit)
        if sample.settled:
            add(f"{sample.label}/all", hit)
        if sample.label is Label.BENIGN:
            tally = strata.setdefault(sample.stratum, [0, 0])
            tally[0] += 1
            tally[1] += hit
    return EvalReport(
        dataset=dataset.name,
        dataset_sha256=dataset_sha256,
        predictor=predictor.name,
        cells={k: Cell(total=t, forwarded=f) for k, (t, f) in sorted(tallies.items())},
        weighted_pass_through=_reweight(strata, dataset.population),
        forwarded=tuple(sorted(forwarded)),
    )


def _reweight(strata: Mapping[str, list[int]], population: Mapping[str, int]) -> dict[str, float]:
    """Benign strata are sampled equally (500 watched, 500 unwatched), but in the population
    unwatched releases far outnumber watched ones; the raw sample rate would overstate the
    pass-through of anything that forwards watched packages. Estimate each group's rate as the
    population-weighted mean of its strata's sample rates."""
    groups: dict[str, list[str]] = {"all": sorted(strata)}
    for key in strata:
        groups.setdefault(key.split("/")[0], []).append(key)
    result = {}
    for group, keys in sorted(groups.items()):
        weight = sum(population.get(k, 0) for k in keys)
        if weight:
            result[group] = (
                sum(population.get(k, 0) * strata[k][1] / strata[k][0] for k in keys) / weight
            )
    return result


def render_markdown(report: EvalReport) -> str:
    rows = [
        f"Predictor `{report.predictor}` on dataset `{report.dataset}` "
        f"(sha256 `{report.dataset_sha256[:12]}`)",
        "",
        "| Cell | Samples | Forwarded | Rate | Meaning |",
        "|---|---|---|---|---|",
    ]
    for key, cell in report.cells.items():
        rate = "n/a" if cell.rate is None else f"{cell.rate:.1%}"
        meaning = "recall" if key.startswith(Label.MALICIOUS) else "pass-through"
        if key.endswith("/provisional"):
            meaning += " (provisional labels)"
        rows.append(f"| {key} | {cell.total} | {cell.forwarded} | {rate} | {meaning} |")
    if report.weighted_pass_through:
        rows += ["", "Benign pass-through re-weighted to stratum sizes (includes provisional):", ""]
        rows += [f"- {k}: {v:.1%}" for k, v in report.weighted_pass_through.items()]
    return "\n".join(rows) + "\n"
