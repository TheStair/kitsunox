"""Score a forwarding decision against an evaluation dataset.

A `Predictor` answers the one question every stage answers: forward this change to the next,
more expensive stage, or clear it? Stage 1 will plug in as a predictor; until then, baselines
show what the pipeline's policy does with no detection at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

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
    dataset: str
    dataset_sha256: str
    predictor: str
    cells: dict[str, Cell]
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
    return EvalReport(
        dataset=dataset.name,
        dataset_sha256=dataset_sha256,
        predictor=predictor.name,
        cells={k: Cell(total=t, forwarded=f) for k, (t, f) in sorted(tallies.items())},
        forwarded=tuple(sorted(forwarded)),
    )


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
    return "\n".join(rows) + "\n"
