"""Live evaluation: a confusion matrix over what the pipeline decided at the time.

`build_live_dataset` joins every run's decision ledger (`evaluation/ledger.py`) with the labels
that arrived later and writes a versioned dataset; `evaluate_live` folds it into matrices.
Definitions are in `docs/evaluation.md` ("Live evaluation"); the owner's decisions behind them
in decision 0019. In short:

- **Population:** each version that entered Stage 4 in a finished run, counted once, in the
  first run that recorded it. Excluded and counted: registry placeholders, OSV matches that
  are only "projected" (decision 0005), `inconclusive` verdicts, and benign versions younger
  than D days at the label set's `fetched_at` (provisional). Versions captured more than
  `CATCH_UP_SPAN` after their release (catch-up runs read them after npm may have removed the
  malware, so their recall is survivor-biased) are reported apart, not in a window.
- **Flagged:** in the run's report as the tick wrote it (a re-score is a secondary, recall-only
  figure).
- **Truth:** *behaviour* (primary): a reviewer verdict wins, then an OSV record; *OSV*
  (alongside): an OSV record wins, then a verdict; *OSV only*: verdicts ignored. npm takedowns
  without an OSV record count only in a sensitivity row. Everything else is benign once
  settled.

Inputs are files with recorded digests: the ledgers, the label set and the label sets before it
(for when a version was first labeled), the takedown log, and the verdict log cut at the label
set's `fetched_at`. The dataset and the metrics are pure functions of them; `as_of` is the
label set's `fetched_at`, never the clock.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from compression import zstd
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal

from pydantic import Field

from kitsunox.core.models import Persisted, Record
from kitsunox.core.retention import HOLD_DAYS, HeldBlob, HoldReason
from kitsunox.core.run import RunManifest
from kitsunox.evaluation.confirmations import TAKEDOWNS_DIR
from kitsunox.evaluation.intervals import Rate, wilson
from kitsunox.evaluation.labels import MalwareLabel
from kitsunox.evaluation.ledger import UNFINISHED_AFTER, Ledger, LedgerRow, ledgers
from kitsunox.evaluation.sample import read_samples, sample_bound
from kitsunox.reporting.markdown import text
from kitsunox.reporting.verdicts import VerdictRecord, current, read_verdicts
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex

DEFAULT_D: Final = 7
D_SENSITIVITY: Final = (3, 7, 14)
CATCH_UP_SPAN: Final = timedelta(hours=6)  # capture (the run's as_of) minus publish

Truth = Literal["behaviour", "osv", "osv-only"]
Cell = Literal["M", "B"]


class LiveWindow(Record):
    """Runs whose `as_of` is in `[start, end)`."""

    name: str
    start: datetime
    end: datetime

    def contains(self, moment: datetime) -> bool:
        return self.start <= moment < self.end


def _day(y: int, m: int, d: int) -> datetime:
    return datetime(y, m, d, tzinfo=UTC)


# Window A: the first week of VM collection with finished runs (mixed rule sets). Window B:
# the owner's rule freeze, 2026-11-12 00:00Z to 2026-11-19 00:00Z (decision 0019).
DEFAULT_WINDOWS: Final = (
    LiveWindow(name="A", start=_day(2026, 10, 29), end=_day(2026, 11, 4)),
    LiveWindow(name="B", start=_day(2026, 11, 12), end=_day(2026, 11, 19)),
)
ALL: Final = "all"
CATCH_UP: Final = "catch-up"


def parse_window(text: str) -> LiveWindow:
    """`NAME:YYYY-MM-DD:YYYY-MM-DD` (start inclusive, end exclusive, UTC days)."""
    name, start, end = text.split(":")
    return LiveWindow(
        name=name,
        start=datetime.fromisoformat(start).replace(tzinfo=UTC),
        end=datetime.fromisoformat(end).replace(tzinfo=UTC),
    )


# --- the dataset ---------------------------------------------------------------------------


class RunInfo(Record):
    as_of: datetime
    window_hours: float
    stage4_version: int | None
    stage4_rules: str | None
    pipeline: str | None = Field(description="The ledger's `pipeline`, as sorted JSON.")
    rescored: bool = False


class LiveInputs(Record):
    label_set: str
    label_set_sha256: str
    label_history: dict[str, str] = Field(description="Earlier label set id -> SHA-256.")
    takedowns_sha256: str | None
    takedowns_scanned_through: str | None
    verdicts_sha256: str = Field(description="SHA-256 of the verdict lines used, in order.")
    verdict_lines: int = Field(description="Verdict lines recorded by `as_of` (used).")
    verdict_lines_total: int
    ledgers: dict[str, str] = Field(description="Ledger file name -> SHA-256.")


class LiveDatasetHeader(Persisted):
    name: str
    ecosystem: str
    as_of: datetime = Field(description="The label set's `fetched_at`.")
    inputs: LiveInputs
    runs: dict[str, RunInfo]
    unfinished: dict[str, int] = Field(
        description="Runs that will never finish (pruned, or older than UNFINISHED_AFTER) -> "
        "changes recorded: the operational loss."
    )
    pending: dict[str, int] = Field(description="Runs whose stages may still finish.")
    samples: int


class LiveSample(Record):
    """One version with every label source attached. Defaults are left out on disk."""

    name: str
    version: str
    run_id: str
    published_at: datetime | None = None
    publisher: str | None = None
    new: bool = False
    watched: bool = False
    hook: bool = False
    placeholder: bool = False
    s1: str = "none"
    s1_forwarded: bool = False
    s2: str = "unread"
    s3: str = "unread"
    score: float = 0.0
    rank: int | None = None
    reported_current: bool | None = Field(
        default=None, description="Reported after a re-score (None: never re-scored)."
    )
    rules: tuple[str, ...] = ()
    tarball: bool = False
    tarball_size: int | None = None
    osv: tuple[str, ...] = Field(default=(), description="Observed OSV MAL- records.")
    projected: bool = False
    osv_published: datetime | None = Field(
        default=None, description="Earliest `published` of the observed records."
    )
    osv_first_set: str | None = Field(
        default=None, description="First label set (by id) that observed it."
    )
    takedown: datetime | None = Field(
        default=None, description="First npm takedown after the release, by `as_of`."
    )
    verdict: str | None = None
    verdict_by: str | None = None
    verdict_at: datetime | None = None
    verdict_tags: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.version)

    @property
    def reported(self) -> bool:
        return self.rank is not None

    @property
    def shape(self) -> str:
        return "B" if self.new else "A"

    @property
    def confirmation_seen(self) -> bool:
        """The verdict was recorded after an OSV record or a takedown was public."""
        seen = [t for t in (self.osv_published, self.takedown) if t is not None]
        return self.verdict_at is not None and bool(seen) and self.verdict_at >= min(seen)


class _Labels:
    """A label set read as raw JSON; records are parsed only for names that are asked for."""

    def __init__(self, data: bytes) -> None:
        raw = json.loads(data)
        self.fetched_at = datetime.fromisoformat(raw["fetched_at"].replace("Z", "+00:00"))
        self.ecosystem: str = raw["ecosystem"]
        self._raw: dict[str, list[object]] = raw["labels"]
        self._parsed: dict[str, tuple[MalwareLabel, ...]] = {}

    def __contains__(self, name: str) -> bool:
        return name in self._raw

    def records(self, name: str) -> tuple[MalwareLabel, ...]:
        if name not in self._parsed:
            self._parsed[name] = tuple(
                MalwareLabel.model_validate(r) for r in self._raw.get(name, ())
            )
        return self._parsed[name]

    def classify(
        self, name: str, version: str, published: datetime | None
    ) -> tuple[list[MalwareLabel], bool]:
        """(observed records, whether any record only projects onto it)."""
        matched = [r for r in self.records(name) if r.affects(version)]
        observed = [r for r in matched if r.observes(version, published)]
        return observed, len(observed) < len(matched)


@dataclass(frozen=True, slots=True)
class LiveSources:
    """Where the inputs are."""

    data_root: Path
    live: Path
    ecosystem: str = "npm"

    @property
    def labels_dir(self) -> Path:
        return self.data_root / "labels" / self.ecosystem

    @property
    def runs(self) -> Path:
        return self.data_root / "runs"

    def label_ids(self) -> list[str]:
        directory = self.labels_dir
        return sorted(p.stem for p in directory.glob("*.json")) if directory.exists() else []


def build_live_dataset(
    sources: LiveSources, *, label_set_id: str | None = None
) -> tuple[LiveDatasetHeader, Path, str]:
    """Join the ledgers with the labels; write `<live>/datasets/live-<labels>.jsonl.zst`.
    Returns the header, the path and its SHA-256."""
    ids = sources.label_ids()
    if not ids:
        raise LookupError("no label set; run `kitsunox labels sync` first")
    chosen = label_set_id or ids[-1]
    if chosen not in ids:
        raise LookupError(f"no label set {chosen}")
    label_bytes = (sources.labels_dir / f"{chosen}.json").read_bytes()
    labels = _Labels(label_bytes)
    as_of = labels.fetched_at
    tick = [lg for lg in ledgers(sources.live) if lg.header.as_of <= as_of]
    rescored = {lg.header.run_id: lg for lg in ledgers(sources.live, "rescored")}
    rescored = {k: v for k, v in rescored.items() if v.header.as_of <= as_of}

    # Pass 1: the versions whose name has a record, for when each was first labeled.
    wanted: dict[tuple[str, str], datetime | None] = {}
    seen: set[tuple[str, str]] = set()
    for lg in tick:
        for row in lg.rows():
            if row.key in seen:
                continue
            seen.add(row.key)
            if row.name in labels:
                wanted[row.key] = row.published_at
    del seen
    first_set, history = _label_history(sources, [i for i in ids if i < chosen], wanted)
    first_set.update(
        {k: chosen for k, p in wanted.items() if k not in first_set and _observed(labels, k, p)}
    )

    takedowns, takedown_sha, scanned = _takedowns(sources, as_of)
    verdicts, verdict_digest, used, total = _verdicts(sources, as_of)
    current_reported = {
        run_id: {row.key for row in lg.rows() if row.reported} for run_id, lg in rescored.items()
    }

    runs = {
        lg.header.run_id: RunInfo(
            as_of=lg.header.as_of,
            window_hours=round(
                (lg.header.window_end - lg.header.window_start).total_seconds() / 3600, 2
            ),
            stage4_version=lg.header.stage4_version,
            stage4_rules=lg.header.stage4_rules,
            pipeline=json.dumps(lg.header.pipeline, sort_keys=True) if lg.header.pipeline else None,
            rescored=lg.header.run_id in rescored,
        )
        for lg in tick
    }
    unfinished, pending = _unfinished(sources, set(runs), as_of)
    name = f"live-{chosen}"
    compressor = zstd.ZstdCompressor(level=10)
    body = bytearray()
    count = 0
    seen = set()
    for lg in tick:
        reported_now = current_reported.get(lg.header.run_id)
        for row in lg.rows():
            if row.key in seen:
                continue
            seen.add(row.key)
            sample = _sample(row, lg, labels, first_set, takedowns, verdicts, reported_now)
            count += 1
            body += compressor.compress(sample.model_dump_json(exclude_defaults=True).encode())
            body += compressor.compress(b"\n")
    header = LiveDatasetHeader(
        name=name,
        ecosystem=labels.ecosystem,
        as_of=as_of,
        inputs=LiveInputs(
            label_set=chosen,
            label_set_sha256=sha256_hex(label_bytes),
            label_history=history,
            takedowns_sha256=takedown_sha,
            takedowns_scanned_through=scanned,
            verdicts_sha256=verdict_digest,
            verdict_lines=used,
            verdict_lines_total=total,
            ledgers={lg.path.name: lg.sha256 for lg in [*tick, *rescored.values()]},
        ),
        runs=runs,
        unfinished=unfinished,
        pending=pending,
        samples=count,
    )
    head = zstd.ZstdCompressor(level=10)
    data = head.compress(header.model_dump_json().encode() + b"\n") + head.flush()
    data += bytes(body) + compressor.flush()
    path = sources.live / "datasets" / f"{name}.jsonl.zst"
    atomic_write(path, data)
    return header, path, sha256_hex(data)


def _observed(labels: _Labels, key: tuple[str, str], published: datetime | None) -> bool:
    return bool(labels.classify(key[0], key[1], published)[0])


def _sample(
    row: LedgerRow,
    lg: Ledger,
    labels: _Labels,
    first_set: Mapping[tuple[str, str], str],
    takedowns: Mapping[str, list[datetime]],
    verdicts: Mapping[tuple[str, str], VerdictRecord],
    reported_now: set[tuple[str, str]] | None,
) -> LiveSample:
    observed, projected = (
        labels.classify(row.name, row.version, row.published_at)
        if row.name in labels
        else ([], False)
    )
    after = [
        t for t in takedowns.get(row.name, ()) if row.published_at is None or t >= row.published_at
    ]
    verdict = verdicts.get(row.key)
    return LiveSample(
        name=row.name,
        version=row.version,
        run_id=lg.header.run_id,
        published_at=row.published_at,
        publisher=row.publisher,
        new=row.new_package,
        watched=row.watched,
        hook=row.hook,
        placeholder=row.placeholder,
        s1=row.s1,
        s1_forwarded=row.s1_forwarded,
        s2=row.s2,
        s3=row.s3,
        score=row.score,
        rank=row.rank,
        reported_current=None if reported_now is None else row.key in reported_now,
        rules=row.rules,
        tarball=row.tarball is not None,
        tarball_size=row.tarball_size,
        osv=tuple(sorted(r.id for r in observed)),
        projected=projected,
        osv_published=min((r.published for r in observed), default=None),
        osv_first_set=first_set.get(row.key) if observed else None,
        takedown=min(after, default=None),
        verdict=verdict.verdict if verdict else None,
        verdict_by=verdict.by if verdict else None,
        verdict_at=verdict.at if verdict else None,
        verdict_tags=tuple(verdict.tags) if verdict else (),
    )


def _label_history(
    sources: LiveSources, earlier: Sequence[str], wanted: Mapping[tuple[str, str], datetime | None]
) -> tuple[dict[tuple[str, str], str], dict[str, str]]:
    """The first earlier label set that observed each wanted version, and every set's digest."""
    first: dict[tuple[str, str], str] = {}
    digests: dict[str, str] = {}
    for label_id in earlier:
        data = (sources.labels_dir / f"{label_id}.json").read_bytes()
        digests[label_id] = sha256_hex(data)
        labels = _Labels(data)
        for key, published in wanted.items():
            if key not in first and key[0] in labels and _observed(labels, key, published):
                first[key] = label_id
        del labels, data
    return first, digests


def _takedowns(
    sources: LiveSources, as_of: datetime
) -> tuple[dict[str, list[datetime]], str | None, str | None]:
    path = sources.data_root / TAKEDOWNS_DIR / f"{sources.ecosystem}.json"
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return {}, None, None
    raw = json.loads(data)
    found: dict[str, list[datetime]] = {}
    for t in raw.get("takedowns", ()):
        when = datetime.fromisoformat(t["published_at"].replace("Z", "+00:00"))
        if when <= as_of:
            found.setdefault(t["name"], []).append(when)
    return found, sha256_hex(data), raw.get("scanned_through")


def _verdicts(
    sources: LiveSources, as_of: datetime
) -> tuple[dict[tuple[str, str], VerdictRecord], str, int, int]:
    records = read_verdicts(sources.data_root, sources.ecosystem)
    used = [r for r in records if r.at <= as_of]
    digest = hashlib.sha256()
    for record in used:
        digest.update(record.model_dump_json().encode() + b"\n")
    return current(used), digest.hexdigest(), len(used), len(records)


def _unfinished(
    sources: LiveSources, ledgered: set[str], as_of: datetime
) -> tuple[dict[str, int], dict[str, int]]:
    lost: dict[str, int] = {}
    pending: dict[str, int] = {}
    if not sources.runs.exists():
        return lost, pending
    for run_dir in sorted(p for p in sources.runs.iterdir() if p.is_dir()):
        if run_dir.name in ledgered or not (run_dir / "manifest.json").exists():
            continue
        try:
            manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
        except ValueError:
            continue
        if manifest.ecosystem != sources.ecosystem or manifest.as_of > as_of:
            continue
        gone = (run_dir / "retention.json").exists() or as_of - manifest.as_of > UNFINISHED_AFTER
        (lost if gone else pending)[manifest.run_id] = manifest.change_count
    return lost, pending


def read_live_dataset(path: Path) -> tuple[LiveDatasetHeader, Iterator[LiveSample]]:
    handle = zstd.open(path, "rb")
    try:
        header = LiveDatasetHeader.load_json(handle.readline())
    except BaseException:
        handle.close()
        raise

    def samples() -> Iterator[LiveSample]:
        with handle:
            for line in handle:
                if line.strip():
                    yield LiveSample.model_validate_json(line)

    return header, samples()


# --- the metrics ---------------------------------------------------------------------------


class Matrix(Record):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    fp_unreviewed: int = Field(default=0, description="FPs presumed benign: no verdict.")
    excluded: dict[str, int] = Field(default_factory=dict)

    @property
    def recall(self) -> Rate:
        return wilson(self.tp, self.tp + self.fn)

    @property
    def precision(self) -> Rate:
        return wilson(self.tp, self.tp + self.fp)

    @property
    def fpr(self) -> Rate:
        return wilson(self.fp, self.fp + self.tn)


@dataclass
class _Matrix:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    fp_unreviewed: int = 0
    excluded: Counter[str] = field(default_factory=Counter)

    def add(self, cell: Cell | str, flagged: bool, reviewed: bool) -> None:
        if cell == "M":
            if flagged:
                self.tp += 1
            else:
                self.fn += 1
        elif cell == "B":
            if flagged:
                self.fp += 1
                self.fp_unreviewed += not reviewed
            else:
                self.tn += 1
        else:
            self.excluded[cell] += 1

    def freeze(self) -> Matrix:
        return Matrix(
            tp=self.tp,
            fp=self.fp,
            fn=self.fn,
            tn=self.tn,
            fp_unreviewed=self.fp_unreviewed,
            excluded=dict(sorted(self.excluded.items())),
        )


def truth(
    sample: LiveSample, mode: Truth, *, settle_by: datetime, weak_takedowns: bool = False
) -> Cell | str:
    """`M`, `B`, or the reason the version is left out (see the module docstring)."""
    if sample.placeholder:
        return "placeholder"
    verdict = None if mode == "osv-only" else sample.verdict
    if mode == "behaviour" and verdict in ("malicious", "benign"):
        return _verdict_cell(verdict)  # an inconclusive verdict leaves it to OSV
    if sample.osv:
        return "M"
    if verdict is not None:
        return _verdict_cell(verdict)
    if sample.projected:
        return "projected"
    if weak_takedowns and sample.takedown is not None:
        return "M"
    published = sample.published_at
    return "B" if published is not None and published <= settle_by else "provisional"


def _verdict_cell(verdict: str) -> Cell | str:
    return "M" if verdict == "malicious" else "B" if verdict == "benign" else "inconclusive"


@dataclass(frozen=True, slots=True)
class _Config:
    name: str
    mode: Truth
    d: int
    weak: bool = False
    current: bool = False  # flagged = reported after a re-score


def configs_for(d: int) -> tuple[_Config, ...]:
    """The matrices of a report whose headline benign delay is `d` days."""
    return (
        _Config("behaviour", "behaviour", d),
        _Config("osv", "osv", d),
        _Config("osv-only", "osv-only", d),
        _Config("behaviour+takedowns", "behaviour", d, weak=True),
        _Config("behaviour/rescored", "behaviour", d, current=True),
        *(_Config(f"behaviour/D{x}", "behaviour", x) for x in D_SENSITIVITY if x != d),
    )


FUNNEL: Final = (
    "entered",
    "s1 rule",
    "s1 forwarded",
    "s2 read",
    "s2 files",
    "s2 flagged",
    "s3 flagged",
    "reported",
)
MISS_CAUSES: Final = (
    "not read by Stage 2",
    "Stage 2 had no files",
    "read, no finding",
    "read, findings below the report bar",
)


def funnel_steps(sample: LiveSample) -> tuple[str, ...]:
    steps = ["entered"]
    if sample.s1 == "rules":
        steps.append("s1 rule")
    if sample.s1_forwarded:
        steps.append("s1 forwarded")
    if sample.s2 != "unread":
        steps.append("s2 read")
    if sample.s2 in ("clear", "flagged"):
        steps.append("s2 files")
    if sample.s2 == "flagged":
        steps.append("s2 flagged")
    if sample.s3 == "flagged":
        steps.append("s3 flagged")
    if sample.reported:
        steps.append("reported")
    return tuple(steps)


def miss_cause(sample: LiveSample) -> str:
    if sample.s2 == "unread":
        return MISS_CAUSES[0]
    if sample.s2 == "no-files":
        return MISS_CAUSES[1]
    return MISS_CAUSES[3] if sample.score > 0 else MISS_CAUSES[2]


class Missed(Record):
    """A labeled-malicious version that wasn't reported, for adjudication."""

    name: str
    version: str
    run_id: str
    shape: str
    cause: str
    osv: tuple[str, ...]
    verdict: str | None
    tarball: bool
    score: float


class Timing(Record):
    n: int
    median_h: float | None
    p75_h: float | None
    max_h: float | None


class RuleSets(Record):
    runs: int
    stage4: dict[str, int] = Field(description="`stage_version/rules` -> runs.")
    pipeline: dict[str, int] = Field(description="Full fingerprint (when recorded) -> runs.")
    unrecorded_pipeline: int = Field(description="Runs whose ledger has no `pipeline`.")
    conflicting_rules: dict[str, list[int]] = Field(
        description="Rules that fired with more than one version."
    )
    single_version: bool


class WindowReport(Record):
    name: str
    start: datetime | None
    end: datetime | None
    versions: int
    matrices: dict[str, Matrix]
    by_shape: dict[str, Matrix] = Field(description="The headline matrix, shape A and B.")
    late_labels: dict[str, int] = Field(
        description="D -> OSV-labeled versions whose record came more than D days after the "
        "release (they would have counted as benign)."
    )
    recall_by_record: Rate
    recall_by_account: Rate
    funnel_malicious: dict[str, dict[str, int]]
    funnel_benign: dict[str, dict[str, int]]
    miss_causes: dict[str, dict[str, int]]
    misses_watched: int
    rules_tp_fp: dict[str, list[int]] = Field(description="Rule id -> [TP, FP] it fired on.")
    verdicts_after_confirmation: int
    rule_sets: RuleSets


class LiveReport(Persisted):
    dataset: str
    dataset_sha256: str
    as_of: datetime
    headline_d: int
    windows: dict[str, WindowReport]
    timing: dict[str, Timing]
    unfinished_runs: int
    unfinished_changes: int
    pending_runs: int
    misses: tuple[Missed, ...]
    malicious: tuple[str, ...] = Field(
        description="`name@version` of every version labeled malicious (headline truth)."
    )
    sample_bound: dict[str, object] = Field(default_factory=dict)


@dataclass
class _Window:
    name: str
    start: datetime | None
    end: datetime | None
    versions: int = 0
    matrices: dict[str, _Matrix] = field(default_factory=dict)
    shapes: dict[str, _Matrix] = field(default_factory=dict)
    late: Counter[str] = field(default_factory=Counter)
    records: dict[str, bool] = field(default_factory=dict)
    accounts: dict[str, bool] = field(default_factory=dict)
    funnel_m: dict[str, Counter[str]] = field(default_factory=dict)
    funnel_b: dict[str, Counter[str]] = field(default_factory=dict)
    causes: dict[str, Counter[str]] = field(default_factory=dict)
    misses_watched: int = 0
    rules: dict[str, list[int]] = field(default_factory=dict)
    confirmed: int = 0
    run_ids: set[str] = field(default_factory=set)
    rule_versions: dict[str, set[int]] = field(default_factory=dict)


def evaluate_live(
    header: LiveDatasetHeader,
    samples: Iterable[LiveSample],
    *,
    dataset_sha256: str,
    windows: Sequence[LiveWindow] = DEFAULT_WINDOWS,
    d: int = DEFAULT_D,
) -> LiveReport:
    """Fold the dataset into a report, one sample at a time."""
    configs = configs_for(d)
    accumulators = [_Window(w.name, w.start, w.end) for w in windows]
    accumulators += [_Window(ALL, None, None), _Window(CATCH_UP, None, None)]
    by_name = {a.name: a for a in accumulators}
    for acc in accumulators:  # every matrix is in the report, empty or not
        acc.matrices = {c.name: _Matrix() for c in configs}
        acc.shapes = {"A": _Matrix(), "B": _Matrix()}
    settle = {c.d: header.as_of - timedelta(days=c.d) for c in configs}
    misses: list[Missed] = []
    malicious: list[str] = []
    timing_rows: dict[str, dict[str, datetime | None]] = {}
    for sample in samples:
        run = header.runs[sample.run_id]
        late = sample.published_at is not None and run.as_of - sample.published_at > CATCH_UP_SPAN
        targets = (
            [by_name[CATCH_UP]]
            if late
            else [by_name[ALL], *(by_name[w.name] for w in windows if w.contains(run.as_of))]
        )
        cells = {
            c.name: truth(sample, c.mode, settle_by=settle[c.d], weak_takedowns=c.weak)
            for c in configs
        }
        headline = cells["behaviour"]
        for acc in targets:
            _add(acc, sample, run, configs, cells, d)
        if headline == "M" and not late:
            malicious.append(f"{sample.name}@{sample.version}")
        if headline == "M" and not late and not sample.reported:
            misses.append(
                Missed(
                    name=sample.name,
                    version=sample.version,
                    run_id=sample.run_id,
                    shape=sample.shape,
                    cause=miss_cause(sample),
                    osv=sample.osv,
                    verdict=sample.verdict,
                    tarball=sample.tarball,
                    score=sample.score,
                )
            )
        if sample.osv and not sample.placeholder:
            for record in sample.osv:
                _timing_add(timing_rows, record, sample, run.as_of)
    return LiveReport(
        dataset=header.name,
        dataset_sha256=dataset_sha256,
        as_of=header.as_of,
        headline_d=d,
        windows={a.name: _freeze(a, header) for a in accumulators},
        timing=_timing(timing_rows),
        unfinished_runs=len(header.unfinished),
        unfinished_changes=sum(header.unfinished.values()),
        pending_runs=len(header.pending),
        misses=tuple(sorted(misses, key=lambda m: (m.run_id, m.name, m.version))),
        malicious=tuple(sorted(malicious)),
    )


def _add(
    acc: _Window,
    sample: LiveSample,
    run: RunInfo,
    configs: Sequence[_Config],
    cells: Mapping[str, Cell | str],
    d: int,
) -> None:
    acc.versions += 1
    acc.run_ids.add(sample.run_id)
    reviewed = sample.verdict is not None
    for c in configs:
        flagged = (
            sample.reported_current
            if c.current and sample.reported_current is not None
            else sample.reported
        )
        acc.matrices.setdefault(c.name, _Matrix()).add(cells[c.name], flagged, reviewed)
    headline = cells["behaviour"]
    acc.shapes.setdefault(sample.shape, _Matrix()).add(headline, sample.reported, reviewed)
    for rule in sample.rules:
        rule_id, _, rest = rule.partition("@")
        version = rest.split(":", 1)[0]
        if version.isdigit():
            acc.rule_versions.setdefault(rule_id, set()).add(int(version))
    if headline not in ("M", "B"):
        return
    funnel = acc.funnel_m if headline == "M" else acc.funnel_b
    for shape in (sample.shape, ALL):
        funnel.setdefault(shape, Counter()).update(funnel_steps(sample))
    if sample.verdict in ("malicious", "benign") and sample.confirmation_seen:
        acc.confirmed += 1
    if sample.reported:
        column = 0 if headline == "M" else 1
        for rule_id in dict.fromkeys(r.split("@", 1)[0] for r in sample.rules):
            acc.rules.setdefault(rule_id, [0, 0])[column] += 1
    if headline != "M":
        return
    for record in sample.osv:
        acc.records[record] = acc.records.get(record, False) or sample.reported
    account = sample.publisher or "(unknown)"
    acc.accounts[account] = acc.accounts.get(account, False) or sample.reported
    if sample.osv and sample.published_at is not None and sample.osv_published is not None:
        lag = sample.osv_published - sample.published_at
        for days in D_SENSITIVITY:
            if lag > timedelta(days=days):
                acc.late[f"D{days}"] += 1
    if not sample.reported:
        kind = "new" if sample.new else "update"
        acc.causes.setdefault(miss_cause(sample), Counter())[kind] += 1
        acc.misses_watched += sample.watched


def _freeze(acc: _Window, header: LiveDatasetHeader) -> WindowReport:
    runs = [header.runs[r] for r in sorted(acc.run_ids)]
    stage4 = Counter(f"{r.stage4_version}/{r.stage4_rules}" for r in runs)
    pipeline = Counter(r.pipeline for r in runs if r.pipeline)
    conflicts = {k: sorted(v) for k, v in sorted(acc.rule_versions.items()) if len(v) > 1}
    return WindowReport(
        name=acc.name,
        start=acc.start,
        end=acc.end,
        versions=acc.versions,
        matrices={k: m.freeze() for k, m in acc.matrices.items()},
        by_shape={k: m.freeze() for k, m in sorted(acc.shapes.items())},
        late_labels={f"D{d}": acc.late[f"D{d}"] for d in D_SENSITIVITY},
        recall_by_record=wilson(sum(acc.records.values()), len(acc.records)),
        recall_by_account=wilson(sum(acc.accounts.values()), len(acc.accounts)),
        funnel_malicious={k: {s: v[s] for s in FUNNEL} for k, v in sorted(acc.funnel_m.items())},
        funnel_benign={k: {s: v[s] for s in FUNNEL} for k, v in sorted(acc.funnel_b.items())},
        miss_causes={
            c: dict(sorted(acc.causes[c].items())) for c in MISS_CAUSES if c in acc.causes
        },
        misses_watched=acc.misses_watched,
        rules_tp_fp=dict(sorted(acc.rules.items())),
        verdicts_after_confirmation=acc.confirmed,
        rule_sets=RuleSets(
            runs=len(runs),
            stage4=dict(sorted(stage4.items())),
            pipeline=dict(sorted(pipeline.items())),
            unrecorded_pipeline=sum(1 for r in runs if not r.pipeline),
            conflicting_rules=conflicts,
            single_version=len(stage4) <= 1 and len(pipeline) <= 1 and not conflicts,
        ),
    )


def _timing_add(
    rows: dict[str, dict[str, datetime | None]], record: str, sample: LiveSample, capture: datetime
) -> None:
    row = rows.setdefault(
        record,
        {
            "capture": capture,
            "publish": sample.published_at,
            "osv": sample.osv_published,
            "first_set": _set_time(sample.osv_first_set),
            "takedown": sample.takedown,
        },
    )
    for key, value in (
        ("capture", capture),
        ("publish", sample.published_at),
        ("takedown", sample.takedown),
    ):
        old = row[key]
        if value is not None and (old is None or value < old):
            row[key] = value
    first = _set_time(sample.osv_first_set)
    if first is not None and (row["first_set"] is None or first < row["first_set"]):
        row["first_set"] = first


def _set_time(label_id: str | None) -> datetime | None:
    if label_id is None:
        return None
    return datetime.strptime(label_id, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


TIMINGS: Final = (
    ("publish -> capture", "publish", "capture"),
    ("capture -> OSV published", "capture", "osv"),
    ("capture -> first label set with it", "capture", "first_set"),
    ("capture -> npm takedown", "capture", "takedown"),
)


def _timing(rows: Mapping[str, Mapping[str, datetime | None]]) -> dict[str, Timing]:
    """Per OSV record, from its versions' earliest capture (a run's `as_of`)."""
    result = {}
    for label, start, end in TIMINGS:
        hours = sorted(
            (b - a).total_seconds() / 3600
            for row in rows.values()
            if (a := row[start]) is not None and (b := row[end]) is not None
        )
        result[label] = _stats(hours)
    return result


def _stats(values: Sequence[float]) -> Timing:
    if not values:
        return Timing(n=0, median_h=None, p75_h=None, max_h=None)
    n = len(values)
    middle = (values[(n - 1) // 2] + values[n // 2]) / 2
    return Timing(
        n=n,
        median_h=round(middle, 1),
        p75_h=round(values[min(n - 1, math.ceil(0.75 * n) - 1)], 1),
        max_h=round(values[-1], 1),
    )


# --- output --------------------------------------------------------------------------------


def _pct(rate: Rate) -> str:
    if rate.value is None or rate.low is None or rate.high is None:
        return "n/a"
    return f"{rate.value:.1%} [{rate.low:.1%}-{rate.high:.1%}]"


MATRIX_TITLES: Final = {
    "behaviour": "Behaviour truth (verdict wins; headline)",
    "osv": "OSV truth (OSV wins; verdict-only malicious kept)",
    "osv-only": "OSV only (verdicts ignored)",
    "behaviour+takedowns": "Behaviour truth + takedowns as weak positives (sensitivity)",
    "behaviour/rescored": "Behaviour truth, flagged = current report after re-scores (recall)",
}


def render_live_markdown(report: LiveReport) -> str:
    """The report as Markdown; rule ids and fingerprints are escaped as untrusted text."""
    out = [
        f"# Live evaluation `{report.dataset}`",
        "",
        f"Labels as of {report.as_of:%Y-%m-%d %H:%MZ}; headline benign delay D = "
        f"{report.headline_d} days; dataset sha256 `{report.dataset_sha256[:16]}`.",
        f"Operational loss: {report.unfinished_runs} runs that never finished "
        f"({report.unfinished_changes:,} changes); {report.pending_runs} runs still pending.",
    ]
    for window in report.windows.values():
        if window.versions == 0:
            continue
        span = (
            f" ({window.start:%Y-%m-%d} to {window.end:%Y-%m-%d}, end exclusive)"
            if window.start and window.end
            else ""
        )
        out += ["", f"## Window {window.name}{span}", "", f"{window.versions:,} versions."]
        out += [
            "",
            "| Matrix | TP | FP | FN | TN | Recall | Precision | FP rate | Excluded |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for key, m in window.matrices.items():
            title = MATRIX_TITLES.get(key, key.replace("behaviour/D", "Behaviour truth, D = "))
            excluded = ", ".join(f"{k} {v:,}" for k, v in m.excluded.items()) or "-"
            out.append(
                f"| {title} | {m.tp:,} | {m.fp:,} ({m.fp_unreviewed:,} unreviewed) | {m.fn:,} "
                f"| {m.tn:,} | {_pct(m.recall)} | {_pct(m.precision)} | {_pct(m.fpr)} "
                f"| {excluded} |"
            )
        out += [
            "",
            "| Shape | TP | FP | FN | TN | Recall | Precision |",
            "|---|---|---|---|---|---|---|",
        ]
        for shape, m in window.by_shape.items():
            out.append(
                f"| {shape} | {m.tp:,} | {m.fp:,} | {m.fn:,} | {m.tn:,} | {_pct(m.recall)} "
                f"| {_pct(m.precision)} |"
            )
        out += [
            "",
            f"Recall by unit: version {_pct(window.matrices['behaviour'].recall)}, "
            f"OSV record {_pct(window.recall_by_record)}, "
            f"publisher account {_pct(window.recall_by_account)}.",
            "Labels later than D days after the release: "
            + ", ".join(f"{k} {v}" for k, v in window.late_labels.items())
            + f". Verdicts recorded after a confirmation was public: "
            f"{window.verdicts_after_confirmation}.",
            "",
            "| Funnel | " + " | ".join(FUNNEL) + " |",
            "|---|" + "---|" * len(FUNNEL),
        ]
        for label, funnel in (
            ("malicious", window.funnel_malicious),
            ("benign", window.funnel_benign),
        ):
            for shape, steps in funnel.items():
                out.append(
                    f"| {label} {shape} | " + " | ".join(f"{steps[s]:,}" for s in FUNNEL) + " |"
                )
        if window.miss_causes:
            out += ["", "| Why missed | New | Update |", "|---|---|---|"]
            for cause, kinds in window.miss_causes.items():
                out.append(f"| {cause} | {kinds.get('new', 0)} | {kinds.get('update', 0)} |")
            out.append(f"\n{window.misses_watched} of the misses are watched packages.")
        sets = window.rule_sets
        out += [
            "",
            f"Rule sets: {sets.runs} runs; Stage 4 "
            + ", ".join(f"{text(k)} x{v}" for k, v in sets.stage4.items())
            + f"; full fingerprints recorded for {sets.runs - sets.unrecorded_pipeline} runs "
            f"({len(sets.pipeline)} distinct); rules with more than one version: "
            + (", ".join(f"{text(k)} {v}" for k, v in sets.conflicting_rules.items()) or "none")
            + f". **Single rule version: {'yes' if sets.single_version else 'no'}.**",
        ]
        if window.rules_tp_fp:
            top = sorted(window.rules_tp_fp.items(), key=lambda kv: (-kv[1][0] - kv[1][1], kv[0]))
            out += ["", "| Rule | TP | FP |", "|---|---|---|"]
            out += [f"| {text(k)} | {tp} | {fp} |" for k, (tp, fp) in top[:20]]
    out += [
        "",
        "## Label timing (per OSV record, hours)",
        "",
        "| Interval | n | median | p75 | max |",
        "|---|---|---|---|---|",
    ]
    for label, t in report.timing.items():
        out.append(f"| {label} | {t.n} | {t.median_h} | {t.p75_h} | {t.max_h} |")
    if any(isinstance(g, dict) and g.get("days") for g in report.sample_bound.values()):
        out += _sample_lines(report.sample_bound)
    out += [
        "",
        f"{len(report.misses)} labeled-malicious versions were not reported "
        "(`kitsunox live misses` lists them for adjudication).",
    ]
    return "\n".join(out) + "\n"


def _sample_lines(bound: Mapping[str, object]) -> list[str]:
    """The review sample's upper bounds on unlabeled malware (`sample.sample_bound`)."""
    out = [
        "",
        "## Review sample: malware nobody labeled (95% upper bounds)",
        "",
        "| Group | Stratum | Population | Sampled | Reviewed | Malicious | Upper bound |",
        "|---|---|---|---|---|---|---|",
    ]
    for group, raw in bound.items():
        if not isinstance(raw, dict) or not raw.get("days"):
            continue
        strata = raw.get("strata")
        for name, b in (strata if isinstance(strata, dict) else {}).items():
            upper = b.get("upper")
            out.append(
                f"| {group} | {name} | {b.get('population', 0):,} | {b.get('sampled', 0)} "
                f"| {b.get('reviewed', 0)} | {b.get('malicious', 0)} "
                f"| {'n/a' if upper is None else f'{upper:.2%}'} |"
            )
        share = raw.get("upper_share")
        if isinstance(share, float):
            out.append(
                f"| {group} | weighted | | | | | {share:.2%} (≤ {raw.get('upper_versions')} "
                "versions) |"
            )
    return out


class LogLine(Record):
    """One line of `<live>/log.jsonl` per build."""

    built_at: datetime
    dataset: str
    dataset_sha256: str
    label_set: str
    versions: int
    malicious: int
    reported_malicious: int
    recall: float | None
    precision: float | None
    newly_labeled: int = Field(description="Malicious versions not in the previous build.")
    newly_reported: int = Field(default=0, description="Of those, how many were reported.")
    sample_unreviewed: int = Field(
        default=0, description="Sampled versions with no verdict yet (any time)."
    )


def live_paths(live: Path, dataset: str) -> tuple[Path, Path]:
    return live / "reports" / f"{dataset}.json", live / "reports" / f"{dataset}.md"


def write_live_report(
    live: Path,
    report: LiveReport,
    markdown: str,
    *,
    built_at: datetime,
    sample_unreviewed: int = 0,
) -> LogLine:
    """Write the report and its Markdown, and append a line to the results log (skipped when
    the same dataset was logged last)."""
    json_path, md_path = live_paths(live, report.dataset)
    atomic_write(md_path, markdown.encode())
    headline = report.windows[ALL].matrices["behaviour"]
    malicious = headline.tp + headline.fn
    log_path = live / "log.jsonl"
    previous = read_log(log_path)
    known = _malicious_keys(live, previous[-1].dataset) if previous else set()
    new = set(report.malicious) - known
    missed = {f"{m.name}@{m.version}" for m in report.misses}
    atomic_write(json_path, report.model_dump_json(indent=2).encode() + b"\n")
    line = LogLine(
        built_at=built_at,
        dataset=report.dataset,
        dataset_sha256=report.dataset_sha256,
        label_set=report.dataset.removeprefix("live-"),
        versions=report.windows[ALL].versions,
        malicious=malicious,
        reported_malicious=headline.tp,
        recall=headline.recall.value,
        precision=headline.precision.value,
        newly_labeled=len(new),
        newly_reported=len(new - missed),
        sample_unreviewed=sample_unreviewed,
    )
    if not previous or previous[-1].dataset_sha256 != line.dataset_sha256:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line.model_dump_json() + "\n")
    return line


def _malicious_keys(live: Path, dataset: str) -> set[str]:
    """Versions labeled malicious (headline truth) in a dataset's report."""
    path = live_paths(live, dataset)[0]
    try:
        return set(LiveReport.load_json(path.read_bytes()).malicious)
    except OSError, ValueError:
        return set()


def read_log(path: Path) -> list[LogLine]:
    if not path.exists():
        return []
    lines = []
    for raw in path.read_bytes().splitlines():
        try:
            lines.append(LogLine.model_validate_json(raw))
        except ValueError:
            continue
    return lines


def run_live_eval(
    sources: LiveSources,
    *,
    built_at: datetime,
    label_set_id: str | None = None,
    windows: Sequence[LiveWindow] = DEFAULT_WINDOWS,
    d: int = DEFAULT_D,
) -> tuple[LiveReport, LogLine, Path]:
    """Build the dataset, evaluate it, write the report, its Markdown and a log line.
    `built_at` only goes into the log."""
    header, path, sha = build_live_dataset(sources, label_set_id=label_set_id)
    _, samples = read_live_dataset(path)
    report = evaluate_live(header, samples, dataset_sha256=sha, windows=windows, d=d)
    bound = sample_bound(
        read_samples(sources.live),
        _verdicts(sources, header.as_of)[0],
        {w.name: (w.start.date(), w.end.date()) for w in windows},
    )
    report = report.model_copy(update={"sample_bound": bound})
    reviewed = current(read_verdicts(sources.data_root, sources.ecosystem))
    unreviewed = sum(
        (v.name, v.version) not in reviewed for s in read_samples(sources.live) for v in s.versions
    )
    line = write_live_report(
        sources.live,
        report,
        render_live_markdown(report),
        built_at=built_at,
        sample_unreviewed=unreviewed,
    )
    return report, line, path


def hold_requests(data_root: Path, live: Path) -> list[tuple[str, HeldBlob]]:
    """What live evaluation asks the label hold (`core.retention`) to keep: the tarballs (and
    diff bases) of reported versions in runs not pruned yet, of the review samples, and, for
    good, of every version the newest live report labels malicious."""
    runs = data_root / "runs"
    labeled: set[str] = set()
    entries = read_log(live / "log.jsonl")
    if entries:
        try:
            report = LiveReport.load_json(live_paths(live, entries[-1].dataset)[0].read_bytes())
            labeled = set(report.malicious)
        except OSError, ValueError:
            labeled = set()
    found: list[tuple[str, HeldBlob]] = []

    def add(
        sha: str | None,
        size: int | None,
        why: HoldReason,
        ref: str,
        run_id: str,
        until: datetime | None,
    ) -> None:
        if sha is not None:
            found.append(
                (sha, HeldBlob(until=until, size=size or 0, reason=why, ref=ref, run_id=run_id))
            )

    for lg in ledgers(live):
        header = lg.header
        recent = not (runs / header.run_id / "retention.json").exists()
        if not (recent or labeled):
            continue
        until = header.as_of + timedelta(days=HOLD_DAYS)
        for row in lg.rows():
            ref = f"{row.name}@{row.version}"
            why: HoldReason | None = (
                "labeled" if ref in labeled else "reported" if recent and row.reported else None
            )
            if why is None:
                continue
            keep = None if why == "labeled" else until
            add(row.tarball, row.tarball_size, why, ref, header.run_id, keep)
            add(row.base_tarball, row.base_tarball_size, why, ref, header.run_id, keep)
    for sample in read_samples(live):
        until = datetime(sample.day.year, sample.day.month, sample.day.day, tzinfo=UTC)
        for v in sample.versions:
            ref = f"{v.name}@{v.version}"
            add(
                v.tarball,
                v.tarball_size,
                "sample",
                ref,
                v.run_id,
                until + timedelta(days=HOLD_DAYS),
            )
            add(v.base_tarball, None, "sample", ref, v.run_id, until + timedelta(days=HOLD_DAYS))
    return found
