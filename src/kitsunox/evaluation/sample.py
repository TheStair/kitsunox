"""The daily review sample of unreported versions: an upper bound on the malware nobody labeled.

External labels only find misses that someone else found. To bound the rest, a reviewer reads
a small, **label-blind** sample of each day's unreported versions (proposal §3, decision 0019).
The sample is a pure function of the day's ledgers: within each stratum, versions are ordered
by `sha256("live-sample\\n" + day + "\\n" + ref)` and the first `n` are kept. No label, verdict
or clock is read to choose them.

| Stratum | Unreported versions | Per day |
|---|---|---|
| U1 | score > 0 | 20 |
| U2 | score 0, a new package or an install hook, not watched | 20 |
| U3 | everything else | 15 |

A day's sample is written once, to `<live>/sample/<day>.json` (and a Markdown review list),
when no run of that day can still finish, and never rewritten. Verdicts on sampled versions go
to the ordinary verdict log with **rank 0** (`kitsunox live verdict`): the version is in no
report. `sample_bound` turns the reviewed sample into a per-stratum upper bound.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Final

from pydantic import Field

from kitsunox.core.models import Persisted, Record, Severity
from kitsunox.core.run import RunManifest
from kitsunox.evaluation.intervals import wilson, zero_bound
from kitsunox.evaluation.ledger import (
    UNFINISHED_AFTER,
    Ledger,
    LedgerHeader,
    LedgerRow,
    ledger_path,
    ledgers,
    read_ledger,
)
from kitsunox.reporting.markdown import text
from kitsunox.reporting.verdicts import (
    FLAG_WORTHY,
    MAX_NOTE_CHARS,
    SEEN,
    Reason,
    Tag,
    Verdict,
    VerdictRecord,
    check_verdict,
)
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex

SAMPLE_DIR: Final = "sample"
SAMPLE_SIZES: Final[Mapping[str, int]] = {"U1": 20, "U2": 20, "U3": 15}
STRATA: Final = {
    "U1": "unreported, score > 0",
    "U2": "unreported, score 0, new package or install hook, unwatched",
    "U3": "unreported, everything else",
}


def stratum(row: LedgerRow) -> str | None:
    """The row's stratum; None for reported versions and registry placeholders."""
    if row.reported or row.placeholder:
        return None
    if row.score > 0:
        return "U1"
    if (row.new_package or row.hook) and not row.watched:
        return "U2"
    return "U3"


def order_key(day: date, ecosystem: str, name: str, version: str) -> str:
    return sha256_hex(f"live-sample\n{day.isoformat()}\n{ecosystem}:{name}@{version}".encode())


class SampledVersion(Record):
    stratum: str
    run_id: str
    name: str
    version: str
    score: float
    new: bool
    hook: bool
    watched: bool
    rules: tuple[str, ...] = ()
    tarball: str | None = None
    tarball_size: int | None = None
    base_tarball: str | None = None


class DailySample(Persisted):
    day: date
    ecosystem: str
    sizes: dict[str, int]
    ledgers: dict[str, str] = Field(description="Ledger file -> SHA-256 the sample was drawn from.")
    population: dict[str, int] = Field(description="Unreported versions per stratum that day.")
    versions: tuple[SampledVersion, ...]


def draw(
    day: date, day_ledgers: Sequence[Ledger], sizes: Mapping[str, int] = SAMPLE_SIZES
) -> DailySample:
    """The sample of `day` from the ledgers of its runs. Keeps only the `n` best-ordered rows
    per stratum while streaming, so memory stays small."""
    best: dict[str, list[tuple[str, SampledVersion]]] = {s: [] for s in sizes}
    population: dict[str, int] = dict.fromkeys(sizes, 0)
    seen: set[tuple[str, str]] = set()
    ecosystem = day_ledgers[0].header.ecosystem if day_ledgers else "npm"
    for lg in sorted(day_ledgers, key=lambda x: x.header.run_id):
        for row in lg.rows():
            if row.key in seen:
                continue
            seen.add(row.key)
            name = stratum(row)
            if name is None or name not in sizes:
                continue
            population[name] += 1
            key = order_key(day, lg.header.ecosystem, row.name, row.version)
            kept = best[name]
            if len(kept) < sizes[name] or key < kept[-1][0]:
                kept.append((key, _sampled(name, lg.header, row)))
                kept.sort(key=lambda kv: kv[0])
                del kept[sizes[name] :]
    return DailySample(
        day=day,
        ecosystem=ecosystem,
        sizes=dict(sizes),
        ledgers={lg.path.name: lg.sha256 for lg in day_ledgers},
        population=population,
        versions=tuple(v for s in sizes for _, v in best[s]),
    )


def _sampled(name: str, header: LedgerHeader, row: LedgerRow) -> SampledVersion:
    return SampledVersion(
        stratum=name,
        run_id=header.run_id,
        name=row.name,
        version=row.version,
        score=row.score,
        new=row.new_package,
        hook=row.hook,
        watched=row.watched,
        rules=row.rules,
        tarball=row.tarball,
        tarball_size=row.tarball_size,
        base_tarball=row.base_tarball,
    )


def sample_path(live: Path, day: date) -> Path:
    return live / SAMPLE_DIR / f"{day.isoformat()}.json"


def due_days(runs_root: Path, live: Path, *, since: date | None = None) -> list[date]:
    """Days with ledgers and no sample yet, once none of their runs can still finish: every
    run of the day has a ledger, was pruned, or is `UNFINISHED_AFTER` older than the newest
    ledger (the reference moment; the clock is never read)."""
    found = ledgers(live)
    if not found:
        return []
    newest = max(lg.header.as_of for lg in found)
    ledgered = {lg.header.run_id for lg in found}
    days = sorted({_day(lg.header.as_of) for lg in found})
    open_days: set[date] = set()
    for run_dir in sorted(runs_root.iterdir()) if runs_root.exists() else ():
        if run_dir.name in ledgered or (run_dir / "retention.json").exists():
            continue
        try:
            manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
        except OSError, ValueError:
            continue
        if newest - manifest.as_of <= UNFINISHED_AFTER:
            open_days.add(_day(manifest.as_of))
    return [
        d
        for d in days
        if d < _day(newest)
        and d not in open_days
        and (since is None or d >= since)
        and not sample_path(live, d).exists()
    ]


def _day(moment: datetime) -> date:
    return moment.astimezone(UTC).date()


def write_samples(runs_root: Path, live: Path, *, since: date | None = None) -> list[DailySample]:
    """Draw and write every due day's sample (JSON and a Markdown review list)."""
    written = []
    by_day: dict[date, list[Ledger]] = {}
    due = due_days(runs_root, live, since=since)
    if not due:
        return []
    for lg in ledgers(live):
        by_day.setdefault(_day(lg.header.as_of), []).append(lg)
    for day in due:
        sample = draw(day, by_day[day])
        path = sample_path(live, day)
        atomic_write(path, sample.model_dump_json(indent=2).encode() + b"\n")
        atomic_write(path.with_suffix(".md"), render_sample(sample).encode())
        written.append(sample)
    return written


def read_samples(live: Path) -> list[DailySample]:
    directory = live / SAMPLE_DIR
    if not directory.exists():
        return []
    return [DailySample.load_json(p.read_bytes()) for p in sorted(directory.glob("*.json"))]


def render_sample(sample: DailySample) -> str:
    """The day's review list. Package text is escaped as untrusted."""
    out = [
        f"# Review sample {sample.day.isoformat()}",
        "",
        "Label-blind: chosen by hash, before any label is read. Review each version by what its "
        "code does (decision 0015) and record the verdict with:",
        "",
        "    kitsunox live verdict RUN_ID NAME VERSION malicious|unwanted|benign --by NAME",
        "    kitsunox live verdict RUN_ID NAME VERSION unverified --reason "
        "gone|remote|obfuscated|binary --by NAME",
        "",
        "| Stratum | Population | Sampled |",
        "|---|---|---|",
    ]
    for name, size in sample.population.items():
        sampled = sum(v.stratum == name for v in sample.versions)
        out.append(f"| {name}: {STRATA.get(name, name)} | {size:,} | {sampled} |")
    out += [
        "",
        "| Stratum | Run | Package | Version | Score | Tarball |",
        "|---|---|---|---|---|---|",
    ]
    for v in sample.versions:
        tarball = (
            f"{v.tarball[:12]} ({v.tarball_size:,} B)" if v.tarball and v.tarball_size else "-"
        )
        out.append(
            f"| {v.stratum} | {v.run_id} | {text(v.name)} | {text(v.version)} | {v.score:g} "
            f"| {tarball} |"
        )
    return "\n".join(out) + "\n"


class StratumBound(Record):
    population: int
    sampled: int
    reviewed: int = Field(description="With a malicious, unwanted or benign verdict.")
    malicious: int
    unwanted: int = 0
    upper: float | None = Field(
        description="95% upper bound on the flag-worthy (malicious or unwanted) share."
    )


def sample_bound(
    samples: Iterable[DailySample],
    verdicts: Mapping[tuple[str, str], VerdictRecord],
    windows: Mapping[str, tuple[date, date]] | None = None,
) -> dict[str, object]:
    """Per window (by sample day) and overall: per stratum, the reviewed share found
    flag-worthy (malicious or unwanted) and its 95% upper bound (exact `zero_bound` when none
    was), and the population-weighted bound on unlabeled flag-worthy versions among unreported
    ones. Reviewed means the behaviour was seen: `unverified` verdicts don't count. The bound
    holds for malware alone too, since malicious versions are a subset."""
    chosen = list(samples)
    groups: dict[str, list[DailySample]] = {"all": chosen}
    for name, (start, end) in (windows or {}).items():
        groups[name] = [s for s in chosen if start <= s.day < end]
    result: dict[str, object] = {}
    for group, members in groups.items():
        strata: dict[str, StratumBound] = {}
        for name in sorted({k for s in members for k in s.population}):
            population = sum(s.population.get(name, 0) for s in members)
            versions = [v for s in members for v in s.versions if v.stratum == name]
            judged = [
                verdicts[(v.name, v.version)].verdict
                for v in versions
                if (v.name, v.version) in verdicts and verdicts[(v.name, v.version)].verdict in SEEN
            ]
            k = sum(j in FLAG_WORTHY for j in judged)
            upper = zero_bound(len(judged)) if k == 0 else wilson(k, len(judged)).high
            strata[name] = StratumBound(
                population=population,
                sampled=len(versions),
                reviewed=len(judged),
                malicious=judged.count("malicious"),
                unwanted=judged.count("unwanted"),
                upper=upper,
            )
        weight = sum(b.population for b in strata.values() if b.upper is not None)
        bounded = sum(b.population * (b.upper or 0.0) for b in strata.values())
        result[group] = {
            "days": len(members),
            "strata": {k: v.model_dump() for k, v in strata.items()},
            "upper_share": bounded / weight if weight else None,
            "upper_versions": round(bounded) if weight else None,
            "unreviewed_strata": sorted(k for k, b in strata.items() if b.upper is None),
        }
    return result


_SEVERITIES: Final = [s.value for s in Severity]


def ledger_verdict(
    header: LedgerHeader,
    row: LedgerRow,
    verdict: Verdict,
    *,
    by: str,
    at: datetime,
    note: str = "",
    tags: Iterable[Tag] = (),
    reason: Reason | None = None,
) -> VerdictRecord:
    """A verdict on a version from its ledger row, for a version in no report (a sampled or a
    missed one): rank 0. Validated as `reporting.verdicts.verdict_record` does."""
    kept = check_verdict(verdict, by=by, tags=tags, reason=reason)
    severities = [r.rsplit(":", 1)[-1] for r in row.rules]
    severity = max(
        (s for s in severities if s in _SEVERITIES), key=_SEVERITIES.index, default="info"
    )
    return VerdictRecord(
        ecosystem=header.ecosystem,
        name=row.name,
        version=row.version,
        verdict=verdict,
        at=at,
        by=by,
        note=note.strip()[:MAX_NOTE_CHARS],
        tags=kept,
        reason=reason,
        run_id=header.run_id,
        rank=row.rank or 0,
        score=row.score,
        severity=str(severity),
        rules=row.rule_ids,
        publisher=row.publisher,
        published_at=row.published_at,
    )


def find_row(live: Path, run_id: str, name: str, version: str) -> tuple[LedgerHeader, LedgerRow]:
    """The ledger row of `name@version` in run `run_id` (as the tick scored it)."""
    path = ledger_path(live, run_id)
    if not path.exists():
        raise LookupError(f"no ledger for run {run_id}")
    header, rows = read_ledger(path)
    for row in rows:
        if row.name == name and row.version == version:
            return header, row
    raise LookupError(f"run {run_id} has no {name}@{version}")
