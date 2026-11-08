"""The per-version decision ledger: what each stage decided about every version of a run.

Live evaluation (`evaluation/live.py`, Phase 9) joins labels that arrive days later (OSV `MAL-`
records, npm takedowns, reviewer verdicts) with the decisions the pipeline made *at the time*.
Run outputs are large (a 405k-version run's `correlate.jsonl` is ~3 GB, with every manifest),
so each finished run is boiled down once to a compact ledger that is kept for good:

- `<live>/ledger/<run_id>.jsonl.zst`: the run as the tick scored it. For a re-scored run that
  is `before-rescore/` (`collect.rescore_run`), never the re-score.
- `<live>/ledger/<run_id>.rescored.jsonl.zst`: the current outputs of a re-scored run, used
  only for a secondary recall figure. Rewritten when the run is re-scored again.

The first line is a `LedgerHeader` (the run, which rule versions scored it, and the SHA-256 of
every input file); then one `LedgerRow` per version that entered Stage 4, in Stage 4's order.
Rows leave out fields at their defaults, so a quiet version is ~150 bytes before compression.

Everything is read one line at a time (`correlate.jsonl` is never loaded whole), and the
ledger is a pure function of the run's files: the same files give the same bytes. Package
text in a row (names, versions, publishers) is untrusted, as everywhere.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterator, Mapping
from compression import zstd
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from pydantic import Field

from kitsunox import __version__
from kitsunox.core.models import Candidate, Persisted, Record, Severity, VersionSnapshot
from kitsunox.core.rules import rules_fingerprint
from kitsunox.core.run import STATIC_SNAPSHOT, RunManifest
from kitsunox.ecosystems.npm.packument import is_registry_placeholder
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts
from kitsunox.rules.static import RULES as STATIC_RULES
from kitsunox.stages.code import CODE_RULES
from kitsunox.stages.correlate import STAGE_VERSION
from kitsunox.stages.review import CORRELATION_RULES
from kitsunox.stages.static import ARTIFACT_RULES_BY_ECOSYSTEM
from kitsunox.stages.triage import RULES_BY_ECOSYSTEM
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex

LIVE_DIR: Final = Path("eval") / "live"  # under the data directory
LEDGER_DIR: Final = "ledger"
RESCORE_ORIGINALS: Final = "before-rescore"  # collect.RESCORE_ORIGINALS (collect imports us)
RESCORE_INFO: Final = "rescore.json"
CORRELATE_INFO: Final = "correlate.json"
REPORT_JSON: Final = Path("report") / "report.json"
REPORT_INDEX: Final = Path("report") / "index.md"
ZSTD_LEVEL: Final = 10
SCORE: Final = re.compile(r"score (-?\d+(?:\.\d+)?)")

Variant = Literal["tick", "rescored"]
# Stage 1's forward route, from its decision reason (`stages/triage.py`).
Route = Literal["rules", "watched", "new", "hook", "grown", "size-unknown", "none", "other"]
# Stages 2 and 3: never read, read without files (size cap, fetch error), read and clear,
# read and flagged.
Read = Literal["unread", "no-files", "clear", "flagged"]

PLACEHOLDER: Final[dict[str, Callable[[VersionSnapshot], bool]]] = {"npm": is_registry_placeholder}


def _npm_hook(snapshot: VersionSnapshot) -> bool:
    return any(hook in INSTALL_HOOKS for hook in scripts(snapshot.manifest))


INSTALL_HOOK: Final[dict[str, Callable[[VersionSnapshot], bool]]] = {"npm": _npm_hook}


class LedgerHeader(Persisted):
    """One run's ledger: which run, which rules scored it, and the inputs it was read from."""

    run_id: str
    ecosystem: str
    variant: Variant
    as_of: datetime
    window_start: datetime
    window_end: datetime
    stage0_tool: str = Field(description="`tool_version` in the run's manifest (Stage 0).")
    stage4_version: int | None = Field(description="`stage_version` in `correlate.json`.")
    stage4_rules: str | None = Field(
        description="`rules` in `correlate.json`: the fingerprint of Stage 4's rule set."
    )
    report_score: float | None
    known_bad: str | None = Field(description="Label set Stage 4's known-malware rule used.")
    watchlist: str | None
    pipeline: dict[str, str] | None = Field(
        default=None,
        description="Rule-set fingerprints of every stage and the tool version, recorded only "
        "when the ledger was written by the process that ran the stages (`collect`); None "
        "for a backfill, which can't know them.",
    )
    rescored_at: str | None = None
    inputs: dict[str, str] = Field(description="File -> SHA-256 of what was read.")
    versions: int
    reported: int
    written_by: str = Field(description="Kitsunox version that wrote the ledger.")


class LedgerRow(Record):
    """What the pipeline decided about one version. Defaults are left out on disk."""

    name: str
    version: str
    published_at: datetime | None = None
    publisher: str | None = None
    previous: str | None = Field(default=None, description="None: a new package (shape B).")
    watched: bool = False
    placeholder: bool = Field(default=False, description="The registry's own stand-in.")
    hook: bool = Field(default=False, description="Declares an install hook.")
    declared_size: int | None = Field(default=None, description="Declared unpacked size.")
    s1: Route = "none"
    s1_forwarded: bool = False
    s2: Read = "unread"
    s3: Read = "unread"
    score: float = 0.0
    forwarded: bool = Field(default=False, description="Stage 4's decision: report it.")
    rank: int | None = Field(default=None, description="Rank in the run's report.")
    rules: tuple[str, ...] = Field(
        default=(), description="`rule_id@version:severity` of every finding above INFO."
    )
    tarball: str | None = Field(default=None, description="SHA-256 of the captured tarball.")
    tarball_size: int | None = None
    base_tarball: str | None = Field(default=None, description="The diff base's, if captured.")
    base_tarball_size: int | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.version)

    @property
    def new_package(self) -> bool:
        return self.previous is None

    @property
    def reported(self) -> bool:
        return self.rank is not None

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(r.split("@", 1)[0] for r in self.rules))


@dataclass(frozen=True, slots=True)
class Ledger:
    path: Path
    header: LedgerHeader
    sha256: str

    def rows(self) -> Iterator[LedgerRow]:
        _, rows = read_ledger(self.path)
        yield from rows


def ledger_dir(live: Path) -> Path:
    return live / LEDGER_DIR


def ledger_path(live: Path, run_id: str, variant: Variant = "tick") -> Path:
    suffix = "" if variant == "tick" else f".{variant}"
    return ledger_dir(live) / f"{run_id}{suffix}.jsonl.zst"


def pipeline_fingerprints() -> dict[str, str]:
    """The rule-set fingerprint of each stage in the running code, and its version. Only
    meaningful when recorded by the process that ran the stages."""
    return {
        "tool": __version__,
        "stage1": rules_fingerprint(RULES_BY_ECOSYSTEM["npm"]),
        "stage2": rules_fingerprint([*STATIC_RULES, *ARTIFACT_RULES_BY_ECOSYSTEM["npm"]]),
        "stage3": rules_fingerprint(CODE_RULES),
        "stage4": rules_fingerprint(CORRELATION_RULES),
        "stage4_version": str(STAGE_VERSION),
    }


def outputs_dir(run_dir: Path, variant: Variant) -> Path:
    """Where a variant's Stage 1-4 outputs and report live."""
    originals = run_dir / RESCORE_ORIGINALS
    return originals if variant == "tick" and originals.is_dir() else run_dir


def finished(run_dir: Path, variant: Variant = "tick") -> bool:
    """Stage 4 and the report are complete (`index.md` is written last), so the ledger can be
    written. A `rescored` variant exists only for a re-scored run."""
    if variant == "rescored" and not (run_dir / RESCORE_INFO).exists():
        return False
    out = outputs_dir(run_dir, variant)
    return (
        all(
            (out / name).exists()
            for name in ("correlate.jsonl", CORRELATE_INFO, REPORT_JSON, REPORT_INDEX)
        )
        and (run_dir / "manifest.json").exists()
    )


def stage1_route(reason: str) -> Route:
    if reason.startswith("rules: "):
        return "rules"
    if reason == "no signal":
        return "none"
    routes: dict[str, Route] = {
        "watched package": "watched",
        "new package": "new",
        "install hook": "hook",
        "unpacked size unknown": "size-unknown",
    }
    if reason in routes:
        return routes[reason]
    return "grown" if reason.startswith("unpacked size grew") else "other"


def _read(candidate: Candidate, stage: str) -> Read:
    decisions = [d for d in candidate.history if d.stage == stage]
    if not decisions:
        return "unread"
    last = decisions[-1]
    if last.reason.startswith("files unavailable"):
        return "no-files"
    return "flagged" if last.forwarded else "clear"


def ledger_row(
    candidate: Candidate,
    ranks: Mapping[tuple[str, str], int],
    tarballs: Mapping[str, tuple[str, int]],
) -> LedgerRow:
    change = candidate.change
    new, previous = change.new, change.previous
    ecosystem = new.ref.ecosystem
    triage = next((d for d in candidate.history if d.stage == "triage"), None)
    correlate = [d for d in candidate.history if d.stage == "correlate"]
    decision = correlate[-1] if correlate else None
    match = SCORE.search(decision.reason) if decision else None
    tarball = tarballs.get(new.artifact.url) if new.artifact else None
    base = tarballs.get(previous.artifact.url) if previous and previous.artifact else None
    is_placeholder = PLACEHOLDER.get(ecosystem)
    has_hook = INSTALL_HOOK.get(ecosystem)
    rules = sorted(
        {
            f"{f.rule_id}@{f.rule_version}:{f.severity.value}"
            for f in candidate.findings
            if f.severity != Severity.INFO
        }
    )
    return LedgerRow(
        name=new.ref.name,
        version=new.ref.version,
        published_at=new.publish.published_at,
        publisher=new.publish.publisher,
        previous=previous.ref.version if previous else None,
        watched=bool(change.popularity and change.popularity.watched),
        placeholder=bool(is_placeholder and is_placeholder(new)),
        hook=bool(has_hook and has_hook(new)),
        declared_size=new.artifact.unpacked_size if new.artifact else None,
        s1=stage1_route(triage.reason) if triage else "other",
        s1_forwarded=bool(triage and triage.forwarded),
        s2=_read(candidate, "static"),
        s3=_read(candidate, "ast"),
        score=float(match.group(1)) if match else 0.0,
        forwarded=bool(decision and decision.forwarded),
        rank=ranks.get((new.ref.name, new.ref.version)),
        rules=tuple(rules),
        tarball=tarball[0] if tarball else None,
        tarball_size=tarball[1] if tarball else None,
        base_tarball=base[0] if base else None,
        base_tarball_size=base[1] if base else None,
    )


def captured_tarballs(path: Path) -> dict[str, tuple[str, int]]:
    """URL -> (SHA-256, size) of every artifact a Stage 2 snapshot fetched successfully."""
    if not path.exists():
        return {}
    raw = json.loads(path.read_bytes())
    entries = raw.get("entries", {}) if isinstance(raw, dict) else {}
    found: dict[str, tuple[str, int]] = {}
    for entry in entries.values():
        if isinstance(entry, dict) and entry.get("status") == 200:
            url, sha, size = entry.get("url"), entry.get("sha256"), entry.get("size")
            if isinstance(url, str) and isinstance(sha, str) and isinstance(size, int):
                found.setdefault(url, (sha, size))
    return found


def report_ranks(path: Path) -> dict[tuple[str, str], int]:
    """(name, version) -> rank, read leniently: reports of every schema version have these."""
    raw = json.loads(path.read_bytes())
    ranks: dict[tuple[str, str], int] = {}
    for entry in raw.get("entries", ()) if isinstance(raw, dict) else ():
        if isinstance(entry, dict):
            name, version, rank = entry.get("name"), entry.get("version"), entry.get("rank")
            if isinstance(name, str) and isinstance(version, str) and isinstance(rank, int):
                ranks.setdefault((name, version), rank)
    return ranks


def build_ledger(
    run_dir: Path, variant: Variant = "tick", *, pipeline: dict[str, str] | None = None
) -> bytes:
    """The compressed ledger of a finished run (`finished`). Streams `correlate.jsonl`."""
    manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
    out = outputs_dir(run_dir, variant)
    info_bytes = (out / CORRELATE_INFO).read_bytes()
    info = json.loads(info_bytes)
    report_bytes = (out / REPORT_JSON).read_bytes()
    ranks = report_ranks(out / REPORT_JSON)
    snapshot = out / STATIC_SNAPSHOT
    if not snapshot.exists():
        snapshot = run_dir / STATIC_SNAPSHOT
    tarballs = captured_tarballs(snapshot)
    rescored_at = None
    if variant == "rescored":
        rescored_at = str(json.loads((run_dir / RESCORE_INFO).read_bytes()).get("rescored_at"))
    digest = hashlib.sha256()
    rows = bytearray()
    count = reported = 0
    compressor = zstd.ZstdCompressor(level=ZSTD_LEVEL)
    with (out / "correlate.jsonl").open("rb") as handle:
        for line in handle:
            digest.update(line)
            if not line.strip():
                continue
            row = ledger_row(Candidate.model_validate_json(line), ranks, tarballs)
            count += 1
            reported += row.reported
            rows += compressor.compress(row.model_dump_json(exclude_defaults=True).encode() + b"\n")
    inputs = {
        "correlate.jsonl": digest.hexdigest(),
        CORRELATE_INFO: sha256_hex(info_bytes),
        "report.json": sha256_hex(report_bytes),
        "changes": manifest.changes_sha256,
    }
    if snapshot.exists():
        inputs[STATIC_SNAPSHOT] = sha256_hex(snapshot.read_bytes())
    header = LedgerHeader(
        run_id=manifest.run_id,
        ecosystem=manifest.ecosystem,
        variant=variant,
        as_of=manifest.as_of,
        window_start=manifest.window.start,
        window_end=manifest.window.end,
        stage0_tool=manifest.tool_version,
        stage4_version=_int(info.get("stage_version")),
        stage4_rules=_str(info.get("rules")),
        report_score=_float(info.get("report_score")),
        known_bad=_str(info.get("known_bad")),
        watchlist=_str(info.get("watchlist")),
        pipeline=pipeline,
        rescored_at=rescored_at,
        inputs=inputs,
        versions=count,
        reported=reported,
        written_by=__version__,
    )
    head = zstd.ZstdCompressor(level=ZSTD_LEVEL)
    first = head.compress(header.model_dump_json().encode() + b"\n") + head.flush()
    return first + bytes(rows) + compressor.flush()


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _float(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def read_ledger(path: Path) -> tuple[LedgerHeader, Iterator[LedgerRow]]:
    """The header and the rows, one at a time."""
    handle = zstd.open(path, "rb")
    try:
        header = LedgerHeader.load_json(handle.readline())
    except BaseException:
        handle.close()
        raise

    def rows() -> Iterator[LedgerRow]:
        with handle:
            for line in handle:
                if line.strip():
                    yield LedgerRow.model_validate_json(line)

    return header, rows()


def load_ledger(path: Path) -> Ledger:
    with zstd.open(path, "rb") as handle:
        header = LedgerHeader.load_json(handle.readline())
    return Ledger(path=path, header=header, sha256=sha256_hex(path.read_bytes()))


def write_ledger(
    runs_root: Path,
    live: Path,
    run_id: str,
    variant: Variant = "tick",
    *,
    pipeline: dict[str, str] | None = None,
) -> Path | None:
    """Write a run's ledger if it is finished and not written yet (a `rescored` ledger is
    rewritten after a later re-score). Returns the path written, or None."""
    run_dir = runs_root / run_id
    if not finished(run_dir, variant):
        return None
    path = ledger_path(live, run_id, variant)
    if path.exists():
        if variant == "tick":
            return None
        rescored_at = json.loads((run_dir / RESCORE_INFO).read_bytes()).get("rescored_at")
        if load_ledger(path).header.rescored_at == str(rescored_at):
            return None
    atomic_write(path, build_ledger(run_dir, variant, pipeline=pipeline))
    return path


def backfill(
    runs_root: Path,
    live: Path,
    *,
    run_ids: list[str] | None = None,
    log: Callable[[str], None] = lambda _: None,
) -> list[Path]:
    """Write the missing ledgers of every finished run (or of `run_ids`), oldest first."""
    if run_ids is None:
        run_ids = sorted(p.name for p in runs_root.iterdir() if p.is_dir())
    written = []
    for run_id in sorted(run_ids):
        for variant in ("tick", "rescored"):
            path = write_ledger(runs_root, live, run_id, variant)
            if path is not None:
                log(f"ledger: {path.name}")
                written.append(path)
    return written


def ledgers(live: Path, variant: Variant = "tick") -> list[Ledger]:
    """Every ledger of a variant, by run id."""
    directory = ledger_dir(live)
    if not directory.exists():
        return []
    suffix = ".jsonl.zst" if variant == "tick" else f".{variant}.jsonl.zst"
    found = []
    for path in sorted(directory.glob("*.jsonl.zst")):
        stem = path.name.removesuffix(suffix)
        if path.name.endswith(suffix) and "." not in stem:
            found.append(load_ledger(path))
    return found
