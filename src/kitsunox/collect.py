"""`kitsunox collect`: one unattended tick of data collection, run hourly by launchd.

Each tick, in order:

1. Rebuild the watchlist if the newest is older than `WATCHLIST_MAX_AGE` (~12 min, 1 GB).
2. Sync OSV labels if the newest set is older than `LABELS_MAX_AGE` (~15 s, 220 MB).
3. Record a chained ingest run continuing from the checkpoint (see `core/run.py`).
4. Triage the run (Stage 1) and run Stage 2 on its batches. This is what captures tarballs:
   npm deletes malicious ones, often within hours, so they are fetched in the same tick.
5. Prune runs older than `keep_days` if the last prune is older than `PRUNE_EVERY`.

Steps 1, 2, 4 and 5 are best-effort: a failure is logged, and the tick carries on with the
previous watchlist or label set, because a missed ingest is lost data while a stale list is not.
A failed step 4 can be redone with `kitsunox triage` and `kitsunox static` (minus any tarball
deleted meanwhile). A failed ingest fails the tick, and the checkpoint is not advanced, so the
next tick covers the gap.

This module only wires existing pieces together. It may read the clock, since it decides *when*
to fetch; the runs it records still carry an explicit `as_of`. The caller holds `DataDir.lock()`.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx

from kitsunox.core.retention import prune
from kitsunox.core.rules import RuleContext
from kitsunox.core.run import DataDir, IngestRequest, RunManifest, record_ingest, record_watchlist
from kitsunox.core.watchlist import MONTHLY_CUTOFF
from kitsunox.ecosystems.npm.packument import ECOSYSTEM as NPM
from kitsunox.ecosystems.npm.registry import ECOSYSTEMS_REGISTRY, NpmEcosystem, packument_url
from kitsunox.evaluation.harness import label_store, sync_labels
from kitsunox.stages.static import record_static
from kitsunox.stages.triage import triage_run

WATCHLIST_MAX_AGE = timedelta(days=7)
LABELS_MAX_AGE = timedelta(hours=20)
PRUNE_EVERY = timedelta(hours=20)
DEFAULT_KEEP_DAYS = 7

Log = Callable[[str], None]


def collect(
    data: DataDir,
    *,
    now: datetime,
    keep_days: int = DEFAULT_KEEP_DAYS,
    log: Log,
    clients: Callable[[], httpx.Client] | None = None,
) -> RunManifest:
    """`clients` makes a fresh HTTP client per step (each step closes its own); tests pass a
    mock. Default: a real client per step."""

    def client() -> httpx.Client | None:
        return clients() if clients else None

    if _age(data.watchlists.latest_id(NPM), now) > WATCHLIST_MAX_AGE:
        _best_effort("watchlist", log, lambda: _watchlist(data, now, client()))
    if _age(label_store(data).latest_id(NPM), now) > LABELS_MAX_AGE:
        _best_effort("labels", log, lambda: _labels(data, now, client()))

    request = IngestRequest(as_of=now, chain=True)
    manifest = record_ingest(data, NpmEcosystem, request, client=client())
    chain = f"chained from {manifest.chained_from}" if manifest.chained_from else "NOT chained"
    log(
        f"ingest: run {manifest.run_id}, feed ({manifest.cursor_since}, {manifest.cursor_until}], "
        f"{manifest.packages_seen} packages, {manifest.change_count} changes, "
        f"{manifest.skipped_count} skipped, {chain}, window covered: {manifest.window_covered}"
    )

    _best_effort("stages", log, lambda: _stages(data, manifest, client()))

    last_prune = _last_prune(data)
    if last_prune is None or now - last_prune > PRUNE_EVERY:
        _best_effort("prune", log, lambda: _prune(data, now, keep_days))
    return manifest


def _watchlist(data: DataDir, now: datetime, client: httpx.Client | None) -> str:
    watchlist, _, _ = record_watchlist(
        data,
        ecosystem=NPM,
        registry=ECOSYSTEMS_REGISTRY,
        built_at=now,
        min_monthly_downloads=MONTHLY_CUTOFF,
        client=client,
    )
    return f"built {watchlist.id} ({len(watchlist.entries)} packages)"


def _stages(data: DataDir, manifest: RunManifest, client: httpx.Client | None) -> str:
    candidates, _ = triage_run(data.run_dir(manifest.run_id), RuleContext(as_of=manifest.as_of))
    batches = record_static(data, manifest.run_id, NpmEcosystem, client=client)
    decisions = [c.history[-1] for b in batches for c in b.versions]
    stage1 = sum(c.history[-1].reason.startswith("rules:") for c in candidates)
    stage2 = sum(d.forwarded for d in decisions)
    missing = sum(d.reason.startswith("files unavailable") for d in decisions)
    return (
        f"{len(candidates)} triaged, {stage1} flagged by Stage 1; {len(decisions)} versions "
        f"read by Stage 2, {stage2} flagged, {missing} without files"
    )


def _labels(data: DataDir, now: datetime, client: httpx.Client | None) -> str:
    labels, _, _ = sync_labels(data, ecosystem=NPM, fetched_at=now, client=client)
    return f"synced {labels.id} ({labels.record_count} records)"


def _prune(data: DataDir, now: datetime, keep_days: int) -> str:
    store = label_store(data)
    labels_id = store.latest_id(NPM)
    if labels_id is None:
        return "skipped: no label set to decide which packuments to keep"
    labels = store.load(NPM, labels_id)
    report = prune(
        data,
        now=now,
        keep_days=keep_days,
        pinned_names=labels.labels.keys(),
        metadata_url=packument_url,
    )
    path = data.root / "state" / "prune.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"last": now.isoformat()}) + "\n")
    return (
        f"{len(report.runs_pruned)} runs pruned, {report.blobs_pinned} blobs pinned, "
        f"{report.blobs_deleted} blobs deleted ({report.bytes_freed / 1e9:.2f} GB)"
    )


def _best_effort(step: str, log: Log, action: Callable[[], str]) -> None:
    try:
        log(f"{step}: {action()}")
    except Exception as exc:  # unattended: keep collecting with the previous data
        log(f"{step}: FAILED ({type(exc).__name__}: {exc}); continuing")


def _age(record_id: str | None, now: datetime) -> timedelta:
    if record_id is None:
        return timedelta.max
    return now - datetime.strptime(record_id, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


def _last_prune(data: DataDir) -> datetime | None:
    path = data.root / "state" / "prune.json"
    if not path.exists():
        return None
    last = json.loads(path.read_text()).get("last")
    return datetime.fromisoformat(last) if isinstance(last, str) else None
