"""Pre-score router.   [USER-OWNED — implement `route()`]

Turns the firehose into three buckets using **metadata only — no code/tarball fetch**:

    Route.IGNORE  — established package, stable maintainers, unremarkable publish
    Route.TIER01  — worth a deterministic scan
    Route.TIER2   — ambiguous / high-blast-radius; fast-track toward LLM reasoning

Contract
--------
``route(change_row, ctx) -> PrescoreResult``   where ``ctx`` carries a ``Repository`` and a
``RegistryClient`` (see ``PrescoreContext`` below).

Signals to combine (see plan; each contributes to a score, threshold picks the bucket):
  - new package (``change_row.looks_new_package``) that ships an install script
  - maintainer set != ``baseline.known_maintainers``  (highest-signal cheap check)
  - dormant package (``last_publish_at`` older than N× ``publish_cadence_days_median``)
    now publishing
  - version-jump anomaly (semver delta vs ``unpacked_size`` delta as a cheap diff proxy)
  - unpublish of a recent version (``change_row.deleted``)
  - popularity (``weekly_downloads`` / ``dependents_count``) escalates severity -> TIER2

Baseline bookkeeping: ``kitsunox.pipeline`` folds each event into ``package_baseline``
*after* routing, so ``route()`` sees the pre-update baseline via
``ctx.repo.get_baseline(name)`` — compare against that.

``route()`` must be cheap and total: never raise, and prefer one abbreviated-packument
fetch (``ctx.client.packument(name, abbreviated=True)``) over the full document.

``tests/test_prescore.py`` pins bucket decisions for representative events and currently
fails.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kitsunox.db.repo import Repository
from kitsunox.ingest.changes_feed import ChangeRow
from kitsunox.ingest.registry_client import RegistryClient
from kitsunox.ir import Route


@dataclass
class PrescoreContext:
    repo: Repository
    client: RegistryClient


@dataclass
class PrescoreResult:
    route: Route
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    # The resolved current version + previous version, if the router looked them up
    # (lets the scanner skip a redundant packument round-trip).
    version: str | None = None
    prev_version: str | None = None


def route(change_row: ChangeRow, ctx: PrescoreContext) -> PrescoreResult:
    """USER: implement. See module docstring."""
    raise NotImplementedError("TODO(user): pre-score router — see module docstring")
