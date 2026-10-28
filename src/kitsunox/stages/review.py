"""Stage 4 wiring for npm: the rule set, known-malware records and repository comparison that
`kitsunox correlate` and `collect` use. Kept apart from `stages/correlate.py`, which is
ecosystem-agnostic (like `stages/code.py` for Stage 3)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

import httpx

from kitsunox.core.models import Candidate
from kitsunox.core.run import CORRELATE_SNAPSHOT, DataDir, RunManifest
from kitsunox.ecosystems.npm.registry import NpmEcosystem
from kitsunox.ecosystems.npm.repo import NpmLocator
from kitsunox.ecosystems.npm.rules.correlate import RULES as NPM_CORRELATION_RULES
from kitsunox.evaluation.labels import label_store
from kitsunox.githost.github import GitHub, GitHubRepo
from kitsunox.rules.repo import RULES as REPO_RULES
from kitsunox.stages.correlate import (
    CorrelationContext,
    CorrelationRule,
    RepoLookup,
    correlate_run,
)
from kitsunox.stages.repo import RepoComparison, compare
from kitsunox.stages.static import ArtifactFiles, Unavailable
from kitsunox.util.http import FetchError, FetchMode, HttpFetcher, Snapshot

NPM: Final = "npm"
CORRELATION_RULES: Final[tuple[CorrelationRule, ...]] = (*NPM_CORRELATION_RULES, *REPO_RULES)


def repo_lookup(fetcher: HttpFetcher) -> RepoLookup:
    """Compare a candidate's release with its repository. The release's files come through
    the same fetcher (Stage 2 already fetched them, so from the immutable index). A network
    failure leaves the version without a comparison rather than failing the run: Stage 4 adds
    evidence; it is not a gate."""
    files = ArtifactFiles(NpmEcosystem(fetcher))
    github = GitHub(fetcher)
    locator = NpmLocator()
    refs: dict[GitHubRepo, Mapping[str, str] | None] = {}

    def lookup(candidate: Candidate) -> RepoComparison | None:
        tree = files(candidate.change.new)
        if isinstance(tree, Unavailable):
            return RepoComparison(unavailable=f"package files {tree.reason}"[:300])
        try:
            return compare(candidate.change, tree, locator, github, refs_cache=refs)
        except FetchError as exc:
            return RepoComparison(unavailable=f"network: {exc}"[:300])

    return lookup


def run_correlate_stage(
    data: DataDir, run_id: str, *, workers: int = 8, client: httpx.Client | None = None
) -> tuple[Candidate, ...]:
    """Stage 4 on a run Stage 3 has processed. Repository requests are recorded in
    `correlate-snapshot.json` next to the run. The caller holds the lock."""
    run_dir = data.run_dir(run_id)
    manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
    labels_id = label_store(data).latest_id(NPM, not_after=manifest.as_of)
    labels = label_store(data).load(NPM, labels_id) if labels_id else None
    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=client,
    )
    try:
        candidates = correlate_run(
            run_dir,
            CorrelationContext(as_of=manifest.as_of, known_bad=labels),
            CORRELATION_RULES,
            repo=repo_lookup(fetcher),
            workers=workers,
        )
    finally:
        fetcher.close()
    snapshot.save(run_dir / CORRELATE_SNAPSHOT)
    return candidates
