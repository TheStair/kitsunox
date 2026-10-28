"""Stage 2: static heuristics over the file contents a package batch adds.

See `docs/stages/static.md`. For a `PackageBatch`, every file content (by SHA-256) that is in
some version but not in the base is analysed once, through a content-addressed cache, and its
findings are attributed to the first version that contained it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Final

import httpx

from kitsunox.core.interfaces import Ecosystem
from kitsunox.core.models import PackageBatch, Record, Severity, StageDecision, VersionSnapshot
from kitsunox.core.rules import FileMatch, FileRule, rules_fingerprint
from kitsunox.core.run import STATIC_SNAPSHOT, DataDir, EcosystemFactory
from kitsunox.rules.static import RULES
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.triage import at_least
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchError, FetchMode, HttpFetcher, Snapshot

STAGE_ID: Final = "static"
# 16 MB, not 2: the Shai-Hulud payload (`bun_environment.js`) is ~10 MB, and 698 of 965
# first-release compromised samples added a file over 2 MB (2026-10-27).
MAX_FILE_BYTES: Final = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES: Final = MAX_FILE_BYTES
DEFAULT_THRESHOLD: Final = Severity.MEDIUM

Tree = Mapping[str, bytes]


class NewContent(Record):
    path: str
    sha256: str
    size: int
    first_version: str


class Unavailable(Record):
    """A version's files could not be read; `reason` says why (too large, fetch failed)."""

    reason: str


def new_contents(
    base: Tree | None, versions: Iterable[tuple[str, Tree]]
) -> Iterator[tuple[NewContent, bytes]]:
    """Contents in any version that the base does not have, each once, in version order (then
    path order). The first path and version a content appears under is the one reported.
    `versions` is consumed lazily, so only one version's files need to be in memory."""
    seen = {sha256_hex(content) for content in (base or {}).values()}
    for version, tree in versions:
        for path in sorted(tree):
            content = tree[path]
            digest = sha256_hex(content)
            if digest in seen:
                continue
            seen.add(digest)
            yield (
                NewContent(path=path, sha256=digest, size=len(content), first_version=version),
                content,
            )


class ContentCache:
    """Rule results by content hash, on disk, per rule-set fingerprint. A pure-function cache:
    entries never need invalidating, because changing a rule changes the fingerprint."""

    def __init__(self, root: Path | None, rules: Sequence[FileRule]) -> None:
        self.rules = rules
        self.dir = root / rules_fingerprint(rules) if root else None

    def matches(self, digest: str, content: bytes) -> tuple[FileMatch, ...]:
        path = self.dir / digest[:2] / f"{digest}.json" if self.dir else None
        if path is not None and path.exists():
            return tuple(FileMatch.model_validate(m) for m in json.loads(path.read_bytes()))
        result = analyse(content, self.rules)
        if path is not None:
            atomic_write(path, json.dumps([m.model_dump(mode="json") for m in result]).encode())
        return result


def analyse(content: bytes, rules: Sequence[FileRule] = RULES) -> tuple[FileMatch, ...]:
    if len(content) > MAX_FILE_BYTES or b"\x00" in content[:8192]:
        return ()  # too large for regex triage, or binary
    text = content.decode("utf-8", errors="replace")
    return tuple(m for rule in rules for m in rule.evaluate_text(text))


def analyse_batch(
    batch: PackageBatch,
    trees: Callable[[VersionSnapshot], Tree | Unavailable],
    cache: ContentCache,
    *,
    threshold: Severity = DEFAULT_THRESHOLD,
) -> PackageBatch:
    """Run Stage 2 on a batch. `trees` gives a version's extracted files (fetching as needed).
    A version whose files are unavailable gets no findings and says why. An unavailable base
    counts as empty: every file of the first version is then new, which costs time but can
    only add findings."""
    base = trees(batch.base) if batch.base else None
    base_note = f"; base unavailable: {base.reason}" if isinstance(base, Unavailable) else ""
    missing: dict[str, str] = {}

    def versions() -> Iterator[tuple[str, Tree]]:
        for candidate in batch.versions:
            version = candidate.change.new.ref.version
            tree = trees(candidate.change.new)
            if isinstance(tree, Unavailable):
                missing[version] = tree.reason
                continue
            yield version, tree

    found: dict[str, list[tuple[str, FileMatch]]] = {}
    base_tree = None if isinstance(base, Unavailable) else base
    for item, content in new_contents(base_tree, versions()):
        for match in cache.matches(item.sha256, content):
            found.setdefault(item.first_version, []).append((item.path, match))
    updated = []
    for candidate in batch.versions:
        version = candidate.change.new.ref.version
        findings = tuple(match.finding(path) for path, match in found.get(version, []))
        flagged = sorted({f.rule_id for f in findings if at_least(f.severity, threshold)})
        if version in missing:
            reason = f"files unavailable: {missing[version]}"
        else:
            reason = f"rules: {', '.join(flagged)}" if flagged else "no signal"
        decision = StageDecision(stage=STAGE_ID, forwarded=bool(flagged), reason=reason + base_note)
        updated.append(
            candidate.model_copy(
                update={
                    "findings": candidate.findings + findings,
                    "history": (*candidate.history, decision),
                }
            )
        )
    return batch.model_copy(update={"versions": tuple(updated)})


class ArtifactFiles:
    """Fetch a version's files through its ecosystem, skipping versions that declare an
    unpacked size over `max_bytes`: almost all of that volume is platform binaries that the
    rules skip anyway (2026-10-27: versions over 16 MB were 9% of releases and 86% of bytes)."""

    def __init__(self, ecosystem: Ecosystem, max_bytes: int = MAX_ARTIFACT_BYTES) -> None:
        self.ecosystem = ecosystem
        self.max_bytes = max_bytes

    def __call__(self, snapshot: VersionSnapshot) -> Tree | Unavailable:
        artifact = snapshot.artifact
        if artifact is None:
            return Unavailable(reason="no artifact")
        if artifact.unpacked_size is not None and artifact.unpacked_size > self.max_bytes:
            return Unavailable(reason=f"declared unpacked size {artifact.unpacked_size} bytes")
        try:
            return self.ecosystem.fetch_artifact(artifact)
        except (FetchError, ValueError) as exc:  # ValueError: integrity or archive errors
            return Unavailable(reason=f"{type(exc).__name__}: {exc}"[:300])


def static_run(
    run_dir: Path,
    files: Callable[[VersionSnapshot], Tree | Unavailable],
    cache: ContentCache,
    *,
    workers: int = 8,
) -> tuple[PackageBatch, ...]:
    """Stage 2 over a triaged run: reads `batches.jsonl`, writes `static.jsonl` (the same
    batches in the same order, each version with Stage 2 findings and decision). `files` must
    be thread-safe."""
    lines = (run_dir / "batches.jsonl").read_bytes().splitlines()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        batches = tuple(
            pool.map(
                lambda line: analyse_batch(PackageBatch.load_json(line), files, cache),
                [line for line in lines if line.strip()],
            )
        )
    write_jsonl(run_dir / "static.jsonl", batches)
    return batches


def record_static(
    data: DataDir,
    run_id: str,
    factory: EcosystemFactory,
    *,
    workers: int = 8,
    client: httpx.Client | None = None,
) -> tuple[PackageBatch, ...]:
    """Stage 2 on a recorded, triaged run, fetching live. Tarballs go into the data directory's
    blob store (immutable, so a tarball already fetched is not fetched again), and the requests
    are recorded in `static-snapshot.json` next to the run. The caller holds `DataDir.lock()`."""
    run_dir = data.run_dir(run_id)
    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=client,
    )
    try:
        files = ArtifactFiles(factory(fetcher))
        cache = ContentCache(data.root / "cache" / "static", RULES)
        batches = static_run(run_dir, files, cache, workers=workers)
    finally:
        fetcher.close()
    snapshot.save(run_dir / STATIC_SNAPSHOT)
    return batches
