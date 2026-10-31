"""Stage 2: static heuristics over the file contents a package batch adds.

See `docs/stages/static.md`. For a `PackageBatch`, every file content (by SHA-256) that is in
some version but not in the base is analysed once, through a content-addressed cache, and its
findings are attributed to the first version that contained it.

A changed file is matched whole, so its old matches would fire again on every release (a
Telegram bot's `api.telegram.org/bot` in every version of the bot). A match the base version's
file at the same path already had (same rule, same explanation up to numbers) is LOW, weight 1,
and says so; a bundler's content-hashed chunk (`registry-BX6j2lnF.mjs`) is compared with the
base's chunks of the same name (`BaseFiles`); a match only in a file that never runs
(documentation, type declarations, source maps, tests) is LOW too (`_demoted`; until
2026-10-30 only `exfil-endpoint`, then every rule: `@atairo/qixi` was MEDIUM for an IP in a
bundled dependency's README).
Nothing is dropped: the evidence stays for the reviewer and for scoring with other signals.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Final

import httpx

from kitsunox.core.interfaces import Ecosystem
from kitsunox.core.models import (
    Finding,
    PackageBatch,
    Record,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.core.rules import ArtifactRule, FileMatch, FileRule, rules_fingerprint
from kitsunox.core.run import STATIC_SNAPSHOT, DataDir, EcosystemFactory
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.rules.static import RULES
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.triage import at_least
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchError, FetchMode, HttpFetcher, Snapshot, TransientFetchError

STAGE_ID: Final = "static"
# 16 MB, not 2: the Shai-Hulud payload (`bun_environment.js`) is ~10 MB, and 698 of 965
# first-release compromised samples added a file over 2 MB (2026-10-27).
MAX_FILE_BYTES: Final = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES: Final = MAX_FILE_BYTES
# Decision reasons for missing files, e.g. "files unavailable: ..." or "; base unavailable, will
# retry: ...". The retry form marks a network failure, which `collect` retries.
UNAVAILABLE: Final = "unavailable: "
WILL_RETRY: Final = "unavailable, will retry: "
DEFAULT_THRESHOLD: Final = Severity.MEDIUM
ARTIFACT_RULES_BY_ECOSYSTEM: Final[dict[str, Sequence[ArtifactRule]]] = {"npm": NPM_ARTIFACT_RULES}

Tree = Mapping[str, bytes]


class NewContent(Record):
    path: str
    sha256: str
    size: int
    first_version: str


class Unavailable(Record):
    """A version's files could not be read; `reason` says why (too large, fetch failed).
    `transient`: a network failure, so fetching again later may work."""

    reason: str
    transient: bool = False


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
            try:
                return tuple(FileMatch.model_validate(m) for m in json.loads(path.read_bytes()))
            except ValueError:
                pass  # a damaged entry is a miss: recompute and overwrite it
        result = analyse(content, self.rules)
        if path is not None:
            atomic_write(path, json.dumps([m.model_dump(mode="json") for m in result]).encode())
        return result


# Files npm ships that never run: documentation, type declarations, source maps, tests.
NON_EXECUTING: Final = re.compile(
    r"(?:^|/)(?:readme|changelog|license|contributing|history|security)[^/]*$"
    r"|\.(?:md|markdown|mdx|txt|rst|d\.ts|d\.mts|d\.cts|map)$"
    r"|(?:^|/)(?:docs?|examples?|test|tests|__tests__|fixtures?)/",
    re.IGNORECASE,
)
_NUMBER: Final = re.compile(r"[0-9]+")
PREVIOUS_NOTE: Final = " Also in the previous version's file: not new in this release."
DOCS_NOTE: Final = " Only in a file that doesn't run (documentation, types, a source map or tests)."


def _key(match: FileMatch) -> tuple[str, str]:
    """A match's identity across versions: its rule and explanation, numbers aside (`3235
    obfuscator-style identifiers` and `3301 ...` are the same finding)."""
    return (match.rule_id, _NUMBER.sub("#", match.explanation))


def _demoted(match: FileMatch, path: str, before: frozenset[tuple[str, str]]) -> FileMatch:
    if match.severity in (Severity.INFO, Severity.LOW):
        return match
    if _key(match) in before:
        note = PREVIOUS_NOTE
    elif NON_EXECUTING.search(path):
        note = DOCS_NOTE
    else:
        return match
    return match.model_copy(
        update={
            "severity": Severity.LOW,
            "weight": min(match.weight, 1.0),
            "explanation": match.explanation + note,
        }
    )


# A bundler's content hash before the extension: `-BX6j2lnF.mjs` (Vite, Rollup), `.3f2a9b1c.js`
# (webpack). It has a digit, so a word (`-registry.js`) is not taken for one.
_HASHED: Final = re.compile(r"[-.](?=[A-Za-z_]*[0-9])[A-Za-z0-9_]{8,20}(\.(?:m?js|cjs))$")
MAX_COUNTERPARTS: Final = 4  # base chunks of one name compared with a new one


def unhashed(path: str) -> str | None:
    """`path` without its content hash (`dist/a-BX6j2lnF.mjs` -> `dist/a.mjs`), or None."""
    match = _HASHED.search(path)
    return path[: match.start()] + match.group(1) if match else None


class BaseFiles:
    """The base version's files a new file is compared with: the one at the same path, or for a
    content-hashed chunk, which gets a new name whenever its content changes, the base's chunks
    of the same name without the hash (`@camstack/addon-post-analysis` 1.2.654: a comment naming
    `*.trycloudflare.com` was HIGH again on every release)."""

    def __init__(self, tree: Tree | None) -> None:
        self.tree: Tree = tree or {}
        self._by_name: dict[str, list[str]] | None = None

    def counterparts(self, path: str) -> list[bytes]:
        if path in self.tree:
            return [self.tree[path]]
        name = unhashed(path)
        if name is None:
            return []
        if self._by_name is None:
            self._by_name = {}
            for other in sorted(self.tree):
                if (other_name := unhashed(other)) is not None:
                    self._by_name.setdefault(other_name, []).append(other)
        return [self.tree[p] for p in self._by_name.get(name, ())[:MAX_COUNTERPARTS]]


def _base_keys(base: BaseFiles, path: str, cache: ContentCache) -> frozenset[tuple[str, str]]:
    """What the base version's counterparts of `path` matched (nothing if it had none)."""
    return frozenset(
        _key(m)
        for content in base.counterparts(path)
        for m in cache.matches(sha256_hex(content), content)
    )


def content_matches(
    item: NewContent, content: bytes, base: BaseFiles, cache: ContentCache
) -> list[FileMatch]:
    """A new content's matches as Stage 2 reports them (`_demoted` against the base)."""
    matches = cache.matches(item.sha256, content)
    before = _base_keys(base, item.path, cache) if matches else frozenset()
    return [_demoted(m, item.path, before) for m in matches]


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
    artifact_rules: Sequence[ArtifactRule] = (),
    threshold: Severity = DEFAULT_THRESHOLD,
) -> PackageBatch:
    """Run Stage 2 on a batch. `trees` gives a version's extracted files (fetching as needed).
    File rules see each new content once; `artifact_rules` see each version's metadata and
    whole file tree. A version whose files are unavailable gets no findings and says why. An
    unavailable base counts as empty: every file of the first version is then new, which costs
    time but can only add findings."""
    base = trees(batch.base) if batch.base else None
    base_note = ""
    if isinstance(base, Unavailable):
        base_note = f"; base {_unavailable(base)}"
    missing: dict[str, Unavailable] = {}
    by_artifact: dict[str, tuple[Finding, ...]] = {}

    def versions() -> Iterator[tuple[str, Tree]]:
        for candidate in batch.versions:
            snapshot = candidate.change.new
            version = snapshot.ref.version
            tree = trees(snapshot)
            if isinstance(tree, Unavailable):
                missing[version] = tree
                continue
            by_artifact[version] = tuple(
                f for rule in artifact_rules for f in rule.evaluate_artifact(snapshot, tree)
            )
            yield version, tree

    found: dict[str, list[tuple[str, FileMatch]]] = {}
    base_tree = None if isinstance(base, Unavailable) else base
    base_files = BaseFiles(base_tree)
    for item, content in new_contents(base_tree, versions()):
        for match in content_matches(item, content, base_files, cache):
            found.setdefault(item.first_version, []).append((item.path, match))
    updated = []
    for candidate in batch.versions:
        version = candidate.change.new.ref.version
        findings = by_artifact.get(version, ()) + tuple(
            match.finding(path) for path, match in found.get(version, [])
        )
        flagged = sorted({f.rule_id for f in findings if at_least(f.severity, threshold)})
        if version in missing:
            reason = f"files {_unavailable(missing[version])}"
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


def _unavailable(missing: Unavailable) -> str:
    return f"{WILL_RETRY if missing.transient else UNAVAILABLE}{missing.reason}"


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
            return Unavailable(
                reason=f"{type(exc).__name__}: {exc}"[:300],
                transient=isinstance(exc, TransientFetchError),
            )


def static_run(
    run_dir: Path,
    files: Callable[[VersionSnapshot], Tree | Unavailable],
    cache: ContentCache,
    *,
    workers: int = 8,
    artifact_rules: Sequence[ArtifactRule] = (),
) -> tuple[PackageBatch, ...]:
    """Stage 2 over a triaged run: reads `batches.jsonl`, writes `static.jsonl` (the same
    batches in the same order, each version with Stage 2 findings and decision). `files` must
    be thread-safe."""
    lines = (run_dir / "batches.jsonl").read_bytes().splitlines()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        batches = tuple(
            pool.map(
                lambda line: analyse_batch(
                    PackageBatch.load_json(line), files, cache, artifact_rules=artifact_rules
                ),
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
    seed: Snapshot | None = None,
) -> tuple[PackageBatch, ...]:
    """Stage 2 on a recorded, triaged run, fetching live. Tarballs go into the data directory's
    blob store (immutable, so a tarball already fetched is not fetched again), and the requests
    are recorded in `static-snapshot.json` next to the run. A `seed` (the run's own earlier
    snapshot, when re-scoring) serves what it holds as recorded and keeps it. The caller holds
    `DataDir.lock()`."""
    run_dir = data.run_dir(run_id)
    snapshot = seed if seed is not None else Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=client,
    )
    try:
        ecosystem = factory(fetcher)
        files = ArtifactFiles(ecosystem)
        cache = ContentCache(data.root / "cache" / "static", RULES)
        batches = static_run(
            run_dir,
            files,
            cache,
            workers=workers,
            artifact_rules=ARTIFACT_RULES_BY_ECOSYSTEM.get(ecosystem.name, ()),
        )
    finally:
        fetcher.close()
    snapshot.save(run_dir / STATIC_SNAPSHOT)
    return batches


def needs_retry(batches: Iterable[PackageBatch]) -> bool:
    """Whether any version or base of a Stage 2 result failed on the network."""
    return any(
        c.history[-1].stage == STAGE_ID and WILL_RETRY in c.history[-1].reason
        for b in batches
        for c in b.versions
    )
