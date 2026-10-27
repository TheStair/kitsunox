"""Stage 2: static heuristics over the file contents a package batch adds.

See `docs/stages/static.md`. For a `PackageBatch`, every file content (by SHA-256) that is in
some version but not in the base is analysed once, through a content-addressed cache, and its
findings are attributed to the first version that contained it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final

from kitsunox.core.models import Candidate, PackageBatch, Record, Severity, StageDecision
from kitsunox.core.rules import FileMatch, FileRule, rules_fingerprint
from kitsunox.rules.static import RULES
from kitsunox.stages.triage import at_least
from kitsunox.util.hashing import sha256_hex

STAGE_ID: Final = "static"
MAX_FILE_BYTES: Final = 2 * 1024 * 1024
DEFAULT_THRESHOLD: Final = Severity.MEDIUM

Tree = Mapping[str, bytes]


class NewContent(Record):
    path: str
    sha256: str
    size: int
    first_version: str


def new_contents(
    base: Tree | None, versions: Sequence[tuple[str, Tree]]
) -> list[tuple[NewContent, bytes]]:
    """Contents in any version that the base does not have, each once, in version order (then
    path order). The first path and version a content appears under is the one reported."""
    seen = {sha256_hex(content) for content in (base or {}).values()}
    out: list[tuple[NewContent, bytes]] = []
    for version, tree in versions:
        for path in sorted(tree):
            content = tree[path]
            digest = sha256_hex(content)
            if digest in seen:
                continue
            seen.add(digest)
            out.append(
                (
                    NewContent(path=path, sha256=digest, size=len(content), first_version=version),
                    content,
                )
            )
    return out


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
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{id(result)}.tmp")
            tmp.write_text(json.dumps([m.model_dump(mode="json") for m in result]))
            tmp.replace(path)
        return result


def analyse(content: bytes, rules: Sequence[FileRule] = RULES) -> tuple[FileMatch, ...]:
    if len(content) > MAX_FILE_BYTES or b"\x00" in content[:8192]:
        return ()  # too large for regex triage, or binary
    text = content.decode("utf-8", errors="replace")
    return tuple(m for rule in rules for m in rule.evaluate_text(text))


def analyse_batch(
    batch: PackageBatch,
    trees: Callable[[Candidate], Tree],
    base_tree: Tree | None,
    cache: ContentCache,
    *,
    threshold: Severity = DEFAULT_THRESHOLD,
) -> PackageBatch:
    """Run Stage 2 on a batch. `trees` gives a version's extracted files (fetching as needed)."""
    versions = [(c.change.new.ref.version, trees(c)) for c in batch.versions]
    found: dict[str, list[tuple[str, FileMatch]]] = {}
    for item, content in new_contents(base_tree, versions):
        for match in cache.matches(item.sha256, content):
            found.setdefault(item.first_version, []).append((item.path, match))
    updated = []
    for candidate in batch.versions:
        hits = found.get(candidate.change.new.ref.version, [])
        findings = tuple(match.finding(path) for path, match in hits)
        flagged = sorted({f.rule_id for f in findings if at_least(f.severity, threshold)})
        decision = StageDecision(
            stage=STAGE_ID,
            forwarded=bool(flagged),
            reason=f"rules: {', '.join(flagged)}" if flagged else "no signal",
        )
        updated.append(
            candidate.model_copy(
                update={
                    "findings": candidate.findings + findings,
                    "history": (*candidate.history, decision),
                }
            )
        )
    return batch.model_copy(update={"versions": tuple(updated)})
