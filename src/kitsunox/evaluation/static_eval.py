"""Stage 2 predictors for evaluation: where each sample's files come from.

- DataDog samples: the package files inside the sample's encrypted zip (decrypted in memory,
  never written out). The base is the previous version's tarball from npm.
- Everything else (benign samples from our runs): new and base tarballs from npm.

npm tarballs are integrity-checked and cached immutably under `data/eval/tarballs/`, so a
re-run is offline. A base that npm no longer serves is treated as empty (every file is new),
and such samples are counted in `notes`, as are samples whose own files are unavailable.
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime

from kitsunox.core.models import ArtifactRef, Change, Severity
from kitsunox.core.rules import RuleContext, run_rules
from kitsunox.core.run import DataDir
from kitsunox.ecosystems.npm.registry import NpmEcosystem
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.ecosystems.npm.rules.artifact import HiddenInstallScript
from kitsunox.ecosystems.npm.rules.metadata import RULES as NPM_RULES
from kitsunox.evaluation.datadog import RAW_URL, SAMPLE_LIMITS, ZIP_PASSWORD
from kitsunox.evaluation.dataset import EvalSample, ExternalSampleSet
from kitsunox.rules.static import RULES as STATIC_RULES
from kitsunox.stages.static import MAX_ARTIFACT_BYTES, ContentCache, new_contents
from kitsunox.stages.triage import at_least, triage
from kitsunox.util.archive import ArtifactTree, extract_zip
from kitsunox.util.http import BlobStore, FetchError, FetchMode, HttpFetcher, Snapshot

Tree = Mapping[str, bytes]


def strip_to_package(tree: Tree) -> dict[str, bytes]:
    """DataDog zips nest files as `tmp/<x>/<name>/package/<file>`; keep what is under the
    first `package/` directory, the same layout as an npm tarball with its prefix stripped."""
    out = {}
    for path, content in tree.items():
        parts = path.split("/")
        if "package" in parts[:-1]:
            out["/".join(parts[parts.index("package") + 1 :])] = content
    return out


class StaticRules:
    """Stage 2 alone: forward if any new file content has a finding at MEDIUM or above."""

    name = "stage2-rules"
    include_stage1 = False

    def __init__(self, data: DataDir, external: list[ExternalSampleSet]) -> None:
        root = data.root / "eval" / "tarballs"
        self.npm = NpmEcosystem(
            HttpFetcher(
                store=BlobStore(root / "blobs"),
                snapshot=Snapshot(),
                mode=FetchMode.RECORD,
                immutable_index=root / "http-immutable",
            )
        )
        self.cache = ContentCache(data.root / "cache" / "static", STATIC_RULES)
        self.malware = BlobStore(data.root / "eval" / "malware" / "blobs")
        self.zip_blobs: dict[str, str] = {}
        for sample_set in external:
            snapshot_path = data.root / "eval" / "external" / sample_set.ecosystem / "snapshots"
            snapshot = Snapshot.load(snapshot_path / f"{sample_set.id}.json")
            by_url = {e.url: e.sha256 for e in snapshot.entries.values()}
            for item in sample_set.samples:
                url = f"{RAW_URL}/{sample_set.commit}/samples/npm/{item.path}"
                if url in by_url:
                    self.zip_blobs[f"{sample_set.source}:{item.path}"] = by_url[url]
        self.notes: Counter[str] = Counter()
        self._lock = threading.Lock()

    def forward(self, change: Change, sample: EvalSample) -> bool:
        try:
            return self._forward(change, sample)
        except Exception as exc:  # hostile archives: count, never abort the evaluation
            self._note(f"error: {type(exc).__name__} (not forwarded)")
            return False

    def _forward(self, change: Change, sample: EvalSample) -> bool:
        if self.include_stage1 and any(
            at_least(f.severity, Severity.MEDIUM)
            for f in run_rules(NPM_RULES, change, RuleContext(as_of=_as_of(change)))
        ):
            return True
        new = self._new_tree(change, sample)
        if new is None:
            self._note("new files unavailable (not forwarded)")
            return False
        # A zip member skipped as oversize would make the size check fire on our own gap.
        complete = not any(s.reason == "over per-file limit" for s in new.skipped)
        rules = NPM_ARTIFACT_RULES if complete else (HiddenInstallScript(),)
        if any(
            at_least(f.severity, Severity.MEDIUM)
            for rule in rules
            for f in rule.evaluate_artifact(change.new, new)
        ):
            return True
        base: Tree | None = self._tarball(change.previous.artifact) if change.previous else {}
        if base is None:
            self._note("base unavailable (all files treated as new)")
        version = change.new.ref.version
        for item, content in new_contents(base or {}, [(version, new)]):
            if any(
                at_least(m.severity, Severity.MEDIUM)
                for m in self.cache.matches(item.sha256, content)
            ):
                return True
        return False

    def _new_tree(self, change: Change, sample: EvalSample) -> ArtifactTree | None:
        label = next((i for i in sample.label_ids if i in self.zip_blobs), None)
        if label is None:
            return self._tarball(change.new.artifact)
        tree = extract_zip(
            self.malware.get(self.zip_blobs[label]),
            limits=SAMPLE_LIMITS,
            password=ZIP_PASSWORD,
            include=lambda p: "/package/" in p,
            skip_oversize=True,
        )
        return ArtifactTree(files=strip_to_package(tree), skipped=tree.skipped)

    def _tarball(self, artifact: ArtifactRef | None) -> ArtifactTree | None:
        if artifact is None:
            return None
        try:
            return self.npm.fetch_artifact(artifact)
        except FetchError, ValueError:
            return None

    def _note(self, key: str) -> None:
        with self._lock:
            self.notes[key] += 1


class StaticAndMetadataRules(StaticRules):
    """Either stage's rules, as if Stage 2 read every release (an upper bound)."""

    name = "stage1+2-rules"
    include_stage1 = True


class Pipeline(StaticRules):
    """What the pipeline flags: Stage 1 rules, or Stage 2 rules on what Stage 1 routes to it
    (watched, new package, grown size) and Stage 2 agrees to fetch (declared size cap)."""

    name = "pipeline"

    def _forward(self, change: Change, sample: EvalSample) -> bool:
        decision = triage(change, RuleContext(as_of=_as_of(change))).history[-1]
        if decision.forwarded and decision.reason.startswith("rules:"):
            return True
        if not decision.forwarded:
            return False
        size = change.new.artifact.unpacked_size if change.new.artifact else None
        if size is not None and size > MAX_ARTIFACT_BYTES:
            return False
        return super()._forward(change, sample)


def _as_of(change: Change) -> datetime:
    return change.new.publish.published_at or datetime(1970, 1, 1, tzinfo=UTC)
