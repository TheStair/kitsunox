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
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Final, override

from pydantic import Field

from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    Finding,
    Record,
    Severity,
    StageDecision,
)
from kitsunox.core.rules import RuleContext, rules_fingerprint
from kitsunox.core.run import DataDir
from kitsunox.ecosystems.npm.install import gyp_commands, install_sources
from kitsunox.ecosystems.npm.registry import NpmEcosystem
from kitsunox.ecosystems.npm.repo import NpmLocator
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.ecosystems.npm.rules.artifact import HiddenInstallScript
from kitsunox.evaluation.datadog import RAW_URL, SAMPLE_LIMITS, ZIP_PASSWORD
from kitsunox.evaluation.dataset import EvalSample, ExternalSampleSet
from kitsunox.evaluation.labels import label_store
from kitsunox.githost.github import TOKEN_ENV, GitHub, GitHubRepo
from kitsunox.rules.static import RULES as STATIC_RULES
from kitsunox.stages.ast import CapabilityCache, code_change
from kitsunox.stages.code import CODE_RULES
from kitsunox.stages.correlate import CorrelationContext, correlate, wants_repo
from kitsunox.stages.repo import RepoMemory, compare, with_history, with_trust
from kitsunox.stages.review import CORRELATION_RULES, NPM, NpmDependencyLookup
from kitsunox.stages.static import (
    BaseFiles,
    ContentCache,
    content_matches,
    fetch_limit,
    new_contents,
)
from kitsunox.stages.triage import at_least, triage
from kitsunox.util.archive import ArtifactTree, extract_zip
from kitsunox.util.disk import DiskSpaceError
from kitsunox.util.env import env_value
from kitsunox.util.http import (
    BlobStore,
    FetchedResponse,
    FetchError,
    FetchMode,
    HttpFetcher,
    Snapshot,
)

Tree = Mapping[str, bytes]
# Prefix of the `notes` that say what a result was computed with (rule fingerprint, watchlist,
# lookup counts), as opposed to the ones that count samples something went wrong for.
ABOUT: Final = "about: "


def strip_to_package(tree: Tree) -> dict[str, bytes]:
    """DataDog zips nest files as `tmp/<x>/<name>/package/<file>`; keep what is under the
    first `package/` directory, the same layout as an npm tarball with its prefix stripped."""
    out = {}
    for path, content in tree.items():
        parts = path.split("/")
        if "package" in parts[:-1]:
            out["/".join(parts[parts.index("package") + 1 :])] = content
    return out


class SampleFindings(Record):
    """Every stage's findings for one sample, as the live pipeline would produce them.

    `routed` is whether Stage 1 forwards the change to the file stages (any reason, decision
    0008) and Stage 2 agrees to fetch it (declared size cap). `stage2`/`stage3` are None when
    the file stages were not run for this predictor, or the sample's files are unavailable.
    """

    stage1: tuple[Finding, ...]
    routed: bool
    stage2: tuple[Finding, ...] | None = None
    stage3: tuple[Finding, ...] | None = None
    package: Mapping[str, bytes] | None = Field(default=None, exclude=True)

    @property
    def stage1_flagged(self) -> bool:
        return _flags(self.stage1)

    @property
    def stage2_flagged(self) -> bool:
        return _flags(self.stage2 or ())

    @property
    def stage3_flagged(self) -> bool:
        return _flags(self.stage3 or ())

    @property
    def findings(self) -> tuple[Finding, ...]:
        return self.stage1 + (self.stage2 or ()) + (self.stage3 or ())


def _flags(findings: Sequence[Finding]) -> bool:
    return any(at_least(f.severity, Severity.MEDIUM) for f in findings)


class StaticRules:
    """Stage 2 alone: forward if any new file content has a finding at MEDIUM or above.

    Subclasses choose which stages run (`include_stage2/3`), when the file stages are needed
    (`needs_files`), and what is forwarded (`decide`)."""

    name = "stage2-rules"
    include_stage2 = True
    include_stage3 = False

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
        self.capabilities = CapabilityCache(data.root / "cache" / "ast")
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
            return self.decide(change, self.collect(change, sample))
        except DiskSpaceError:
            raise
        except Exception as exc:  # hostile archives: count, never abort the evaluation
            self._note(f"error: {type(exc).__name__} (not forwarded)")
            return False

    def needs_files(self, found: SampleFindings) -> bool:
        return True

    def decide(self, change: Change, found: SampleFindings) -> bool:
        return found.stage2_flagged

    def collect(self, change: Change, sample: EvalSample) -> SampleFindings:
        candidate = triage(change, RuleContext(as_of=_as_of(change)))
        size = change.new.artifact.unpacked_size if change.new.artifact else None
        found = SampleFindings(
            stage1=candidate.findings,
            routed=candidate.history[-1].forwarded
            and (size is None or size <= fetch_limit(change.new)),
        )
        if not self.needs_files(found):
            return found
        new = self._new_tree(change, sample)
        if new is None:
            self._note("new files unavailable (not forwarded)")
            return found
        base: Tree | None = self._tarball(change.previous.artifact) if change.previous else {}
        if base is None:
            self._note("base unavailable (all files treated as new)")
        stage2 = self._stage2(change, new, base) if self.include_stage2 else None
        stage3 = None
        if self.include_stage3:
            code = code_change(
                change.new,
                new,
                base if change.previous else None,
                self.capabilities,
                install_sources,
                change.previous.ref.version if change.previous else None,
                build_commands=gyp_commands,
            )
            stage3 = tuple(f for rule in CODE_RULES for f in rule.evaluate_code(code))
        return found.model_copy(update={"stage2": stage2, "stage3": stage3, "package": new})

    def _stage2(self, change: Change, new: ArtifactTree, base: Tree | None) -> tuple[Finding, ...]:
        # A zip member skipped as oversize would make the size check fire on our own gap.
        complete = not any(s.reason == "over per-file limit" for s in new.skipped)
        rules = NPM_ARTIFACT_RULES if complete else (HiddenInstallScript(),)
        version = change.new.ref.version
        base_files = BaseFiles(base)
        return tuple(f for rule in rules for f in rule.evaluate_artifact(change.new, new)) + tuple(
            m.finding(item.path)
            for item, content in new_contents(base or {}, [(version, new)])
            for m in content_matches(item, content, base_files, self.cache)
        )

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

    def needs_files(self, found: SampleFindings) -> bool:
        return not found.stage1_flagged

    def decide(self, change: Change, found: SampleFindings) -> bool:
        return found.stage1_flagged or found.stage2_flagged


class Pipeline(StaticRules):
    """What the pipeline flags: Stage 1 rules, or Stage 2 rules on what Stage 1 routes to it
    (watched, new package, grown size) and Stage 2 agrees to fetch (declared size cap)."""

    name = "pipeline"

    def needs_files(self, found: SampleFindings) -> bool:
        return found.routed and not found.stage1_flagged

    def decide(self, change: Change, found: SampleFindings) -> bool:
        return found.stage1_flagged or found.stage2_flagged or found.stage3_flagged


class PinnedFetcher(HttpFetcher):
    """A fetcher that treats every response as immutable: the first successful response to a
    request is kept in its immutable index and served to every later evaluation, even for
    documents that change (packuments). That makes an evaluation re-run offline and stable,
    as of the first run; a failed request (and a 404, which the index doesn't keep) is asked
    again."""

    @override
    def needs_network(
        self, url: str, *, headers: Mapping[str, str] | None = None, immutable: bool = False
    ) -> bool:
        return super().needs_network(url, headers=headers, immutable=True)

    @override
    def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, immutable: bool = False
    ) -> FetchedResponse:
        return super().get(url, headers=headers, immutable=True)


def _as_of(change: Change) -> datetime:
    return change.new.publish.published_at or datetime(1970, 1, 1, tzinfo=UTC)


class CodeRules(StaticRules):
    """Stage 3 rules alone, as if Stage 3 read every release."""

    name = "stage3-rules"
    include_stage2 = False
    include_stage3 = True

    def decide(self, change: Change, found: SampleFindings) -> bool:
        return found.stage3_flagged


class PipelineWithCode(Pipeline):
    """`pipeline` plus Stage 3 on the same routed versions."""

    name = "pipeline+3"
    include_stage3 = True


class Correlated(PipelineWithCode):
    """End to end with Stage 4: what the pipeline would report. Stages 1-3 run on the routed
    versions as in `pipeline+3`; Stage 4 runs on every version, as live. Known-malware records
    count only if published by the release's publish time (later labels don't leak in), and
    the repository comparison runs for the versions `wants_repo` picks, with repository data
    cached under `data/eval/repos/`. Dependency records come from the registry with the request
    a live run sends, one per name and no limits, pinned under `data/eval/dependencies/`
    (`PinnedFetcher`): the first evaluation to fetch a packument fixes it for every later one,
    so a re-run is offline and doesn't drift as packages are taken down. Only versions
    published by the sample's publish time count. Watched means on the newest watchlist, the
    one DataDog samples were imported with. With a GitHub token (`GITHUB_TOKEN`), clean
    comparisons get the repository's facts as live (`with_trust`), pinned under
    `data/eval/github-api/` like the dependency records: as of the first evaluation that asked,
    not as of the release (a repository deleted since reads as not shown, so the release
    stays reported). Compared updates get their history (`with_history`) the same way; two
    commits relate the same way whenever they are asked about.

    `notes` also records (under `ABOUT`) what a result depends on besides the dataset: the
    correlation rules' fingerprint, the watchlist and label set ids, and the dependency lookup
    counts (looked up, found, missing, failed)."""

    name = "pipeline+4"

    def __init__(self, data: DataDir, external: list[ExternalSampleSet]) -> None:
        super().__init__(data, external)
        labels_id = label_store(data).latest_id(NPM)
        self.labels = label_store(data).load(NPM, labels_id) if labels_id else None
        root = data.root / "eval" / "repos"
        self.github = GitHub(
            HttpFetcher(
                store=BlobStore(root / "blobs"),
                snapshot=Snapshot(),
                mode=FetchMode.RECORD,
                immutable_index=root / "http-immutable",
            )
        )
        self.locator = NpmLocator()
        self.refs: dict[GitHubRepo, Mapping[str, str] | None] = {}
        root = data.root / "eval" / "github-api"
        self.api = GitHub(
            PinnedFetcher(
                store=BlobStore(root / "blobs"),
                snapshot=Snapshot(),
                mode=FetchMode.RECORD,
                immutable_index=root / "http-immutable",
            ),
            token=env_value(TOKEN_ENV),
        )
        self.trust_memory = RepoMemory(self.refs)
        watchlist_id = data.watchlists.latest_id(NPM)
        self.watchlist = data.watchlists.load(NPM, watchlist_id) if watchlist_id else None
        root = data.root / "eval" / "dependencies"
        self.dependencies = NpmDependencyLookup(
            PinnedFetcher(
                store=BlobStore(root / "blobs"),
                snapshot=Snapshot(),
                mode=FetchMode.RECORD,
                immutable_index=root / "http-immutable",
            ),
            cap=None,
            per_release=None,
        )
        self.notes[f"{ABOUT}correlation rules {rules_fingerprint(CORRELATION_RULES)}"] = 1
        self.notes[f"{ABOUT}watchlist {watchlist_id}"] = 1
        self.notes[f"{ABOUT}labels {labels_id}"] = 1

    def needs_files(self, found: SampleFindings) -> bool:
        return found.routed

    def decide(self, change: Change, found: SampleFindings) -> bool:
        return self.correlated(change, found).history[-1].forwarded

    def correlated(self, change: Change, found: SampleFindings) -> Candidate:
        candidate = Candidate(
            change=change,
            findings=found.findings,
            history=(
                StageDecision(
                    stage="triage",
                    forwarded=found.routed,
                    reason="rules: stage 1" if found.stage1_flagged else "routed",
                ),
                StageDecision(stage="static", forwarded=found.stage2_flagged, reason="eval"),
                StageDecision(stage="ast", forwarded=found.stage3_flagged, reason="eval"),
            ),
        )
        repo = None
        if wants_repo(candidate) and found.package is not None:
            try:
                repo = compare(
                    change, found.package, self.locator, self.github, refs_cache=self.refs
                )
            except FetchError as exc:
                self._note(f"repo: {type(exc).__name__} (no comparison)")
            flagged = any(at_least(f.severity, Severity.MEDIUM) for f in found.findings)
            if repo is not None and flagged:
                repo = with_trust(repo, self.api, self.trust_memory)
            if repo is not None:
                repo = with_history(
                    repo, change, self.locator, self.api, self.trust_memory, ask_range=flagged
                )
        ctx = CorrelationContext(
            as_of=_as_of(change),
            known_bad=self.labels,
            repo=repo,
            watchlist=self.watchlist,
            dependencies=self.dependencies,
        )
        result = correlate(candidate, ctx, CORRELATION_RULES)
        self._dependency_notes()
        return result

    def _dependency_notes(self) -> None:
        """The lookup counts so far, under the notes lock: the last sample to finish writes the
        final ones, since every lookup finished before its own sample did."""
        with self._lock:
            stats = self.dependencies.stats()
            for key in ("looked_up", "found", "missing", "failed"):
                count = stats[key]
                if isinstance(count, int):
                    self.notes[f"{ABOUT}dependency lookups {key}"] = count
