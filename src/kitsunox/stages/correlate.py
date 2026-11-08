"""Stage 4: correlation and scoring. Puts every stage's findings for a version together, adds
the findings that need more than one stage's view or outside knowledge, and decides what a
human should review.

- **Input:** every version Stage 1 triaged (`triage.jsonl`), with Stages 2-3's findings for
  those routed to them (`ast.jsonl`). Versions never routed still carry Stage 1's weak
  signals, and two weak signals together can be worth a look: on `day1`, most malicious
  updates the pipeline missed were never routed, and many had the same two LOW findings.
- **Correlation rules** see the whole `Candidate`: the change and every finding so far. Some
  read outside data through the `CorrelationContext` (known-malware records, the comparison
  with the source repository, the registry records of new dependencies, the run's
  watchlist); combination rules read only the findings.
- **Score:** each rule counts once, at its largest weight (Stage 2 reports one finding per
  file, and twenty matching files are not twenty signals); INFO counts nothing. Every term is a
  named rule, so the report can show how the number was reached. Reports are ordered by it.
- **Decision:** report a version when any finding is MEDIUM or above (each stage's own bar, so
  recall is never lower than Stages 1-3 together), or when LOW findings add up to
  `REPORT_SCORE`. See `docs/stages/correlate.md` for the numbers.

Like the other stages, nothing here reads the clock: "known by" means known by the run's
`as_of`, so a re-run with a later label set doesn't change an old run's answers.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Final, Protocol, overload

from kitsunox.core.models import Candidate, Finding, PackageBatch, Severity, StageDecision
from kitsunox.core.rules import rules_fingerprint
from kitsunox.core.watchlist import Watchlist
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.repo import NetworkRequests, RepoComparison
from kitsunox.stages.triage import at_least
from kitsunox.util.files import LineFile, atomic_write

STAGE_ID: Final = "correlate"
# Stage 4's own behaviour, apart from its rules (whose versions `rules_fingerprint` covers),
# recorded in `correlate.json`. 2: network failures retried in passes, with per-pass memory of
# failed repositories and the outage guard. 3: failures remembered per request (refs, or an
# archive at one commit) with one explanation per request; the outage guard counts requests;
# release files that failed on the network are left to Stage 2. 4: the context carries the run's
# watchlist and a dependency lookup (registry records of added dependencies, capped and
# accounted in `correlate.json`). 5: dependency lookups are fetched before the rules run (a
# per-release limit, updates planned first) and those that failed on the network are retried in
# the same passes and under the same outage guard as repository lookups. 6: a missing file
# whose content is elsewhere in the repository is explained, and an install hook a repository
# file writes is noted (`ManifestDifference.built_by`). 7: LOW findings together add at most
# `LOW_CAP` to the score. 8: `code.capability-gained` and `static.webhook-placeholder` join
# `WEAK_ALONE`. 9: clean comparisons can carry the repository's facts (`repo.established-match`);
# clearing install-code findings with it exists but is off (`CLEAR_ESTABLISHED`). 10: compared
# updates carry the previous release's commit (`RepoComparison.history`): `repo.history-match`,
# `repo.commit-after-release`, `npm.repo.no-new-commits`; clearing with a history match is off
# too (`CLEAR_HISTORY`). 11: at most `MAX_REPO_COMPARISONS` versions a run are compared,
# flagged ones first (`plan_comparisons`). 12: a dependency lookup that returned 404 (`MISSING`)
# is a finding (`npm.dependency.missing`), no longer only a count. 13: an earlier stage's
# explanation finding makes the finding it explains LOW (`EXPLAINED`: Stage 3's
# `npm.install-build-tool` for `npm.install-hook`). 14: Stage 3's `npm.install-explained`
# (S1-S3 shapes) explains the three install rules. Output without the field is 1.
STAGE_VERSION: Final = 14
REPORT_SEVERITY: Final = Severity.MEDIUM
# Measured on `day1`: LOW findings of Stages 1-3 summing to 3, 4 or 5 added 0.6, 0.2 and 0
# points of recall on malicious updates for 2.0, 0.8 and 0.4 points of benign updates reported;
# at 6 they add neither. Below 6, routine LOWs (process-exec + network + npm-publish) add up.
REPORT_SCORE: Final = 6.0
# LOW findings together add at most this to the score, so routine LOWs alone never reach
# REPORT_SCORE. A large release matches six generic regexes at once (process-exec, network,
# dynamic-code, env-harvest, npm-publish, sensitive-path; many in CHANGELOGs and tests): such
# LOW-only versions were 165 of the 1,078 unreviewed live-queue versions still reported under
# the current rules (2026-10-30). On `vm-day1` the cap costs no malicious sample (2,496 kept)
# and drops 2 of 20 benign; a weak MEDIUM (`WEAK_ALONE`) with three LOWs still reaches 6.
LOW_CAP: Final = 3.0
CORRELATE_INFO: Final = "correlate.json"
# Repository (and dependency) lookups that failed on the network are tried again after the
# first pass, at most this many times, and only while a pass still recovers some (decision 0010
# addendum). Each request already gets `HttpFetcher`'s own attempts and back-off; no pass
# sleeps.
RETRY_PASSES: Final = 2
# ... unless the first pass looks like an outage: at least `OUTAGE_SHARE` of the distinct
# repository requests sent to the network, and at least `OUTAGE_MIN` of them, failed there
# (`NetworkRequests`). Flaky connections and rate limits fail a few of an hour's requests; half
# failing means GitHub (or our link) is down, and a retry pass minutes later would mostly wait
# out the fetcher's back-off again (up to ~1 min per request, over 8 workers). Below
# `OUTAGE_MIN` a retry pass costs a few minutes at most, so a small run always retries.
# Requests, not versions: one failed refs request of a 30-package monorepo burst is one
# failure. Counting requests, not time, keeps the decision off the clock. Dependency lookups
# (one registry request per name) are guarded on their own: a different host, so a GitHub
# outage says nothing about the registry.
OUTAGE_SHARE: Final = 0.5
OUTAGE_MIN: Final = 20
# Appended to the decision reason of a version whose comparison still failed on the network, so
# reviewers see it and `repo_network_failures` can count it (like Stage 2's `WILL_RETRY`).
NETWORK_UNCOMPARED: Final = "; not compared with its repository: network failure"
# The most versions of one run compared with their repository, and the note on the decision of
# each version `wants_repo` picked that is over it. An hourly run wants ~500; the 4-day catch-up
# of 2026-11-07 (405,710 changes) wanted 80,934 (1,745 flagged), and its archives filled the
# disk to the blob store's floor after 108 GB, so Stage 4 failed, the archives were pruned
# unreferenced, and the next tick started over. 2,000 is ~4 hours of normal ticks: at most
# ~30-40 GB of archives (~14 MB each on the first live day, ~20 MB in that run; versions that
# share a commit share one). Flagged versions come first (`plan_comparisons`).
MAX_REPO_COMPARISONS: Final = 2_000
BUDGET_UNCOMPARED: Final = "; not compared with its repository: over the run's comparison budget"
# Explanation prefix of an INFO finding saying a rule could not be evaluated for part of a
# version (e.g. a dependency whose registry record failed to load), so that "not checked" is
# never mistaken for "checked and clean". `correlate.json` counts the versions that have one.
NOT_EVALUATED: Final = "Not evaluated: "


class KnownBad(Protocol):
    """Outside knowledge about packages (e.g. OSV malware records)."""

    @property
    def id(self) -> str: ...

    def known_malware(self, name: str, as_of: datetime) -> tuple[str, ...]: ...


class DependencyStatus(StrEnum):
    FOUND = "found"
    MISSING = "missing"  # the registry had no such package (404) when the run asked
    FAILED = "failed"  # the lookup failed (the network, a malformed record): not evaluated
    CAPPED = "capped"  # not looked up: over the release's or the run's lookup limit


@dataclass(frozen=True)
class DependencyVersion:
    """One version of a dependency, as its registry record has it. `accounts` (maintainers and
    publisher) is empty for a version the registry no longer lists (taken down)."""

    version: str
    published_at: datetime
    accounts: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyRecord:
    """What the registry says about a package another one depends on. `versions` is every
    version with a publish time (oldest first), including later ones: rules keep those no
    later than `as_of`. `maintainers` is the record's current top-level list. `transient`: a
    `FAILED` lookup that failed on the network, so a retry pass may recover it."""

    name: str
    status: DependencyStatus
    versions: tuple[DependencyVersion, ...] = ()
    maintainers: tuple[str, ...] = ()
    transient: bool = False


class DependencyLookup(Protocol):
    """Registry records of the packages a release depends on; must be thread-safe, and answers
    each name once per pass (one request per name)."""

    def plan(self, candidates: Sequence[Candidate], ctx: CorrelationContext, /) -> Sequence[str]:
        """Called by `correlate_run` with every version in run order, before any rule runs:
        decide which names will be looked up (its limits pick the same names however the
        workers are scheduled) and return them. `correlate_run` looks them all up, and retries
        those that failed on the network, before the rules ask."""
        ...

    def __call__(self, name: str, /) -> DependencyRecord: ...

    def new_pass(self) -> None:
        """Called before each retry pass: forget the lookups that failed on the network."""
        ...

    def requests(self) -> NetworkRequests:
        """The network requests of the current pass (since `new_pass`, or the start)."""
        ...

    def stats(self) -> Mapping[str, object]:
        """Counts (and errors) for `correlate.json`."""
        ...


@dataclass(frozen=True)
class CorrelationContext:
    """What correlation rules may know besides the candidate: the run's `as_of`, outside
    knowledge, the run's watchlist, registry records of dependencies, and (per candidate) the
    comparison with its source repository."""

    as_of: datetime
    known_bad: KnownBad | None = None
    repo: RepoComparison | None = None
    watchlist: Watchlist | None = None
    dependencies: DependencyLookup | None = None


class RepoLookup(Protocol):
    """Compares a version with its repository; must be thread-safe."""

    def __call__(self, candidate: Candidate, /) -> RepoComparison | None: ...

    def new_pass(self) -> None:
        """Called before each retry pass: forget what the last pass learned about failures
        (e.g. which requests failed), so the retry really goes to the network."""
        ...

    def requests(self) -> NetworkRequests:
        """The network requests of the current pass (since `new_pass`, or the start)."""
        ...


def _flagged(candidate: Candidate) -> bool:
    return any(
        d.forwarded and (d.stage != "triage" or d.reason.startswith("rules:"))
        for d in candidate.history
    )


def wants_repo(candidate: Candidate) -> bool:
    """Which versions get the repository comparison (chosen 2026-10-28): any version an earlier
    stage flagged, and every update of a watched package. About 500 versions an hour, most of
    them watched-package updates, which share archives when a burst or a monorepo shares a
    commit. A run compares at most `MAX_REPO_COMPARISONS` of them (`plan_comparisons`)."""
    change = candidate.change
    watched = bool(change.popularity and change.popularity.watched)
    return _flagged(candidate) or (watched and change.previous is not None)


@dataclass(frozen=True)
class ComparisonPlan:
    """Which versions of a run are compared with their repository (indices in triage order),
    and which `wants_repo` picked but are over the run's budget."""

    compared: frozenset[int]
    over_budget: frozenset[int]
    flagged: int

    def counts(self, cap: int) -> dict[str, int]:
        return {
            "max_comparisons": cap,
            "wanted": len(self.compared) + len(self.over_budget),
            "flagged": self.flagged,
            "over_budget": len(self.over_budget),
        }


def plan_comparisons(versions: Sequence[Candidate], cap: int) -> ComparisonPlan:
    """The versions `wants_repo` picks, flagged ones first and then watched-package updates,
    each in triage order, up to `cap`; decided before any request, so the choice depends only on
    the run's input. A flagged version is far more likely to matter than a routine update of a
    watched package, so after a long gap the budget goes to them."""
    flagged: list[int] = []
    watched: list[int] = []
    for i in range(len(versions)):
        candidate = versions[i]
        if _flagged(candidate):
            flagged.append(i)
        elif wants_repo(candidate):
            watched.append(i)
    ordered = flagged + watched
    return ComparisonPlan(frozenset(ordered[:cap]), frozenset(ordered[cap:]), len(flagged))


class CorrelationRule(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def version(self) -> int: ...

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]: ...


def score(findings: Iterable[Finding]) -> float:
    """Each rule once, at its largest weight; INFO findings count nothing, and rules whose
    findings are all LOW together count at most `LOW_CAP`."""
    weights: dict[str, float] = {}
    above_low: set[str] = set()
    for f in findings:
        if f.severity == Severity.INFO:
            continue
        weights[f.rule_id] = max(weights.get(f.rule_id, 0.0), f.weight)
        if f.severity != Severity.LOW:
            above_low.add(f.rule_id)
    low = sum(w for rule, w in weights.items() if rule not in above_low)
    return sum(w for rule, w in weights.items() if rule in above_low) + min(low, LOW_CAP)


# Findings an earlier stage's INFO finding explains: rule -> ((explaining rule, note), ...),
# the first explaining rule present applying. With an explanation present, the rule's MEDIUM
# and HIGH findings become LOW, weight at most 1, and say why (like Stage 2's "not new" notes),
# so the score still shows every rule that fired.
# - `npm.install-build-tool` (Stage 3): every install hook only runs a build tool and
#   `binding.gyp` runs no command. 12 benign live reports, no positive; none of the 433
#   `vm-day1` malicious samples reported only through the install rules has such hooks
#   (`docs/proposals/precision-round2.md`, F2).
# - `npm.install-explained` (Stage 3, STAGE_VERSION 14): the install code is a platform-binary
#   launcher, an own-release download with a checksum, or an agent-skill copier whose copied
#   configuration passes the owner's three guards (S1-S3). It explains the three install
#   rules, never a content finding (`npm.install-script-obfuscated`, `static.*`,
#   `known-signature`) or `code.capability-gained`. Measured in `docs/stages/correlate.md`.
_SHAPE_NOTE: Final = " The install code has an explained shape (npm.install-explained)."
EXPLAINED: Final[Mapping[str, tuple[tuple[str, str], ...]]] = {
    "npm.install-hook": (
        (
            "npm.install-build-tool",
            " Only a build tool runs, and `binding.gyp` runs no command (npm.install-build-tool).",
        ),
        ("npm.install-explained", _SHAPE_NOTE),
    ),
    "npm.install-script-changed": (("npm.install-explained", _SHAPE_NOTE),),
    "npm.install-script-code": (("npm.install-explained", _SHAPE_NOTE),),
}


def explained(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """`findings` with those an explanation accounts for (`EXPLAINED`) made LOW."""
    present = {f.rule_id for f in findings}
    out = []
    for f in findings:
        note = next(
            (n for rule, n in EXPLAINED.get(f.rule_id, ()) if rule in present),
            None,
        )
        if note is not None and f.severity not in (Severity.INFO, Severity.LOW):
            f = f.model_copy(
                update={
                    "severity": Severity.LOW,
                    "weight": min(f.weight, 1.0),
                    "explanation": f.explanation + note,
                }
            )
        out.append(f)
    return tuple(out)


def correlate(
    candidate: Candidate,
    ctx: CorrelationContext,
    rules: Sequence[CorrelationRule],
    *,
    report_score: float = REPORT_SCORE,
) -> Candidate:
    """Run the rules in order (each sees the findings of those before it), make the findings
    an explanation accounts for LOW (`explained`), and decide."""
    for rule in rules:
        found = tuple(rule.evaluate_candidate(candidate, ctx))
        if found:
            candidate = candidate.model_copy(update={"findings": candidate.findings + found})
    findings = explained(candidate.findings)
    if findings != candidate.findings:
        candidate = candidate.model_copy(update={"findings": findings})
    decision = decide(candidate.findings, report_score=report_score)
    if ctx.repo is not None and ctx.repo.transient:
        decision = decision.model_copy(update={"reason": decision.reason + NETWORK_UNCOMPARED})
    return candidate.model_copy(update={"history": (*candidate.history, decision)})


def repo_over_budget(candidates: Iterable[Candidate]) -> int:
    """How many versions Stage 4 left uncompared because the run was over its budget
    (`MAX_REPO_COMPARISONS`)."""
    return sum(
        c.history[-1].stage == STAGE_ID and c.history[-1].reason.endswith(BUDGET_UNCOMPARED)
        for c in candidates
    )


def repo_network_failures(candidates: Iterable[Candidate]) -> int:
    """How many versions Stage 4 left uncompared because a repository request failed on the
    network (after retries). Release files that failed on the network are Stage 2's to retry
    and not counted here (`repo_network.package_files_network` in `correlate.json`)."""
    return sum(
        c.history[-1].stage == STAGE_ID and c.history[-1].reason.endswith(NETWORK_UNCOMPARED)
        for c in candidates
    )


def unevaluated(candidates: Iterable[Candidate]) -> int:
    """How many versions carry a `NOT_EVALUATED` finding: a rule couldn't check part of them
    (e.g. a dependency lookup failed or was over the cap)."""
    return sum(
        any(
            f.severity is Severity.INFO and f.explanation.startswith(NOT_EVALUATED)
            for f in c.findings
        )
        for c in candidates
    )


# MEDIUM findings that don't report a version on their own, only through the score or beside
# another MEDIUM:
# - an unwatched package published by hand after CI releases (242 versions in two live days,
#   almost all a maintainer's own manual publish; 0 malicious `vm-day1` samples reported by it
#   alone);
# - (2026-11-01) code that gains capabilities, and a webhook URL with a placeholder id: 60 and 3
#   of the 888 live benign verdicts still reported were carried by one of them alone; no
#   malicious or inconclusive verdict, and no `vm-day1` malicious sample, is.
WEAK_ALONE: Final = frozenset(
    {"npm.publish-method.downgrade", "code.capability-gained", "static.webhook-placeholder"}
)


# MEDIUM findings about install code that a release matching an established repository
# explains (`repo.established-match`): the code `npm install` runs is the repository's own,
# byte for byte, at a commit on its default branch. Never cleared: anything HIGH (an install
# hook *added* to an update is HIGH), any other MEDIUM (Stage 2's, Stage 5's), or a score that
# reaches `REPORT_SCORE` without them. Measured 2026-11-04 (decision 0017): clears 33 of 1,231
# live reported versions with a GitHub repository (all 20 reviewed benign), and loses 1 of the
# 2,507 `vm-day1` malicious samples reported (`gina@0.7.1`, whose code is in its 2013
# repository). So it is off until the owner decides.
CLEAR_ESTABLISHED: Final = False
ESTABLISHED_MATCH: Final = "repo.established-match"
# The same findings, explained instead by the repository's history (`repo.history-match`): the
# release is the repository's code at a commit ahead of the previous release's. Measured
# 2026-11-06 (decision 0018) on live compared updates and `vm-day1`; it too loses
# `gina@0.7.1`, whose 44 commits since its previous release are its maintainer's. Off until
# the owner decides.
CLEAR_HISTORY: Final = False
HISTORY_MATCH: Final = "repo.history-match"
CLEARED_BY_REPO: Final = frozenset(
    {"npm.install-hook", "npm.install-script-changed", "npm.install-script-code"}
)


def _severe(finding: Finding) -> bool:
    if not at_least(finding.severity, REPORT_SEVERITY):
        return False
    return finding.rule_id not in WEAK_ALONE or at_least(finding.severity, Severity.HIGH)


def decide(
    findings: Sequence[Finding],
    *,
    report_score: float = REPORT_SCORE,
    clear_established: bool = CLEAR_ESTABLISHED,
    clear_history: bool = CLEAR_HISTORY,
) -> StageDecision:
    total = score(findings)
    severe = sorted({f.rule_id for f in findings if _severe(f)})
    clearing = [
        rule
        for rule, on in ((ESTABLISHED_MATCH, clear_established), (HISTORY_MATCH, clear_history))
        if on and any(f.rule_id == rule for f in findings)
    ]
    if clearing and severe and _cleared_by_repo(findings, severe, report_score):
        return StageDecision(
            stage=STAGE_ID,
            forwarded=False,
            reason=f"score {total:g}; {', '.join(severe)} cleared by {', '.join(clearing)}",
        )
    if severe:
        reason = f"score {total:g}; {REPORT_SEVERITY.value}: {', '.join(severe)}"
    else:
        reason = f"score {total:g}" + (f" >= {report_score:g}" if total >= report_score else "")
    return StageDecision(
        stage=STAGE_ID, forwarded=bool(severe) or total >= report_score, reason=reason
    )


def _cleared_by_repo(
    findings: Sequence[Finding], severe: Sequence[str], report_score: float
) -> bool:
    """Whether a match (the caller checked one is present and switched on) explains every
    finding that would report the version."""
    return (
        set(severe) <= CLEARED_BY_REPO
        and not any(at_least(f.severity, Severity.HIGH) for f in findings)
        and score(f for f in findings if f.rule_id not in CLEARED_BY_REPO) < report_score
    )


def correlate_run(
    run_dir: Path,
    ctx: CorrelationContext,
    rules: Sequence[CorrelationRule],
    *,
    repo: RepoLookup | None = None,
    report_score: float = REPORT_SCORE,
    workers: int = 8,
    retry_passes: int = RETRY_PASSES,
    max_comparisons: int = MAX_REPO_COMPARISONS,
) -> CandidateFile:
    """Stage 4 over a run Stage 3 has processed. Reads every triaged version
    (`triage.jsonl`), taking Stages 2-3's version of those routed to them (`ast.jsonl`); writes
    `correlate.jsonl` (one Candidate per line, in triage order) and `correlate.json` (which
    outside data and rules were used, and how many repository lookups failed on the network).
    `repo` compares a version with its repository (`wants_repo` decides which, and
    `plan_comparisons` keeps at most `max_comparisons`; the rest get `BUDGET_UNCOMPARED`, and
    `correlate.json` counts them under `repo_budget`). Lookups that
    come back `transient` are run again after the first pass, up to `retry_passes` times,
    stopping early when a pass recovers none; no retry pass runs when the first pass looks
    like an outage (`OUTAGE_SHARE`, `OUTAGE_MIN`). `files_transient` lookups are not retried.
    `ctx.dependencies`, if given, is planned with every version, its planned names are looked
    up before the rules run and retried the same way (with their own outage guard), and its
    counts go to `correlate.json` as `dependency_lookups`.

    Versions are read from disk when needed (`RunVersions`) and written as they are
    correlated, never all held at once: a 110k-version run's candidates take ~4 GB as objects,
    and Stage 4 holding them (with its input and output) was OOM-killed at 21.6 GB on the VM on
    2026-10-30. Only the repository comparisons and dependency records stay in memory. Returns
    the output, read on demand."""
    versions = RunVersions(run_dir / "triage.jsonl", run_dir / "ast.jsonl")
    plan = (
        plan_comparisons(versions, max_comparisons)
        if repo is not None
        else ComparisonPlan(frozenset(), frozenset(), 0)
    )

    def lookup(i: int) -> RepoComparison | None:
        if repo is None or i not in plan.compared:
            return None
        return repo(versions[i])

    deps = ctx.dependencies
    indices = range(len(versions))
    totals = _Totals()

    def one(i: int) -> Candidate:
        comparison = comparisons[i]
        candidate = correlate(
            versions[i], replace(ctx, repo=comparison), rules, report_score=report_score
        )
        if i in plan.over_budget:
            *earlier, decision = candidate.history
            noted = decision.model_copy(update={"reason": decision.reason + BUDGET_UNCOMPARED})
            candidate = candidate.model_copy(update={"history": (*earlier, noted)})
        totals.add(candidate)
        return candidate

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            names = list(deps.plan(versions, ctx)) if deps is not None else []
            records = list(pool.map(deps, names)) if deps is not None else []
            comparisons = list(pool.map(lookup, indices))
            network = {
                "lookups": sum(c is not None for c in comparisons),
                **_retry_transient(
                    pool,
                    lookup,
                    lambda c: c is not None and c.transient,
                    repo,
                    indices,
                    comparisons,
                    retry_passes,
                ),
            }
            # After the repository passes: the registry gets those minutes to recover too.
            dependency_network = (
                _retry_transient(
                    pool, deps, lambda r: r.transient, deps, names, records, retry_passes
                )
                if deps is not None
                else {}
            )
            write_jsonl(run_dir / "correlate.jsonl", _in_order(pool, one, len(versions)))
    finally:
        versions.close()
    errors = network.pop("errors")  # last in `repo_network`, after the counts
    info = {
        "as_of": ctx.as_of.isoformat(),
        "known_bad": ctx.known_bad.id if ctx.known_bad else None,
        "watchlist": ctx.watchlist.id if ctx.watchlist else None,
        "stage_version": STAGE_VERSION,
        "rules": rules_fingerprint(rules),
        "report_score": report_score,
        "repo_network": {
            **network,
            "still_failing": totals.network_uncompared,
            "package_files_network": sum(c is not None and c.files_transient for c in comparisons),
            "errors": errors,
        },
        "repo_budget": plan.counts(max_comparisons),
    }
    if deps is not None:
        stats = dict(deps.stats())
        # The error of every name whose lookup still failed (network or not), not only the
        # network failures of the last pass.
        dependency_errors = stats.pop("errors", {})
        dependency_network.pop("errors")
        info["dependency_lookups"] = {
            **stats,
            **dependency_network,
            "still_failing": sum(r.transient for r in records),
            "versions_not_evaluated": totals.not_evaluated,
            "errors": dependency_errors,
        }
    atomic_write(run_dir / CORRELATE_INFO, json.dumps(info, indent=2).encode())
    return CandidateFile(run_dir / "correlate.jsonl")


# Versions correlated per batch of the final pass: what is held in memory before writing.
WRITE_WINDOW: Final = 2048


def _in_order[R](pool: ThreadPoolExecutor, fn: Callable[[int], R], count: int) -> Iterator[R]:
    """`fn` over `range(count)` on the pool, in order, at most `WRITE_WINDOW` results held."""
    for start in range(0, count, WRITE_WINDOW):
        yield from pool.map(fn, range(start, min(start + WRITE_WINDOW, count)))


class _Totals:
    """What `correlate.json` counts over the output, gathered as it is written (thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.network_uncompared = 0
        self.not_evaluated = 0

    def add(self, candidate: Candidate) -> None:
        uncompared, unchecked = repo_network_failures([candidate]), unevaluated([candidate])
        with self._lock:
            self.network_uncompared += uncompared
            self.not_evaluated += unchecked


class CandidateFile(Sequence[Candidate]):
    """A JSONL file of `Candidate`s (one per line), parsed on demand: a 110k-version run's
    candidates take ~4 GB as objects but 16 bytes a line here. Each access parses the line
    again, so callers iterate it rather than index it repeatedly."""

    def __init__(self, path: Path) -> None:
        self._lines = LineFile(path)

    def __len__(self) -> int:
        return len(self._lines)

    @overload
    def __getitem__(self, index: int) -> Candidate: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[Candidate]: ...

    def __getitem__(self, index: int | slice) -> Candidate | Sequence[Candidate]:
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        return self._load(self._lines[index])

    def _load(self, line: bytes) -> Candidate:
        return Candidate.model_validate_json(line)

    def close(self) -> None:
        self._lines.close()


class RunVersions(CandidateFile):
    """Stage 4's input, read on demand: every version Stage 1 triaged (`triage.jsonl`, in
    order), as Stages 2-3 left it for those routed to them (`ast.jsonl`; a version in more
    than one batch takes the last). Only where each version is is kept; a few parsed
    `ast.jsonl` batches are cached, since a package's versions are read together."""

    def __init__(self, triage: Path, ast: Path) -> None:
        super().__init__(triage)
        self._batches = LineFile(ast)
        self._analysed: dict[str, tuple[int, int]] = {}
        for line in range(len(self._batches)):
            batch = PackageBatch.load_json(self._batches[line])
            for position, candidate in enumerate(batch.versions):
                self._analysed[str(candidate.change.new.ref)] = (line, position)
        self._batch = lru_cache(maxsize=BATCH_CACHE)(self._read_batch)

    def _read_batch(self, line: int) -> PackageBatch:
        return PackageBatch.load_json(self._batches[line])

    def _load(self, line: bytes) -> Candidate:
        candidate = Candidate.model_validate_json(line)
        where = self._analysed.get(str(candidate.change.new.ref))
        if where is None:
            return candidate
        return self._batch(where[0]).versions[where[1]]

    def close(self) -> None:
        super().close()
        self._batches.close()


BATCH_CACHE: Final = 32


class _Passes(Protocol):
    """What a lookup retried in passes tells `_retry_transient` (`RepoLookup`,
    `DependencyLookup`)."""

    def new_pass(self) -> None: ...

    def requests(self) -> NetworkRequests: ...


def _retry_transient[T, R](
    pool: ThreadPoolExecutor,
    lookup: Callable[[T], R],
    transient: Callable[[R], bool],
    memory: _Passes | None,
    items: Sequence[T],
    results: list[R],
    max_passes: int,
) -> dict[str, object]:
    """Run the lookups whose result is `transient` (failed on the network) again, updating
    `results` in place. Returns what `correlate.json` records: how many failed on the network
    in the first pass; the distinct requests that pass sent and how many failed (what the
    outage guard counts); retry passes run; why retrying was skipped (`outage`), if it was;
    and the error of each request that failed in the last pass run."""

    def failed() -> list[int]:
        return [i for i, r in enumerate(results) if transient(r)]

    def requests() -> NetworkRequests:
        return memory.requests() if memory is not None else NetworkRequests()

    pending = failed()
    first_pass, first, passes = len(pending), requests(), 0
    outage = first.failed >= OUTAGE_MIN and first.failed >= OUTAGE_SHARE * first.sent
    last = first
    while pending and passes < max_passes and not outage:
        passes += 1
        if memory is not None:
            memory.new_pass()
        retried = pool.map(lookup, [items[i] for i in pending])
        for i, result in zip(pending, retried, strict=True):
            results[i] = result
        last = requests()
        still = failed()
        if len(still) == len(pending):
            break  # nothing recovered: the network is down, not flaky
        pending = still
    return {
        "first_pass": first_pass,
        "requests": first.sent,
        "failed_requests": first.failed,
        "retry_passes": passes,
        "retry_skipped": "outage" if outage and max_passes > 0 else None,
        "errors": dict(last.errors),
    }
