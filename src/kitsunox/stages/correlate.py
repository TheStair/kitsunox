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
import os
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Final, Protocol, overload

from kitsunox.core.models import (
    Candidate,
    Evidence,
    EvidenceKind,
    Finding,
    PackageBatch,
    Record,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.core.rules import rules_fingerprint
from kitsunox.core.watchlist import Watchlist
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.repo import NetworkRequests, RepoComparison
from kitsunox.stages.triage import at_least
from kitsunox.util.files import LineFile, atomic_write, sync_file

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
# (S1-S3 shapes) explains the three install rules. 15: packages Stage 3's
# `npm.undeclared-package` names are looked up after the declared dependencies, and a 404 is
# `npm.undeclared.missing`. 16: Stage 3's `npm.install-inert` (install hooks that run only
# inert package code or a constant `echo`) explains `npm.install-hook`. 17: Stage 2's
# `npm.artifact.install-target-missing` (every hook runs a file the package doesn't ship)
# explains `npm.install-hook`. 18: a follow-on pass (`correlate_run(follow_on=...)`): a
# release whose previous release the run reported, still holding that report's payload
# evidence, is correlated again with it (`correlate.follow-on`), and `correlate.json` counts
# the pass under `follow_on`. 19: `static.disguised-file` (Stage 2) is carried by follow-ons
# (`FOLLOW_ON_ALONE`). 20: `npm.obfuscation-only` (a new package whose only signal is
# obfuscated JavaScript) explains `static.obfuscated`. Output without the field is 1.
STAGE_VERSION: Final = 20
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


class CarriedEvidence(Record):
    """One piece of a reported release's evidence that a later release may still hold: a
    flagged file (same path, same bytes) or a flagged manifest field (same value). `rule_id`
    and `severity` are those of the finding it came from."""

    rule_id: str
    severity: Severity
    evidence: Evidence


class ReportedRelease(Record):
    """A release Stage 4 reported, with the evidence a follow-on release can carry
    (`reported_release`). `run_id`: the run that reported it, when not the current one (an
    earlier run's `FOLLOW_ON_INDEX`)."""

    release: VersionSnapshot
    reason: str
    evidence: tuple[CarriedEvidence, ...]
    run_id: str | None = None


class FollowOn(Record):
    """What a follow-on release still holds of the reported release before it (`previous`):
    the carried evidence that is unchanged. `unavailable`: some of it could not be checked
    (files too large or not fetched); `transient`: because of a network failure, so a retry
    may work."""

    previous: str
    previous_reason: str
    hours: float
    previous_run: str | None = None
    carried: tuple[CarriedEvidence, ...] = ()
    unavailable: str | None = None
    transient: bool = False


class FollowOnLookup(Protocol):
    """Checks which of a reported release's evidence a later release of the same package still
    holds (must be thread-safe). None: not a follow-on to check (e.g. too long after it)."""

    def __call__(self, earlier: ReportedRelease, candidate: Candidate, /) -> FollowOn | None: ...


@dataclass(frozen=True)
class CorrelationContext:
    """What correlation rules may know besides the candidate: the run's `as_of`, outside
    knowledge, the run's watchlist, registry records of dependencies, and (per candidate) the
    comparison with its source repository and, for a follow-on of a release this run reported,
    what it still holds of that release's evidence (`follow_on`)."""

    as_of: datetime
    known_bad: KnownBad | None = None
    repo: RepoComparison | None = None
    watchlist: Watchlist | None = None
    dependencies: DependencyLookup | None = None
    follow_on: FollowOn | None = None


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
# - `npm.install-inert` (Stage 3, STAGE_VERSION 16): every install hook only runs package code
#   Stage 3 read in full that reaches no network, process, environment, dynamic code, native
#   module, other package or path outside the package, or only echoes a message that isn't a
#   probe's "it ran". Explains `npm.install-hook` only
#   (`docs/proposals/precision-round4-B.md`, B1).
# - `npm.artifact.install-target-missing` (Stage 2, STAGE_VERSION 17): every install hook is
#   `node <file>` and the whole tarball has no such file, so nothing runs at install. Explains
#   `npm.install-hook` only (`docs/proposals/precision-round6-Q.md`, Q1).
# - `npm.obfuscation-only` (Stage 4, STAGE_VERSION 20): a new package whose only finding above
#   INFO is `static.obfuscated` MEDIUM, with no web page, no script npm runs at install
#   (`prepare` included), and a declared repository or homepage. Explains `static.obfuscated`
#   only. Measured in `docs/proposals/precision-round8-P.md` (P1).
_SHAPE_NOTE: Final = " The install code has an explained shape (npm.install-explained)."
OBFUSCATION_ONLY: Final = "npm.obfuscation-only"
EXPLAINED: Final[Mapping[str, tuple[tuple[str, str], ...]]] = {
    "npm.install-hook": (
        (
            "npm.install-build-tool",
            " Only a build tool runs, and `binding.gyp` runs no command beyond header lookups"
            " (npm.install-build-tool).",
        ),
        ("npm.install-explained", _SHAPE_NOTE),
        (
            "npm.install-inert",
            " Every install hook only prints a message or runs package code, read in full,"
            " that reaches nothing outside the package (npm.install-inert).",
        ),
        (
            "npm.artifact.install-target-missing",
            " Every install hook runs a file the package doesn't ship, so nothing runs"
            " (npm.artifact.install-target-missing).",
        ),
    ),
    "npm.install-script-changed": (("npm.install-explained", _SHAPE_NOTE),),
    "npm.install-script-code": (("npm.install-explained", _SHAPE_NOTE),),
    "static.obfuscated": (
        (
            OBFUSCATION_ONLY,
            " A new package whose only signal is this obfuscation: no other finding, no install"
            " script, no web page, a declared repository or homepage (npm.obfuscation-only).",
        ),
    ),
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


# Follow-on releases (decision 0007 addendum, `docs/proposals/precision-round6-U.md`). Stages
# 1-3 judge what a release changes, so a release that keeps a reported release's payload
# unchanged shows nothing: `pdf-html5-page-flip@2.0.2` (published 15 minutes after 2.0.1 with
# the same stealer file, byte for byte) scored 3 while 2.0.1 was reported. After the run's
# decisions, a release whose previous release this run reported, and which still holds a piece
# of that report's severe evidence, gets `correlate.follow-on` (MEDIUM): the earlier release
# named, the evidence listed.
FOLLOW_ON: Final = "correlate.follow-on"
# What a follow-on carries is narrow on purpose (`payload_evidence`). Live (replay of 812
# follow-ons of reported releases, 2026-11-11, round 6 U), carrying every severe content
# finding of a reported release onto its unchanged same-run follow-ons would have reported 65
# more positives and 64 more benign versions (with install hooks and non-registry
# dependencies: 80 and 171): benign packages reported once publish often (`@wirecat/*` CLIs
# with a bundled ngrok table, hooks that only build). Carried, in parts (each its own commit,
# measured on the same follow-ons):
# - A: a finding of a rule the owner wants on every release (`FOLLOW_ON_ALONE`): a known
#   family's signature, a WhatsApp fork's channel follow or tagging (Stage 2's `ALWAYS_NEW`,
#   which an unchanged file never reaches). +10 unwanted, 0 benign.
# - B1: a hard-coded destination (`FOLLOW_ON_DESTINATION`, MEDIUM or above) in a file that
#   the same release also found reading secrets or running at install (`FOLLOW_ON_COMPANION`,
#   any severity): the stealer in `pdf-html5-page-flip`'s font file, `template-cards`'s
#   install-time beacon. +3 malicious, +2 benign (`chuxin-agentdesk@0.1.1`,
#   `@prismatic-io/components-bigcommerce@0.1.0`).
# - B2: install code that persists (`npm.install-persistence`, owner rulings in decision
#   0015), in `FOLLOW_ON_ALONE`. +22 unwanted, +4 benign, +1 unverified.
# - T (round 6, integrator): a disguised file (`static.disguised-file`, MEDIUM or HIGH: a
#   script or executable under a font/image/media name) is carried on its own, so a follow-on
#   too small for Stage 2's routing still reports. Live cost 0: across 230,290 tarballs its
#   only severe findings are `pdf-html5-page-flip` 2.0.1/2.0.2; INFO launchers aren't carried.
FOLLOW_ON_ALONE: Final = frozenset(
    {
        "static.known-signature",
        "static.channel-follow",
        "static.channel-tagging",
        "npm.install-persistence",
        "static.disguised-file",
    }
)
FOLLOW_ON_DESTINATION: Final = frozenset({"static.hardcoded-ip", "static.exfil-endpoint"})
FOLLOW_ON_COMPANION: Final = frozenset(
    {
        "static.sensitive-path",
        "static.env-harvest",
        "npm.install-script-code",
        "npm.install-script-loader",
        "npm.install-script-exfil",
        "npm.install-persistence",
    }
)
# A run's reported releases with payload evidence (one `ReportedRelease` a line), read by later
# runs' follow-on passes, and the earlier runs' entries this run's pass used (its input).
FOLLOW_ON_INDEX: Final = "follow-on.jsonl"
FOLLOW_ON_HISTORY: Final = "follow-on-history.jsonl"
# A follow-on is checked only when published at most this long after the reported release.
FOLLOW_ON_WINDOW: Final = timedelta(days=7)
# Evidence items listed in one follow-on finding at most.
FOLLOW_ON_EVIDENCE: Final = 10


def _carried_kind(evidence: Evidence) -> bool:
    return bool(evidence.path) and evidence.kind in (
        EvidenceKind.FILE_SPAN,
        EvidenceKind.MANIFEST_FIELD,
    )


def payload_evidence(
    findings: Sequence[Finding],
    *,
    alone: frozenset[str] = FOLLOW_ON_ALONE,
    destinations: frozenset[str] = FOLLOW_ON_DESTINATION,
    companions: frozenset[str] = FOLLOW_ON_COMPANION,
) -> list[CarriedEvidence]:
    """The evidence of `findings` (a reported release's) that a follow-on carries: each file or
    manifest field of a severe finding of `alone`, and each file of a severe finding of
    `destinations` that a finding of `companions` (LOW or above) of the same release also
    names."""
    paired = {
        e.path
        for f in findings
        if f.rule_id in companions and f.severity is not Severity.INFO
        for e in f.evidence
        if e.kind is EvidenceKind.FILE_SPAN and e.path
    }
    items = []
    for f in findings:
        if not _severe(f):
            continue
        for e in f.evidence:
            if not _carried_kind(e):
                continue
            if f.rule_id in alone or (
                f.rule_id in destinations and e.kind is EvidenceKind.FILE_SPAN and e.path in paired
            ):
                items.append(CarriedEvidence(rule_id=f.rule_id, severity=f.severity, evidence=e))
    return items


CarryPolicy = Callable[[Sequence[Finding]], list[CarriedEvidence]]


def reported_release(
    candidate: Candidate,
    follow_on: FollowOn | None = None,
    carry: CarryPolicy = payload_evidence,
) -> ReportedRelease | None:
    """`candidate` (correlated) as a reported release a follow-on can carry evidence from: what
    `carry` takes of its findings, plus what it carried itself as a follow-on (`follow_on`, when
    that is a severe finding of it). None when Stage 4 didn't report it or there is nothing to
    carry. One item per (kind, path), the first in finding order."""
    decision = candidate.history[-1] if candidate.history else None
    if decision is None or decision.stage != STAGE_ID or not decision.forwarded:
        return None
    items = carry(candidate.findings)
    if follow_on is not None and any(
        f.rule_id == FOLLOW_ON and _severe(f) for f in candidate.findings
    ):
        items.extend(follow_on.carried)
    unique: dict[tuple[str, str | None], CarriedEvidence] = {}
    for item in items:
        unique.setdefault((item.evidence.kind.value, item.evidence.path), item)
    if not unique:
        return None
    return ReportedRelease(
        release=candidate.change.new, reason=decision.reason, evidence=tuple(unique.values())
    )


# An absent manifest field (`ManifestField`'s answer when a path names nothing).
ABSENT: Final = object()
ManifestField = Callable[[Mapping[str, object], str], object]
ReleaseFiles = Callable[[VersionSnapshot], "Mapping[str, bytes] | FilesUnavailable"]


class FilesUnavailable(Protocol):
    """Why a release's files could not be read (`stages.static.Unavailable`)."""

    @property
    def reason(self) -> str: ...

    @property
    def transient(self) -> bool: ...


class ReleaseFollowOn:
    """A `FollowOnLookup` over the releases' files (`files`, e.g. Stage 2's `ArtifactFiles`
    through the run's fetcher, so a replay reads the same bytes) and manifests (`field`: the
    value at an evidence path such as `package.json:scripts.postinstall`, or `ABSENT`; the
    ecosystem's own format). A file is still there when the later release has the same bytes at
    the same path; a manifest field when it has the same value."""

    def __init__(
        self,
        files: ReleaseFiles,
        field: ManifestField,
        *,
        window: timedelta = FOLLOW_ON_WINDOW,
    ) -> None:
        self.files = files
        self.field = field
        self.window = window

    def __call__(self, earlier: ReportedRelease, candidate: Candidate) -> FollowOn | None:
        new = candidate.change.new
        before, after = earlier.release.publish.published_at, new.publish.published_at
        if before is None or after is None or not timedelta(0) <= after - before <= self.window:
            return None
        trees: tuple[Mapping[str, bytes], Mapping[str, bytes]] | None = None
        unavailable: FilesUnavailable | None = None
        if any(i.evidence.kind is EvidenceKind.FILE_SPAN for i in earlier.evidence):
            old, now = self.files(earlier.release), self.files(new)
            if isinstance(old, Mapping) and isinstance(now, Mapping):
                trees = (old, now)
            else:
                unavailable = old if not isinstance(old, Mapping) else now  # type: ignore[assignment]
        carried = []
        for item in earlier.evidence:
            path = item.evidence.path or ""
            if item.evidence.kind is EvidenceKind.MANIFEST_FIELD:
                value = self.field(earlier.release.manifest, path)
                if value is not ABSENT and value == self.field(new.manifest, path):
                    carried.append(item)
            elif trees is not None and path in trees[0] and trees[1].get(path) == trees[0][path]:
                carried.append(item)
        return FollowOn(
            previous=earlier.release.ref.version,
            previous_reason=earlier.reason,
            previous_run=earlier.run_id,
            hours=round((after - before) / timedelta(hours=1), 2),
            carried=tuple(carried),
            unavailable=f"files {unavailable.reason}"[:300] if unavailable else None,
            transient=bool(unavailable and unavailable.transient),
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
    follow_on: FollowOnLookup | None = None,
    history: Mapping[tuple[str, str], ReportedRelease] | None = None,
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

    With `follow_on`, a second pass follows (`_follow_ons`): every version whose previous
    release is in this run and was reported with evidence a follow-on can carry
    (`reported_release`) is checked against it and correlated again with what it still holds
    (`ctx.follow_on`), in dependency order, so a chain of follow-ons carries the evidence on.
    Those lines of `correlate.jsonl` are replaced; `correlate.json` counts them as `follow_on`.
    `history` holds earlier runs' reported releases (their `FOLLOW_ON_INDEX`): a version whose
    previous release is there instead of in this run is checked against it the same way. The
    run writes its own reported releases with payload evidence to `FOLLOW_ON_INDEX` and the
    `history` entries it used to `FOLLOW_ON_HISTORY`, so a re-score can read exactly those.

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
    releases = _RunReleases()

    def correlated(i: int, follow: FollowOn | None = None) -> Candidate:
        comparison = comparisons[i]
        candidate = correlate(
            versions[i],
            replace(ctx, repo=comparison, follow_on=follow),
            rules,
            report_score=report_score,
        )
        if i in plan.over_budget:
            *earlier, decision = candidate.history
            noted = decision.model_copy(update={"reason": decision.reason + BUDGET_UNCOMPARED})
            candidate = candidate.model_copy(update={"history": (*earlier, noted)})
        return candidate

    def one(i: int) -> Candidate:
        candidate = correlated(i)
        totals.add(candidate)
        if follow_on is not None:
            releases.add(i, candidate)
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
            if follow_on is not None:
                follow_info, used = _follow_ons(
                    pool,
                    follow_on,
                    releases,
                    lambda i: versions[i],
                    correlated,
                    totals,
                    retry_passes,
                    history or {},
                )
                if follow_info.pop("replaced"):
                    _replace_lines(run_dir / "correlate.jsonl", releases.replaced)
                _write_records(run_dir / FOLLOW_ON_HISTORY, [(history or {})[k] for k in used])
                _write_records(
                    run_dir / FOLLOW_ON_INDEX,
                    [
                        r.model_copy(update={"run_id": run_dir.name})
                        for _, r in sorted(releases.reported.items())
                    ],
                )
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
    if follow_on is not None:
        info["follow_on"] = follow_info
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

    def add(self, candidate: Candidate, sign: int = 1) -> None:
        uncompared, unchecked = repo_network_failures([candidate]), unevaluated([candidate])
        with self._lock:
            self.network_uncompared += sign * uncompared
            self.not_evaluated += sign * unchecked


class _RunReleases:
    """What the follow-on pass needs from the first pass (thread-safe): where each release of
    the run is, the versions whose previous release is named, and the reported releases with
    evidence to carry (`reported_release`). Then the candidates the pass replaced."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.index: dict[tuple[str, str], int] = {}
        self.followers: list[tuple[int, str, str, str]] = []  # (index, name, version, previous)
        self.reported: dict[tuple[str, str], ReportedRelease] = {}
        self._reported_at: dict[tuple[str, str], int] = {}
        self.replaced: dict[int, Candidate] = {}

    def add(self, i: int, candidate: Candidate) -> None:
        change = candidate.change
        key = (change.new.ref.name, change.new.ref.version)
        release = reported_release(candidate)
        with self._lock:
            # A version in the run twice (two batches) counts at its first place.
            self.index[key] = min(self.index.get(key, i), i)
            if change.previous is not None:
                self.followers.append((i, *key, change.previous.ref.version))
            if release is not None and self._reported_at.get(key, i) >= i:
                self._reported_at[key] = i
                self.reported[key] = release


def _follow_ons(
    pool: ThreadPoolExecutor,
    lookup: FollowOnLookup,
    releases: _RunReleases,
    version_at: Callable[[int], Candidate],
    correlated: Callable[[int, FollowOn | None], Candidate],
    totals: _Totals,
    retry_passes: int,
    history: Mapping[tuple[str, str], ReportedRelease],
) -> tuple[dict[str, object], list[tuple[str, str]]]:
    """The follow-on pass of `correlate_run`. A version whose previous release is in the run
    waits until that release is settled (not itself still waiting), then, if that release is
    reported with evidence to carry, is checked (`lookup`; network failures retried like the
    other lookups) and, when it still holds some of it or couldn't be checked, correlated again
    with the result: it may be reported now, and carry the evidence on to its own follow-on. A
    version whose previous release is not in the run but in `history` (earlier runs' reported
    releases) is checked against that entry. Deterministic: every pass takes the ready
    versions in run order. Returns the counts for `correlate.json` (`replaced`: whether any
    line changed) and the `history` keys checked against."""
    pending = {
        i: ((name, previous), (name, version))
        for i, name, version, previous in sorted(releases.followers)
        if ((name, previous) in releases.index or (name, previous) in history)
        and releases.index.get((name, version)) == i
    }
    in_run = sum(previous in releases.index for previous, _ in pending.values())
    counts = {"in_run": in_run, "earlier_runs": len(pending) - in_run, "checked": 0}
    counts |= {"carried": 0, "reported": 0, "newly_reported": 0, "not_evaluated": 0}
    counts["retry_passes"] = 0
    errors: dict[str, str] = {}
    used: set[tuple[str, str]] = set()

    def earlier(previous: tuple[str, str]) -> ReportedRelease | None:
        if previous in releases.index:
            return releases.reported.get(previous)
        return history.get(previous)

    while pending:
        waiting = {key for _, key in pending.values()}
        reported = {
            i: entry for i, (previous, _) in pending.items() if (entry := earlier(previous))
        }
        # A cycle of previous releases (never seen) would wait forever: take them as they are.
        ready = [i for i in reported if pending[i][0] not in waiting] or list(reported)
        if not ready:
            break  # the rest follow releases that weren't reported
        pairs = [(reported[i], i) for i in sorted(ready)]
        used.update(pending[i][0] for i in ready if pending[i][0] not in releases.index)

        def check(pair: tuple[ReportedRelease, int]) -> FollowOn | None:
            return lookup(pair[0], version_at(pair[1]))

        results = list(pool.map(check, pairs))
        retried = _retry_transient(
            pool, check, lambda r: r is not None and r.transient, None, pairs, results, retry_passes
        )
        counts["retry_passes"] = max(counts["retry_passes"], int(str(retried["retry_passes"])))
        for (_, i), follow in zip(pairs, results, strict=True):
            key = pending.pop(i)[1]
            if follow is None:
                continue
            counts["checked"] += 1
            counts["carried"] += bool(follow.carried)
            if follow.unavailable is not None:
                counts["not_evaluated"] += 1
                errors[f"{key[0]}@{key[1]}"] = follow.unavailable
            if not follow.carried and follow.unavailable is None:
                continue
            old, new = correlated(i, None), correlated(i, follow)
            totals.add(old, -1)
            totals.add(new)
            releases.replaced[i] = new
            forwarded = new.history[-1].forwarded
            counts["reported"] += forwarded
            counts["newly_reported"] += forwarded and not old.history[-1].forwarded
            release = reported_release(new, follow)
            if release is not None:
                releases.reported[key] = release
    info = {**counts, "replaced": bool(releases.replaced), "errors": dict(sorted(errors.items()))}
    return info, sorted(used)


def _write_records(path: Path, records: Iterable[Record]) -> None:
    """Small JSONL files later runs read (`FOLLOW_ON_INDEX`): written whole or not at all."""
    atomic_write(path, b"".join(r.model_dump_json().encode() + b"\n" for r in records))


def _replace_lines(path: Path, replaced: Mapping[int, Candidate]) -> None:
    """`path` (JSONL, one record a line) with the lines at `replaced`'s indices rewritten,
    streamed through a synced temp file and renamed into place."""
    lines = LineFile(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with tmp.open("wb") as out:
            for i in range(len(lines)):
                candidate = replaced.get(i)
                out.write(lines[i] if candidate is None else candidate.model_dump_json().encode())
                if candidate is not None:
                    out.write(b"\n")
        sync_file(tmp)
        os.replace(tmp, path)
    finally:
        lines.close()
        tmp.unlink(missing_ok=True)


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
