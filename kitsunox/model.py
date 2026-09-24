"""Data model for a "change" — the unit of analysis for the whole pipeline.

A change is either a merged pull request or a direct push to a repo's default branch.
Both are representable uniformly — as it turns out, all 5 current incidents (xz-utils,
event-stream, reviewdog/action-setup, tj-actions/changed-files, colors.js) were direct
commits with no PR involved, but the PR shape still matters for the control sample.
`fetch.py` is the only module that constructs `Change`/`FileDiff` objects from live
data; `incidents.py` constructs the one hardcoded incident (tj-actions) by hand in the
same shape, from `kitsunox/fixtures/tj_actions_changed_files_2025.json`.

Kept free of any GitHub API or LLM specifics — this is the shared vocabulary that
fetch.py, rules.py, llm.py, incidents.py, and evaluate.py all speak.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

ChangeType = Literal["added", "modified", "removed"]
Source = Literal["pr", "push"]
GroundTruth = Literal["malicious", "benign"]
Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass
class FileDiff:
    """One changed file within a change. `patch` is the unified-diff hunk text GitHub
    returns for that file — bounded to that file's changes, never a full file body."""

    path: str
    change_type: ChangeType
    is_binary: bool
    additions: int = 0
    deletions: int = 0
    patch: str = ""


@dataclass
class Finding:
    """One Tier 0 rule hit. Mirrors the Finding shape from the original npm-registry
    design. `evidence` must stay a short, bounded snippet — never a whole file."""

    rule_id: str
    severity: Severity
    rationale: str

    # The historical attack this pattern is drawn from, if any. Kept apart from
    # `rationale` because it is a teaching aid for a human reading a report, not evidence
    # about this change -- and because naming a ground-truth incident inside a Tier 2
    # prompt hands the model the answer it is being measured on. Reports show it; prompts
    # never do.
    precedent: str = ""
    file_path: str | None = None
    line: int | None = None
    evidence: str = ""


@dataclass
class Change:
    """A merged PR or a direct push, normalized to one shape.

    PR-only fields (`pr_number`, `author_association`, `merged_by`,
    `approving_review_count`) are left at their defaults for push-sourced changes.
    """

    repo: str  # "owner/name"
    source: Source
    sha: str  # head commit sha for a push; PR head/merge sha for a PR
    author: str | None
    committed_at: datetime | None
    files: list[FileDiff] = field(default_factory=list)

    # Every commit sha in this change — a single-item list for a push, the full commit
    # list for a PR (fetched via `GET /pulls/{number}/commits`). `sha` above is always
    # one of these (normally the last one); this is here for anything that needs the
    # whole history rather than just the head.
    shas: list[str] = field(default_factory=list)

    # Check-runs state (`GET /commits/{sha}/check-runs`) for `sha`: True if every run
    # completed without a failing conclusion, False if any failed, None if runs are
    # still in progress or no checks were ever configured (most historical incidents
    # predate required CI on the repo). The legacy Combined Status API is deliberately
    # not used — it reports empty/pending on repos that run CI through GitHub Actions.
    checks_passed: bool | None = None

    pr_number: int | None = None
    author_association: str | None = None  # e.g. "OWNER", "FIRST_TIME_CONTRIBUTOR"
    merged_by: str | None = None
    approving_review_count: int = 0

    # How long this author had been contributing to *this repo* when the change landed,
    # and how many commits they had already made. Both None when not looked up (the
    # lookup costs an API call per author) or when the history is unavailable.
    #
    # This is the only view we get of Ladisa et al.'s AV-800 "Become a Maintainer":
    # event-stream's attacker had 5 days and 9 commits of history when he added the
    # malicious dependency, against the owner's 7 years and 248. GitHub exposes no
    # record of when commit rights were granted, so first-commit date is the proxy.
    author_tenure_days: int | None = None
    author_prior_commits: int | None = None

    # Set only by incidents.py (labels the 5 known-malicious changes) and by
    # evaluate.py (labels the control sample "benign"). fetch.py and rules.py must
    # never read or set this — Tier 0/Tier 2 have to work without knowing the answer.
    ground_truth: GroundTruth | None = None

    @property
    def is_first_time_contributor(self) -> bool:
        return self.author_association == "FIRST_TIME_CONTRIBUTOR"

    @property
    def merged_by_author(self) -> bool:
        return self.source == "pr" and bool(self.merged_by) and self.merged_by == self.author
