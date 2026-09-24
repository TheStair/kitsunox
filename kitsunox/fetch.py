"""GitHub REST API client — turns (owner, repo, sha/PR#) into `model.Change` objects.

Auth via a `GITHUB_TOKEN` env var (a `.env` file is loaded automatically; public-repo
read scope is enough). Works with no token too, at GitHub's much lower unauthenticated
rate limit (60/hr vs 5000/hr) — useful for quick local checks.

No pattern-matching, scoring, or LLM logic lives here — this module only fetches and
normalizes into `model.Change`/`model.FileDiff`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from kitsunox.model import Change, ChangeType, FileDiff

load_dotenv()

log = logging.getLogger(__name__)

API_BASE = "https://api.github.com"
CACHE_DIR = Path(".cache/gh")
_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

if not _TOKEN:
    log.warning("GITHUB_TOKEN not set — using GitHub's unauthenticated rate limit (60/hr)")

_session = requests.Session()
_session.headers.update(
    {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        **({"Authorization": f"Bearer {_TOKEN}"} if _TOKEN else {}),
    }
)


class FetchError(Exception):
    """A commit/PR/repo could not be fetched (404, or a request that kept failing).

    Callers (incidents.py in particular) must be able to catch this specifically and
    fall back to hardcoded data rather than crashing the whole run.
    """


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)


def _cache_path(url: str, params: dict | None) -> Path:
    key = hashlib.sha256(f"{url}?{json.dumps(params or {}, sort_keys=True)}".encode()).hexdigest()
    return CACHE_DIR / f"{key}.json"


def _get_json(url: str, params: dict | None = None, *, use_cache: bool = True) -> Any:
    """GET a GitHub API endpoint, with on-disk caching and rate-limit backoff.

    Caching is deliberately simple (no TTL/invalidation): merged PRs and past commits
    don't change, so a cached response is reused indefinitely. Delete `.cache/gh/` to
    force a refresh.
    """
    cache_file = _cache_path(url, params)
    if use_cache and cache_file.exists():
        return json.loads(cache_file.read_text(encoding="utf-8"))

    for _ in range(2):  # one retry after a rate-limit sleep, no more
        resp = _session.get(url, params=params, timeout=30)

        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset_at = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait_s = max(0, reset_at - int(time.time())) + 1
            log.warning("GitHub rate limit hit; sleeping %ss", wait_s)
            time.sleep(wait_s)
            continue

        if resp.status_code >= 400:
            raise FetchError(f"{resp.status_code} {resp.reason} for {url}: {resp.text[:200]}")

        data = resp.json()
        if use_cache:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(data), encoding="utf-8")
        return data

    raise FetchError(f"gave up after rate-limit retries: {url}")


def _paginated(url: str, params: dict, *, max_items: int) -> list[dict]:
    items: list[dict] = []
    page = 1
    while len(items) < max_items:
        batch = _get_json(url, {**params, "per_page": 100, "page": page})
        if not batch:
            break
        items.extend(batch)
        page += 1
    return items[:max_items]


def _file_diffs(raw_files: list[dict]) -> list[FileDiff]:
    status_map: dict[str, ChangeType] = {
        "added": "added",
        "removed": "removed",
        "renamed": "modified",
        "modified": "modified",
    }
    diffs = []
    for f in raw_files:
        diffs.append(
            FileDiff(
                path=f["filename"],
                change_type=status_map.get(f.get("status", "modified"), "modified"),
                is_binary="patch" not in f,
                additions=f.get("additions", 0),
                deletions=f.get("deletions", 0),
                patch=f.get("patch", ""),
            )
        )
    return diffs


def _fetch_commit_all_files(owner: str, repo: str, sha: str) -> dict:
    """`GET /commits/{sha}`, paginating the `files` array past GitHub's ~300-file page.

    The commit endpoint isn't a list endpoint, but GitHub paginates its `files` array
    the same way once a diff is large enough: repeat the request with `page`/`per_page`
    and keep appending until a page comes back with fewer than `per_page` files.
    """
    data = _get_json(f"{API_BASE}/repos/{owner}/{repo}/commits/{sha}", {"per_page": 300})
    files = list(data.get("files", []))
    page = 2
    while len(files) and len(files) % 300 == 0:
        more = _get_json(
            f"{API_BASE}/repos/{owner}/{repo}/commits/{sha}", {"per_page": 300, "page": page}
        )
        extra = more.get("files", [])
        if not extra:
            break
        files.extend(extra)
        page += 1
    data["files"] = files
    return data


_FAILING_CONCLUSIONS = {"failure", "timed_out", "action_required", "stale", "cancelled"}


def _fetch_checks_passed(owner: str, repo: str, sha: str) -> bool | None:
    """Check-runs state (`GET /commits/{sha}/check-runs`) -> True/False/None.

    GitHub Actions (and most modern CI apps) report through the Check Runs API, not
    the legacy Combined Status API — the latter comes back empty/pending on most
    current repos even when Actions ran and passed, so it can't be used here.

    Best-effort: no checks configured (`total_count == 0`), or the lookup failing
    outright, both return None rather than a false verdict.
    """
    try:
        data = _get_json(
            f"{API_BASE}/repos/{owner}/{repo}/commits/{sha}/check-runs", {"per_page": 100}
        )
    except FetchError:
        return None

    runs = data.get("check_runs", [])
    if not runs:
        return None
    if any(r.get("conclusion") in _FAILING_CONCLUSIONS for r in runs):
        return False
    if any(r.get("status") != "completed" for r in runs):
        return None  # still running; not a verdict either way
    return True


def author_tenure(owner: str, repo: str, author: str, until: datetime) -> tuple[int | None, int | None]:
    """(days since this author's first commit to this repo, commits they had made) as of
    `until`.

    GitHub exposes no record of when someone was granted commit rights, so the first
    commit in the repo is the proxy for "how long have they been around here".

    Pages must be walked to the end rather than stopping at the first 100: the oldest
    commit on page 1 is only the author's 100th-most-recent, which understates a prolific
    author's tenure enormously. Reading a single page put xz's attacker at 91 days
    instead of ~2 years — one day the wrong side of the "new maintainer" threshold, and a
    false positive that would have looked like a correct miss.

    Capped at 10 pages: an author with 1000+ commits here is established under any
    threshold worth having. Cached on disk and keyed per (repo, author), so a whole-repo
    scan pays this once per author rather than once per commit.
    """
    batch: list[dict] = []
    count = 0
    page = 1
    while page <= 10:
        try:
            batch = _get_json(
                f"{API_BASE}/repos/{owner}/{repo}/commits",
                {"author": author, "until": until.isoformat() + "Z", "per_page": 100, "page": page},
            )
        except FetchError:
            return None, None
        if not batch:
            break
        count += len(batch)
        if len(batch) < 100:
            break  # last page: its final entry is the author's earliest commit
        page += 1

    if not count:
        return None, None
    if not batch:
        return None, count  # ran off the end on a page boundary; count is still sound

    first = _parse_ts(batch[-1].get("commit", {}).get("author", {}).get("date"))
    if first is None:
        return None, count
    return max(0, (until - first).days), count


def _attach_tenure(change: Change, owner: str, repo: str) -> Change:
    if change.author and change.committed_at:
        change.author_tenure_days, change.author_prior_commits = author_tenure(
            owner, repo, change.author, change.committed_at
        )
    return change


def fetch_commit(owner: str, repo: str, sha: str) -> Change:
    """Fetch a single commit's diff + metadata — for direct-push-style incidents
    (colors.js, most of xz-utils, the reviewdog/action-setup ref rewrite).

    Best-effort cross-references the commit to an associated PR (if any) to set
    `pr_number`; does not fetch that PR's reviews/files — use `fetch_merged_prs` (or a
    second `fetch_commit`-style call) if that's needed too.
    """
    data = _fetch_commit_all_files(owner, repo, sha)

    pr_number = None
    try:
        pulls = _get_json(f"{API_BASE}/repos/{owner}/{repo}/commits/{sha}/pulls")
        if pulls:
            pr_number = pulls[0]["number"]
    except FetchError:
        pass  # association lookup is best-effort; absence isn't an error

    author = (data.get("author") or {}).get("login") or (data.get("commit", {}).get("author") or {}).get("name")

    return _attach_tenure(
        Change(
            repo=f"{owner}/{repo}",
            source="push",
            sha=sha,
            shas=[sha],
            author=author,
            committed_at=_parse_ts(data.get("commit", {}).get("author", {}).get("date")),
            files=_file_diffs(data.get("files", [])),
            checks_passed=_fetch_checks_passed(owner, repo, sha),
            pr_number=pr_number,
        ),
        owner,
        repo,
    )


def fetch_merged_prs(owner: str, repo: str, limit: int) -> list[Change]:
    """Fetch up to `limit` recently-merged PRs for a repo, each with its diff and
    review-approval count. Used for the control sample; none of the current 5 incidents
    are PR-based (all turned out to be direct pushes — see incidents.py), but keep this
    around for any future incident that is.

    The list endpoint (`GET /pulls?state=closed`) is only used to discover which PR
    numbers are merged — its items omit `merged_by`, so each candidate's full detail
    is re-fetched from `GET /pulls/{number}` before building the `Change`. "closed"
    includes closed-without-merging PRs (sometimes the majority, e.g. bot/stale
    closures), so pages are walked until enough merged PRs are found rather than
    guessing a fixed over-fetch size; capped at 20 pages (2000 closed PRs) so a repo
    with very few actual merges can't spin forever.
    """
    merged_numbers: list[int] = []
    page = 1
    while len(merged_numbers) < limit and page <= 20:
        batch = _get_json(
            f"{API_BASE}/repos/{owner}/{repo}/pulls",
            {"state": "closed", "sort": "updated", "direction": "desc", "per_page": 100, "page": page},
        )
        if not batch:
            break
        merged_numbers += [pr["number"] for pr in batch if pr.get("merged_at")]
        page += 1
    merged_numbers = merged_numbers[:limit]

    changes = []
    for number in merged_numbers:
        pr = _get_json(f"{API_BASE}/repos/{owner}/{repo}/pulls/{number}")
        files_raw = _paginated(
            f"{API_BASE}/repos/{owner}/{repo}/pulls/{number}/files", {}, max_items=300
        )
        reviews = _get_json(f"{API_BASE}/repos/{owner}/{repo}/pulls/{number}/reviews")
        approvals = sum(1 for r in reviews if r.get("state") == "APPROVED")
        commits_raw = _paginated(
            f"{API_BASE}/repos/{owner}/{repo}/pulls/{number}/commits", {}, max_items=250
        )
        shas = [c["sha"] for c in commits_raw]

        head_sha = pr["merge_commit_sha"] or pr["head"]["sha"]
        changes.append(
            _attach_tenure(
                Change(
                    repo=f"{owner}/{repo}",
                    source="pr",
                    sha=head_sha,
                    shas=shas or [head_sha],
                    author=(pr.get("user") or {}).get("login"),
                    committed_at=_parse_ts(pr.get("merged_at")),
                    files=_file_diffs(files_raw),
                    checks_passed=_fetch_checks_passed(owner, repo, head_sha),
                    pr_number=number,
                    author_association=pr.get("author_association"),
                    merged_by=(pr.get("merged_by") or {}).get("login"),
                    approving_review_count=approvals,
                ),
                owner,
                repo,
            )
        )
    return changes


def fetch_direct_pushes(
    owner: str, repo: str, limit: int, *, exclude: set[str] | None = None
) -> list[Change]:
    """Up to `limit` recent commits pushed straight to the default branch, newest first.

    All five ground-truth incidents are direct pushes, so a control sample made only of
    merged PRs measures false positives on a population that structurally cannot trigger
    the push-based rules. This supplies the missing half.

    A commit counts as a direct push when it has no associated pull request. Merge
    commits (2+ parents) are skipped outright — they are the *result* of review, carry no
    diff of their own worth scanning, and would dilute the sample.

    `exclude` drops known-malicious SHAs, so an incident's own repo can safely be used as
    a source of benign commits — which makes the hardest possible control set: the
    attacker's other commits, in the same repo, in the same style.
    """
    exclude = exclude or set()
    changes: list[Change] = []
    page = 1
    while len(changes) < limit and page <= 10:
        batch = _get_json(
            f"{API_BASE}/repos/{owner}/{repo}/commits", {"per_page": 100, "page": page}
        )
        if not batch:
            break
        for entry in batch:
            if len(changes) >= limit:
                break
            sha = entry["sha"]
            if sha in exclude or len(entry.get("parents", [])) > 1:
                continue
            try:
                if _get_json(f"{API_BASE}/repos/{owner}/{repo}/commits/{sha}/pulls"):
                    continue  # landed via a PR, so it belongs in the PR sample
                changes.append(fetch_commit(owner, repo, sha))
            except FetchError:
                continue
        page += 1
    return changes
