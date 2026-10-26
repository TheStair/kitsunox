"""GitHub REST API client — turns (owner, repo, sha/PR#) into `model.Change` objects.

Auth via a `GITHUB_TOKEN` env var (a `.env` file is loaded automatically; public-repo
read scope is enough). Works with no token too, at GitHub's much lower unauthenticated
rate limit (60/hr vs 5000/hr) — useful for quick local checks.

No pattern-matching, scoring, or LLM logic lives here — this module only fetches and
normalizes into `model.Change`/`model.FileDiff`.
"""

from __future__ import annotations

import difflib
import functools
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

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


# GitHub omits `patch` for three different reasons, and only one of them is a binary file.
# Treating every missing patch as binary was the largest single source of false alerts in
# the first holdout hunt: an empty `.gitkeep` read as an opaque executable, a 13,000-line
# `dist/index.js` and `package-lock.json` as unreviewable binaries. Worse, a *modified*
# bundle with an omitted patch was never scanned at all -- exactly where tj-actions hid
# its payload.
EMPTY_BLOB_SHA = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"  # git's hash of a 0-byte file

# GitHub reports 0/0 line counts both for binaries and for text files past its per-commit
# diff budget. A source extension is enough to try reading the file before calling it
# binary; the content sniff in `_recover_omitted` settles it.
TEXT_SUFFIXES = {
    ".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".json", ".map", ".md", ".txt",
    ".yml", ".yaml", ".toml", ".py", ".sh", ".css", ".html", ".xml", ".svg",
}


def _suffix(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    return "." + name.rsplit(".", 1)[-1] if "." in name.lstrip(".") else ""


def _file_diffs(raw_files: list[dict]) -> list[FileDiff]:
    status_map: dict[str, ChangeType] = {
        "added": "added",
        "removed": "removed",
        "renamed": "modified",
        "modified": "modified",
    }
    diffs = []
    for f in raw_files:
        added, deleted = f.get("additions", 0), f.get("deletions", 0)
        if "patch" in f or f.get("sha") == EMPTY_BLOB_SHA:
            binary, omitted = False, False
        elif added or deleted or _suffix(f["filename"]) in TEXT_SUFFIXES:
            binary, omitted = False, True  # text: line counts exist, the diff was withheld
        else:
            binary, omitted = True, False
        diffs.append(
            FileDiff(
                path=f["filename"],
                change_type=status_map.get(f.get("status", "modified"), "modified"),
                is_binary=binary,
                additions=added,
                deletions=deleted,
                patch=f.get("patch", ""),
                patch_omitted=omitted,
            )
        )
    return diffs


# Rebuilding an omitted diff costs two file reads, so it is bounded per change. Third-party
# code, lockfiles and source maps are skipped: Tier 0 does not scan them, so reading them
# buys nothing.
MAX_RECOVERED_FILES = 15
MAX_RECOVERED_BYTES = 5_000_000
_NOT_RECOVERED = ("node_modules/", "vendor/", "third_party/", "bower_components/")


def _get_raw(owner: str, repo: str, path: str, ref: str) -> bytes | None:
    """A file's bytes at `ref`, cached like any other response (content at a commit sha
    never changes). None if it cannot be read or is too large to diff."""
    url = f"{API_BASE}/repos/{owner}/{repo}/contents/{quote(path)}"
    cache_file = _cache_path(url, {"ref": ref, "raw": True}).with_suffix(".bin")
    if cache_file.exists():
        return cache_file.read_bytes()
    try:
        resp = _session.get(url, params={"ref": ref}, timeout=60,
                            headers={"Accept": "application/vnd.github.raw"})
    except requests.RequestException:
        return None
    if resp.status_code >= 400 or len(resp.content) > MAX_RECOVERED_BYTES:
        return None
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file.write_bytes(resp.content)
    return resp.content


def _recover_omitted(owner: str, repo: str, sha: str, parent: str | None,
                     raw_files: list[dict], diffs: list[FileDiff]) -> None:
    """Rebuild the patches GitHub withheld, in place, by reading both versions of each file.

    A file whose content turns out to contain NUL bytes is a binary after all, whatever
    its name. Anything that cannot be read stays `patch_omitted`, for Tier 0 to report as
    unscanned.
    """
    budget = MAX_RECOVERED_FILES
    for raw, diff in zip(raw_files, diffs):
        if not diff.patch_omitted or diff.change_type == "removed" or budget <= 0:
            continue
        low = diff.path.lower()
        if any("/" + s in "/" + low for s in _NOT_RECOVERED) or \
                low.endswith(("lock.json", ".lock", "lock.yaml", ".map")):
            continue
        budget -= 1
        new = _get_raw(owner, repo, diff.path, sha)
        old_path = raw.get("previous_filename") or diff.path
        if diff.change_type == "added":
            old: bytes | None = b""
        else:
            old = _get_raw(owner, repo, old_path, parent) if parent else None
        if new is None or old is None:
            continue
        if b"\x00" in new[:8000]:
            diff.is_binary, diff.patch_omitted = True, False
            continue
        before = old.decode("utf-8", errors="replace")
        after = new.decode("utf-8", errors="replace")
        lines = list(difflib.unified_diff(before.splitlines(), after.splitlines(),
                                          lineterm="", n=3))
        diff.patch = "\n".join(lines[2:])  # drop the ---/+++ file header, keep the hunks
        diff.baseline = before
        diff.patch_omitted = False


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


def author_history(owner: str, repo: str, author: str) -> list[datetime]:
    """Every commit date this author has in this repo, oldest first.

    Fetched once per (repo, author) and cached on disk. This is what makes repo-scale
    scanning affordable: `author_tenure` used to key its cache on the change's timestamp,
    so a thousand commits by the same author meant a thousand multi-page refetches of the
    same history. Now it is one fetch, and every tenure question is answered locally.

    Capped at 10 pages — an author with 1000+ commits here is established under any
    threshold worth having.
    """
    dates: list[datetime] = []
    page = 1
    while page <= 10:
        try:
            batch = _get_json(
                f"{API_BASE}/repos/{owner}/{repo}/commits",
                {"author": author, "per_page": 100, "page": page},
            )
        except FetchError:
            break
        if not batch:
            break
        for entry in batch:
            stamp = _parse_ts(entry.get("commit", {}).get("author", {}).get("date"))
            if stamp is not None:
                dates.append(stamp)
        if len(batch) < 100:
            break
        page += 1
    return sorted(dates)


def author_tenure(owner: str, repo: str, author: str, until: datetime) -> tuple[int | None, int | None]:
    """(days since this author's first commit to this repo, commits they had made) as of
    `until`.

    GitHub exposes no record of when someone was granted commit rights, so the first
    commit in the repo is the proxy for "how long have they been around here". Both
    figures are derived from `author_history`, which is fetched once per author and
    cached, so asking this for every commit in a repo costs one request per author.

    Counting must be done as-of `until`, not over the whole history: an author's later
    commits say nothing about how established they were when *this* change landed.
    """
    history = author_history(owner, repo, author)
    prior = [d for d in history if d <= until]
    if not prior:
        return None, None
    return max(0, (until - prior[0]).days), len(prior)


@functools.lru_cache(maxsize=512)
def repo_started_at(owner: str, repo: str) -> datetime | None:
    """When the project began: the date of the repository's earliest commit.

    Not GitHub's `created_at`. A project migrated to GitHub carries years of history from
    before that date -- tukaani-project/xz's GitHub repository is younger than the project,
    so measured from `created_at` its 2022 contributors looked like founders. Migrated
    repositories are exactly the long-established projects a newcomer attack targets.

    The earliest commit is the last page of the commit listing. Finding that page needs
    the Link header, which the JSON cache does not keep, so this costs one uncached call
    per repository per run (memoised in-process) plus one cached page. Falls back to
    `created_at` if the listing cannot be read.
    """
    url = f"{API_BASE}/repos/{owner}/{repo}/commits"
    try:
        resp = _session.get(url, params={"per_page": 1}, timeout=30)
        last = re.search(r'[?&]page=(\d+)>;\s*rel="last"', resp.headers.get("Link", ""))
        page = int(last.group(1)) if last else 1
        oldest = _get_json(url, {"per_page": 1, "page": page})
        if oldest:
            return _parse_ts(oldest[-1].get("commit", {}).get("author", {}).get("date"))
    except (FetchError, requests.RequestException, ValueError):
        pass
    try:
        return _parse_ts(_get_json(f"{API_BASE}/repos/{owner}/{repo}").get("created_at"))
    except FetchError:
        return None


def _attach_tenure(change: Change, owner: str, repo: str) -> Change:
    if change.author and change.committed_at:
        change.author_tenure_days, change.author_prior_commits = author_tenure(
            owner, repo, change.author, change.committed_at
        )
        created = repo_started_at(owner, repo) if change.author_tenure_days is not None else None
        if created is not None:
            first_seen = change.committed_at - timedelta(days=change.author_tenure_days)
            # Clamped at zero for the fallback case, where only created_at was available.
            change.author_arrival_days = max(0, (first_seen - created).days)
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
    raw_files = data.get("files", [])
    files = _file_diffs(raw_files)
    parent = ((data.get("parents") or [{}])[0] or {}).get("sha")
    _recover_omitted(owner, repo, sha, parent, raw_files, files)

    return _attach_tenure(
        Change(
            repo=f"{owner}/{repo}",
            source="push",
            sha=sha,
            shas=[sha],
            author=author,
            message=(data.get("commit", {}) or {}).get("message", ""),
            committed_at=_parse_ts(data.get("commit", {}).get("author", {}).get("date")),
            files=files,
            checks_passed=_fetch_checks_passed(owner, repo, sha),
            parent_sha=parent,
            pr_number=pr_number,
        ),
        owner,
        repo,
    )


def fetch_merged_prs(owner: str, repo: str, limit: int, *, fresh: bool = False) -> list[Change]:
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

    `fresh` re-reads the PR *listing* instead of serving it from cache. Evaluation leaves
    it off so the control corpus stays reproducible; hunting turns it on, or a second hunt
    would replay the first one's listing and never see a new PR. Per-PR details are
    immutable once merged and stay cached either way.
    """
    merged_numbers: list[int] = []
    page = 1
    while len(merged_numbers) < limit and page <= 20:
        batch = _get_json(
            f"{API_BASE}/repos/{owner}/{repo}/pulls",
            {"state": "closed", "sort": "updated", "direction": "desc", "per_page": 100, "page": page},
            use_cache=not fresh,
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
                    # A PR's stated intent is its title and body.
                    message="\n\n".join(
                        part for part in (pr.get("title"), pr.get("body")) if part
                    ),
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
    owner: str, repo: str, limit: int, *, exclude: set[str] | None = None,
    fresh: bool = False,
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

    `fresh` re-reads the commit *listing* rather than serving it from cache, for the same
    reason as in `fetch_merged_prs`: hunting has to see commits made since the last run.
    """
    exclude = exclude or set()
    changes: list[Change] = []
    page = 1
    while len(changes) < limit and page <= 10:
        batch = _get_json(
            f"{API_BASE}/repos/{owner}/{repo}/commits", {"per_page": 100, "page": page},
            use_cache=not fresh,
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


# --------------------------------------------------------------------------- tags
# GitHub Actions consumers pin a *tag* (`uses: owner/action@v4`), so what runs in their
# CI is whatever that tag points at -- not what is on the default branch. Both Actions
# incidents in the ground truth exploited that: reviewdog's malicious commit was never on
# any branch, and tj-actions rewrote every version tag to point at one commit (Ladisa
# AV-303, Tamper with Version Control System). Scanning the default branch alone cannot
# see either.
#
# Everything here bypasses the cache. Tags move -- that is the attack -- and a cached tag
# list would make a moved tag undetectable by construction.


def default_branch(owner: str, repo: str) -> str | None:
    """The repository's default branch name. Stable, so cached."""
    try:
        return _get_json(f"{API_BASE}/repos/{owner}/{repo}").get("default_branch")
    except FetchError:
        return None


def list_tags(owner: str, repo: str, *, limit: int = 500) -> list[tuple[str, str]]:
    """(tag name, commit sha) for every tag, freshly read. Annotated tags arrive already
    dereferenced to their commit."""
    tags: list[tuple[str, str]] = []
    page = 1
    while len(tags) < limit:
        try:
            batch = _get_json(
                f"{API_BASE}/repos/{owner}/{repo}/tags", {"per_page": 100, "page": page},
                use_cache=False,
            )
        except FetchError:
            break
        if not batch:
            break
        tags += [
            (entry["name"], entry["commit"]["sha"])
            for entry in batch
            if entry.get("name") and (entry.get("commit") or {}).get("sha")
        ]
        if len(batch) < 100:
            break
        page += 1
    return tags[:limit]


def list_branches(owner: str, repo: str, *, limit: int = 300) -> list[str]:
    """Branch names, freshly read."""
    names: list[str] = []
    page = 1
    while len(names) < limit:
        try:
            batch = _get_json(
                f"{API_BASE}/repos/{owner}/{repo}/branches", {"per_page": 100, "page": page},
                use_cache=False,
            )
        except FetchError:
            break
        if not batch:
            break
        names += [b["name"] for b in batch if b.get("name")]
        if len(batch) < 100:
            break
        page += 1
    return names[:limit]


# Release branches are where a legitimately tagged commit is most likely to live when it is
# not on the default branch, so they are checked first and most commits resolve in one or
# two calls. Measured on the first Actions hunt: tgymnich/fork-sync tags commits on
# releases/v1.7.1 and Azure/k8s-deploy on releases/v4.
_RELEASE_BRANCH = re.compile(r"^(releases?|rel|stable|dist|v\d)", re.IGNORECASE)
_BOT_BRANCH = re.compile(r"^(dependabot|renovate|snyk|greenkeeper)/", re.IGNORECASE)


def on_any_branch(owner: str, repo: str, sha: str, *, max_compares: int = 60) -> bool | None:
    """Whether `sha` is reachable from any branch; None if it cannot be told.

    The signal that matters for a tag target is a commit on no branch at all -- reviewdog's
    f0d342 was exactly that. A commit on a release branch is ordinary practice, which is
    why the first version, checking only the default branch, raised 18 alerts on the first
    Actions hunt and 10 with no other evidence.

    Branches are tried default first, then release-like names, then the rest, with bot
    branches last. A False answer requires every branch to have been checked; hitting
    `max_compares` first returns None rather than a guess. Not cached: branches move, and
    a commit can land on one after a first check.

    Known evasion, stated rather than hidden: an attacker who can push a tag can usually
    push a branch too, and parking the commit on one defeats this check.
    """
    branches = list_branches(owner, repo)
    if not branches:
        return None
    default = default_branch(owner, repo)
    order = sorted(
        branches,
        key=lambda b: (b != default, not _RELEASE_BRANCH.match(b), bool(_BOT_BRANCH.match(b)), b),
    )
    for checked, branch in enumerate(order):
        if checked >= max_compares:
            return None
        try:
            data = _get_json(
                f"{API_BASE}/repos/{owner}/{repo}/compare/{branch}...{sha}", use_cache=False
            )
        except FetchError:
            continue  # e.g. "no common ancestor": not on this branch
        if data.get("status") in ("behind", "identical"):
            return True
    return False


def fetch_recent_commits(owner: str, repo: str, limit: int, *, fresh: bool = True) -> list[Change]:
    """The newest `limit` non-merge commits on the default branch, however they landed.

    This is the hunting view, distinct from `fetch_direct_pushes`. That function splits
    commits into populations for the evaluation's control sample, skipping anything that
    arrived through a pull request -- which in a repository that merges almost everything
    through PRs means walking up to a thousand commits, one association lookup each, to
    find a handful of direct pushes. A hunt asks a simpler question: what recently landed
    where consumers will run it? Every commit on the default branch qualifies.

    Merge commits are still skipped: they carry no diff of their own.
    """
    changes: list[Change] = []
    per_page = min(100, max(limit, 10))
    page = 1
    while len(changes) < limit and page <= 3:
        batch = _get_json(
            f"{API_BASE}/repos/{owner}/{repo}/commits",
            {"per_page": per_page, "page": page},
            use_cache=not fresh,
        )
        if not batch:
            break
        last_page = len(batch) < per_page  # a short page is the final one; don't ask again
        for entry in batch:
            if len(changes) >= limit:
                break
            if len(entry.get("parents", [])) > 1:
                continue
            try:
                changes.append(fetch_commit(owner, repo, entry["sha"]))
            except FetchError:
                continue
        if last_page:
            break
        page += 1
    return changes
