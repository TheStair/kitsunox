"""fetch.py — GitHub API client, fully mocked (no real network calls).

`responses` intercepts at the transport level, so it works against the module's
shared `_session`. Each test's on-disk cache is redirected to a tmp dir by the
autouse `isolated_cache` fixture in conftest.py.
"""

from __future__ import annotations

import responses

from kitsunox import fetch

BASE = fetch.API_BASE


def _rate_limited_headers(remaining: str = "0", reset_in_s: int = 1) -> dict:
    import time

    return {"X-RateLimit-Remaining": remaining, "X-RateLimit-Reset": str(int(time.time()) + reset_in_s)}


# --------------------------------------------------------------------- _file_diffs
def test_file_diffs_status_mapping_and_binary_detection():
    raw = [
        {"filename": "new.js", "status": "added", "additions": 5, "deletions": 0, "patch": "+x"},
        {"filename": "gone.js", "status": "removed", "additions": 0, "deletions": 3, "patch": "-x"},
        {"filename": "moved.js", "status": "renamed", "additions": 1, "deletions": 1, "patch": "@@"},
        {"filename": "changed.js", "status": "modified", "additions": 2, "deletions": 2, "patch": "@@"},
        {"filename": "blob.bin", "status": "added", "additions": 0, "deletions": 0},  # no 'patch' -> binary
    ]
    diffs = fetch._file_diffs(raw)
    by_path = {d.path: d for d in diffs}
    assert by_path["new.js"].change_type == "added"
    assert by_path["gone.js"].change_type == "removed"
    assert by_path["moved.js"].change_type == "modified"  # renamed collapses to modified
    assert by_path["changed.js"].change_type == "modified"
    assert by_path["blob.bin"].is_binary
    assert not by_path["new.js"].is_binary


# ------------------------------------------------------------------------ _get_json
@responses.activate
def test_get_json_caches_after_first_call():
    responses.add(responses.GET, f"{BASE}/x", json={"ok": True}, status=200)

    assert fetch._get_json(f"{BASE}/x") == {"ok": True}
    assert fetch._get_json(f"{BASE}/x") == {"ok": True}  # served from disk cache

    assert len(responses.calls) == 1


@responses.activate
def test_get_json_raises_fetch_error_on_404():
    responses.add(responses.GET, f"{BASE}/missing", json={"message": "Not Found"}, status=404)

    try:
        fetch._get_json(f"{BASE}/missing")
        assert False, "expected FetchError"
    except fetch.FetchError as exc:
        assert "404" in str(exc)


@responses.activate
def test_get_json_backs_off_and_retries_on_rate_limit(monkeypatch):
    slept = []
    monkeypatch.setattr(fetch.time, "sleep", lambda s: slept.append(s))

    responses.add(responses.GET, f"{BASE}/rl", json={}, status=403, headers=_rate_limited_headers())
    responses.add(responses.GET, f"{BASE}/rl", json={"ok": True}, status=200)

    assert fetch._get_json(f"{BASE}/rl", use_cache=False) == {"ok": True}
    assert len(slept) == 1
    assert len(responses.calls) == 2


# ------------------------------------------------------------------ _fetch_checks_passed
@responses.activate
def test_checks_passed_true_when_all_completed_and_successful():
    responses.add(
        responses.GET,
        f"{BASE}/repos/o/r/commits/sha/check-runs",
        json={"total_count": 2, "check_runs": [
            {"status": "completed", "conclusion": "success"},
            {"status": "completed", "conclusion": "neutral"},
        ]},
    )
    assert fetch._fetch_checks_passed("o", "r", "sha") is True


@responses.activate
def test_checks_passed_false_when_any_conclusion_failing():
    responses.add(
        responses.GET,
        f"{BASE}/repos/o/r/commits/sha/check-runs",
        json={"total_count": 2, "check_runs": [
            {"status": "completed", "conclusion": "success"},
            {"status": "completed", "conclusion": "failure"},
        ]},
    )
    assert fetch._fetch_checks_passed("o", "r", "sha") is False


@responses.activate
def test_checks_passed_none_when_still_running():
    responses.add(
        responses.GET,
        f"{BASE}/repos/o/r/commits/sha/check-runs",
        json={"total_count": 1, "check_runs": [{"status": "in_progress", "conclusion": None}]},
    )
    assert fetch._fetch_checks_passed("o", "r", "sha") is None


@responses.activate
def test_checks_passed_none_when_no_checks_configured():
    responses.add(
        responses.GET, f"{BASE}/repos/o/r/commits/sha/check-runs", json={"total_count": 0, "check_runs": []}
    )
    assert fetch._fetch_checks_passed("o", "r", "sha") is None


@responses.activate
def test_checks_passed_none_on_fetch_error():
    responses.add(responses.GET, f"{BASE}/repos/o/r/commits/sha/check-runs", json={}, status=404)
    assert fetch._fetch_checks_passed("o", "r", "sha") is None


# -------------------------------------------------------------------------- fetch_commit
@responses.activate
def test_fetch_commit_paginates_files_and_links_pr_and_checks():
    sha = "deadbeef"
    page1_files = [{"filename": f"f{i}.py", "status": "modified", "patch": "@@"} for i in range(300)]
    page2_files = [{"filename": "f300.py", "status": "added", "patch": "@@"}]

    commit_url = f"{BASE}/repos/o/r/commits/{sha}"
    responses.add(
        responses.GET,
        commit_url,
        json={
            "sha": sha,
            "author": {"login": "alice"},
            "commit": {"author": {"name": "alice", "date": "2024-01-01T00:00:00Z"}},
            "files": page1_files,
        },
    )
    responses.add(responses.GET, commit_url, json={"files": page2_files})
    responses.add(responses.GET, f"{BASE}/repos/o/r/commits/{sha}/pulls", json=[{"number": 42}])
    responses.add(
        responses.GET,
        f"{BASE}/repos/o/r/commits/{sha}/check-runs",
        json={"total_count": 1, "check_runs": [{"status": "completed", "conclusion": "success"}]},
    )

    change = fetch.fetch_commit("o", "r", sha)

    assert len(change.files) == 301  # paginated past the first 300
    assert change.pr_number == 42
    assert change.checks_passed is True
    assert change.shas == [sha]
    assert change.source == "push"
    assert change.author == "alice"


@responses.activate
def test_fetch_commit_pr_association_is_best_effort():
    sha = "cafef00d"
    responses.add(
        responses.GET,
        f"{BASE}/repos/o/r/commits/{sha}",
        json={"sha": sha, "author": None, "commit": {"author": {"name": "bob", "date": None}}, "files": []},
    )
    # association lookup 404s — must not blow up fetch_commit
    responses.add(responses.GET, f"{BASE}/repos/o/r/commits/{sha}/pulls", json={}, status=404)
    responses.add(
        responses.GET, f"{BASE}/repos/o/r/commits/{sha}/check-runs", json={"total_count": 0, "check_runs": []}
    )

    change = fetch.fetch_commit("o", "r", sha)
    assert change.pr_number is None
    assert change.author == "bob"  # falls back to commit.author.name when author.login is absent


# ---------------------------------------------------------------------- fetch_merged_prs
@responses.activate
def test_fetch_merged_prs_skips_unmerged_and_walks_pages_until_enough_found():
    page1 = [{"number": 1, "merged_at": None}, {"number": 2, "merged_at": None}]  # all closed-not-merged
    page2 = [
        {"number": 3, "merged_at": "2024-01-01T00:00:00Z"},
        {"number": 4, "merged_at": "2024-01-02T00:00:00Z"},
    ]
    list_url = f"{BASE}/repos/o/r/pulls"
    responses.add(responses.GET, list_url, json=page1)
    responses.add(responses.GET, list_url, json=page2)

    for number, merged_by, reviews in [
        (3, "carol", [{"state": "APPROVED"}, {"state": "COMMENTED"}]),
        (4, None, []),
    ]:
        responses.add(
            responses.GET,
            f"{BASE}/repos/o/r/pulls/{number}",
            json={
                "number": number,
                "merge_commit_sha": f"sha{number}",
                "head": {"sha": f"head{number}"},
                "merged_at": "2024-01-01T00:00:00Z",
                "user": {"login": "dave"},
                "author_association": "CONTRIBUTOR",
                "merged_by": {"login": merged_by} if merged_by else None,
            },
        )
        responses.add(responses.GET, f"{BASE}/repos/o/r/pulls/{number}/files", json=[])
        responses.add(responses.GET, f"{BASE}/repos/o/r/pulls/{number}/reviews", json=reviews)
        responses.add(responses.GET, f"{BASE}/repos/o/r/pulls/{number}/commits", json=[{"sha": f"sha{number}"}])
        responses.add(responses.GET, f"{BASE}/repos/o/r/pulls/{number}/commits", json=[])  # end of pagination
        responses.add(
            responses.GET,
            f"{BASE}/repos/o/r/commits/sha{number}/check-runs",
            json={"total_count": 0, "check_runs": []},
        )

    changes = fetch.fetch_merged_prs("o", "r", limit=2)

    assert [c.pr_number for c in changes] == [3, 4]
    assert changes[0].merged_by == "carol"
    assert changes[0].approving_review_count == 1  # only the APPROVED review counts
    assert changes[1].merged_by is None
    assert changes[0].shas == ["sha3"]
    assert changes[0].author_association == "CONTRIBUTOR"
