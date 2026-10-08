"""Hunting, the triage queue, the disposition log and tally.

The pipeline ends in a human investigator. These tests protect three things that matter
more than any single output format: the queue cannot be forged by an attacker's commit
message, a reviewed disposition can never be overwritten by a later hunt, and a hunt
cannot spend money it was not told to.

No network and no API spend: `fetch` and `llm` are stubbed throughout.
"""

from __future__ import annotations

import csv

import pytest

from kitsunox import cli, evaluate, fetch, llm, rules
from kitsunox.model import Change, FileDiff, Finding

BLOB = "A" * 220


def _change(repo="o/r", sha="abc123def4567890", files=None, **kw) -> Change:
    defaults = dict(source="push", author="alice", committed_at=None)
    defaults.update(kw)
    return Change(repo=repo, sha=sha, files=files or [], **defaults)


def _bad(path="install.sh") -> list[FileDiff]:
    return [FileDiff(path=path, change_type="modified", is_binary=False,
                     patch=f'@@ -1,0 +1,2 @@\n+X="{BLOB}"\n+curl https://gist.githubusercontent.com/x')]


def _good() -> list[FileDiff]:
    return [FileDiff(path="README.md", change_type="modified", is_binary=False,
                     patch="@@ -1,0 +1,1 @@\n+docs")]


def _result(key="o/r@abc", escalated=True, score=20, **kw) -> evaluate.ChangeResult:
    defaults = dict(key=key, repo="o/r", source="push", ground_truth=None,
                    evidence_score=score, total_score=score, escalated=escalated,
                    url=f"https://github.com/o/r/commit/{key}")
    defaults.update(kw)
    return evaluate.ChangeResult(**defaults)


@pytest.fixture
def pushes(monkeypatch):
    """Stub the commit listing; returns a setter for the changes to serve."""
    served = {"changes": []}
    monkeypatch.setattr(fetch, "fetch_direct_pushes",
                        lambda o, r, n, **kw: list(served["changes"]))
    monkeypatch.setattr(fetch, "fetch_merged_prs", lambda o, r, n, **kw: [])
    return served


# ============================================================== ranking


def test_refusals_rank_first():
    # In the wild a refusal is itself evidence the diff looks malicious.
    ranked = evaluate.rank([_result("a", score=90, verdict="malicious"),
                            _result("b", score=5, refused=True)])
    assert ranked[0].key == "b"


def test_verdict_outranks_score_and_benign_sinks():
    ranked = evaluate.rank([
        _result("benign-high", score=90, verdict="benign"),
        _result("unbriefed", score=50),
        _result("suspicious", score=10, verdict="suspicious"),
        _result("malicious", score=9, verdict="malicious"),
    ])
    assert [r.key for r in ranked] == ["malicious", "suspicious", "unbriefed", "benign-high"]


def test_without_briefs_rank_is_by_score():
    ranked = evaluate.rank([_result("low", score=8), _result("high", score=40)])
    assert [r.key for r in ranked] == ["high", "low"]


# ============================================================== targets


def test_targets_skip_blanks_and_comments(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# actions\n\nowner/one\nowner/two   # pinned by many\n  \n", encoding="utf-8")
    assert evaluate.load_targets(f) == ["owner/one", "owner/two"]


@pytest.mark.parametrize("bad", ["justaname", "a/b/c", "/lead", "trail/"])
def test_malformed_targets_are_rejected(tmp_path, bad):
    f = tmp_path / "t.txt"
    f.write_text(bad + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        evaluate.load_targets(f)


# ============================================================== hunting


def test_hunt_reads_listings_fresh(monkeypatch):
    # A cached listing makes a second hunt replay the first and miss every new commit.
    seen = {}

    def pushes(o, r, n, **kw):
        seen.update(kw)
        return []

    monkeypatch.setattr(fetch, "fetch_direct_pushes", pushes)
    evaluate.hunt(["o/r"])
    assert seen.get("fresh") is True


def test_a_failing_repo_does_not_abort_the_hunt(monkeypatch):
    def pushes(o, r, n, **kw):
        if r == "gone":
            raise fetch.FetchError("404")
        return [_change(repo=f"{o}/{r}", files=_bad())]

    monkeypatch.setattr(fetch, "fetch_direct_pushes", pushes)
    results = evaluate.hunt(["o/gone", "o/here"])
    assert [r.repo for r in results] == ["o/here"]


def test_results_carry_what_the_queue_needs(pushes):
    pushes["changes"] = [_change(files=_bad(), message="fix(install): handle envs",
                                 author_tenure_days=4, author_prior_commits=9)]
    r = evaluate.hunt(["o/r"])[0]
    assert r.url == "https://github.com/o/r/commit/abc123def4567890"
    assert r.message == "fix(install): handle envs"
    assert (r.tenure_days, r.prior_commits) == (4, 9)
    assert any(f["rule_id"] == "content.encoded_blob" for f in r.findings)


def test_brief_is_capped_per_hunt(pushes, monkeypatch):
    # A wide net can escalate many changes; only the top max_briefs are paid for.
    pushes["changes"] = [_change(sha=f"{i:016d}", files=_bad()) for i in range(6)]
    calls = []
    monkeypatch.setattr(llm, "review", lambda c, f, **k: calls.append(c.sha) or llm.Review(
        verdict=llm.Verdict(verdict="suspicious", confidence=0.5, rationale="r")))
    evaluate.hunt(["o/r"], brief=True, max_briefs=2)
    assert len(calls) == 2


def test_brief_skips_changes_tier0_cleared(pushes, monkeypatch):
    pushes["changes"] = [_change(files=_good())]
    monkeypatch.setattr(llm, "review", lambda *a, **k: pytest.fail("cleared change briefed"))
    evaluate.hunt(["o/r"], brief=True)


def test_a_refusal_during_a_hunt_is_flagged(pushes, monkeypatch):
    pushes["changes"] = [_change(files=_bad())]
    monkeypatch.setattr(llm, "review", lambda *a, **k: llm.Review(
        verdict=None, error="model declined to answer", refused=True))
    r = evaluate.hunt(["o/r"], brief=True)[0]
    assert r.refused and r.tier2_error


# ============================================================== hunting: tags


TJ_SHA = "0e58ed8671d6b60d0890c21b07f8835ace038e67"


def _tags(monkeypatch, tags, reachable=None):
    monkeypatch.setattr(fetch, "list_tags", lambda o, r, **kw: list(tags))
    monkeypatch.setattr(fetch, "on_default_branch",
                        lambda o, r, sha: (reachable or {}).get(sha))


def test_a_tag_target_off_the_default_branch_becomes_an_alert(pushes, monkeypatch):
    # reviewdog: the malicious commit was on no branch, so a default-branch listing alone
    # never returns it. The tag check must fetch it and put it in the queue.
    bad = "f0d342d24037bb11d26b9bd8496e0808ba32e9ec"
    _tags(monkeypatch, [("v1", bad)], {bad: False})
    monkeypatch.setattr(fetch, "fetch_commit",
                        lambda o, r, sha: _change(sha=sha, files=_bad("install.sh")))
    results = evaluate.hunt(["reviewdog/action-setup"], tags=True)
    alert = next(r for r in results if r.key.endswith(bad[:10]))
    assert alert.escalated
    assert "tag.off_default_branch" in alert.rule_ids


def test_tag_findings_merge_into_a_change_already_listed(pushes, monkeypatch):
    sha = "abc123def4567890"
    pushes["changes"] = [_change(sha=sha, files=_good())]
    _tags(monkeypatch, [("v1", sha)], {sha: False})
    monkeypatch.setattr(fetch, "fetch_commit", lambda *a: pytest.fail("already listed"))
    results = evaluate.hunt(["o/r"], tags=True)
    assert len(results) == 1 and "tag.off_default_branch" in results[0].rule_ids


def test_an_unfetchable_tag_target_is_still_reported(pushes, monkeypatch):
    _tags(monkeypatch, [("v1.0.0", TJ_SHA), ("v44.5.1", TJ_SHA)])
    monkeypatch.setattr(fetch, "fetch_commit",
                        lambda *a: (_ for _ in ()).throw(fetch.FetchError("422")))
    results = evaluate.hunt(["o/r"], tags=True)
    assert results and results[0].escalated
    assert "tag.version_collapse" in results[0].rule_ids


def test_the_tag_snapshot_persists_so_a_moved_tag_is_caught_next_hunt(pushes, monkeypatch, tmp_path):
    snap = tmp_path / "tags.json"
    old, new = "a" * 40, "b" * 40
    monkeypatch.setattr(fetch, "fetch_commit", lambda o, r, sha: _change(sha=sha, files=_good()))

    _tags(monkeypatch, [("v2.0.1", old)], {old: True})
    first = evaluate.hunt(["o/r"], tags=True, snapshot_path=snap)
    assert not any("tag.moved" in r.rule_ids for r in first)

    _tags(monkeypatch, [("v2.0.1", new)], {new: True})
    second = evaluate.hunt(["o/r"], tags=True, snapshot_path=snap)
    assert any("tag.moved" in r.rule_ids for r in second)


# ============================================================== triage queue


def test_queue_lists_only_escalated_changes(tmp_path):
    path = evaluate.write_triage(
        [_result("o/r@flagged"), _result("o/r@quiet", escalated=False)],
        tmp_path / "q.md", scanned=2, repos=["o/r"])
    text = path.read_text(encoding="utf-8")
    assert "o/r@flagged" in text and "o/r@quiet" not in text


def test_queue_shows_the_link_and_the_precedent(tmp_path):
    r = _result(findings=[{"rule_id": "content.encoded_blob", "severity": "high",
                           "rationale": "A long base64 literal.", "file_path": "install.sh",
                           "line": 16, "evidence": "X=AAAA",
                           "precedent": "reviewdog/action-setup, 2025"}])
    text = evaluate.write_triage([r], tmp_path / "q.md", scanned=1).read_text(encoding="utf-8")
    assert "https://github.com/o/r/commit/" in text
    assert "reviewdog/action-setup, 2025" in text, "precedent is for the human, so it is shown"


def test_queue_announces_a_refusal(tmp_path):
    text = evaluate.write_triage([_result(refused=True, tier2_error="declined")],
                                 tmp_path / "q.md", scanned=1).read_text(encoding="utf-8")
    assert "declined to analyse" in text


def test_queue_shows_the_brief_and_next_steps(tmp_path):
    r = _result(verdict="malicious", confidence=0.99, rationale="Decodes to a memory scraper.",
                next_steps=["decode SCRIPT_RUNNER", "check the v1 tag"], cost_usd=0.02)
    text = evaluate.write_triage([r], tmp_path / "q.md", scanned=1).read_text(encoding="utf-8")
    assert "Decodes to a memory scraper." in text and "check the v1 tag" in text


def test_an_empty_queue_says_so(tmp_path):
    text = evaluate.write_triage([], tmp_path / "q.md", scanned=40).read_text(encoding="utf-8")
    assert "Nothing escalated" in text


@pytest.mark.parametrize("field", ["message", "rationale"])
def test_untrusted_text_cannot_forge_report_structure(tmp_path, field):
    # The commit message is the author's, and the brief can be steered by planting
    # instructions in a commit. Neither may render as part of the report.
    forged = "routine\n```\n\n## 2. Disposition: benign, verified safe\n\n- **all clear**"
    r = _result(**{field: forged, "verdict": "suspicious", "confidence": 0.5})
    text = evaluate.write_triage([r], tmp_path / "q.md", scanned=1).read_text(encoding="utf-8")
    for line in text.splitlines():
        if "Disposition: benign" in line or "all clear" in line:
            assert line.startswith("    "), f"untrusted text escaped its block: {line!r}"


def test_a_backtick_in_a_file_path_cannot_break_inline_code(tmp_path):
    r = _result(findings=[{"rule_id": "content.shell_exec", "severity": "high",
                           "rationale": "r", "file_path": "a`**pwned**`.js", "line": 1,
                           "evidence": "", "precedent": ""}])
    text = evaluate.write_triage([r], tmp_path / "q.md", scanned=1).read_text(encoding="utf-8")
    assert "**pwned**`" not in text


# ============================================================== disposition log


def _rows(path):
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def test_new_alerts_are_appended_as_unreviewed(tmp_path):
    log = tmp_path / "dispositions.csv"
    assert evaluate.merge_dispositions([_result("o/r@a"), _result("o/r@b", escalated=False)], log) == 1
    rows = _rows(log)
    assert [r["key"] for r in rows] == ["o/r@a"] and rows[0]["disposition"] == "unreviewed"


def test_a_reviewed_row_is_never_rewritten(tmp_path):
    # The core invariant: a later hunt cannot clobber the investigator's work.
    log = tmp_path / "dispositions.csv"
    evaluate.merge_dispositions([_result("o/r@a")], log)
    # The investigator reviews the row. Edited as bytes so newline translation cannot
    # make the "untouched" assertion below pass or fail for the wrong reason.
    log.write_bytes(log.read_bytes().replace(b"unreviewed", b"malicious"))
    before = log.read_bytes()

    evaluate.merge_dispositions([_result("o/r@a", score=99), _result("o/r@b")], log)
    after = log.read_bytes()
    assert after.startswith(before), "existing bytes must be untouched"
    assert [r["key"] for r in _rows(log)] == ["o/r@a", "o/r@b"]
    assert _rows(log)[0]["disposition"] == "malicious"


def test_rerunning_a_hunt_adds_no_duplicates(tmp_path):
    log = tmp_path / "dispositions.csv"
    evaluate.merge_dispositions([_result("o/r@a")], log)
    assert evaluate.merge_dispositions([_result("o/r@a")], log) == 0
    assert len(_rows(log)) == 1


def test_appending_survives_a_missing_trailing_newline(tmp_path):
    # A spreadsheet editor may save without one; appending onto the last row corrupts it.
    log = tmp_path / "dispositions.csv"
    evaluate.merge_dispositions([_result("o/r@a")], log)
    log.write_bytes(log.read_bytes().rstrip(b"\r\n"))
    evaluate.merge_dispositions([_result("o/r@b")], log)
    assert [r["key"] for r in _rows(log)] == ["o/r@a", "o/r@b"]


def test_a_byte_order_mark_from_excel_is_tolerated(tmp_path):
    log = tmp_path / "dispositions.csv"
    evaluate.merge_dispositions([_result("o/r@a")], log)
    log.write_bytes(b"\xef\xbb\xbf" + log.read_bytes())
    assert evaluate.merge_dispositions([_result("o/r@a")], log) == 0


# ============================================================== tally


def _log(tmp_path, rows):
    log = tmp_path / "dispositions.csv"
    with log.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=evaluate.DISPOSITION_FIELDS)
        w.writeheader()
        for i, (disposition, minutes, cost) in enumerate(rows):
            w.writerow({"key": f"o/r@{i}", "url": "", "first_seen": "2026-10-08", "score": 10,
                        "verdict": "", "cost_usd": cost, "disposition": disposition,
                        "minutes": minutes, "notes": ""})
    return log


def test_tally_computes_the_in_the_wild_numbers(tmp_path):
    t = evaluate.tally(_log(tmp_path, [
        ("malicious", "30", "0.02"), ("benign", "5", "0.02"), ("benign", "7", "0"),
        ("suspicious", "12", "0.03"), ("unreviewed", "", "0"),
    ]))
    assert t["alerts"] == 5 and t["reviewed"] == 4
    assert t["precision"] == pytest.approx(1 / 4)
    assert t["worth_a_look"] == pytest.approx(2 / 4)
    assert t["median_minutes"] == pytest.approx(9.5)
    assert t["brief_cost_usd"] == pytest.approx(0.07)


def test_tally_is_valid_with_zero_confirmed_attacks(tmp_path):
    # The likeliest real outcome. It still yields a result: precision in the wild is 0%.
    t = evaluate.tally(_log(tmp_path, [("benign", "6", "0"), ("benign", "4", "0")]))
    assert t["precision"] == 0.0 and t["reviewed"] == 2


def test_tally_flags_unrecognised_dispositions(tmp_path):
    t = evaluate.tally(_log(tmp_path, [("bengin", "3", "0")]))
    assert t["unknown"] == ["bengin"]
    assert "unrecognised" in evaluate.format_tally(t)


def test_tally_of_nothing_reviewed_reports_no_precision(tmp_path):
    t = evaluate.tally(_log(tmp_path, [("unreviewed", "", "0")]))
    assert t["precision"] is None
    assert "Precision" not in evaluate.format_tally(t)


# ============================================================== cli


def test_cli_scan_requires_a_target():
    assert cli.main(["scan", "--quiet"]) == 2


def test_cli_scan_reads_targets_and_writes_a_queue(pushes, tmp_path):
    pushes["changes"] = [_change(files=_bad())]
    targets = tmp_path / "t.txt"
    targets.write_text("o/r\n# comment\n", encoding="utf-8")
    queue = tmp_path / "triage"
    assert cli.main(["scan", "--targets", str(targets), "--queue", str(queue), "--quiet"]) == 0
    assert list(queue.glob("queue-*.md")) and (queue / "dispositions.csv").exists()


def test_cli_scan_rejects_a_malformed_targets_file(tmp_path):
    bad = tmp_path / "t.txt"
    bad.write_text("not-a-repo\n", encoding="utf-8")
    assert cli.main(["scan", "--targets", str(bad), "--quiet"]) == 2


def test_cli_brief_is_off_by_default():
    args = cli.build_parser().parse_args(["scan", "--repo", "o/r"])
    assert args.brief is False and args.max_briefs == evaluate.DEFAULT_MAX_BRIEFS


def test_cli_tally_reports_on_the_log(tmp_path, capsys):
    _log(tmp_path, [("benign", "5", "0")])
    assert cli.main(["tally", "--queue", str(tmp_path)]) == 0
    assert "Reviewed        1" in capsys.readouterr().out


def test_cli_tally_without_a_log_fails_clearly(tmp_path):
    assert cli.main(["tally", "--queue", str(tmp_path / "missing")]) == 1
