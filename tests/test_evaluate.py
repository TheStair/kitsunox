"""evaluate.py and cli.py — orchestration.

No network and no API spend: `fetch` and `llm` are stubbed throughout. The single most
important property here is that Tier 2 never runs unless asked.
"""

from __future__ import annotations

import json

import pytest

from kitsunox import cli, evaluate, fetch, llm, rules
from kitsunox.model import Change, FileDiff


def _change(repo="o/r", sha="abc123def4", files=None, **kw) -> Change:
    defaults = dict(source="push", author="alice", committed_at=None)
    defaults.update(kw)
    return Change(repo=repo, sha=sha, files=files or [], **defaults)


def _malicious_files() -> list[FileDiff]:
    """A diff that trips Tier 0 hard enough to escalate."""
    blob = "A" * 220
    return [
        FileDiff(
            path="install.sh", change_type="modified", is_binary=False,
            patch=f'@@ -1,0 +1,2 @@\n+X="{blob}"\n+curl https://gist.githubusercontent.com/x',
        )
    ]


def _benign_files() -> list[FileDiff]:
    return [
        FileDiff(path="README.md", change_type="modified", is_binary=False,
                 patch="@@ -1,0 +1,1 @@\n+Some documentation.")
    ]


# ============================================================== detected semantics


def test_without_tier2_detection_follows_tier0_escalation():
    hit = evaluate.ChangeResult(key="k", repo="o/r", source="push", ground_truth="malicious",
                                evidence_score=20, total_score=20, escalated=True)
    miss = evaluate.ChangeResult(key="k", repo="o/r", source="push", ground_truth="malicious",
                                 evidence_score=1, total_score=1, escalated=False)
    assert hit.detected is True and miss.detected is False


@pytest.mark.parametrize(
    "verdict,expected",
    [("malicious", True), ("suspicious", True), ("benign", False)],
)
def test_with_tier2_the_verdict_decides(verdict, expected):
    result = evaluate.ChangeResult(key="k", repo="o/r", source="push", ground_truth="malicious",
                                   evidence_score=20, total_score=20, escalated=True, verdict=verdict)
    assert result.detected is expected


def test_a_failed_tier2_call_is_unknowable_not_clean():
    # Counting an API error as "not detected" would understate the detection rate;
    # counting it as detected would inflate it. Neither is honest.
    result = evaluate.ChangeResult(key="k", repo="o/r", source="push", ground_truth="malicious",
                                   evidence_score=20, total_score=20, escalated=True,
                                   tier2_error="500: boom")
    assert result.detected is None


def test_rates_exclude_unknowable_results():
    report = evaluate.Report(
        incidents=[
            evaluate.ChangeResult(key="a", repo="r", source="push", ground_truth="malicious",
                                  evidence_score=20, total_score=20, escalated=True, verdict="malicious"),
            evaluate.ChangeResult(key="b", repo="r", source="push", ground_truth="malicious",
                                  evidence_score=20, total_score=20, escalated=True,
                                  tier2_error="timeout"),
        ]
    )
    assert report.detection_rate == (1, 1), "the errored change must leave the denominator"
    assert len(report.errors) == 1


# ============================================================== tier 2 gating


def test_tier2_is_not_called_when_disabled(monkeypatch):
    called = []
    monkeypatch.setattr(llm, "review", lambda *a, **k: called.append(1))
    evaluate._run_one(_change(files=_malicious_files()), threshold=8, tier2=False)
    assert called == []


def test_tier2_is_not_called_for_a_change_below_threshold(monkeypatch):
    called = []
    monkeypatch.setattr(llm, "review", lambda *a, **k: called.append(1))
    result = evaluate._run_one(_change(files=_benign_files()), threshold=8, tier2=True)
    assert not result.escalated
    assert called == [], "paying for a change Tier 0 cleared defeats the whole funnel"


def test_tier2_runs_and_records_cost_when_escalated(monkeypatch):
    review = llm.Review(
        verdict=llm.Verdict(verdict="malicious", confidence=0.9, rationale="exfil"),
        usage=llm.Usage(input_tokens=1000, output_tokens=100),
    )
    monkeypatch.setattr(llm, "review", lambda *a, **k: review)
    result = evaluate._run_one(_change(files=_malicious_files()), threshold=8, tier2=True)

    assert result.escalated and result.verdict == "malicious"
    assert result.confidence == 0.9 and result.rationale == "exfil"
    assert result.cost_usd > 0 and result.input_tokens == 1000


def test_tier2_failure_is_recorded_not_raised(monkeypatch):
    monkeypatch.setattr(llm, "review", lambda *a, **k: llm.Review(verdict=None, error="503"))
    result = evaluate._run_one(_change(files=_malicious_files()), threshold=8, tier2=True)
    assert result.tier2_error == "503" and result.verdict is None


def test_threshold_is_honoured():
    files = _malicious_files()
    assert evaluate._run_one(_change(files=files), threshold=1, tier2=False).escalated
    assert not evaluate._run_one(_change(files=files), threshold=9999, tier2=False).escalated


# ============================================================== run scoping


def test_incidents_only_skips_the_control_fetch(monkeypatch):
    monkeypatch.setattr(
        evaluate, "load_control",
        lambda *a, **k: pytest.fail("control sample must not be fetched"),
    )
    monkeypatch.setattr(evaluate, "INCIDENTS", [])
    report = evaluate.evaluate(incidents=True, control=False)
    assert report.control == []


def test_control_only_skips_loading_incidents(monkeypatch):
    monkeypatch.setattr(
        evaluate, "load_incident",
        lambda *a, **k: pytest.fail("incidents must not be loaded"),
    )
    monkeypatch.setattr(evaluate, "load_control", lambda *a, **k: [])
    report = evaluate.evaluate(incidents=False, control=True)
    assert report.incidents == []


def test_control_changes_are_labelled_benign(monkeypatch):
    monkeypatch.setattr(fetch, "fetch_merged_prs", lambda o, r, n: [_change(source="pr", pr_number=1)])
    monkeypatch.setattr(fetch, "fetch_direct_pushes", lambda o, r, n: [_change()])
    changes = evaluate.load_control(["o/r"], prs_per_repo=1, pushes_per_repo=1)
    assert len(changes) == 2
    assert all(c.ground_truth == "benign" for c in changes)


def test_control_sample_includes_both_prs_and_pushes(monkeypatch):
    # All five incidents are pushes; a PR-only control cannot trigger the push rules.
    monkeypatch.setattr(fetch, "fetch_merged_prs", lambda o, r, n: [_change(source="pr", pr_number=1)])
    monkeypatch.setattr(fetch, "fetch_direct_pushes", lambda o, r, n: [_change(source="push")])
    assert {c.source for c in evaluate.load_control(["o/r"], prs_per_repo=1, pushes_per_repo=1)} == {"pr", "push"}


def test_a_failing_repo_does_not_abort_the_control_fetch(monkeypatch):
    def flaky(owner, repo, n):
        if repo == "bad":
            raise fetch.FetchError("404")
        return [_change(repo=f"{owner}/{repo}")]

    monkeypatch.setattr(fetch, "fetch_merged_prs", flaky)
    monkeypatch.setattr(fetch, "fetch_direct_pushes", lambda o, r, n: [])
    changes = evaluate.load_control(["o/bad", "o/good"], prs_per_repo=1, pushes_per_repo=0)
    assert [c.repo for c in changes] == ["o/good"]


def test_zero_counts_skip_that_half_entirely(monkeypatch):
    monkeypatch.setattr(fetch, "fetch_merged_prs", lambda *a: pytest.fail("should not fetch PRs"))
    monkeypatch.setattr(fetch, "fetch_direct_pushes", lambda o, r, n: [_change()])
    assert len(evaluate.load_control(["o/r"], prs_per_repo=0, pushes_per_repo=1)) == 1


# ============================================================== reporting


def test_summary_states_when_tier2_did_not_run():
    report = evaluate.Report(tier2_ran=False)
    assert "not run" in evaluate.format_summary(report)


def test_summary_reports_both_rates():
    report = evaluate.Report(
        incidents=[evaluate.ChangeResult(key="xz", repo="r", source="push", ground_truth="malicious",
                                         evidence_score=8, total_score=8, escalated=True)],
        control=[evaluate.ChangeResult(key="c", repo="r", source="pr", ground_truth="benign",
                                       evidence_score=0, total_score=0, escalated=False)],
    )
    text = evaluate.format_summary(report)
    assert "1/1 incidents" in text and "0/1 benign" in text


def test_report_json_round_trips(tmp_path):
    report = evaluate.Report(
        incidents=[evaluate.ChangeResult(key="xz", repo="r", source="push", ground_truth="malicious",
                                         evidence_score=8, total_score=8, escalated=True,
                                         rule_ids=["content.binary_added"])],
    )
    path = evaluate.write_report(report, tmp_path / "sub" / "report.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["summary"]["detection"] == {"detected": 1, "of": 1}
    assert payload["incidents"][0]["rule_ids"] == ["content.binary_added"]
    assert payload["tier2_ran"] is False


def test_cost_totals_across_every_change():
    report = evaluate.Report(
        incidents=[evaluate.ChangeResult(key="a", repo="r", source="push", ground_truth="malicious",
                                         evidence_score=8, total_score=8, escalated=True, cost_usd=0.01)],
        control=[evaluate.ChangeResult(key="b", repo="r", source="pr", ground_truth="benign",
                                       evidence_score=8, total_score=8, escalated=True, cost_usd=0.02)],
    )
    assert report.total_cost_usd == pytest.approx(0.03)
    assert report.escalated_count == 2


# ============================================================== repo scan


def test_scan_ranks_by_total_score(monkeypatch):
    monkeypatch.setattr(
        fetch, "fetch_direct_pushes",
        lambda o, r, n: [_change(sha="quiet00001", files=_benign_files()),
                         _change(sha="loud000001", files=_malicious_files())],
    )
    ranked = evaluate.scan_repo("o", "r", 10)
    assert ranked[0].total_score >= ranked[-1].total_score
    assert "loud" in ranked[0].key


def test_scan_never_calls_tier2(monkeypatch):
    monkeypatch.setattr(fetch, "fetch_direct_pushes",
                        lambda o, r, n: [_change(files=_malicious_files())])
    monkeypatch.setattr(llm, "review", lambda *a, **k: pytest.fail("scan must not spend"))
    assert evaluate.scan_repo("o", "r", 10)


# ============================================================== cli


def test_cli_requires_a_subcommand():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_cli_tier2_is_off_by_default():
    args = cli.build_parser().parse_args(["evaluate"])
    assert args.tier2 is False, "spending must never be the default"


def test_cli_tier2_flag_opts_in():
    assert cli.build_parser().parse_args(["evaluate", "--tier2"]).tier2 is True


def test_cli_scope_flags_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["evaluate", "--incidents-only", "--control-only"])


def test_cli_check_requires_a_target():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["check", "--repo", "o/r"])


def test_cli_check_accepts_sha_or_pr():
    parser = cli.build_parser()
    assert parser.parse_args(["check", "--repo", "o/r", "--sha", "abc"]).sha == "abc"
    assert parser.parse_args(["check", "--repo", "o/r", "--pr", "7"]).pr == 7


def test_cli_repo_flag_is_repeatable():
    args = cli.build_parser().parse_args(["evaluate", "--repo", "a/b", "--repo", "c/d"])
    assert args.repo == ["a/b", "c/d"]


def test_cli_evaluate_passes_scope_through(monkeypatch):
    seen = {}

    def fake(**kwargs):
        seen.update(kwargs)
        return evaluate.Report()

    monkeypatch.setattr(evaluate, "evaluate", fake)
    assert cli.main(["evaluate", "--incidents-only", "--quiet"]) == 0
    assert seen["incidents"] is True and seen["control"] is False and seen["tier2"] is False


def test_cli_evaluate_writes_a_report_when_asked(monkeypatch, tmp_path):
    monkeypatch.setattr(evaluate, "evaluate", lambda **k: evaluate.Report())
    out = tmp_path / "r.json"
    assert cli.main(["evaluate", "--quiet", "--out", str(out)]) == 0
    assert out.is_file()


def test_cli_check_reports_a_fetch_failure_as_an_error_code(monkeypatch, capsys):
    monkeypatch.setattr(fetch, "fetch_commit",
                        lambda *a: (_ for _ in ()).throw(fetch.FetchError("422")))
    assert cli.main(["check", "--repo", "o/r", "--sha", "bad"]) == 1


def test_cli_check_prints_findings(monkeypatch, capsys):
    monkeypatch.setattr(fetch, "fetch_commit", lambda *a: _change(files=_malicious_files()))
    assert cli.main(["check", "--repo", "o/r", "--sha", "abc"]) == 0
    out = capsys.readouterr().out
    assert "escalates     True" in out and "content.encoded_blob" in out


def test_cli_scan_returns_an_error_when_nothing_found(monkeypatch):
    monkeypatch.setattr(fetch, "fetch_direct_pushes", lambda o, r, n: [])
    assert cli.main(["scan", "--repo", "o/r", "--quiet"]) == 1


def test_anonymize_reaches_llm_review(monkeypatch):
    seen = {}

    def fake_review(change, findings, *, anonymize=False, **kw):
        seen["anonymize"] = anonymize
        return llm.Review(verdict=llm.Verdict(verdict="benign", confidence=0.5, rationale="r"))

    monkeypatch.setattr(llm, "review", fake_review)
    evaluate._run_one(_change(files=_malicious_files()), threshold=8, tier2=True, anonymize=True)
    assert seen["anonymize"] is True


def test_cli_anonymize_is_off_by_default():
    assert cli.build_parser().parse_args(["evaluate"]).anonymize is False
    assert cli.build_parser().parse_args(["evaluate", "--anonymize"]).anonymize is True
