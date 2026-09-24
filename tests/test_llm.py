"""llm.py — Tier 2 escalation.

No API calls are made anywhere in this file. `review()` is exercised against a fake
client, and every other function is pure. A test here must never cost money.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kitsunox import llm, rules
from kitsunox.model import Change, FileDiff, Finding


def _file(path: str, patch: str = "", **kw) -> FileDiff:
    kw.setdefault("change_type", "modified")
    kw.setdefault("is_binary", False)
    return FileDiff(path=path, patch=patch, **kw)


def _change(files: list[FileDiff], **kw) -> Change:
    defaults = dict(repo="o/r", source="push", sha="abc", author="alice", committed_at=None)
    defaults.update(kw)
    return Change(files=files, **defaults)


def _finding(rule_id="content.encoded_blob", **kw) -> Finding:
    defaults = dict(severity="high", rationale="because", file_path="a.js", line=None, evidence="")
    defaults.update(kw)
    return Finding(rule_id=rule_id, **defaults)


class FakeUsage:
    def __init__(self, i=100, o=50, c=0):
        self.input_tokens, self.output_tokens, self.cache_read_input_tokens = i, o, c


class FakeResponse:
    def __init__(self, parsed=None, stop_reason="end_turn", usage=None):
        self.parsed_output = parsed
        self.stop_reason = stop_reason
        self.usage = usage or FakeUsage()


class FakeClient:
    """Records the request and returns a canned response. Never touches the network."""

    def __init__(self, response=None, raises=None):
        self._response = response or FakeResponse(
            llm.Verdict(verdict="malicious", confidence=0.9, rationale="r")
        )
        self._raises = raises
        self.calls: list[dict] = []
        self.messages = self

    def parse(self, **kwargs):
        self.calls.append(kwargs)
        if self._raises:
            raise self._raises
        return self._response


# ============================================================== verdict schema


def test_verdict_rejects_out_of_range_confidence():
    with pytest.raises(ValidationError):
        llm.Verdict(verdict="benign", confidence=1.5, rationale="r")


def test_verdict_rejects_an_unknown_label():
    with pytest.raises(ValidationError):
        llm.Verdict(verdict="probably-fine", confidence=0.5, rationale="r")


def test_verdict_decisive_files_defaults_to_empty():
    assert llm.Verdict(verdict="benign", confidence=0.5, rationale="r").decisive_files == []


# ============================================================== cost accounting


def test_cost_uses_the_configured_rates():
    usage = llm.Usage(input_tokens=1_000_000, output_tokens=1_000_000)
    assert usage.cost_usd == pytest.approx(llm.INPUT_COST_PER_MTOK + llm.OUTPUT_COST_PER_MTOK)


def test_cached_input_is_billed_at_a_tenth():
    cached = llm.Usage(input_tokens=0, cache_read_tokens=1_000_000)
    uncached = llm.Usage(input_tokens=1_000_000)
    assert cached.cost_usd == pytest.approx(uncached.cost_usd * 0.1)


def test_zero_usage_costs_nothing():
    assert llm.Usage().cost_usd == 0.0


# ============================================================== prompt construction


def test_prompt_never_reveals_the_ground_truth_label():
    # Tier 2 is being measured against this label; telling it the answer would make the
    # whole §7 evaluation meaningless.
    change = _change([_file("a.js", "@@ -1,0 +1,1 @@\n+bad()")], ground_truth="malicious")
    prompt = llm.build_prompt(change, [_finding(line=1)])
    assert "malicious" not in prompt.lower().split("flagged")[0]
    assert "ground_truth" not in prompt


def test_prompt_includes_the_rule_rationales():
    prompt = llm.build_prompt(
        _change([_file("a.js", "@@ -1,0 +1,1 @@\n+x")]),
        [_finding(rule_id="content.shell_exec", rationale="runs a shell", line=1)],
    )
    assert "content.shell_exec" in prompt and "runs a shell" in prompt


def test_prompt_reports_author_tenure_when_known():
    prompt = llm.build_prompt(
        _change([_file("a.js")], author_tenure_days=4, author_prior_commits=9),
        [_finding(file_path=None)],
    )
    assert "4 day(s)" in prompt and "9 prior commit" in prompt


def test_prompt_omits_review_fields_for_a_push():
    prompt = llm.build_prompt(_change([_file("a.js")]), [_finding(file_path=None)])
    assert "Approving reviews" not in prompt
    assert "direct push" in prompt


def test_prompt_includes_review_fields_for_a_pr():
    prompt = llm.build_prompt(
        _change([_file("a.js")], source="pr", pr_number=7, merged_by="bob", approving_review_count=2),
        [_finding(file_path=None)],
    )
    assert "#7" in prompt and "Approving reviews: 2" in prompt and "Merged by: bob" in prompt


def test_prompt_dedupes_repeated_rule_hits():
    hits = [_finding(line=1) for _ in range(30)]
    prompt = llm.build_prompt(_change([_file("a.js", "@@ -1,0 +1,1 @@\n+x")]), hits)
    assert prompt.count("content.encoded_blob") == 1


def test_prompt_is_truncated_with_an_explicit_warning(monkeypatch):
    monkeypatch.setattr(llm, "MAX_EVIDENCE_CHARS", 200)
    patch = "@@ -1,0 +1,400 @@\n" + "\n".join(f"+line {i} of filler" for i in range(400))
    # Flag lines throughout the file, so the extracted evidence genuinely exceeds the cap.
    hits = [_finding(rule_id=f"content.r{i}", file_path="big.js", line=i) for i in range(1, 400, 7)]
    prompt = llm.build_prompt(_change([_file("big.js", patch)]), hits)
    assert "truncated" in prompt
    # The model must be told to prefer 'suspicious' over guessing past a truncation.
    assert "suspicious" in prompt


def test_prompt_handles_a_change_with_no_extractable_diff():
    prompt = llm.build_prompt(_change([]), [_finding(file_path=None)])
    assert "judge on the metadata" in prompt


# ============================================================== hunk extraction


def test_only_flagged_regions_are_sent_not_the_whole_file():
    patch = "@@ -1,0 +1,200 @@\n" + "\n".join(f"+line{i}" for i in range(200))
    blocks = llm._hunks_for(_change([_file("a.js", patch)]), [_finding(file_path="a.js", line=100)])
    body = "\n".join(blocks)
    assert "line99" in body  # the flagged line, with context around it
    assert "line5" not in body  # ...but not the rest of the file
    assert len(body) < len(patch) / 5


def test_gaps_between_flagged_regions_are_marked():
    patch = "@@ -1,0 +1,60 @@\n" + "\n".join(f"+line{i}" for i in range(60))
    change = _change([_file("a.js", patch)])
    blocks = llm._hunks_for(change, [_finding(file_path="a.js", line=2), _finding(file_path="a.js", line=50)])
    assert "..." in "\n".join(blocks)


def test_binary_files_are_named_not_dumped():
    change = _change([_file("blob.bin", change_type="added", is_binary=True)])
    body = "\n".join(llm._hunks_for(change, [_finding(file_path="blob.bin")]))
    assert "binary file" in body and "contents not shown" in body


def test_path_only_findings_fall_back_to_the_head_of_the_patch():
    patch = "@@ -1,0 +1,50 @@\n" + "\n".join(f"+line{i}" for i in range(50))
    body = "\n".join(llm._hunks_for(_change([_file("a.js", patch)]), [_finding(file_path="a.js", line=None)]))
    assert "line0" in body and "line49" not in body


def test_findings_for_files_absent_from_the_change_are_skipped():
    assert llm._hunks_for(_change([_file("a.js")]), [_finding(file_path="ghost.js")]) == []


# ============================================================== review()


def test_review_returns_a_parsed_verdict_and_usage():
    client = FakeClient(
        FakeResponse(
            llm.Verdict(verdict="malicious", confidence=0.95, rationale="exfiltrates a token"),
            usage=FakeUsage(i=1000, o=200, c=500),
        )
    )
    result = llm.review(_change([_file("a.js")]), [_finding(file_path=None)], client=client)

    assert result.ok and result.verdict.verdict == "malicious"
    assert result.usage.input_tokens == 1000 and result.usage.cache_read_tokens == 500
    assert result.usage.cost_usd > 0
    assert result.error is None


def test_review_sends_the_configured_model_and_schema():
    client = FakeClient()
    llm.review(_change([_file("a.js")]), [_finding(file_path=None)], client=client)
    call = client.calls[0]
    assert call["model"] == llm.MODEL
    assert call["output_format"] is llm.Verdict
    assert call["max_tokens"] == llm.MAX_TOKENS


def test_review_caches_the_system_prompt():
    # The system prompt is byte-identical on every change in an evaluation run, so the
    # breakpoint is what keeps the per-call cost down across ~100 escalations.
    client = FakeClient()
    llm.review(_change([_file("a.js")]), [_finding(file_path=None)], client=client)
    assert client.calls[0]["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_review_makes_exactly_one_call():
    client = FakeClient()
    llm.review(_change([_file("a.js")]), [_finding(file_path=None)], client=client)
    assert len(client.calls) == 1


def test_review_reports_a_refusal_as_an_error_not_a_verdict():
    client = FakeClient(FakeResponse(parsed=None, stop_reason="refusal"))
    result = llm.review(_change([_file("a.js")]), [_finding(file_path=None)], client=client)
    assert not result.ok and "declined" in result.error


def test_review_reports_an_unparseable_response_as_an_error():
    client = FakeClient(FakeResponse(parsed=None))
    result = llm.review(_change([_file("a.js")]), [_finding(file_path=None)], client=client)
    assert not result.ok and "schema" in result.error


def test_a_failed_review_is_distinguishable_from_a_benign_one():
    # If a failure read as benign, §7 would silently score API errors as clean changes.
    failed = llm.review(_change([_file("a.js")]), [_finding(file_path=None)],
                        client=FakeClient(FakeResponse(parsed=None)))
    benign = llm.review(_change([_file("a.js")]), [_finding(file_path=None)],
                        client=FakeClient(FakeResponse(
                            llm.Verdict(verdict="benign", confidence=0.9, rationale="fine"))))
    assert not failed.ok
    assert benign.ok and benign.verdict.verdict == "benign"


def test_review_captures_api_errors_rather_than_raising():
    # One bad call must not abort an evaluation run partway through.
    import anthropic

    client = FakeClient(raises=anthropic.APIConnectionError(request=None))
    result = llm.review(_change([_file("a.js")]), [_finding(file_path=None)], client=client)
    assert not result.ok and "connection error" in result.error


def test_review_reports_missing_credentials_instead_of_raising(monkeypatch):
    # Credential resolution is the SDK's job (env var, auth token, OAuth profile, WIF),
    # so this must not check one variable -- it must report what the SDK could not do.
    import anthropic

    def no_creds():
        raise anthropic.AnthropicError("could not resolve authentication")

    monkeypatch.setattr(anthropic, "Anthropic", no_creds)
    result = llm.review(_change([_file("a.js")]), [_finding(file_path=None)])
    assert not result.ok
    assert "credentials" in result.error
    assert result.prompt, "the prompt should still be built so it can be inspected offline"


def test_review_uses_sdk_credential_resolution_not_a_single_env_var(monkeypatch):
    # A machine with ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile and no
    # ANTHROPIC_API_KEY is properly authenticated; refusing there would be wrong.
    import anthropic

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(anthropic, "Anthropic", lambda: FakeClient())
    result = llm.review(_change([_file("a.js")]), [_finding(file_path=None)])
    assert result.ok


def test_review_keeps_the_prompt_on_the_result():
    client = FakeClient()
    result = llm.review(_change([_file("a.js")]), [_finding(file_path=None)], client=client)
    assert result.prompt == client.calls[0]["messages"][0]["content"]


# ============================================================== integration (offline)


def test_a_real_incident_produces_a_bounded_prompt():
    from kitsunox.incidents import INCIDENTS_BY_KEY, load_incident

    change = load_incident(INCIDENTS_BY_KEY["tj-actions"])  # fixture-backed, no network
    findings = rules.scan(change)
    prompt = llm.build_prompt(change, findings)

    full_diff = sum(len(f.patch) for f in change.files)
    assert len(prompt) < full_diff, "Tier 2 must send less than the whole diff"
    assert len(prompt) <= llm.MAX_EVIDENCE_CHARS + 4000
    assert "dist/index.js" in prompt


# ============================================================== recognition ablation

# Every ground-truth incident is a famous public attack. The first Tier 2 run cited
# CVE-2024-3094 by number, so verdicts were partly recall rather than reasoning.
# Withholding the two identifier fields measures how much.


def test_anonymize_withholds_repository_and_author():
    change = _change([_file("a.js", "@@ -1,0 +1,1 @@\n+x")], repo="tukaani-project/xz", author="JiaT75")
    prompt = llm.build_prompt(change, [_finding(line=1)], anonymize=True)
    assert "tukaani-project" not in prompt and "JiaT75" not in prompt
    assert "<redacted>" in prompt


def test_anonymize_withholds_the_merger_too():
    change = _change([_file("a.js")], source="pr", pr_number=1, merged_by="someone", author="bob")
    prompt = llm.build_prompt(change, [_finding(file_path=None)], anonymize=True)
    assert "someone" not in prompt and "bob" not in prompt


def test_anonymize_keeps_the_evidence_and_the_tenure_numbers():
    # Redacting the evidence would not be a control, it would be a different experiment.
    # Tenure is a measured signal, not an identifier, so it stays.
    change = _change(
        [_file("tests/files/bad-3-corrupt_lzma2.xz", change_type="added", is_binary=True)],
        repo="tukaani-project/xz", author="JiaT75",
        author_tenure_days=756, author_prior_commits=431,
    )
    prompt = llm.build_prompt(change, [_finding(file_path="tests/files/bad-3-corrupt_lzma2.xz")],
                              anonymize=True)
    assert "bad-3-corrupt_lzma2.xz" in prompt
    assert "756 day(s)" in prompt and "431 prior commit" in prompt


def test_identified_prompts_are_the_default():
    change = _change([_file("a.js")], repo="o/r", author="alice")
    assert "o/r" in llm.build_prompt(change, [_finding(file_path=None)])


def test_review_passes_anonymize_through_to_the_prompt():
    client = FakeClient()
    llm.review(_change([_file("a.js")], repo="tukaani-project/xz"), [_finding(file_path=None)],
               client=client, anonymize=True)
    assert "tukaani-project" not in client.calls[0]["messages"][0]["content"]
