"""Stage 5 job selection: hooks from the tarball's own package.json, the entry rule, order, cap
and deferral, and the not-run and result-rejected findings."""

from __future__ import annotations

import json
import tarfile

import pytest

from conftest import TarEntry, make_tar_gz
from kitsunox.core.models import (
    Candidate,
    Change,
    EvidenceKind,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.sandbox.models import JobBundle
from kitsunox.sandbox.ossf import RESULT_TOO_LARGE
from kitsunox.sandbox.select import (
    BUNDLE_INCOMPLETE,
    BUNDLED,
    DEFAULT_CAP,
    INSTALL_FAILED,
    MAX_LISTED,
    NO_MANIFEST,
    NOT_CAPTURED,
    NOT_RUN,
    RESULT_REJECTED,
    UNEXTRACTABLE,
    Inspection,
    TarballInfo,
    deferred,
    inspect_tarball,
    manifest_hooks,
    priority,
    reported,
    select,
    tarball_hooks,
)

STAGE4 = (
    StageDecision(stage="triage", forwarded=True, reason="rules: x"),
    StageDecision(stage="correlate", forwarded=True, reason="score 5"),
)


def finding(rule_id: str, weight: float, severity: Severity = Severity.LOW) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=1,
        severity=severity,
        weight=weight,
        title="t",
        explanation="e",
    )


def candidate(
    name: str = "kx",
    version: str = "1.0.0",
    *,
    findings: tuple[Finding, ...] = (),
    history: tuple[StageDecision, ...] = STAGE4,
) -> Candidate:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
        publish=PublishInfo(),
        manifest={},  # never read: hooks come from the tarball
    )
    return Candidate(change=Change(new=snapshot), findings=findings, history=history)


def tarball(manifest: object, *extra: TarEntry, top: str = "package") -> bytes:
    raw = manifest if isinstance(manifest, bytes) else json.dumps(manifest).encode()
    return make_tar_gz([TarEntry(f"{top}/package.json", raw), *extra])


# --- hooks from the tarball -------------------------------------------------------------------


def test_manifest_hooks_in_npm_order_ignoring_empty_and_non_strings() -> None:
    scripts = {
        "postinstall": "node post.js",
        "test": "jest",
        "preinstall": "node pre.js",
        "install": "   ",
        "prepare": "tsc",
    }
    assert manifest_hooks({"scripts": scripts}, False) == ("preinstall", "postinstall")
    assert manifest_hooks({"scripts": {"install": 1, "postinstall": None}}, False) == ()
    assert manifest_hooks({"scripts": ["preinstall"]}, False) == ()
    assert manifest_hooks(["not", "a", "manifest"], True) == ()


def test_binding_gyp_is_an_implicit_install_hook_as_npm_normalises_it() -> None:
    assert manifest_hooks({}, True) == ("install",)
    assert manifest_hooks({"scripts": {"postinstall": "x"}}, True) == ("install", "postinstall")
    assert manifest_hooks({"scripts": {"preinstall": "x"}}, True) == ("preinstall",)
    assert manifest_hooks({"scripts": {"install": "make"}}, True) == ("install",)
    assert manifest_hooks({"gypfile": False}, True) == ()
    assert manifest_hooks({}, False) == ()


def test_tarball_hooks_read_the_tarballs_own_package_json() -> None:
    assert tarball_hooks(tarball({"scripts": {"preinstall": "node p.js"}})) == ("preinstall",)
    assert tarball_hooks(tarball({"name": "kx"})) == ()
    # npm strips whatever the top directory is called
    assert tarball_hooks(tarball({"scripts": {"install": "x"}}, top="kx-1.0.0")) == ("install",)
    gyp = tarball({"name": "kx"}, TarEntry("package/binding.gyp", b"{}"))
    assert tarball_hooks(gyp) == ("install",)
    nested_gyp = tarball({"name": "kx"}, TarEntry("package/src/binding.gyp", b"{}"))
    assert tarball_hooks(nested_gyp) == ()


def test_the_tarballs_own_name_is_read_when_it_is_an_npm_name() -> None:
    """Round-3 review: package-analysis's import phase requires the -package name, while npm
    installs a tarball under its package.json name; the name now comes from the tarball."""
    hooks = {"scripts": {"postinstall": "x"}}
    listed = frozenset({"package.json"})
    assert inspect_tarball(tarball({"name": "helper", **hooks})) == TarballInfo(
        ("postinstall",), "helper", listed
    )
    assert inspect_tarball(tarball({"name": "@scope/Legacy.Name_1", **hooks})) == TarballInfo(
        ("postinstall",), "@scope/Legacy.Name_1", listed
    )
    for odd in ("", "../x", "a b", ".x", 7, None, "x" * 215, "@s/", "a\nb", "é"):
        found = inspect_tarball(tarball({"name": odd, **hooks}))
        assert isinstance(found, TarballInfo) and found.name is None, odd
    assert inspect_tarball(b"not gzip") == UNEXTRACTABLE


def test_the_tarballs_file_list_is_every_regular_file_as_npm_unpacks_it() -> None:
    """The rules' `shipped`: every regular file's path, the top directory stripped, from the
    same pass that reads the manifest. Links and unsafe paths are skipped by the extractor,
    and only the manifest and binding.gyp are read."""
    body = tarball(
        {"name": "kx", "scripts": {"postinstall": "node install.js"}},
        TarEntry("package/install.js", b"x"),
        TarEntry("package/bin/tool", b"\x7fELF"),
        TarEntry("package/lib/", type=tarfile.DIRTYPE),
        TarEntry("package/link", type=tarfile.SYMTYPE, linkname="/etc/passwd"),
        TarEntry("package/../escape.js", b"x"),
        TarEntry("package/node_modules/dep/package.json", b"{}"),
    )
    found = inspect_tarball(body)
    assert isinstance(found, TarballInfo)
    assert found.files == {
        "package.json",
        "install.js",
        "bin/tool",
        "node_modules/dep/package.json",
    }


def test_the_last_package_json_in_the_archive_wins_as_when_extracting() -> None:
    body = make_tar_gz(
        [
            TarEntry("package/package.json", b'{"name": "kx"}'),
            TarEntry("package/package.json", b'{"scripts": {"preinstall": "node evil.js"}}'),
        ]
    )
    assert tarball_hooks(body) == ("preinstall",)


@pytest.mark.parametrize(
    "body",
    [
        tarball(b"{not json"),
        tarball(b"[" * 100_000 + b"]" * 100_000),  # deeper than the decoder's recursion limit
        tarball(["a", "list"]),
        tarball(b'"a string"'),
        make_tar_gz([TarEntry("package/index.js", b"module.exports = 1")]),
        make_tar_gz([TarEntry("package.json", b'{"scripts": {"preinstall": "x"}}')]),  # no top dir
        make_tar_gz(
            [TarEntry("package/package.json", type=tarfile.SYMTYPE, linkname="/etc/passwd")]
        ),
    ],
    ids=["invalid", "deep", "list", "string", "missing", "top-level", "symlink"],
)
def test_an_unreadable_manifest_is_a_reason_not_a_crash(body: bytes) -> None:
    assert tarball_hooks(body) == NO_MANIFEST


def test_an_oversize_manifest_is_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    from kitsunox.sandbox import select as select_module

    monkeypatch.setattr(select_module, "MAX_MANIFEST_BYTES", 10)
    assert tarball_hooks(tarball({"scripts": {"preinstall": "node p.js"}})) == NO_MANIFEST


def test_not_a_tarball_is_unextractable() -> None:
    assert tarball_hooks(b"not gzip at all") == UNEXTRACTABLE


# --- the entry rule, order and cap -------------------------------------------------------------


def test_reported_means_stage4_forwarded_last() -> None:
    assert reported(candidate())
    dropped = (StageDecision(stage="correlate", forwarded=False, reason="score 0"),)
    assert not reported(candidate(history=dropped))
    assert not reported(candidate(history=STAGE4[:1]))
    assert not reported(candidate(history=()))


def test_select_statuses_in_stage4_order() -> None:
    inspected: list[tuple[Candidate, Inspection]] = [
        (candidate("a"), ("postinstall",)),
        (candidate("b"), ()),
        (candidate("c"), NOT_CAPTURED),
        (candidate("d"), ("preinstall", "install")),
    ]
    entries = select(inspected)
    assert [(e.candidate.change.new.ref.name, e.status) for e in entries] == [
        ("a", "selected"),
        ("b", "no-hook"),
        ("c", "unchecked"),
        ("d", "selected"),
    ]
    assert entries[2].reason == NOT_CAPTURED
    assert entries[3].hooks == ("preinstall", "install")


def test_highest_score_first_then_the_sort_key_and_the_rest_deferred() -> None:
    low = candidate("low", findings=(finding("r", 1.0),))
    high = candidate("high", findings=(finding("r", 9.0),))
    tie_b = candidate("tie-b", findings=(finding("r", 4.0),))
    tie_a = candidate("tie-a", findings=(finding("r", 4.0),))
    hooks = ("postinstall",)
    entries = select([(low, hooks), (high, hooks), (tie_b, hooks), (tie_a, hooks)], cap=2)
    statuses = {e.candidate.change.new.ref.name: e.status for e in entries}
    assert statuses == {
        "high": "selected",
        "tie-a": "selected",
        "tie-b": "deferred",
        "low": "deferred",
    }
    assert priority(high) < priority(tie_a) < priority(tie_b) < priority(low)
    assert [e.status for e in select([(low, hooks)], cap=0)] == ["deferred"]


def test_cap_must_not_be_negative() -> None:
    with pytest.raises(ValueError, match="negative"):
        select([], cap=-1)
    assert DEFAULT_CAP > 0
    assert deferred(7) == "deferred: over the per-tick cap of 7"


# --- the findings -------------------------------------------------------------------------------


def test_not_run_is_info_weight_zero_with_the_reason_as_evidence() -> None:
    found = NOT_RUN.because(NOT_CAPTURED)
    assert found.rule_id == "sandbox.not-run"
    assert (found.severity, found.weight) == (Severity.INFO, 0.0)
    assert NOT_CAPTURED in found.explanation
    (evidence,) = found.evidence
    assert (evidence.kind, evidence.snippet) == (EvidenceKind.METADATA, NOT_CAPTURED)


def test_result_rejected_is_scored() -> None:
    found = RESULT_REJECTED.because("the result is not valid JSON")
    assert found.rule_id == "sandbox.result-rejected"
    assert (found.severity, found.weight) == (Severity.MEDIUM, 3.0)
    assert "not valid JSON" in found.explanation
    assert found.evidence[0].snippet == "the result is not valid JSON"


def test_a_result_too_large_is_rejected_at_high() -> None:
    """Round-3 review: inflating one's own record past the size cap traded a CRITICAL for a
    MEDIUM 3. It is HIGH 5 now."""
    found = RESULT_REJECTED.because(RESULT_TOO_LARGE)
    assert found.rule_id == "sandbox.result-rejected" and found.rule_version == 3
    assert (found.severity, found.weight) == (Severity.HIGH, 5.0)
    assert found.evidence[0].snippet == "result too large"
    assert "inflates its own record" in found.explanation


def test_install_failed_is_info_and_names_the_airgap_as_the_likely_cause() -> None:
    failed = INSTALL_FAILED.because()
    assert (failed.rule_id, failed.rule_version) == ("sandbox.install-failed", 2)
    assert (failed.severity, failed.weight) == (Severity.INFO, 0.0)
    assert "airgapped" in failed.explanation and "registry dependencies" in failed.explanation
    assert failed.evidence[0].snippet == "install error_analysis (airgapped)"


def test_the_bundle_findings_say_what_was_analysed_and_never_score() -> None:
    names = tuple(f"dep{i:02d}" for i in range(MAX_LISTED + 2))
    bundle = JobBundle(
        format="kitsunox-npm-bundle/1",
        tar_sha256="a" * 64,
        dependencies_sha256="b" * 64,
        original_sha256="c" * 64,
        assumes={"npm": "11.12.1", "node": "24.15.0", "os": "linux", "cpu": "x64", "libc": "glibc"},
        added=12,
        dependencies=names,
        top_level=names,
        package_json_changes=("bundleDependencies", "dependencies"),
        supplied_by_package=1,
        skipped=2,
        predicted_network=1,
    )
    bundled = BUNDLED.because(bundle)
    assert (bundled.severity, bundled.weight) == (Severity.INFO, 0.0)
    text = bundled.explanation
    assert "not the registry tarball" in text and "linux/x64/glibc" in text
    assert "and 2 more" in text and "1 shipped by the package itself" in text
    assert "2 optional packages skipped" in text and "1 expected to need the network" in text
    assert "c" * 64 in text and "a" * 64 in text
    incomplete = BUNDLE_INCOMPLETE.because("over-cap: files")
    assert (incomplete.severity, incomplete.weight) == (Severity.INFO, 0.0)
    assert "Unresolved" not in incomplete.explanation
    assert incomplete.evidence[0].snippet == "over-cap: files"
