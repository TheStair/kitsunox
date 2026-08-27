"""Tier 0 heuristics — USER-OWNED. xfail(strict): flips to failure once implemented."""

from __future__ import annotations

import pytest

from kitsunox.analysis.tier0 import heuristics
from kitsunox.ir import ChangeType, Ecosystem, FileDiff, PackageRef, VersionMeta

# `shannon_entropy` is a provided helper (test runs normally). Everything that calls
# `heuristics.check()` is USER-OWNED and xfail(strict) until implemented.
_needs_impl = pytest.mark.xfail(reason="USER-OWNED: implement heuristics.check()", strict=True)


def _meta(*, scripts=None, deps=None, size=None) -> VersionMeta:
    return VersionMeta(
        ref=PackageRef(ecosystem=Ecosystem.NPM, name="demo"),
        version="1.1.0",
        install_scripts=scripts or {},
        dependencies=deps or {},
        unpacked_size=size,
    )


def test_shannon_entropy_helper_sane():
    assert heuristics.shannon_entropy(b"") == 0.0
    assert heuristics.shannon_entropy(b"aaaaaaaa") < 0.01
    assert heuristics.shannon_entropy(bytes(range(256))) > 7.9


@_needs_impl
def test_new_install_script_where_none_existed():
    prev = _meta(scripts={})
    cur = _meta(scripts={"postinstall": "node ./x.js"})
    findings = heuristics.check([], prev, cur)
    assert heuristics.RULE_NEW_INSTALL_SCRIPT in {f.rule_id for f in findings}


@_needs_impl
def test_new_binary_blob_added():
    diff = FileDiff(path="bin/helper.node", change_type=ChangeType.ADDED, is_binary=True, size_after=2048)
    findings = heuristics.check([diff], _meta(), _meta())
    assert heuristics.RULE_NEW_BINARY in {f.rule_id for f in findings}


@_needs_impl
def test_nonregistry_dependency_spec():
    cur = _meta(deps={"leftpad": "git+https://github.com/evil/leftpad.git"})
    findings = heuristics.check([], _meta(), cur)
    assert heuristics.RULE_NONREGISTRY_DEP in {f.rule_id for f in findings}


@_needs_impl
def test_clean_diff_no_findings():
    diff = FileDiff(path="README.md", change_type=ChangeType.MODIFIED, is_binary=False,
                    size_before=100, size_after=120, hunks="+ a line\n")
    assert heuristics.check([diff], _meta(), _meta()) == []
