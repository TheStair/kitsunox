"""Stage 2 file rules on inert, hand-written snippets (patterns only, nothing runnable)."""

import pytest

from kitsunox.rules.static import RULES, EncodedBlob, Obfuscated
from kitsunox.stages.static import analyse

B64 = "QUJD" * 50 + "ZGVm0123XYZ" * 5  # >200 chars, mixed case and digits


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ('post("https://discord.com/api/webhooks/1/abc")', "static.exfil-endpoint"),
        ("fetch('https://api.telegram.org/botTOKEN/sendMessage')", "static.exfil-endpoint"),
        ("x.oastify.com", "static.exfil-endpoint"),
        ("readFileSync(home + '/.npmrc')", "static.sensitive-path"),
        ("path.join(os.homedir(), '.ssh/id_rsa')", "static.sensitive-path"),
        ("send(JSON.stringify(process.env))", "static.env-harvest"),
        ("for (k of Object.keys(process.env)) {}", "static.env-harvest"),
        ("get('http://45.33.32.156:8080/p')", "static.hardcoded-ip"),
        (f'const p = "{B64}"', "static.encoded-blob"),
        ("eval(atob(x))", "static.dynamic-code"),
        ("new Function('a', body)", "static.dynamic-code"),
        ("execSync('npm publish')", "static.npm-publish"),
        ("const cp = require('child_process')", "static.process-exec"),
        ("import https from 'node:https'", "static.network"),
    ],
)
def test_rule_fires(text: str, rule: str) -> None:
    assert rule in {m.rule_id for m in analyse(text.encode())}


@pytest.mark.parametrize(
    "text",
    [
        "get('http://127.0.0.1:3000/')",  # loopback
        "get('http://10.0.0.1/')",  # private
        "var g = Function('return this')();",  # global-object polyfill
        'new Function("return this")()',
        "obj.eval(x); retrieval(x)",  # method / substring, not the global eval
        f'url("data:image/png;base64,{B64}")',  # embedded image
        "a" * 400,  # not base64-like
        "const env = process.env.NODE_ENV",
    ],
)
def test_benign_lookalikes_do_not_fire(text: str) -> None:
    flagged = {m.rule_id for m in analyse(text.encode()) if m.severity.value != "low"}
    assert flagged == set(), flagged


def test_matches_carry_line_and_truncated_snippet() -> None:
    text = "line one\n" + "x = '" + "Ab1" * 400 + "'\n"
    (match,) = EncodedBlob().evaluate_text(text)
    assert match.line == 2 and len(match.snippet) < 200


def test_obfuscation_needs_many_identifiers() -> None:
    few = " ".join(f"_0x{i:04x}" for i in range(5))
    many = " ".join(f"_0x{i:04x}" for i in range(30))
    assert Obfuscated().evaluate_text(few) == []
    assert len(Obfuscated().evaluate_text(many)) == 1


def test_binary_and_huge_files_are_skipped() -> None:
    assert analyse(b"\x00\x01eval(x)") == ()
    assert analyse(b"eval(x)" + b" " * (17 * 1024 * 1024)) == ()


def test_matches_are_capped_per_rule() -> None:
    assert len([m for m in analyse(b"eval(a);" * 50) if m.rule_id == "static.dynamic-code"]) == 3
    assert len(RULES) == len({r.id for r in RULES})
