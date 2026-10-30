"""Stage 2 file rules on inert, hand-written snippets (patterns only, nothing runnable)."""

import time

import pytest

from kitsunox.rules.static import RULES, EncodedBlob, EncodedUrl, FunctionRequire, Obfuscated
from kitsunox.stages.static import analyse

B64 = "QUJD" * 50 + "ZGVm0123XYZ" * 5  # >200 chars, mixed case and digits


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (
            'post("https://discord.com/api/webhooks/1093847562019384756/aB-c_d")',
            "static.exfil-endpoint",
        ),
        ("discordapp.com/api/v10/webhooks/987362514092837465/x", "static.exfil-endpoint"),
        ("fetch('https://api.telegram.org/botTOKEN/sendMessage')", "static.exfil-endpoint"),
        ("x.oastify.com", "static.exfil-endpoint"),
        (
            "post('https://hooks.slack.com/services/T04KQ7Z2M/B05RJ8XW1PL/xyz')",
            "static.exfil-endpoint",
        ),
        ("https://requestbin.net/r/abc", "static.exfil-endpoint"),
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
        ('DEV_API_KEY: "aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvaW5kZXguanNvbg=="', "static.encoded-url"),
        (
            "g('68747470733A2F2F6578616D706C652E696E76616C69642F696E6465782E6A736F6E')",
            "static.encoded-url",
        ),
        ("const u = `d3NzOi8vZXhhbXBsZS5pbnZhbGlkL3M=`", "static.encoded-url"),
        ('const h = new Function.constructor("require", body)', "static.function-require"),
        ("const h = new (Function.constructor)('require', res.token)", "static.function-require"),
        ("Function(`require`, src)(require)", "static.function-require"),
    ],
)
def test_rule_fires(text: str, rule: str) -> None:
    assert rule in {m.rule_id for m in analyse(text.encode())}


@pytest.mark.parametrize(
    "text",
    [
        "get('http://127.0.0.1:3000/')",  # loopback
        "get('http://10.0.0.1/')",  # private
        "isOnline([`https://1.1.1.1`, `https://8.8.8.8`])",  # public DNS resolvers (v2)
        "var g = Function('return this')();",  # global-object polyfill
        'new Function("return this")()',
        "obj.eval(x); retrieval(x)",  # method / substring, not the global eval
        f'url("data:image/png;base64,{B64}")',  # embedded image
        "a" * 400,  # not base64-like
        "const env = process.env.NODE_ENV",
        "// Webhook URL (https://hooks.slack.com/services/...)",  # docs placeholder
        "https://discord.com/api/webhooks/xxxx/xxxx",  # no digits: not even a placeholder id
        "type OscoreRequestBinding = {}",  # identifier, not the service
        "x = 'data:application/json;base64,eyJzb3VyY2VzIjpbImh0dHBzOi8veCJdfQ=='",  # source map
        "x = 'abcaHR0cHM6Ly9leGFtcGxlLmludmFsaWQvaW5kZXguanNvbg=='",  # not the whole literal
        "x = 'aHR0cHM6Ly8BAmJhZA=='",  # decodes to control characters
        "x = '68747470733a2f2f'",  # the scheme alone
        "new Function('exports', 'require', 'module', src)",  # require is not the first argument
        "obj.myFunction('require', x)",  # a method that ends in Function
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


@pytest.mark.parametrize(
    "text",
    [
        "url: 'https://hooks.slack.com/services/xxx/xxx/xxx'",  # lower-case placeholder ids
        # Slack's documented placeholder, built here so secret scanners don't flag the literal.
        "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24,
        "https://discord.com/api/webhooks/123/abc",  # too short for a snowflake
        "https://discord.com/api/webhooks/000000000000000000/token",  # repeated digit
        "https://discord.com/api/webhooks/123456789012345678/token",  # counting up
    ],
)
def test_placeholder_webhooks_are_labelled_not_dropped(text: str) -> None:
    ids = {m.rule_id: m.severity.value for m in analyse(text.encode())}
    assert ids.get("static.webhook-placeholder") == "medium", ids
    assert "static.exfil-endpoint" not in ids


def test_tunnel_suffixes_and_region_hosts_still_count() -> None:
    """Benign code has these too, but 11 `vm-day1` samples are caught only through ngrok's
    region hosts and 29 only through bare suffixes or `bot${token}` (2026-10-30)."""

    def fires(text: str) -> bool:
        return any(m.rule_id == "static.exfil-endpoint" for m in analyse(text.encode()))

    assert fires('const regions = ["ap.ngrok.io", "EU.ngrok.io", "us.ngrok.io"];')
    assert fires("host.endsWith('.trycloudflare.com')")
    assert fires("fetch(`https://api.telegram.org/bot${token}/sendMessage`)")
    assert fires("fetch('https://3f2a-81-2-69-142.ngrok-free.app/c')")


def test_a_real_looking_webhook_is_not_also_a_placeholder() -> None:
    ids = {
        m.rule_id
        for m in analyse(b"post('https://discord.com/api/webhooks/1093847562019384756/x')")
    }
    assert ids >= {"static.exfil-endpoint"} and "static.webhook-placeholder" not in ids


def test_encoded_url_says_what_it_decodes_to() -> None:
    text = "const u = atob('aHR0cDovLzIwMy4wLjExMy45L3A=')"
    (match,) = EncodedUrl().evaluate_text(text)
    assert match.severity.value == "medium"
    assert "`http://203.0.113.9/p`" in match.explanation


def test_encoded_url_accepts_url_safe_base64() -> None:
    (match,) = EncodedUrl().evaluate_text('"aHR0cHM6Ly9leGFtcGxlLmludmFsaWQvP2E9Pj4-"')
    assert "https://example.invalid/?a=>>>" in match.explanation


def test_function_require_is_linear_on_long_whitespace() -> None:
    # Quadratic before possessive quantifiers: 32k spaces took 0.44 s, 1M would take minutes.
    rule = FunctionRequire()
    for text in (
        "Function" + " " * 1_000_000 + "x",
        "Function" + " " * 500_000 + ")" + " " * 500_000,
    ):
        started = time.perf_counter()
        assert not list(rule.pattern.finditer(text))
        assert time.perf_counter() - started < 1.0
    assert rule.pattern.search("Function \n ) ( 'require' , body")


def test_encoded_blob_is_linear_on_runs_just_too_short() -> None:
    # Before the lookbehind every position of a 199-character run rescanned it: 4M chars of
    # such runs took 2.4 s (now 50 ms).
    rule = EncodedBlob()
    for run in ("A" * 199, "a1" * 99 + "f"):
        text = (run + ".") * 20_000
        started = time.perf_counter()
        assert not list(rule.pattern.finditer(text))
        assert time.perf_counter() - started < 1.0
    text = "x." + "A" * 199 + "." + B64 + "==AAAA"
    assert [m.span() for m in rule.pattern.finditer(text)] == [(202, 202 + len(B64) + 2)]
