"""Stage 2 file rules: regular expressions and simple statistics over one file's text.

Ecosystem-agnostic: they look at code, not at npm concepts. Each rule is a pure function of the
text (so results can be cached by content hash). Severities are starting points; the numbers
behind each are in `docs/stages/static.md`.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Sequence
from typing import ClassVar, Final

from kitsunox.core.models import Severity
from kitsunox.core.rules import FileMatch
from kitsunox.rules.signatures import KnownSignature, decoded_strings

MAX_MATCHES_PER_RULE: Final = 3
SNIPPET_RADIUS: Final = 60


def _line_and_snippet(text: str, start: int, end: int) -> tuple[int, str]:
    line = text.count("\n", 0, start) + 1
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    lo, hi = max(line_start, start - SNIPPET_RADIUS), min(line_end, end + SNIPPET_RADIUS)
    snippet = text[lo:hi]
    if hi - lo > 2 * SNIPPET_RADIUS + 40:  # the match itself is long (e.g. a blob)
        snippet = snippet[:SNIPPET_RADIUS] + f"...[{hi - lo} chars]"
    return line, snippet


class RegexRule:
    """Fires once per match of `pattern` (up to `MAX_MATCHES_PER_RULE`), unless `accept`
    rejects the match."""

    id: ClassVar[str]
    version: ClassVar[int] = 1
    severity: ClassVar[Severity]
    weight: ClassVar[float]
    title: ClassVar[str]
    pattern: ClassVar[re.Pattern[str]]

    def accept(self, match: re.Match[str]) -> bool:
        return True

    def lowered(self, match: re.Match[str]) -> str | None:
        """Why an accepted match is only LOW (weight at most 1), as a note for its explanation;
        None to keep the rule's severity."""
        return None

    def explain(self, match: re.Match[str]) -> str:
        return f"Found `{match.group(0)[:80]}`."

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        """At most `MAX_MATCHES_PER_RULE` matches at the rule's severity, and as many LOW
        (`lowered`) ones: a file's first matches being placeholders never hides a real one."""
        out: list[FileMatch] = []
        kept = low = 0
        for match in self.pattern.finditer(text):
            if not self.accept(match):
                continue
            note = self.lowered(match)
            if note is not None and low >= MAX_MATCHES_PER_RULE:
                continue
            line, snippet = _line_and_snippet(text, match.start(), match.end())
            out.append(
                FileMatch(
                    rule_id=self.id,
                    rule_version=self.version,
                    severity=self.severity if note is None else Severity.LOW,
                    weight=self.weight if note is None else min(self.weight, 1.0),
                    title=self.title,
                    explanation=self.explain(match) + (note or ""),
                    line=line,
                    snippet=snippet,
                )
            )
            if note is not None:
                low += 1
                continue
            kept += 1
            if kept >= MAX_MATCHES_PER_RULE:
                break
        return out


class ExfilEndpoint(RegexRule):
    """Services attackers use to receive stolen data without running a server."""

    # v2: webhook URLs need an id after the path (docs write `hooks.slack.com/services/...`),
    # and `requestbin` needs a dot (it matched `OscoreRequestBinding`). Live run 2026-10-28.
    # v3: webhook ids must look real. Discord ids are 17-20-digit snowflakes (every one in the
    # DataDog samples has 19); Slack's are `T...`/`B...` in upper case (v2's `[A-Z0-9]` was
    # case-insensitive, so `/services/xxx/xxx` matched). Repeated or counting-up ids are
    # placeholders (`123/abc`, `T00000000/B00000000`). URLs built in code (`bot${token}`,
    # `webhooks/" + id`) never carried a literal id, so v2 and v3 both miss or both keep them.
    # Kept on purpose (2026-10-30, first VM day): bare suffixes (`".trycloudflare.com"`),
    # `bot${token}` and lists of ngrok's region hosts (`eu.ngrok.io`). Live benign code has
    # them, but dropping the first two cost 29 malicious `vm-day1` samples caught by nothing
    # else (against 3 benign), and dropping region hosts cost 11 (`gina`, `cro-pricing`, ...)
    # to clear 6 benign packages. See docs/stages/static.md.
    # v4 (2026-10-31): `bot` followed by a written placeholder (`bot<token>`, `botYOUR_TOKEN`,
    # `bot...`) is documentation: `glimmervoid`'s settings help text was HIGH in 25 releases.
    # v5 (2026-11-03): `interact.sh` needs a boundary after it (`this.interact.shareLink()` was
    # HIGH), and a deny list is not an endpoint: a host written as a whole string literal
    # (`'webhook.site'`, `'x.pipedream.net'`, `'api.telegram.org/bot'`) with literals of 3 or
    # more different such services within 400 characters (`dsh-security-pack`'s vet checks,
    # agent policy engines). `vm-day1`: no malicious sample lost. A URL (`"https://...`) is
    # never a whole host literal, so `"https://api.telegram.org/bot" + token` still counts.
    # v6 (2026-11-08, `docs/proposals/precision-round2.md` F3b, F3c): LOW, weight 1, for a
    # tunnel host whose own label is a placeholder (`example.ngrok.app`, `xxx.trycloudflare.com`,
    # `<your-tunnel>.serveo.net`, `*.ngrok.io`, `${sub}.ngrok-free.app`;
    # `_PLACEHOLDER_LABEL`), and for a whole host literal among at least two other quoted
    # domain literals within 400 characters that are not endpoints themselves (`LIST_DOMAINS`:
    # a disposable-mail list naming `webhook.site` among mail domains; a table of ngrok's
    # region hosts stays HIGH, as v5 decided). Real quick-tunnel names
    # (`purple-river-1234.trycloudflare.com`) and bare suffixes stay HIGH. Live: 33 benign
    # reports, no positive; none of the 63 `vm-day1` malicious samples at risk lost. Matches
    # on comment lines stay HIGH: that loses `elf-stats-piney-pinecone-203@1.0.0`.
    # v7 (2026-11-09, `docs/proposals/precision-round3.md` X1-X4): LOW, weight 1, too for
    # what can't be an endpoint: the one paste core-js cites in a comment
    # (`pastebin.com/N21QzeQA`, bundled into many builds; a paste can't be rewritten by
    # someone else); a host pattern (`*.oastify.com`, `*.m.pipedream.net`: a `*` is never a
    # host one connects to); a host that is a whole entry of a list separated by newlines,
    # tabs or commas with at least two other domains that are not endpoints (a disposable-mail
    # list in one string, a public-suffix list; v6's test for quoted entries, for unquoted
    # ones); and an OAST host whose own label is a placeholder (`YOUR-COLLABORATOR-ID.
    # oastify.com`, v6's test for tunnel hosts). Real OAST ids and quick-tunnel names, bare
    # suffixes, `bot${token}` and tables of endpoints stay HIGH.

    id = "static.exfil-endpoint"
    version = 7
    severity = Severity.HIGH
    weight = 5.0
    title = "Known exfiltration endpoint"
    pattern = re.compile(
        r"discord(?:app)?\.com/api/(?:v\d{1,2}/)?webhooks/(?P<discord>\d{17,20})/"
        r"|hooks\.slack\.com/services/(?P<slack>(?-i:T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}))/"
        r"|api\.telegram\.org/bot"
        r"|pastebin\.com/|paste\.ee/|hastebin\.|webhook\.site|requestbin\.|pipedream\.net"
        r"|\.oast\.(?:fun|me|pro|site|live|online)|oastify\.com|burpcollaborator\.net"
        r"|interact\.sh(?![\w-])|\.ngrok(?:-free)?\.(?:io|app)|\.trycloudflare\.com|\.serveo\.net",
        re.IGNORECASE,
    )

    def accept(self, match: re.Match[str]) -> bool:
        if match.group(0).lower().endswith("/bot") and _TELEGRAM_PLACEHOLDER.match(
            match.string, match.end()
        ):
            return False
        webhook_id = match.group("discord") or match.group("slack")
        if webhook_id is not None:
            return not _placeholder_id(webhook_id)
        return not _in_deny_list(match)

    def lowered(self, match: re.Match[str]) -> str | None:
        if match.group(0).startswith(".") and _PLACEHOLDER_LABEL.search(
            match.string, max(0, match.start() - 64), match.start()
        ):
            return PLACEHOLDER_NOTE
        if _OAST.fullmatch(match.group(0)) and _placeholder_oast(match):
            return PLACEHOLDER_NOTE
        if _CORE_JS_PASTE.match(match.string, match.start()):
            return CORE_JS_NOTE
        if _host_pattern(match):
            return PATTERN_NOTE
        if _in_domain_list(match) or _in_separated_list(match):
            return LIST_NOTE
        return None


# A placeholder written as a tunnel host's own label, ending right before `.ngrok.io`,
# `.trycloudflare.com` or `.serveo.net`: a word label on its own (`example`, `xxx`, `your-app`,
# `foo`; not `sidebar`), or `<...>`, `*`, `${...}`, `{...}`, `..`.
_PLACEHOLDER_LABEL: Final = re.compile(
    r"(?:(?<![\w-])(?:examples?|x{3,}|your[-_]?[\w-]*|foo|bar|baz|abc\d*|random"
    r"|my[-_]?(?:app|tunnel|subdomain|domain))|<[^<>\n]*>|\*|\$?\{[^{}\n]*\}|\.{2,})$",
    re.IGNORECASE,
)
PLACEHOLDER_NOTE: Final = " A placeholder host: documentation, not an endpoint."
# A whole quoted domain literal (`"mailinator.com"`): its last label is letters.
_DOMAIN_LITERAL: Final = re.compile(
    r"""(?P<q>["'`])[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"""
    r"""\.[a-z]{2,}(?P=q)""",
    re.IGNORECASE,
)
LIST_DOMAINS: Final = 2
LIST_NOTE: Final = " A host in a list of domains, not an endpoint."
# v7: the OAST services, whose own label is the id a researcher registered.
_OAST: Final = re.compile(
    r"oastify\.com|burpcollaborator\.net|interact\.sh|\.oast\.(?:fun|me|pro|site|live|online)",
    re.IGNORECASE,
)
# v7: the paste core-js cites in a comment about a Safari debugger crash; its builds are
# bundled into many packages. Paste ids are case-sensitive and a paste can't be rewritten by
# anyone but its author.
_OAST_PLACEHOLDER: Final = re.compile(
    r"(?<![\w-])(?:your[-_]?[a-z-]*|x{3,}|examples?|<[a-z_ -]*>)$", re.IGNORECASE
)
_CORE_JS_PASTE: Final = re.compile(r"(?i:pastebin\.com)/N21QzeQA(?![\w-])")
CORE_JS_NOTE: Final = (
    " The paste core-js cites in a code comment (a Safari debugger crash): not an endpoint."
)
PATTERN_NOTE: Final = " A host pattern (`*.`), which nothing connects to: not an endpoint."
# v7: an entry of a list separated by newlines, tabs or commas, written out or as `\n` / `\t`
# escapes in a string: `...\nwebclub.infos.st\nwebhook.site\nwebinarmoa.com\n...`.
_SEPARATOR: Final = re.compile(r"(?:\\[nt]|[\n\t,])[ \t]*$")
_SEPARATOR_AFTER: Final = re.compile(r"[ \t]*(?:\\[nt]|[\n\t,])")
_LIST_ENTRY: Final = re.compile(
    r"(?:\\[nt]|[\n\t,])[ \t]*"
    r"(?P<host>[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})"
    r"""(?=[ \t]*(?:\\[nt]|[\n\t,"'`]|$))""",
    re.IGNORECASE,
)
_QUOTES: Final = "\"'`"
# What documentation writes after `api.telegram.org/bot` instead of a token.
_TELEGRAM_PLACEHOLDER: Final = re.compile(r"<|\[|YOUR_|\.\.\.")
# A whole string literal naming one exfiltration or OAST service, optionally with a subdomain.
_SERVICE_LITERAL: Final = re.compile(
    r"""(?P<q>["'`])[\w.-]*?(?P<service>webhook\.site|pipedream\.net|requestbin\.\w+"""
    r"""|hastebin\.\w+|pastebin\.com|paste\.ee|oast\.(?:fun|me|pro|site|live|online)"""
    r"""|oastify\.com|burpcollaborator\.net|interact\.sh|ngrok(?:-free)?\.(?:io|app)"""
    r"""|trycloudflare\.com|serveo\.net|beeceptor\.com|requestcatcher\.com|hookbin\.com"""
    r"""|localhost\.run|api\.telegram\.org/bot)(?P=q)""",
    re.IGNORECASE,
)
DENY_LIST_SERVICES: Final = 3
DENY_LIST_WINDOW: Final = 400


def _whole_literal(match: re.Match[str]) -> tuple[int, int] | None:
    """The span of the host `match` is in when that host is a whole string literal."""
    text, start, end = match.string, match.start(), match.end()
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "._-"):
        start -= 1
    tail = end
    if not match.group(0).lower().endswith("/bot"):
        while tail < len(text) and (text[tail].isalnum() or text[tail] in "._-"):
            tail += 1
    quote = text[start - 1 : start]
    if not quote or quote not in "\"'`" or text[tail : tail + 1] != quote:
        return None
    return start, tail


def _host_span(match: re.Match[str]) -> tuple[int, int]:
    """The host `match` is part of: its labels before the match and, unless the match ends in
    a path (`api.telegram.org/bot`), after it."""
    text, start, end = match.string, match.start(), match.end()
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "._-"):
        if start >= 2 and text[start - 2] == "\\" and text[start - 1] in "nt":
            break  # `...\nwebhook.site`: the `n` belongs to the escape
        start -= 1
    if not match.group(0).lower().endswith("/bot"):
        while end < len(text) and (text[end].isalnum() or text[end] in "._-"):
            end += 1
    return start, end


def _placeholder_oast(match: re.Match[str]) -> bool:
    """An OAST host whose own label (the id a researcher registers) is a written placeholder:
    `YOUR-COLLABORATOR-ID.oastify.com`, `xxxxxxxxx.oastify.com`, `<id>.oastify.com`. Stricter
    than the tunnel test: no digit (a registered id has them: `YourServer929w1e5….oastify.com`
    is a real one with a prefix) and no template (`${id}.oastify.com` is how DNS exfiltration
    builds its host)."""
    text, start = match.string, match.start()
    if start == 0 or text[start - 1] != ".":
        return False
    return _OAST_PLACEHOLDER.search(text, max(0, start - 65), start - 1) is not None


def _host_pattern(match: re.Match[str]) -> bool:
    """`*.oastify.com`, `*.m.pipedream.net`: a wildcard host, as allow and deny lists write
    them (not `**webhook.site**`, Markdown emphasis)."""
    start, _ = _host_span(match)
    text = match.string
    return start > 0 and text[start] == "." and text[start - 1] == "*"


def _in_separated_list(match: re.Match[str]) -> bool:
    """Whether `match` is a host that is a whole entry of a list separated by newlines, tabs or
    commas (written out, or as `\\n` / `\\t` escapes inside a string), with at least
    `LIST_DOMAINS` other entries within `DENY_LIST_WINDOW` characters that are domains and not
    endpoints themselves. One side may be the string's quote (its first or last entry)."""
    if match.group(0).lower().endswith("/bot"):
        return False
    start, end = _host_span(match)
    text = match.string
    left = _SEPARATOR.search(text, max(0, start - 8), start) is not None
    right = _SEPARATOR_AFTER.match(text, end, min(len(text), end + 8)) is not None
    quoted_left = start > 0 and text[start - 1] in _QUOTES
    quoted_right = end < len(text) and text[end] in _QUOTES
    if not (left or right) or not (left or quoted_left) or not (right or quoted_right):
        return False
    own = text[start:end].lower()
    lo = max(0, start - DENY_LIST_WINDOW)
    hi = min(len(text), end + DENY_LIST_WINDOW)
    others = {m.group("host").lower() for m in _LIST_ENTRY.finditer(text, lo, hi)}
    return len({d for d in others - {own} if not ExfilEndpoint.pattern.search(d)}) >= LIST_DOMAINS


def _in_domain_list(match: re.Match[str]) -> bool:
    """Whether `match` is a host written as a whole string literal with quoted literals of at
    least `LIST_DOMAINS` other domains within `DENY_LIST_WINDOW` characters, none of them
    itself an endpoint: a table of a tunnel's region hosts (`'eu.ngrok.io'`, `'us.ngrok.io'`)
    is kept, as v5 decided (`gina`, `cro-pricing`)."""
    span = _whole_literal(match)
    if span is None:
        return False
    start, tail = span
    text = match.string
    lo = max(0, start - DENY_LIST_WINDOW)
    hi = min(len(text), tail + DENY_LIST_WINDOW)
    own = text[start:tail].lower()
    others = {m.group(0)[1:-1].lower() for m in _DOMAIN_LITERAL.finditer(text, lo, hi)}
    return len({d for d in others - {own} if not ExfilEndpoint.pattern.search(d)}) >= LIST_DOMAINS


def _in_deny_list(match: re.Match[str]) -> bool:
    """Whether `match` is a host written as a whole string literal among literals of at least
    `DENY_LIST_SERVICES` different services: a block or deny list, not an endpoint."""
    span = _whole_literal(match)
    if span is None:
        return False
    start, tail = span
    text = match.string
    lo = max(0, start - DENY_LIST_WINDOW)
    hi = min(len(text), tail + DENY_LIST_WINDOW)
    services = {
        m.group("service").lower().split(".")[0] for m in _SERVICE_LITERAL.finditer(text, lo, hi)
    }
    return len(services) >= DENY_LIST_SERVICES


def _placeholder_id(webhook_id: str) -> bool:
    """`000000000000000000`, `T00000000/B00000000`, `123456789012345678`: a documentation
    example, not a webhook someone created."""
    digits = "".join(c for c in webhook_id if c.isdigit())
    parts = [p[1:] if p[:1].isalpha() else p for p in webhook_id.split("/")]
    if any(len(set(p)) == 1 for p in parts):
        return True
    return len(digits) >= 8 and digits[:8] in "01234567890123456789"


class WebhookPlaceholder(RegexRule):
    """A Discord or Slack webhook URL whose id is a placeholder (`/services/xxx/xxx`,
    `/webhooks/123/abc`): what `exfil-endpoint` v2 matched and v3 no longer calls an
    exfiltration endpoint.

    Kept at MEDIUM, so Stage 2 still forwards it, because dropping these cost recall: on
    `vm-day1` 42 DataDog samples (a `chai-as-*` typosquat family carrying a notifier template)
    were caught end to end only through this match, against one benign package
    (`@zerodot/discord`). The finding now says what it is, and scores 3 instead of 5.
    Since `encoded-url` (below), 42 of those 43 are also caught by what they actually do; the
    one this rule alone still catches is `jsonlogbundler`, against the same benign package."""

    id = "static.webhook-placeholder"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Webhook URL with a placeholder id"
    pattern = re.compile(
        r"discord(?:app)?\.com/api/(?:v\d{1,2}/)?webhooks/\d|hooks\.slack\.com/services/[A-Z0-9]",
        re.IGNORECASE,
    )

    def accept(self, match: re.Match[str]) -> bool:
        real = ExfilEndpoint.pattern.match(match.string, match.start())
        return real is None or not ExfilEndpoint().accept(real)

    def explain(self, match: re.Match[str]) -> str:
        return (
            f"Found `{match.group(0)[:80]}` with a placeholder id: a template or documentation "
            "example, or a URL the code completes later."
        )


class EncodedUrl(RegexRule):
    """A string literal that is a URL in base64 or hex: `"aHR0cHM6Ly9..."` is `https://...`.

    Code that talks to a server it means to has no reason to hide the address. Encoding it
    keeps the host out of plain-text search, so this is a general sign of a hidden endpoint
    (a second-stage download, a C2 or an exfiltration host), whatever the code then does with
    it. Only a whole literal that decodes to printable text starting `http(s)://` or
    `ws(s)://` counts: the same bytes inside a longer blob (an inline source map) do not.

    Added 2026-10-30 for a `vm-day1` family of 43 DataDog samples (pino clones named
    `chai-as-*`, `chai-await-*`, `aligners`, ...) that fetch a URL decoded with `atob` (or a
    hex helper) and run the response with `new Function("require", body)` or `eval`."""

    id = "static.encoded-url"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "URL hidden in base64 or hex"
    pattern = re.compile(
        r"""(?P<q>["'`])(?:"""
        r"""(?P<b64>(?:aHR0c(?:HM6Ly|DovL)|d3M6Ly|d3NzOi8v)[A-Za-z0-9+/_-]{4,}={0,2})"""
        r"""|(?P<hex>(?i:(?:68747470|7773)(?:73)?3a2f2f)(?:[0-9a-fA-F]{2}){4,})"""
        r""")(?P=q)""",
    )

    def accept(self, match: re.Match[str]) -> bool:
        return _decoded_url(match) is not None

    def explain(self, match: re.Match[str]) -> str:
        return f"An encoded string literal decodes to `{_decoded_url(match) or ''}`."


def _decoded_url(match: re.Match[str]) -> str | None:
    """The literal decoded, truncated to 100 characters, if it is a printable URL."""
    try:
        if match.group("hex"):
            raw = bytes.fromhex(match.group("hex"))
        else:
            b64 = match.group("b64").replace("-", "+").replace("_", "/").rstrip("=")
            raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
        text = raw.decode("ascii")
    except ValueError:  # binascii.Error and UnicodeDecodeError are ValueErrors
        return None
    if not text.isprintable() or not re.match(r"(?:https?|wss?)://\w", text):
        return None
    return text[:100]


class FunctionRequire(RegexRule):
    """A function compiled at runtime whose first parameter is `require`:
    `new Function("require", body)` (also via `Function.constructor`). Code built from a
    string is handed the module loader, so whatever the string turns out to be (typically a
    response just downloaded) can load `child_process`, `fs` or `https` itself. A loader for
    a second stage needs exactly this; bundlers and template engines compile code without
    giving it `require`."""

    id = "static.function-require"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Compiles code at runtime and hands it `require`"
    pattern = re.compile(
        # Possessive `*+`: `\s` never matches `.`, `)` or `(`, so giving whitespace back can't
        # help, and without them "Function" plus a long run of spaces backtracks quadratically
        # (32k spaces took 0.44 s; a 16 MB file of them would stall Stage 2).
        r"""(?<![\w$])Function(?:\s*+\.\s*+constructor)?\s*+\)?\s*+\(\s*+["'`]require["'`]\s*+,"""
    )


class SensitivePath(RegexRule):
    """Credential and secret stores a package has no business reading."""

    # v2: MEDIUM -> LOW. 2026-10-27, A/B first releases: benign 2.0%/1.6%, malicious 4.0%/5.1%.

    id = "static.sensitive-path"
    version = 2
    severity = Severity.LOW
    weight = 1.0
    title = "Reference to a credential or secret store"
    pattern = re.compile(
        r"\.npmrc|\.ssh/id_|\.ssh[\"'`]?\s*,\s*[\"'`]id_|\.aws/credentials|\.git-credentials"
        r"|\.bash_history|\.zsh_history|\.docker/config\.json|\.kube/config"
        r"|Login Data|Local State[\"'`]|\.config/gcloud|Exodus/exodus\.wallet|\.electrum/wallets"
        r"|Library/Keychains|/etc/shadow",
    )


class EnvHarvest(RegexRule):
    """The whole environment serialised or enumerated: environment variables hold CI tokens."""

    # v2: MEDIUM -> LOW. 2026-10-27, A/B first releases: benign 0.9%/2.4%, malicious 3.2%/2.0%.

    id = "static.env-harvest"
    version = 2
    severity = Severity.LOW
    weight = 1.0
    title = "Collects all environment variables"
    pattern = re.compile(
        r"JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)"
        r"|\{\s*\.\.\.process\.env\s*\}\s*\)|os\.environ\.copy\(\)|dict\(os\.environ\)",
    )


# Public DNS resolvers, reached by IP in connectivity checks (`apify-cli`: `isOnline` tries
# `https://1.1.1.1` and `https://8.8.8.8`). 29 of the 56 MEDIUM `hardcoded-ip` findings on the
# live queue (2026-10-30), none of the 159 in `vm-day1`'s malicious samples.
PUBLIC_RESOLVERS: Final = frozenset(
    {
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
        "208.67.222.222",
        # v4: the secondary OpenDNS address and the big Chinese public resolvers (AliDNS,
        # DNSPod, 114DNS), written in DoH and proxy configs as `https://223.5.5.5/dns-query`.
        "208.67.220.220",
        "223.5.5.5",
        "223.6.6.6",
        "119.29.29.29",
        "114.114.114.114",
        "114.114.115.115",
    }
)
# v4: addresses documentation writes as an example: counting digits (`1.2.3.4`,
# `123.45.67.89`) and example.com's long-standing address. LOW, not dropped: still shown.
EXAMPLE_IPS: Final = frozenset(
    {"1.2.3.4", "4.3.2.1", "12.34.56.78", "123.45.67.89", "11.22.33.44", "93.184.216.34"}
)
EXAMPLE_IP_NOTE: Final = " An address documentation uses as an example."


class HardcodedIp(RegexRule):
    """A URL to a raw public IPv4 address: common for second-stage downloads and C2. v2: not a
    well-known public DNS resolver (`PUBLIC_RESOLVERS`). v3 (2026-11-08, F4b): LOW in files
    that hold data or tests and in `package.json`'s own repository, homepage and bugs URLs; a
    path test, so it is in Stage 2 (`stages.static.IP_DATA_FILES`, `_metadata_url`). 20 benign
    live reports, no positive; neither `vm-day1` malicious sample at risk lost. v4 (2026-11-09,
    `docs/proposals/precision-round3.md` X5): more public resolvers (AliDNS, DNSPod, 114DNS,
    OpenDNS's second address), and LOW, weight 1, for an example address (`EXAMPLE_IPS`:
    `https://1.2.3.4:8443` as an input placeholder or in a help string)."""

    id = "static.hardcoded-ip"
    version = 4
    severity = Severity.MEDIUM
    weight = 3.0
    title = "URL with a hardcoded public IP address"
    pattern = re.compile(r"(?:https?|wss?|tcp)://((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?")

    def accept(self, match: re.Match[str]) -> bool:
        try:
            address = ipaddress.IPv4Address(match.group(1))
        except ValueError:
            return False
        return address.is_global and str(address) not in PUBLIC_RESOLVERS

    def lowered(self, match: re.Match[str]) -> str | None:
        return EXAMPLE_IP_NOTE if match.group(1) in EXAMPLE_IPS else None


class EncodedBlob(RegexRule):
    """Long base64 or hex runs: packed payloads. Image and font data URIs are excluded."""

    # v2: MEDIUM -> LOW. 2026-10-27, A/B first releases: benign 2.2%/2.6%, malicious 6.0%/2.7%.

    id = "static.encoded-blob"
    version = 2
    severity = Severity.LOW
    weight = 1.0
    title = "Large encoded blob"
    MIN_LENGTH: ClassVar[int] = 200
    # A match starts where a run does (inside a run, a shorter run fails too): the lookbehind
    # skips those starts, which scanned up to 199 characters each (1M chars of them: 0.6 s).
    pattern = re.compile(
        r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{200,}={0,2}|(?:[0-9a-fA-F]{2}){100,})"
    )
    _DATA_URI = re.compile(
        r"data:(?:image|font|application/font|application/x-font)[^,]{0,60};base64,$"
    )

    def accept(self, match: re.Match[str]) -> bool:
        before = match.string[max(0, match.start() - 80) : match.start()]
        if self._DATA_URI.search(before):
            return False
        blob = match.group(0)
        # Exclude runs of a single repeated character class, like long dashes or all-letter
        # identifiers: real base64 mixes cases and digits.
        return (any(c.isdigit() for c in blob) and any(c.isupper() for c in blob)) or _is_hex(blob)

    def explain(self, match: re.Match[str]) -> str:
        return f"Encoded run of {len(match.group(0))} characters."


def _is_hex(blob: str) -> bool:
    """Hex payloads mix digits and letters; a run like `aaaa...` is not one."""
    return (
        all(c in "0123456789abcdefABCDEF" for c in blob)
        and any(c.isdigit() for c in blob)
        and any(c.isalpha() for c in blob)
    )


class DynamicCode(RegexRule):
    """Code built and run at runtime, the usual way to hide a payload from static review."""

    # v2: MEDIUM -> LOW. 2026-10-27, A/B first releases: benign 2.3%/2.6%, malicious 2.0%/6.0%.

    id = "static.dynamic-code"
    version = 2
    severity = Severity.LOW
    weight = 1.0
    title = "Runs dynamically built code"
    pattern = re.compile(
        r"(?<![\w.$])eval\s*\(|new\s+Function\s*\(|vm\.runIn(?:New|This)?Context\s*\("
        r"|vm\.Script\s*\(",
    )
    _POLYFILL = re.compile(r"Function\s*\(\s*[\"']return this[\"']\s*\)")

    def accept(self, match: re.Match[str]) -> bool:
        return not self._POLYFILL.search(match.string, match.start(), match.end() + 20)


class Obfuscated(RegexRule):
    """javascript-obfuscator style output: many `_0x1a2b3c` identifiers."""

    id = "static.obfuscated"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Obfuscated code"
    MIN_IDENTIFIERS: ClassVar[int] = 20
    pattern = re.compile(r"\b_0x[0-9a-f]{4,6}\b")

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        matches = list(self.pattern.finditer(text))
        if len(matches) < self.MIN_IDENTIFIERS:
            return []
        first = matches[0]
        line, snippet = _line_and_snippet(text, first.start(), first.end())
        return [
            FileMatch(
                rule_id=self.id,
                rule_version=self.version,
                severity=self.severity,
                weight=self.weight,
                title=self.title,
                explanation=f"{len(matches)} obfuscator-style identifiers.",
                line=line,
                snippet=snippet,
            )
        ]


class NpmPublish(RegexRule):
    """Code that uses npm credentials or publishes packages: how npm worms spread."""

    # v2: MEDIUM -> LOW. 2026-10-27, A/B first releases: benign 6.4%/8.0% (publishing tools
    # mention NPM_TOKEN), malicious 10.9%/20.9%.

    id = "static.npm-publish"
    version = 2
    severity = Severity.LOW
    weight = 1.0
    title = "Publishes to npm or uses npm tokens"
    pattern = re.compile(
        r"npm\s+publish|NPM_TOKEN|_authToken|registry\.npmjs\.org/-/(?:whoami|npm/v1/tokens)",
    )


class ProcessExec(RegexRule):
    id = "static.process-exec"
    severity = Severity.LOW
    weight = 1.0
    title = "Starts processes"
    pattern = re.compile(
        r"""(?:require\(\s*|from\s+|import\(\s*)["'`](?:node:)?child_process["'`]"""
    )


class Network(RegexRule):
    id = "static.network"
    severity = Severity.LOW
    weight = 1.0
    title = "Uses low-level network modules"
    pattern = re.compile(
        r"""(?:require\(\s*|from\s+|import\(\s*)["'`](?:node:)?(?:https?|net|dns|dgram|tls)["'`]"""
    )


_RC: Final = (
    r"(?:\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zprofile|\.zshenv|\.zlogin|\.profile"
    r"|\.cshrc|\.tcshrc|\.kshrc|\.config/fish/config\.fish|config\.fish)"
)
_HOME_PREFIX: Final = r"(?:~|\$HOME|\$\{HOME\}|\$\{?ZDOTDIR\}?|%USERPROFILE%)"


class ShellStartup:
    """Code that writes a user's shell start-up files (`~/.bashrc`, `~/.zshrc`, `~/.profile`,
    fish's `config.fish`, the PowerShell profile): whatever it adds runs in every new shell,
    so it is a way to persist. Four forms, each at most one match per file:

    - `hook`: an install hook in a `package.json` appends to one (`>> ~/.bashrc`), on every
      `npm install`;
    - `shell`: a shell command elsewhere does (`echo ... >> "$HOME/.zshrc"`, `tee -a`,
      `Add-Content $PROFILE`);
    - `inject`: code that writes files and refers to the home directory, and either sets a
      prompt that runs a command (`setopt prompt_subst` with `PROMPT="$(...)"`) or, next to a
      start-up file's name, holds a line sourcing a file under the home directory that isn't
      itself a start-up file (`@atedone/workspace-context`: `source "$HOME/.config/.../init.zsh"`,
      later a prompt rendered from a server's reply);
    - `code`: a start-up file's name as a string, a file write within `NEAR` characters and a
      home-directory reference, in one file (completion and PATH installers do this too).

    Legitimate CLIs add PATH and completion lines the same way, so the severity per form comes
    from live benign traffic (2026-11-08, `docs/proposals/prefreeze-recall.md`): over 4.6 days
    of what Stage 2 read, `hook` and `inject` (MEDIUM, weight 3) newly reported one version, a
    completion installer (`@heyvamz/carry`); `shell` and `code` stay LOW evidence (weight 1):
    at MEDIUM they reported about 8 and 2 benign CLIs a day (`backupd`, `westkite`). An
    `inject` that sourced start-up files themselves (`. "$HOME/.profile"`) or any `PROMPT=`
    variable reported at least 10 more benign versions before it was narrowed to these."""

    id: ClassVar[str] = "static.shell-startup"
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Writes to shell start-up files"
    SEVERITY: ClassVar[dict[str, tuple[Severity, float]]] = {
        "hook": (Severity.MEDIUM, 3.0),
        "inject": (Severity.MEDIUM, 3.0),
        "shell": (Severity.LOW, 1.0),
        "code": (Severity.LOW, 1.0),
    }
    NEAR: ClassVar[int] = 1000

    _SHELL: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:>>?|\btee\s++(?:-a\s++|--append\s++)?)\s*+[\"'\\]*+"
        + _HOME_PREFIX
        + r"[/\\]"
        + _RC
        + r"(?![\w.-])"
        r"|(?:Add-Content|Out-File)\b[^\n;|]{0,40}\$PROFILE\b|>>\s*+\$PROFILE\b"
    )
    _HOOK: ClassVar[re.Pattern[str]] = re.compile(
        r"\"(?:pre|post)?install\"\s*+:\s*+\"((?:[^\"\\]|\\.)*+)\""
    )
    _NAME: ClassVar[re.Pattern[str]] = re.compile(
        r"[\"'`](?:" + _HOME_PREFIX + r"/)?" + _RC + r"[\"'`]|Microsoft\.PowerShell_profile\.ps1"
    )
    _WRITE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w$])(?:appendFileSync|appendFile|writeFileSync|writeFile|createWriteStream"
        r"|outputFileSync|outputFile)\s*+\("
    )
    # A line sourcing a file under the home directory; one that sources a start-up file itself
    # (`. "$HOME/.profile"`, "run source ~/.zshrc") only reloads the user's own settings.
    _SOURCE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w-])(?:source|\.) [\"']?" + _HOME_PREFIX + r"/(?P<path>[\w.-][\w./-]*)"
    )
    _STARTUP_FILE: ClassVar[re.Pattern[str]] = re.compile(r"(?:.*/)?" + _RC)
    _PROMPT: ClassVar[re.Pattern[str]] = re.compile(r"\b(?:PROMPT|PS1)=[\"']?\$\(")
    # Each form needs one of these words, so the regexes only run on files that have one (a
    # 9.5 MB CLI bundle that has them: 0.48 s, all Stage 2 rules 2.7 s; 7 MB without: 0.05 s).
    NAMES: ClassVar[tuple[str, ...]] = (
        "bashrc", "zshrc", "bash_profile", ".profile", "zprofile", "zshenv", "config.fish",
        "cshrc", "kshrc", "zlogin", "bash_login", "$PROFILE", "PowerShell_profile",
    )  # fmt: skip
    INJECTS: ClassVar[tuple[str, ...]] = (
        "prompt_subst", "PROMPT=", "PS1=", "source ~/", ". ~/", "source $HOME", ". $HOME",
        'source "$HOME', '. "$HOME', "source ${HOME", ". ${HOME", 'source "${HOME', '. "${HOME',
        "source '$HOME", ". '$HOME", "source $ZDOTDIR", "source ${ZDOTDIR",
    )  # fmt: skip
    HOMES: ClassVar[tuple[str, ...]] = ("homedir", "HOME", "USERPROFILE", "ZDOTDIR")

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        named = any(word in text for word in self.NAMES)
        injects = any(word in text for word in self.INJECTS)
        if not (named or injects):
            return []
        found: dict[str, re.Match[str]] = {}
        if named and '"scripts"' in text:
            for hook in self._HOOK.finditer(text):
                if inner := self._SHELL.search(hook.group(1)):
                    found["hook"] = inner
                    break
        if named and "hook" not in found and (shell := self._SHELL.search(text)):
            found["shell"] = shell
        writes = (
            [w.start() for w in self._WRITE.finditer(text)]
            if any(word in text for word in self.HOMES)
            else []
        )
        names = list(self._NAME.finditer(text)) if writes and named else []
        if writes and injects and (inject := self._injected(text, bool(names))):
            found["inject"] = inject
        for name in names:
            if any(abs(w - name.start()) <= self.NEAR for w in writes):
                found["code"] = name
                break
        out = []
        for form, match in found.items():
            severity, weight = self.SEVERITY[form]
            if form == "hook":  # `match` is inside the hook's value; place it in the text
                start = text.find(match.group(0))
                line, snippet = _line_and_snippet(text, start, start + len(match.group(0)))
            else:
                line, snippet = _line_and_snippet(text, match.start(), match.end())
            out.append(
                FileMatch(
                    rule_id=self.id,
                    rule_version=self.version,
                    severity=severity,
                    weight=weight,
                    title=self.title,
                    explanation=f"{_SHELL_FORMS[form]} (form `{form}`).",
                    line=line,
                    snippet=snippet,
                )
            )
        return out

    def _injected(self, text: str, named: bool) -> re.Match[str] | None:
        """A prompt that runs a command under `setopt prompt_subst`, or (in a file that names a
        start-up file) a line sourcing a file under the home directory that isn't one."""
        if "prompt_subst" in text and (prompt := self._PROMPT.search(text)):
            return prompt
        if named:
            for line in self._SOURCE.finditer(text):
                if not self._STARTUP_FILE.fullmatch(line.group("path")):
                    return line
        return None


_SHELL_FORMS: Final = {
    "hook": "An install hook appends to a shell start-up file: it runs on every `npm install`",
    "shell": "A shell command writes to a shell start-up file",
    "inject": "Code writes a shell start-up file with a line that sources a file from the home "
    "directory or a prompt that runs a command",
    "code": "Code writes next to a shell start-up file's name and the home directory",
}


class ChannelFollow:
    """A WhatsApp library (a Baileys fork) that makes the user's account follow channels it
    chose: a FOLLOW query or `newsletterFollow(...)` call outside the API's own definitions,
    in a file that also names the channels (a `...@newsletter` id or a `0029V...` invite code,
    in plain text, base64 or char codes), fetches them, or calls the code an auto-follow or
    auto-join. A follow behind an explicit opt-in (`if (autoFollow === true)`) does not count.

    The owner's policy (decision 0015 addenda of 2026-11-08): a fork that follows channels with
    the user's account is *unwanted*, hidden or disclosed; one that follows only when asked is
    benign. A file rule can't read the README, so the finding says what the code does and
    claims no malware. MEDIUM, weight 3: a fork that does it is reported. Upstream Baileys
    defines `newsletterFollow(jid)` and calls nothing itself, so it never matches.

    Added 2026-11-08; the numbers are in `docs/proposals/prefreeze-recall.md`."""

    id: ClassVar[str] = "static.channel-follow"
    version: ClassVar[int] = 1
    severity: ClassVar[Severity] = Severity.MEDIUM
    weight: ClassVar[float] = 3.0
    title: ClassVar[str] = "Auto-follows WhatsApp channels (unwanted)"

    # A FOLLOW query id used (not assigned: `QueryIds["FOLLOW"] = "..."`), or the follow call.
    _USE: ClassVar[re.Pattern[str]] = re.compile(
        r"[\w$\])]\s*+(?:\.\s*+FOLLOW\b|\[\s*+[\"'`]FOLLOW[\"'`]\s*+\])(?!\s*=[^=])"
        r"|(?<![\w$])newsletterFollow\s*+\("
    )
    # The API's own methods (`newsletterFollow: async (jid) => ...`, `async newsletterFollow(jid)
    # {`), whose bodies run the FOLLOW query on the caller's `jid`.
    _API: ClassVar[re.Pattern[str]] = re.compile(
        r"newsletter(?:Follow|Mute|Unfollow|Unmute)\w*\s*[:=]\s*(?:async\s*)?(?:function\s*)?"
        r"(?:\(\s*[\w$]*\s*(?::\s*\w+)?\s*\)|[\w$]+)\s*(?:=>)?"
        r"|(?:async\s+)?newsletter(?:Follow|Mute|Unfollow|Unmute)\w*\s*\([^)]{0,40}\)"
        r"\s*(?::\s*[\w<>]+\s*)?\{"
    )
    _DEFINED: ClassVar[re.Pattern[str]] = re.compile(r"(?:async|function)\s+newsletterFollow\s*\(")
    _OPT_IN: ClassVar[re.Pattern[str]] = re.compile(
        r"if\s*\(\s*[\w$.?]*(?i:follow)[\w$.?]*\s*===\s*true\s*\)"
    )
    _CHANNEL: ClassVar[re.Pattern[str]] = re.compile(
        r"\b\d{15,22}@newsletter\b|(?<![A-Za-z0-9])0029V[A-Za-z0-9]{18,22}(?![A-Za-z0-9])"
    )
    _FETCH: ClassVar[re.Pattern[str]] = re.compile(
        r"raw\.githubusercontent\.com|(?<![\w$.])fetch\s*\(|axios\s*\.\s*get\s*\(|https?\.get\s*\("
    )
    _AUTO: ClassVar[re.Pattern[str]] = re.compile(
        r"auto_?(?:follow|join)|follow_?list", re.IGNORECASE
    )
    _CHAR_CODES: ClassVar[re.Pattern[str]] = re.compile(
        r"\[\s*+(?:\d{2,3}\s*+,\s*+){7,}\d{2,3}\s*+\]"
    )
    API_WINDOW: ClassVar[int] = 220
    OPT_IN_WINDOW: ClassVar[int] = 600

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        if "newsletter" not in text:
            return []
        uses = [m for m in self._USE.finditer(text) if self._invoked(text, m)]
        hidden = self._char_coded(text)
        if not uses and not any("newsletterFollow" in s for s in hidden):
            return []
        reasons = self._reasons(text, hidden)
        if not reasons:
            return []
        if uses:
            line, snippet = _line_and_snippet(text, uses[0].start(), uses[0].end())
        else:
            line, snippet = 1, "(method name and channels built from char codes)"
        return [
            FileMatch(
                rule_id=self.id,
                rule_version=self.version,
                severity=self.severity,
                weight=self.weight,
                title=self.title,
                explanation=(
                    "Follows WhatsApp channels with the user's account, outside the library's "
                    f"own follow method; the file {', '.join(reasons)}. Unwanted (account "
                    "abuse), not by itself a sign of malware."
                ),
                line=line,
                snippet=snippet,
            )
        ]

    def _invoked(self, text: str, match: re.Match[str]) -> bool:
        """A follow the code makes itself: not the API's definition, and not opt-in."""
        start = match.start()
        if self._DEFINED.search(text, max(0, start - 15), match.end()):
            return False
        if self._API.search(text, max(0, start - self.API_WINDOW), start):
            return False
        return not self._OPT_IN.search(text, max(0, start - self.OPT_IN_WINDOW), start)

    def _char_coded(self, text: str) -> list[str]:
        out = []
        for match in self._CHAR_CODES.finditer(text):
            codes = [int(n) for n in re.findall(r"\d+", match.group(0))]
            if all(32 <= c < 127 for c in codes):
                out.append("".join(map(chr, codes)))
        return out

    def _reasons(self, text: str, hidden: list[str]) -> list[str]:
        reasons = []
        if self._CHANNEL.search(text):
            reasons.append("names channels")
        elif any(self._CHANNEL.search(s) for s in hidden) or any(
            self._CHANNEL.search(s) for s in decoded_strings(text)
        ):
            reasons.append("hides channel ids (base64 or char codes)")
        if self._FETCH.search(text):
            reasons.append("fetches over the network")
        if self._AUTO.search(text):
            reasons.append("calls it an auto-follow or auto-join")
        return reasons


RULES: Final = (
    KnownSignature(),
    ChannelFollow(),
    ShellStartup(),
    ExfilEndpoint(),
    WebhookPlaceholder(),
    EncodedUrl(),
    FunctionRequire(),
    SensitivePath(),
    EnvHarvest(),
    HardcodedIp(),
    EncodedBlob(),
    DynamicCode(),
    Obfuscated(),
    NpmPublish(),
    ProcessExec(),
    Network(),
)
