"""Stage 2 file rules: regular expressions and simple statistics over one file's text.

Ecosystem-agnostic: they look at code, not at npm concepts. Each rule is a pure function of the
text (so results can be cached by content hash). Severities are starting points; the numbers
behind each are in `docs/stages/static.md`.
"""

from __future__ import annotations

import base64
import functools
import ipaddress
import itertools
import json
import re
from collections.abc import Iterator, Sequence
from typing import ClassVar, Final

from kitsunox.core.models import Severity
from kitsunox.core.rules import FileMatch
from kitsunox.rules.padding import PaddedCode
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
    # v8 (2026-11-10, `docs/proposals/precision-round4-D.md` D1, D2): what is sent, not only
    # where to. LOW, weight 1, for a Telegram bot API URL whose token the code is handed
    # (`bot${config.botToken}`, `"bot" + token`, `bot{{TOKEN}}`), and for a `webhook.site`
    # URL with no token id (a UUID) within `TOKEN_WINDOW` characters, both only in a file that
    # collects nothing to send (`_collects`: no machine identity, environment dump, directory
    # walk or file upload, process, credential store or Telegram token literal) and not on an
    # install hook's line. A notifier for the user's own bot, a usage example. Telegram calls
    # in a file that also reads the hostname, runs commands or uploads files stay HIGH
    # (`@eooce/sbx`, `foundry-toolkit`, `github-badge-bot` on `vm-day1`), as does any literal
    # token (`bot7123…:AA…`), a shell `bot$TOKEN` and a `webhook.site` host near a UUID
    # (`hostname: 'webhook.site', path: '/89403f83-…'`).

    # v9 (2026-11-11, `docs/proposals/precision-round5-L.md` L2, L3): LOW, weight 1, for what
    # can't be the endpoint it names, not on an install hook's line: a `trycloudflare.com` host
    # that is not a quick tunnel's name (`_not_quick_tunnel`: Cloudflare names every quick
    # tunnel with hyphen-joined words, `diameter-coins-limitations-parents`; `demo.`, `api.`,
    # `a.b.`, `word-word-word-word.` are not one), and a URL written as a UI placeholder or an
    # example (`placeholder: 'cezar.ngrok.app'`, `example: "curl https://webhook.site/…"`,
    # `e.g. https://…`; `_example_value`). v8's "collects nothing" still asks the whole file,
    # a bundle too: a window around the match (L4) was rejected by the owner (2026-11-10), as a
    # bundled drainer's Telegram send naturally sits far from its collection.
    # Also LOW: `pastebin.com/` with no paste or API after it (`_PASTE`: the site, a user's
    # page, `doc_api`; a site list's entry); a tunnel host whose label is an ellipsis
    # (`https://….trycloudflare.com`); `api.telegram.org/bot` followed by a comma (an entry of
    # a list of service prefixes, with no token); and a whole host literal among literals of
    # three services where brand names alone count (`"webhook.site", "requestbin", "ngrok"`:
    # a detection rule's substrings, `_in_name_list`). `bot&lt;token&gt;` (HTML for
    # `bot<token>`) is a written placeholder, as v4 decided for `bot<token>`.
    # v10 (2026-11-11, `docs/proposals/precision-round6-P.md` P1, P2): LOW, weight 1, not on an
    # install hook's line and whatever else the file does: a tunnel's bare suffix that a host
    # check compares with or an allowed-hosts setting lists (`_host_check`:
    # `hostname.endsWith(".trycloudflare.com")`, `allowedHosts: ['.ngrok.app']`,
    # `ALLOWED_HOSTS=.trycloudflare.com`), which v8 lowered only in a file that collects
    # nothing; and a bare service host named in a parenthesised list in prose (`_prose_list`:
    # "collectors (webhook.site, requestbin, ngrok, interact.sh)"); and, as `hardcoded-ip` v7
    # (P4), a host in a JSON catalog with URLs on `CATALOG_HOSTS` or more hosts (`_catalog`: an
    # MCP server directory listing a quick tunnel among thousands of servers).
    # v11 (round 7, `docs/proposals/precision-round7-X.md` X3, X4): LOW, weight 1, not on an
    # install hook's line, for a host anywhere inside the value of an `example` / `examples`
    # field (`_in_example`: an OpenAPI document's sample webhook log), and v8's handed
    # Telegram token written over two statements, the API's prefix assigned to a name on its
    # own (`BASE_URL='https://api.telegram.org/bot',`), only in a file that collects nothing.

    id = "static.exfil-endpoint"
    version = 11
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
        if match.group(0).lower() == "pastebin.com/" and not _PASTE.match(
            match.string, match.end()
        ):
            return NO_PASTE_NOTE
        if _host_pattern(match):
            return PATTERN_NOTE
        if _in_domain_list(match) or _in_separated_list(match) or _in_name_list(match):
            return LIST_NOTE
        if (
            match.group(0).lower().endswith("/bot")
            and match.string[match.end() : match.end() + 1] == ","
        ):
            return LIST_NOTE  # `…,api.telegram.org/bot,hooks.slack.com/…`: no token, a list
        if not _on_hook_line(match):
            if _not_quick_tunnel(match):
                return QUICK_TUNNEL_NOTE
            if _example_value(match, _host_span(match)[0]):
                return EXAMPLE_NOTE
            if _in_example(match.string, _host_span(match)[0]):
                return EXAMPLE_SCOPE_NOTE
            if _host_check(match):
                return HOST_CHECK_NOTE
            if _prose_list(match):
                return PROSE_LIST_NOTE
            if _catalog(match.string):
                return CATALOG_NOTE
        return _sends_nothing(match)


# A placeholder written as a tunnel host's own label, ending right before `.ngrok.io`,
# `.trycloudflare.com` or `.serveo.net`: a word label on its own (`example`, `xxx`, `your-app`,
# `foo`; not `sidebar`), or `<...>`, `*`, `${...}`, `{...}`, `..`.
_PLACEHOLDER_LABEL: Final = re.compile(
    r"(?:(?<![\w-])(?:examples?|x{3,}|your[-_]?[\w-]*|foo|bar|baz|abc\d*|random"
    r"|my[-_]?(?:app|tunnel|subdomain|domain))|<[^<>\n]*>|\*|\$?\{[^{}\n]*\}|\.{2,}|…)$",
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
# v9 (L2): what after `pastebin.com/` reads or writes a paste: a paste id (8 letters and
# digits; 5 to 16 taken, for margin), its raw, download, embed and print views, the API. The
# site's own pages (`pastebin.com/`, `/u/<user>`, `/doc_api`) hold nothing anyone wrote there.
_PASTE: Final = re.compile(
    r"(?:raw|dl|embed\w*|print|api)\b|raw\.php|[A-Za-z0-9]{5,16}(?![\w-])", re.IGNORECASE
)
NO_PASTE_NOTE: Final = (
    " `pastebin.com` itself, a user's page or its documentation: no paste and not the API."
)
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
_TELEGRAM_PLACEHOLDER: Final = re.compile(r"<|&lt;|\[|YOUR_|\.\.\.")
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


# v9: a service named by its brand alone, as a whole string literal (`"ngrok"`, `"oastify"`):
# what deny lists of substrings write; no host.
_SERVICE_NAME: Final = re.compile(
    r"""(?P<q>["'`])(?P<service>webhook|requestbin|pipedream|ngrok|burpcollaborator|oastify"""
    r"""|interactsh|canarytokens|requestcatcher|beeceptor|hookbin|pastebin|hastebin)(?P=q)""",
    re.IGNORECASE,
)


def _in_name_list(match: re.Match[str]) -> bool:
    """v9: a host written as a whole string literal among literals of at least
    `DENY_LIST_SERVICES` different services, brand names alone counting too (`"webhook.site",
    "requestbin", "pipedream", "ngrok"`: a detection rule's substrings)."""
    span = _whole_literal(match)
    if span is None:
        return False
    start, tail = span
    text = match.string
    lo = max(0, start - DENY_LIST_WINDOW)
    hi = min(len(text), tail + DENY_LIST_WINDOW)
    services = {
        m.group("service").lower().split(".")[0]
        for pattern in (_SERVICE_LITERAL, _SERVICE_NAME)
        for m in pattern.finditer(text, lo, hi)
    }
    return len(services) >= DENY_LIST_SERVICES


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


# v8: a Telegram bot token the code is handed, right after `api.telegram.org/bot`: a template
# (`${token}`, `{{TOKEN}}`, Python's `{token}` / `%s`) or the end of a string joined to an
# expression (`"…/bot" + token`, PHP's `'…/bot'.$token`). Not a shell `bot$TOKEN`: hooks and
# scripts write that.
_HANDED_TOKEN: Final = re.compile(r"""\$\{|\{\{|\{[A-Za-z_]|%s|["'`]\s*[+.]""")
# Round 7 (X4, `exfil-endpoint` v11): the API's prefix assigned to a name on its own, a
# constant the token is joined to later (`BASE_URL='https://api.telegram.org/bot',`,
# `const PREFIX = "…/bot";`): v8's handed token, written over two statements, and so also
# only in a file that collects nothing. An entry of a string array (`['…/bot', 'includes']`,
# obfuscator output, whose collection is hidden in the array too) is not assigned and stays.
_PREFIX_NAME: Final = re.compile(r"""(?<![\w$.])[A-Za-z_$][\w$]*\s*=\s*["'`](?:https?://)?$""")
_PREFIX_END: Final = re.compile(r"""["'`]\s*(?:[,;]|\r?\n)""")
# A Telegram bot token written out: `123456789:AA` and 33 more characters.
_TOKEN_LITERAL: Final = re.compile(r"(?<!\d)\d{8,10}:AA[A-Za-z0-9_-]{30,}")
# A webhook.site token: the UUID that names a bin (`/89403f83-77bf-4ccb-8ba0-e5a652841e0a`),
# often written apart from the host (`hostname: 'webhook.site', path: '/<uuid>'`).
_UUID: Final = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
TOKEN_WINDOW: Final = 300
# An install hook's line in a `package.json`: never lowered.
_HOOK_LINE: Final = re.compile(r'"(?:preinstall|install|postinstall|prepare)"\s*:')
# What a file collects to send, besides the environment (`EnvHarvest`) and credential stores
# (`SensitivePath`): machine identity (hostname, user, interfaces, public IP), a directory
# walk or a file upload, a process, a wallet secret, a Telegram token literal.
_COLLECT_PARTS: Final = (
    r"\bos\.(?:hostname|userInfo|networkInterfaces)\s*\(|\b(?:hostname|userInfo"
    r"|networkInterfaces)\(\)|\bwhoami\b|\$\(\s*(?:hostname|id|uname)\b|ipify|ifconfig\.me"
    r"|ipinfo\.io|ip-api\.com|icanhazip|checkip\.amazonaws|socket\.gethostname|getpass\.getuser",
    r"readdirSync|\breaddir\(|opendirSync|createReadStream|os\.walk|os\.listdir"
    r"|send(?:Document|Photo|Audio|Video|MediaGroup)\b",
    r"child_process|\b(?:execSync|execFileSync|spawnSync)\b|shell_exec|proc_open|subprocess"
    r"|os\.system|\bpopen\(",
    r"(?i:mnemonic|seed ?phrase|private ?key|wallet\.dat|keystore)",
    _TOKEN_LITERAL.pattern,
)
TELEGRAM_NOTE: Final = (
    " A Telegram bot API URL with a token the code is handed, in a file that collects nothing"
    " to send (no machine identity, environment, directory walk or upload, process,"
    " credential store or token literal): a notifier for the user's own bot."
)
# v8: a tunnel's domain suffix written bare (`host.endsWith(".trycloudflare.com")`,
# `allowedHosts: [".ngrok-free.app"]`, `https://….trycloudflare.com` in help text), and the
# API `cloudflared` registers quick tunnels with (`api.trycloudflare.com`): no tunnel's name.
_TUNNEL_SUFFIXES: Final = frozenset(
    {
        ".ngrok.io",
        ".ngrok.app",
        ".ngrok-free.io",
        ".ngrok-free.app",
        ".trycloudflare.com",
        ".serveo.net",
    }
)
_CF_API: Final = re.compile(r"(?<![\w.-])api$", re.IGNORECASE)
_HOST_END: Final = re.compile(r"(?![\w.-])")
TUNNEL_SUFFIX_NOTE: Final = (
    " A tunnel's bare domain suffix (a host check, an allowed-hosts list, help text), in a file"
    " that collects nothing to send: no tunnel's name, not an endpoint."
)
WEBHOOK_SITE_NOTE: Final = (
    " `webhook.site` with no token id near it, in a file that collects nothing to send (no"
    " machine identity, environment, directory walk or upload, process, credential store or"
    " token literal): a mention, not an endpoint."
)


@functools.cache
def _collect_pattern() -> re.Pattern[str]:
    return re.compile(
        "|".join((*_COLLECT_PARTS, SensitivePath.pattern.pattern, EnvHarvest.pattern.pattern))
    )


@functools.lru_cache(maxsize=4)
def _collects(text: str) -> bool:
    """Whether `text` (a whole file) collects something to send: `_COLLECT_PARTS`, a
    credential store (`SensitivePath`) or the whole environment (`EnvHarvest`). Cached: a
    file's matches all ask about the same text."""
    return _collect_pattern().search(text) is not None


def _sends_nothing(match: re.Match[str]) -> str | None:
    """v8: the note for a match that names a service but no endpoint on it, in a file that
    collects nothing (`_collects`) and not on an install hook's line: a Telegram bot API URL
    with a handed token (`TELEGRAM_NOTE`), a `webhook.site` mention with no token id within
    `TOKEN_WINDOW` characters and no subdomain (`WEBHOOK_SITE_NOTE`), a tunnel's bare domain
    suffix or Cloudflare's own `api.trycloudflare.com` (`TUNNEL_SUFFIX_NOTE`). None otherwise."""
    text, start, end = match.string, match.start(), match.end()
    found = match.group(0).lower()
    before = text[start - 1] if start > 0 else ""
    if found.endswith("/bot"):
        handed = _HANDED_TOKEN.match(text, end) or (
            _PREFIX_END.match(text, end) and _PREFIX_NAME.search(text, max(0, start - 80), start)
        )
        note = TELEGRAM_NOTE if handed else None
    elif found == "webhook.site":
        near = _UUID.search(text, max(0, start - TOKEN_WINDOW), end + TOKEN_WINDOW)
        note = None if near or before.isalnum() or before in "-." else WEBHOOK_SITE_NOTE
    elif found in _TUNNEL_SUFFIXES:
        bare = not (before.isalnum() or before in "-_") or _CF_API.search(text, 0, start)
        note = TUNNEL_SUFFIX_NOTE if bare and _HOST_END.match(text, end) else None
    else:
        note = None
    if note is None or _on_hook_line(match) or _collects(text):
        return None
    return note


def _on_hook_line(match: re.Match[str]) -> bool:
    """Whether `match` is on an install hook's line of a `package.json`."""
    text, start = match.string, match.start()
    return _HOOK_LINE.search(text, text.rfind("\n", 0, start) + 1, start) is not None


# v9: what Cloudflare names a quick tunnel: words joined by hyphens, four on every one seen
# (`diameter-coins-limitations-parents`, `gtk-optimize-webpage-tc` on `vm-day1`); at least
# three are asked for, and digits allowed, for margin.
_QUICK_TUNNEL_NAME: Final = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+){2,}")
_HOST_LABELS: Final = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.?")
QUICK_TUNNEL_NOTE: Final = (
    " Not a quick tunnel's name (Cloudflare names them with hyphen-joined words): a placeholder"
    " or Cloudflare's own host, which no one else can serve."
)


def _not_quick_tunnel(match: re.Match[str]) -> bool:
    """A `….trycloudflare.com` host written out whole whose name can't be a quick tunnel's: one
    word (`demo`, `api`, `u8bcd`), more than one label (`a.b`), fewer than three words
    (`abc-def`, `travel-calm`) or one word repeated (`word-word-word-word`). Not a name
    built in code (`${id}x.trycloudflare.com`, `id + "x.trycloudflare.com"`, `"-x.`)."""
    if match.group(0).lower() != ".trycloudflare.com":
        return False
    text, start = match.string, match.start()
    host_start, _ = _host_span(match)
    label = text[host_start:start].lower()
    if not label or not _HOST_LABELS.fullmatch(label) or label[0] == "-":
        return False
    before = text[host_start - 1] if host_start > 0 else ""
    if before and before in "}$)]+{%*\\":  # a name built in code: `${id}x.`, `(a)x.`
        return False
    if before and before in "\"'`" and text[: host_start - 1].rstrip().endswith("+"):
        return False  # `id + "x.trycloudflare.com"`
    words = label.split("-")
    return not _QUICK_TUNNEL_NAME.fullmatch(label) or len(set(words)) == 1


# v10 (round 6, P1): a tunnel's bare domain suffix that a host check compares with, or an
# allowed-hosts setting lists: `hostname.endsWith(".trycloudflare.com")`, Vite's
# `allowedHosts: ['.trycloudflare.com']`, `__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=.ngrok.app`.
# Code checks a host it was given against the suffix; nothing connects to a suffix.
_HOST_CHECK_LEAD: Final = re.compile(
    r"\.ends?[Ww]ith\(\s*[\"'`]$"
    r"|(?i:allowed_?hosts?)[\"'`]?\s*[:=]\s*\[[^\]\n]{0,160}[\"'`]$"
    r"|(?i:allowed_?hosts?)\s*=\s*[\"'`]?$"
)
HOST_CHECK_NOTE: Final = (
    " A tunnel's bare domain suffix that a host check compares with (`endsWith`) or an"
    " allowed-hosts setting lists: no tunnel's name, not an endpoint."
)


def _host_check(match: re.Match[str]) -> bool:
    """v10: a bare tunnel suffix (`_TUNNEL_SUFFIXES`, the whole host) right after
    `_HOST_CHECK_LEAD`."""
    text, start, end = match.string, match.start(), match.end()
    if match.group(0).lower() not in _TUNNEL_SUFFIXES or not _HOST_END.match(text, end):
        return False
    return _HOST_CHECK_LEAD.search(text, max(0, start - 200), start) is not None


# v10 (P2): a service named in prose, as an entry of a parenthesised list after a word:
# "collectors (webhook.site, requestbin, ngrok, interact.sh) or", "a request catcher
# (webhook.site, interact.sh)". The bare service host (no id, no scheme, no path) among other
# short entries; code never writes a host unquoted in a list after a space.
_PROSE_ITEM: Final = re.compile(r"[`*]{0,2}[\w][\w. /-]{0,30}[`*]{0,2}")
PROSE_LIST_NOTE: Final = (
    " A service named in a parenthesised list in prose (`(webhook.site, interact.sh)`): no id"
    " and no URL, not an endpoint."
)


def _prose_list(match: re.Match[str]) -> bool:
    """v10: a bare service host that is a whole entry of a `(a, b, c)` list opened after a
    space, with at least one other entry, each entry a short word or host."""
    if match.group(0).startswith("."):
        return False
    text = match.string
    start, end = _host_span(match)
    if (start, end) != (match.start(), match.end()):
        return False  # a subdomain or a path: an id
    lo = text.rfind("(", max(0, start - 120), start)
    hi = text.find(")", end, end + 120)
    if lo < 1 or hi < 0 or text[lo - 1] != " ":
        return False
    items = [item.strip() for item in text[lo + 1 : hi].split(",")]
    own = text[start:end]
    return (
        len(items) >= 2
        and all(_PROSE_ITEM.fullmatch(item) for item in items)
        and any(item.strip("`*") == own for item in items)
    )


# v9 (exfil-endpoint, hardcoded-ip): a URL written as the value of a UI placeholder
# (`placeholder: '…'`, `placeholder="…"`, `tunnelUrlPlaceholder:"…"`) or an `example:` field,
# up to 80 characters into the string, or right after `e.g.` / `for example`.
_EXAMPLE_LEAD: Final = re.compile(
    r"(?:(?i:placeholder)\\{0,3}[\"']?\s*[:=]|(?i:\bexamples?)\\{0,3}[\"']?\s*:)"
    r"\s*\\{0,3}[\"'`][^\"'`\n]{0,80}$"
    r"|(?i:\be\.g\.|\bfor example\b)[,:]?\s*[`'\"(]?(?:[a-z]+://)?$"
)
EXAMPLE_NOTE: Final = (
    " Written as a UI placeholder or an example (`placeholder:`, `example:`, `e.g.`): text shown"
    " to a user, not an endpoint."
)


def _example_value(match: re.Match[str], at: int) -> bool:
    """Whether the text before `at` (the match's host or URL) on its line, at most 120
    characters of it, ends in `_EXAMPLE_LEAD`."""
    text = match.string
    lo = max(text.rfind("\n", 0, at) + 1, at - 120)
    return _EXAMPLE_LEAD.search(text, lo, at) is not None


# Round 7 (X3; `exfil-endpoint` v11, `hardcoded-ip` v8): a URL anywhere inside the value of an
# `example` / `examples` field, an object or array opened right after the key: a parameter
# schema's sample call (`example: { server: "http://…", file: "…" }`), an OpenAPI document's
# `"examples": {"Example 1": {"value": {…}}}`, a form's `examples: [['http://…', 'what it
# does']]`. v9's `_example_value` asks only about the text right before the URL on its line.
_EXAMPLE_KEY: Final = re.compile(r"(?i:\b(?:x-)?examples?)\\{0,3}[\"']?\s*:\s*\\{0,3}[\"']?$")
EXAMPLE_SCOPE: Final = 2000
EXAMPLE_SCOPE_NOTE: Final = (
    " Inside the value of an `example` / `examples` field (a schema's or API document's sample"
    " data): shown to a user, not an endpoint."
)


def _openers(text: str, at: int, limit: int) -> Iterator[int]:
    """The positions of the brackets (`(`, `[`, `{`) still open at `at`, innermost first,
    within `limit` characters before it. Brackets are counted as written, strings and
    comments included: a balanced pair inside a string (`"{{ json data }}"`) changes nothing,
    an unbalanced one can only end the scan early or misplace it by a level."""
    depth = 0
    for i in range(at - 1, max(0, at - limit) - 1, -1):
        char = text[i]
        if char in ")]}":
            depth += 1
        elif char in "([{":
            if depth:
                depth -= 1
            else:
                yield i


def _in_example(text: str, at: int) -> bool:
    """X3: some object or array enclosing `at` (within `EXAMPLE_SCOPE` characters) is the
    value of an `example(s)` key, and no call's argument list is open in between: a URL
    handed to a function (`example: { x: get("http://…") }`) is used, not shown."""
    for i in _openers(text, at, EXAMPLE_SCOPE):
        if text[i] == "(":
            return False
        if _EXAMPLE_KEY.search(text, max(0, i - 40), i):
            return True
    return False


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
    giving it `require`.

    v2 (2026-11-10, `docs/proposals/precision-round4-D.md` D5): LOW, weight 1, for a module
    wrapper (`Function("require", "module", "exports", code)`: the code gets its own `module`
    and `exports`, as a CommonJS loader gives a file) in a file that neither fetches nor
    decodes anything (`_LOADS_REMOTE`): a config loader, a template or test sandbox evaluating
    code the package just compiled from local files. The second-stage loaders on `vm-day1`
    either pass `require` alone (`Function("require", runnable)`, the `chai-as-*` family) or
    fetch what they run (`alpha-replicator`'s module wrapper evaluates `data.credits` from a
    `fetch`), and stay MEDIUM."""

    id = "static.function-require"
    version = 2
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Compiles code at runtime and hands it `require`"
    pattern = re.compile(
        # Possessive `*+`: `\s` never matches `.`, `)` or `(`, so giving whitespace back can't
        # help, and without them "Function" plus a long run of spaces backtracks quadratically
        # (32k spaces took 0.44 s; a 16 MB file of them would stall Stage 2).
        r"""(?<![\w$])Function(?:\s*+\.\s*+constructor)?\s*+\)?\s*+\(\s*+["'`]require["'`]\s*+,"""
    )

    def lowered(self, match: re.Match[str]) -> str | None:
        if not _MODULE_WRAPPER.match(match.string, match.end()):
            return None
        return None if _loads_remote(match.string) else MODULE_WRAPPER_NOTE


# v2: the rest of a module wrapper's parameter list, after `require,`: string literals up to
# one naming `module` or `exports`.
_MODULE_WRAPPER: Final = re.compile(
    r"""\s*+(?:["'`]\w+["'`]\s*+,\s*+)*?["'`](?:module|exports)["'`]"""
)
# v2: a file that fetches or decodes something, so the code it compiles may not be its own.
_LOADS_REMOTE: Final = re.compile(
    r"\bfetch\s*\(|axios|\bhttps?\.(?:get|request)\b|XMLHttpRequest|\bgot\s*\(|WebSocket"
    r"|\bnet\.connect|\.json\(\)|\bresponse\b|(?i:base64|atob\(|decrypt|decipher|fromCharCode)"
)
MODULE_WRAPPER_NOTE: Final = (
    " A module wrapper (`module`/`exports`) in a file that neither fetches nor decodes"
    " anything: code the package compiled itself, as a loader or sandbox."
)


@functools.lru_cache(maxsize=4)
def _loads_remote(text: str) -> bool:
    return _LOADS_REMOTE.search(text) is not None


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
    `https://1.2.3.4:8443` as an input placeholder or in a help string). v5 (2026-11-10,
    `docs/proposals/precision-round4-D.md` D4): LOW, weight 1, on a comment line (`//`, `#`,
    a block comment's `/*` or `*` line, `<!--`): a commented-out base URL or a documented
    alternative, which nothing connects to as written. Not a URL after a block comment closes
    on the same line (`/*! v1 */ fetch("http://…")`). v6 (2026-11-11,
    `docs/proposals/precision-round5-L.md` L3): LOW, weight 1, for a URL written as a UI
    placeholder or an example (`placeholder: 'http://8.130.134.171'`, `# e.g. http://…`;
    `_example_value`, as `exfil-endpoint` v9), not on an install hook's line. v7 (2026-11-11,
    `docs/proposals/precision-round6-P.md` P3-P5): LOW, weight 1, not on an install hook's
    line, for an environment variable's fallback (`process.env.X || 'http://…'`,
    `_ENV_DEFAULT`), a URL in a JSON catalog with URLs on `CATALOG_HOSTS` or more hosts
    (`_catalog`), and a literal compared with or hashed (`=== 'http://…'`, `[…].includes(`,
    `.update(`; `_compared`). v8 (round 7, `docs/proposals/precision-round7-X.md` X2, X3,
    X5): LOW, weight 1, not on an install hook's line, for the default of a declared option
    or field (`{ name, type, default: 'http://…' }`, `.default('http://…')`;
    `_option_default`), a URL inside the value of an `example` / `examples` field
    (`_in_example`) and an entry of a set only asked `.has(` (`_set_member`), P5's searched
    array written as a `Set`; and (X1, its own commit) a constant used only as an environment
    variable's fallback (`const DEFAULT = 'http://…'` and `process.env.X || DEFAULT`;
    `_named_env_default`)."""

    id = "static.hardcoded-ip"
    version = 8
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
        if match.group(1) in EXAMPLE_IPS:
            return EXAMPLE_IP_NOTE
        if not _on_hook_line(match):
            if _example_value(match, match.start()):
                return EXAMPLE_NOTE
            if _in_example(match.string, match.start()):
                return EXAMPLE_SCOPE_NOTE
            if _option_default(match):
                return OPTION_DEFAULT_NOTE
            if _ENV_DEFAULT.search(match.string, max(0, match.start() - 120), match.start()):
                return ENV_DEFAULT_NOTE
            if _named_env_default(match):
                return ENV_DEFAULT_NOTE
            if _catalog(match.string):
                return CATALOG_NOTE
            if _compared(match) or _set_member(match):
                return COMPARED_NOTE
        return IP_COMMENT_NOTE if _on_comment_line(match) else None


# v7 and `exfil-endpoint` v10 (P4): a JSON document that lists URLs on at least
# `CATALOG_HOSTS` different hosts: a directory of other people's services (radio stations,
# MCP servers, threat-intel IOCs, fingerprint rules), not one program's configuration, which
# names its own few servers.
CATALOG_HOSTS: Final = 20
_URL_HOST: Final = re.compile(r"(?i:https?|wss?|tcp)://([A-Za-z0-9.-]+)")
CATALOG_NOTE: Final = (
    f" In a JSON document listing URLs on {CATALOG_HOSTS} or more hosts: a catalog of other"
    " people's services, not one program's configuration."
)


@functools.lru_cache(maxsize=4)
def _catalog(text: str) -> bool:
    """v7: `text` is a JSON document (it parses) with URLs on `CATALOG_HOSTS` or more
    different hosts."""
    if text.lstrip()[:1] not in ("{", "["):
        return False
    hosts: set[str] = set()
    for m in _URL_HOST.finditer(text):
        hosts.add(m.group(1).lower())
        if len(hosts) >= CATALOG_HOSTS:
            break
    else:
        return False
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


# v7 (P5): a URL literal that code compares a value with (`url.origin === "http://…"`,
# `["http://…", …].includes(x)`) or hashes (`createHash(…).update("http://…")`): a value
# checked against, which nothing connects to.
# The right side of a comparison, or a hash's input: `=== "…`, `.update("…`.
_COMPARED_RIGHT: Final = re.compile(r"(?:[=!]==?|\.update\()\s*[\"'`]$")
# The left side: the rest of the literal, its quote, then `===` (not `=>`).
_COMPARED_LEFT: Final = re.compile(r"[^\"'`\n]{0,200}[\"'`]\s*[=!]==?(?![=>])")
# An entry of an array of string literals that is searched: `["…", "…"].includes(`, also
# written `[…]['includes'](` (javascript-obfuscator's property form).
_ARRAY_BEFORE: Final = re.compile(r"\[\s*(?:[\"'`][^\"'`\n]{0,200}[\"'`]\s*,\s*){0,8}[\"'`]$")
_ARRAY_AFTER: Final = re.compile(
    r"[^\"'`\n]{0,200}[\"'`]\s*(?:,\s*[\"'`][^\"'`\n]{0,200}[\"'`]\s*){0,8}\]\s*"
    r"(?:\.includes|\[\s*[\"']includes[\"']\s*\])\("
)
COMPARED_NOTE: Final = (
    " A literal that code compares a value with (`===`, `[…].includes`) or hashes: checked"
    " against, not connected to."
)


def _compared(match: re.Match[str]) -> bool:
    """v7: `match` (a URL) is a string literal compared with `===`/`!==`/`==`/`!=` on either
    side, hashed (`.update("…")`), or an entry of an array of string literals searched with
    `.includes(`."""
    text, start, end = match.string, match.start(), match.end()
    lo, hi = max(0, start - 2000), min(len(text), end + 2000)
    if _COMPARED_RIGHT.search(text, lo, start) or _COMPARED_LEFT.match(text, end, hi):
        return True
    return bool(_ARRAY_BEFORE.search(text, lo, start) and _ARRAY_AFTER.match(text, end, hi))


# v8 (round 7, X5): P5's searched array written as a set: `LEGACY_URLS = /* @__PURE__ */ new
# Set(["http://…"])` whose name is used only as `LEGACY_URLS.has(x)`, a membership check
# (a legacy-address migration). A set the code also iterates (`for (u of S)`, `[...S]`,
# `S.forEach`) stays MEDIUM.
_SET_BEFORE: Final = re.compile(
    r"(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:/\*[^*\n]{0,40}\*/\s*)?new\s+Set\(\s*\[\s*"
    r"(?:[\"'`][^\"'`\n]{0,200}[\"'`]\s*,\s*){0,8}[\"'`]$"
)
_SET_AFTER: Final = re.compile(
    r"[^\"'`\n]{0,200}[\"'`]\s*(?:,\s*[\"'`][^\"'`\n]{0,200}[\"'`]\s*){0,8},?\s*\]\s*\)"
)


def _set_member(match: re.Match[str]) -> bool:
    """X5: `match` (a URL) is an entry of a set of string literals assigned to a name that
    the file uses, outside its declaration, only to ask `.has(`."""
    text, start, end = match.string, match.start(), match.end()
    declared = _SET_BEFORE.search(text, max(0, start - 2000), start)
    if declared is None or not _SET_AFTER.match(text, end, min(len(text), end + 2000)):
        return False
    name = declared.group("name")
    uses = [
        m.end()
        for m in re.finditer(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text)
        if m.start() != declared.start("name")
    ]
    return bool(uses) and all(text.startswith(".has(", at) for at in uses)


# v7 (round 6, P3): a URL that is an environment variable's fallback, as a configurable
# product writes its default backend: `process.env.X || 'http://…'`,
# `process.env["X"]?.trim() || "…"`, `process.env.X ?? …`, Python's
# `os.environ.get("X", "…")` / `os.getenv("X", "…")`, a shell `${X:-http://…}`.
_ENV_DEFAULT: Final = re.compile(
    r"(?:process\.env(?:\.\w+|\[\s*[\"'`]\w+[\"'`]\s*\])(?:\?\.\w+\(\))?\s*(?:\|\||\?\?)\s*"
    r"|os\.(?:environ\.get|getenv)\(\s*[\"']\w+[\"']\s*,\s*"
    r"|\$\{\w+:-)[\"'`]?$"
)
ENV_DEFAULT_NOTE: Final = (
    " The fallback of an environment variable (`process.env.X || '…'`): a configurable"
    " product's default server, which the user can point elsewhere."
)
# v8 (round 7, X1): P3's fallback written through a constant, `const DEFAULT_API_BASE =
# 'http://…'` and then `process.env.OMNI_API_BASE_URL || DEFAULT_API_BASE` (or `??`,
# `os.environ.get("X", NAME)`). Only when the constant is declared with the URL as its whole
# value and every other use of its name in the file is such a fallback: a constant the code
# also connects to directly (`fetch(C2 + path)`) stays MEDIUM.
_NAMED_URL: Final = re.compile(
    r"(?:\b(?:const|let|var)\s+|^[ \t]*)(?P<name>[A-Za-z_$][\w$]*)\s*=\s*[\"'`]$"
)
_ENV_LEAD: Final = re.compile(
    r"(?:process\.env(?:\.\w+|\[\s*[\"'`]\w+[\"'`]\s*\])(?:\?\.\w+\(\))?\s*(?:\|\||\?\?)\s*"
    r"|os\.(?:environ\.get|getenv)\(\s*[\"']\w+[\"']\s*,\s*)$"
)
_STATEMENT_END: Final = re.compile(r"\s*;?\s*(?:(?://|#).*)?\r?$")


def _named_env_default(match: re.Match[str]) -> bool:
    """X1: `match` (a URL) is the whole value of a constant (`_NAMED_URL`, the literal ends
    right after the URL's path) whose name is used, outside its declaration, only as an
    environment variable's fallback (`_ENV_LEAD` right before it), at least once."""
    text, start = match.string, match.start()
    line_start = text.rfind("\n", 0, start) + 1
    declared = _NAMED_URL.search(text[line_start:start])
    if declared is None:
        return False
    quote = text[start - 1]
    close = text.find(quote, match.end(), match.end() + 400)
    if close < 0 or "\n" in text[match.end() : close]:
        return False
    line_end = text.find("\n", close)
    if not _STATEMENT_END.match(text[close + 1 : len(text) if line_end < 0 else line_end]):
        return False  # `= 'http://…' + path`: more than the literal
    name = declared.group("name")
    uses = [
        m.start()
        for m in re.finditer(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text)
        if not line_start <= m.start() < close
    ]
    return bool(uses) and all(_ENV_LEAD.search(text, max(0, at - 120), at) for at in uses)


# v8 (round 7, X2): a URL that is the default of a declared option or field, the same kind of
# overridable setting as P3's environment fallback: `{ displayName: 'B46 URL', name: 'b46Url',
# type: 'string', default: 'http://…' }` (an n8n credential), `{ name: "bugUrl", label: "…",
# default: "http://…" }` (a form input), zod's `z.string().default("http://…")`. A `default:`
# key counts only in an object that also declares the option (`_OPTION_KEY`: its name, type,
# label or description), so a bare `{ default: 'http://…' }` lookup table stays MEDIUM.
_DEFAULT_KEY: Final = re.compile(r"(?<![\w$.])[\"']?default[\"']?\s*:\s*[\"'`]$")
_DEFAULT_CALL: Final = re.compile(r"\.default\(\s*[\"'`]$")
_OPTION_KEY: Final = re.compile(
    r"[{,\s][\"']?(?:name|type|label|displayName|description|desc|describe|title|help)[\"']?\s*:"
)
OPTION_SCOPE: Final = 400
OPTION_DEFAULT_NOTE: Final = (
    " The default value of a declared option or field (`{ name, type, default: '…' }`,"
    " `.default('…')`): a setting the user can change."
)


def _option_default(match: re.Match[str]) -> bool:
    """X2: `match` (a URL) is the string after `.default(`, or after a `default:` key in an
    object (the innermost bracket open at the URL is a `{`, within `OPTION_SCOPE` characters)
    that also has an `_OPTION_KEY` before or after it."""
    text, start = match.string, match.start()
    lo = max(0, start - 120)
    if _DEFAULT_CALL.search(text, lo, start):
        return True
    if not _DEFAULT_KEY.search(text, lo, start):
        return False
    opener = next(_openers(text, start, OPTION_SCOPE), None)
    if opener is None or text[opener] != "{":
        return False
    depth, close = 0, min(len(text), match.end() + OPTION_SCOPE)
    for i in range(match.end(), close):  # the object's end: its keys after the default too
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            if not depth:
                close = i
                break
            depth -= 1
    return _OPTION_KEY.search(text, opener, close) is not None


# v5: a line that is a comment where the match is: `//`, `# ` (not a shebang or a CSS `#id`
# selector), or inside a block comment opened on the line (`/*`) or continued from an earlier
# one (`*`), or HTML's `<!--`, with no close before the match.
_COMMENT_LEAD: Final = re.compile(r"[ \t]*(?P<lead>//|#(?=[ \t#])|/\*|\*(?!/)|<!--)")
_COMMENT_CLOSE: Final = {"/*": "*/", "*": "*/", "<!--": "-->"}
IP_COMMENT_NOTE: Final = " On a comment line: a commented-out or documented URL, not code."


def _on_comment_line(match: re.Match[str]) -> bool:
    """Whether `match` is on a comment line (`_COMMENT_LEAD`) whose comment is still open."""
    text, start = match.string, match.start()
    line_start = text.rfind("\n", 0, start) + 1
    lead = _COMMENT_LEAD.match(text, line_start, start)
    if lead is None:
        return False
    close = _COMMENT_CLOSE.get(lead.group("lead"))
    return close is None or close not in text[lead.end() : start]


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
    """javascript-obfuscator style output: many `_0x1a2b3c` identifiers.

    v2 (2026-11-11, `docs/proposals/precision-round5-L.md` L1): LOW, weight 1, in Emscripten
    glue whose `_0x` names are a minifier's, not an obfuscator's: a file with Emscripten's
    runtime (`getCFunc`, `HEAP8`/`HEAP32`, `Module["_" + name]`, at least `EMSCRIPTEN_MARKERS`
    of them), fewer than `GLUE_NAMES` distinct `_0x` names, and none of javascript-obfuscator's
    string-array machinery (`_STRING_ARRAY`: a lookup by hex index `_0x1a2b(0x1f3)`, the
    rotation loop `while(!![])`, `['push'](_0x…['shift']())`, `parseInt(_0x…(`).
    `emulatorjs-build`'s asm.js unzip workers rename 25 locals of `getCFunc` that way; every
    obfuscator.io payload on `vm-day1` and live has the string array, and stays MEDIUM."""

    id = "static.obfuscated"
    version = 2
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Obfuscated code"
    MIN_IDENTIFIERS: ClassVar[int] = 20
    EMSCRIPTEN_MARKERS: ClassVar[int] = 20
    GLUE_NAMES: ClassVar[int] = 100
    pattern = re.compile(r"\b_0x[0-9a-f]{4,6}\b")

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        matches = list(self.pattern.finditer(text))
        if len(matches) < self.MIN_IDENTIFIERS:
            return []
        first = matches[0]
        line, snippet = _line_and_snippet(text, first.start(), first.end())
        glue = self._emscripten_glue(text, {m.group(0) for m in matches})
        return [
            FileMatch(
                rule_id=self.id,
                rule_version=self.version,
                severity=Severity.LOW if glue else self.severity,
                weight=min(self.weight, 1.0) if glue else self.weight,
                title=self.title,
                explanation=f"{len(matches)} obfuscator-style identifiers."
                + (EMSCRIPTEN_NOTE if glue else ""),
                line=line,
                snippet=snippet,
            )
        ]

    def _emscripten_glue(self, text: str, names: set[str]) -> bool:
        if len(names) >= self.GLUE_NAMES or _STRING_ARRAY.search(text):
            return False
        markers = itertools.islice(_EMSCRIPTEN.finditer(text), self.EMSCRIPTEN_MARKERS)
        return sum(1 for _ in markers) >= self.EMSCRIPTEN_MARKERS


# v2: Emscripten's runtime glue, and javascript-obfuscator's string array (the part of its
# output that hides strings; renaming alone hides nothing a reader needs).
_EMSCRIPTEN: Final = re.compile(
    r"\bgetCFunc\b|\bHEAP(?:U?8|U?16|U?32|F32|F64)\b|Module\[\s*[\"']_[\"']\s*\+|\bSTACKTOP\b"
    r"|\bwasmMemory\b|\b_emscripten_\w+"
)
_STRING_ARRAY: Final = re.compile(
    r"\b_0x[0-9a-f]{3,8}\(\s*-?(?:0x[0-9a-f]+|[\"']0x[0-9a-f]+[\"'])"
    r"|while\s*\(\s*!!\[\]\s*\)"
    r"|\[[\"']push[\"']\]\(\s*_0x[0-9a-f]+\[[\"']shift[\"']\]\(\)\)"
    r"|\.push\(\s*_0x[0-9a-f]+\.shift\(\)\)|parseInt\(\s*_0x[0-9a-f]+\("
)
EMSCRIPTEN_NOTE: Final = (
    " In Emscripten glue (its runtime, a few renamed locals, no string array): a minifier's"
    " names, not an obfuscator's."
)


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
    variable reported at least 10 more benign versions before it was narrowed to these.

    v2 (2026-11-13, round 11 P3, `docs/proposals/gap-fixes-round11-N2.md`): the `inject` form
    is never "not new" in Stage 2 (`stages.static.ALWAYS_NEW_FORMS`) and a reported release's
    `inject` match is carried to its unchanged follow-ons (`FOLLOW_ON_ALONE`): a release that
    plants a sourced file or a prompt command in the shell start-up files does it again on
    every install. The matching itself is unchanged."""

    id: ClassVar[str] = "static.shell-startup"
    version: ClassVar[int] = 2
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

    @staticmethod
    def form(explanation: str) -> str | None:
        """The form (`hook`, `shell`, `inject`, `code`) a match's explanation names."""
        found = _FORM.search(explanation)
        return found.group(1) if found else None

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


_FORM: Final = re.compile(r"\(form `(\w+)`\)")
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


# Round 4: notes for LOW that depend on the rest of the file (what it collects, fetches or
# decodes), so the same match can be LOW in one version and not in the next. Stage 2 compares
# a match with the previous version's without them (`stages.static._key`): a Telegram URL the
# base already had is "not new" whether or not its file now collects.
CONTEXT_NOTES: Final = (
    TELEGRAM_NOTE,
    WEBHOOK_SITE_NOTE,
    TUNNEL_SUFFIX_NOTE,
    IP_COMMENT_NOTE,
    MODULE_WRAPPER_NOTE,
    # Round 6 (P): the same match is LOW in a version whose file is a catalog, checks a host
    # or compares it, and not in one that isn't (`dsh-pick` 0.5.1's catalog has URLs on 76
    # hosts, 0.5.2's on 14): with the note in its key, 0.5.2's IP was "new".
    HOST_CHECK_NOTE,
    PROSE_LIST_NOTE,
    CATALOG_NOTE,
    ENV_DEFAULT_NOTE,
    COMPARED_NOTE,
    # Round 7 (X): an enclosing `example` object or an option declaration can sit outside the
    # snippet and change between versions while the URL doesn't.
    EXAMPLE_SCOPE_NOTE,
    OPTION_DEFAULT_NOTE,
)


class ChannelTagging:
    """A WhatsApp library (a Baileys fork) that attaches a channel it chose to the messages the
    user sends: a newsletter JID written into the code (`newsletterJid: "1203...@newsletter"`,
    also as the fallback of an environment variable) in a file that builds the forwarded-
    newsletter context WhatsApp shows on a message (`ForwardedNewsletterMessageInfo`). Every
    image or message the user's account sends then advertises the author's channel.

    The owner's ruling (decision 0015, addendum 2026-11-09, "Baileys media tagging"): covert
    channel promotion, **unwanted**, like an auto-follow (`@codexverified/baileys` 2.19.18 and
    2.19.19). Upstream Baileys only defines the protobuf field and writes no JID. MEDIUM,
    weight 3, as `static.channel-follow`. Added 2026-11-09 (round 4,
    `docs/proposals/precision-round4-A.md`): before, those two versions were reported only
    because a Node-version check their `preinstall` runs had changed."""

    id: ClassVar[str] = "static.channel-tagging"
    version: ClassVar[int] = 1
    severity: ClassVar[Severity] = Severity.MEDIUM
    weight: ClassVar[float] = 3.0
    title: ClassVar[str] = "Tags the user's WhatsApp messages with a channel (unwanted)"

    _JID: ClassVar[re.Pattern[str]] = re.compile(
        r"\bnewsletterJid\s*+:\s*+(?:[\w$.]+\s*+(?:\|\||\?\?)\s*+)?[\"'`]\d{15,22}@newsletter[\"'`]"
    )
    _CONTEXT: ClassVar[re.Pattern[str]] = re.compile(r"(?i:forwardedNewsletterMessageInfo)")

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        if "@newsletter" not in text or not self._CONTEXT.search(text):
            return []
        match = self._JID.search(text)
        if match is None:
            return []
        line, snippet = _line_and_snippet(text, match.start(), match.end())
        return [
            FileMatch(
                rule_id=self.id,
                rule_version=self.version,
                severity=self.severity,
                weight=self.weight,
                title=self.title,
                explanation=(
                    "Writes a fixed WhatsApp channel into the forwarded-newsletter context of "
                    "messages: what the user's account sends advertises that channel. Unwanted "
                    "(covert channel promotion), not by itself a sign of malware."
                ),
                line=line,
                snippet=snippet,
            )
        ]


RULES: Final = (
    KnownSignature(),
    ChannelFollow(),
    ChannelTagging(),
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
    PaddedCode(),
)
