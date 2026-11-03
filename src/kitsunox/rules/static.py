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
from kitsunox.rules.signatures import KnownSignature

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

    def explain(self, match: re.Match[str]) -> str:
        return f"Found `{match.group(0)[:80]}`."

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        out: list[FileMatch] = []
        for match in self.pattern.finditer(text):
            if not self.accept(match):
                continue
            line, snippet = _line_and_snippet(text, match.start(), match.end())
            out.append(
                FileMatch(
                    rule_id=self.id,
                    rule_version=self.version,
                    severity=self.severity,
                    weight=self.weight,
                    title=self.title,
                    explanation=self.explain(match),
                    line=line,
                    snippet=snippet,
                )
            )
            if len(out) >= MAX_MATCHES_PER_RULE:
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

    id = "static.exfil-endpoint"
    version = 5
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


def _in_deny_list(match: re.Match[str]) -> bool:
    """Whether `match` is a host written as a whole string literal among literals of at least
    `DENY_LIST_SERVICES` different services: a block or deny list, not an endpoint."""
    text, start, end = match.string, match.start(), match.end()
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "._-"):
        start -= 1
    tail = end
    if not match.group(0).lower().endswith("/bot"):
        while tail < len(text) and (text[tail].isalnum() or text[tail] in "._-"):
            tail += 1
    quote = text[start - 1 : start]
    if not quote or quote not in "\"'`" or text[tail : tail + 1] != quote:
        return False
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
    {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222"}
)


class HardcodedIp(RegexRule):
    """A URL to a raw public IPv4 address: common for second-stage downloads and C2. v2: not a
    well-known public DNS resolver (`PUBLIC_RESOLVERS`)."""

    id = "static.hardcoded-ip"
    version = 2
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


RULES: Final = (
    KnownSignature(),
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
