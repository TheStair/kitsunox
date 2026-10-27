"""Stage 2 file rules: regular expressions and simple statistics over one file's text.

Ecosystem-agnostic: they look at code, not at npm concepts. Each rule is a pure function of the
text (so results can be cached by content hash). Severities are starting points; the numbers
behind each are in `docs/stages/static.md`.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import ClassVar, Final

from kitsunox.core.models import Severity
from kitsunox.core.rules import FileMatch

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

    id = "static.exfil-endpoint"
    severity = Severity.HIGH
    weight = 5.0
    title = "Known exfiltration endpoint"
    pattern = re.compile(
        r"discord(?:app)?\.com/api/webhooks/|hooks\.slack\.com/services/|api\.telegram\.org/bot"
        r"|pastebin\.com/|paste\.ee/|hastebin\.|webhook\.site|requestbin|pipedream\.net"
        r"|\.oast\.(?:fun|me|pro|site|live|online)|oastify\.com|burpcollaborator\.net"
        r"|interact\.sh|\.ngrok(?:-free)?\.(?:io|app)|\.trycloudflare\.com|\.serveo\.net",
        re.IGNORECASE,
    )


class SensitivePath(RegexRule):
    """Credential and secret stores a package has no business reading."""

    id = "static.sensitive-path"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Reference to a credential or secret store"
    pattern = re.compile(
        r"\.npmrc|\.ssh/id_|\.ssh[\"'`]?\s*,\s*[\"'`]id_|\.aws/credentials|\.git-credentials"
        r"|\.bash_history|\.zsh_history|\.docker/config\.json|\.kube/config"
        r"|Login Data|Local State[\"'`]|\.config/gcloud|Exodus/exodus\.wallet|\.electrum/wallets"
        r"|Library/Keychains|/etc/shadow",
    )


class EnvHarvest(RegexRule):
    """The whole environment serialised or enumerated: environment variables hold CI tokens."""

    id = "static.env-harvest"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Collects all environment variables"
    pattern = re.compile(
        r"JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)"
        r"|\{\s*\.\.\.process\.env\s*\}\s*\)|os\.environ\.copy\(\)|dict\(os\.environ\)",
    )


class HardcodedIp(RegexRule):
    """A URL to a raw public IPv4 address: common for second-stage downloads and C2."""

    id = "static.hardcoded-ip"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "URL with a hardcoded public IP address"
    pattern = re.compile(r"(?:https?|wss?|tcp)://((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?")

    def accept(self, match: re.Match[str]) -> bool:
        try:
            address = ipaddress.IPv4Address(match.group(1))
        except ValueError:
            return False
        return address.is_global


class EncodedBlob(RegexRule):
    """Long base64 or hex runs: packed payloads. Image and font data URIs are excluded."""

    id = "static.encoded-blob"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Large encoded blob"
    MIN_LENGTH: ClassVar[int] = 200
    pattern = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}|(?:[0-9a-fA-F]{2}){100,}")
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

    id = "static.dynamic-code"
    severity = Severity.MEDIUM
    weight = 3.0
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

    id = "static.npm-publish"
    severity = Severity.MEDIUM
    weight = 3.0
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
    ExfilEndpoint(),
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
