"""Signatures of malware families Kitsunox has confirmed: a repost is known on arrival.

Every signature comes from our own malicious verdicts (`data/verdicts/npm.jsonl`): a family's
endpoints, accounts and wallets, or a set of strings its payload always carries. None comes
from a registry takedown or an outside list (decision 0016: the pipeline finds its own
malware). Each names the verdicts it was taken from, so a reviewer can read the original.

Matching (`static.known-signature`, a Stage 2 file rule) looks at a file's text and at the
strings its obfuscation hides (`decoded_strings`):

- the tavern family's string tables: a base64 string array next to a one-byte XOR key
  (`["..."];const _0x1a2b=0x9f;`), re-keyed on every republish;
- javascript-obfuscator's string arrays (base64 with its lowercase-first alphabet), only in a
  file with its `_0x` identifiers;
- plain base64 string literals of 16+ characters (`kevinx-baileys` hid its channel ids so,
  `node-ac3` its `curl` command).

A signature fires when all of its patterns match the file's text plus decoded strings.
Findings are HIGH and, unlike other Stage 2 matches, are not demoted when the previous
version's file matched too: a known payload stays known. A match only in documentation, types
or tests is demoted as usual (a security tool's README may list these indicators).

`SIGNATURES_VERSION` is the rule's version: change it with the set, so a replay recomputes.
Measured before each addition on every captured tarball with a verdict and a sample of other
captured tarballs (`docs/stages/static.md`).
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import ClassVar, Final

from kitsunox.core.models import Severity
from kitsunox.core.rules import FileMatch

SIGNATURES_VERSION: Final = 1
MAX_DECODED: Final = 20_000  # decoded strings kept per file
MAX_LITERALS: Final = 5_000  # base64 literals tried per file
SNIPPET: Final = 160


@dataclass(frozen=True)
class Signature:
    id: str
    family: str
    patterns: tuple[re.Pattern[str], ...]  # all must match the text or a decoded string
    seen_in: tuple[str, ...]  # the malicious verdicts it was taken from (name@version)


def _p(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p) for p in patterns)


SIGNATURES: Final = (
    Signature(
        "KX-0001",
        "tavern LLM-credential stealer (AWS, Bedrock and invoice API calls in XOR string tables)",
        _p(
            r"/create-foundation-model-agreement",
            r"AWSInvoicingService\.ListInvoiceSummaries",
            r"Action=GetCallerIdentity&Version=2011-06-15",
        ),
        (
            "tavern-ai-sdk@1.0.0",
            "char-ai-sdk@1.0.0",
            "character-ai-sdk@1.0.0",
            "persona-ai-sdk@1.0.0",
        ),
    ),
    Signature(
        "KX-0002",
        "tavern LLM-credential stealer's TRON wallets",
        _p(r"\bT(?:MfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|XfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG)\b"),
        ("tavern-ai-sdk@1.0.0", "persona-ai-sdk@1.0.0"),
    ),
    Signature(
        "KX-0003",
        "claims-* install-time recon (payload tarballs in the GamerD11/ping_test repository)",
        _p(r"GamerD11/ping_test"),
        ("claims-acct-unlock@25.2.1", "claims-ac1@1.0.0"),
    ),
    Signature(
        "KX-0004",
        "dependency-confusion probe sending user, host and directory to 38.242.235.206/depconf",
        _p(r"\b38\.242\.235\.206\b"),
        ("internal-renderers@1.0.0", "ms-client-portal@1.0.0", "pandafortunerush@1.0.0"),
    ),
    Signature(
        "KX-0005",
        "notsemz probes posting host data (webhook.site token, 130.162.231.177:8443)",
        _p(r"d730a68c-27bd-4bb5-b1b9-d57a0a4b17ac|\b130\.162\.231\.177\b"),
        ("@pcb-dp/qa-commons@1.0.0", "ssite-mock-server@0.0.1"),
    ),
    Signature(
        "KX-0006",
        "out-of-band beacon ids of known probe authors (interactsh, Burp Collaborator)",
        _p(r"dbhmeq71af5395un3p70tujr84cuwuyg7|94bp9h8fte9kz9v8btc6in8qnht8h85x"),
        ("@mobile-platform/magnetic-components@0.0.3", "dependencykfeg@2.1.3"),
    ),
    Signature(
        "KX-0007",
        "Discord webhook of calculator-preinstall-hook-demo (hostname and user name at install)",
        _p(r"discord(?:app)?\.com/api/webhooks/1566215853794394162\b"),
        ("calculator-preinstall-hook-demo@1.1.2",),
    ),
    Signature(
        "KX-0008",
        "Baileys fork that makes the user's WhatsApp account follow hard-coded channels",
        _p(r"\b\d{15,22}@newsletter\b", r"\bFOLLOW\b", r"newsletterWMexQuery"),
        ("@chatbridgeworld/baileys@1.0.0", "kevinx-baileys@1.2.2", "@bil-rgb/baileys@1.0.0"),
    ),
    Signature(
        "KX-0009",
        "Baileys forks fetching the channel list they follow (NOXLEYS, saurus)",
        _p(r"noxXza/data|push-saurus\.yorunime\.sbs"),
        ("luna-baileys@1.0.0", "sauruspro-bail@5.0.0"),
    ),
)

# A base64 string array right before a one-byte key: the tavern family's string tables.
_XOR_TABLE: Final = re.compile(
    r"\[((?:\"[A-Za-z0-9+/=]*\",?){3,})\];\s*const\s+[\w$]+\s*=\s*0x([0-9a-fA-F]{1,2})\s*;"
)
_QUOTED: Final = re.compile(r'"([^"]*)"')
_B64_LITERAL: Final = re.compile(r"""["'`]([A-Za-z0-9+/]{16,}={0,2})["'`]""")
_OBFUSCATOR: Final = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
_STD: Final = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_OBFUSCATOR_ALPHABET: Final = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/", _STD
)


def _b64(text: str) -> bytes | None:
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except binascii.Error, ValueError:
        return None


def _printable(data: bytes) -> str | None:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if decoded and decoded.isprintable() else None


def decoded_strings(text: str) -> Iterator[str]:
    """Strings a file's obfuscation hides, at most `MAX_DECODED` (see the module docstring)."""
    count = 0
    for table in _XOR_TABLE.finditer(text):
        key = int(table.group(2), 16)
        for item in _QUOTED.findall(table.group(1)):
            raw = _b64(item)
            if raw is not None and (decoded := _printable(bytes(b ^ key for b in raw))):
                yield decoded
                count += 1
                if count >= MAX_DECODED:
                    return
    obfuscated = len(_OBFUSCATOR.findall(text, 0, 1_000_000)) >= 20
    for i, literal in enumerate(_B64_LITERAL.finditer(text)):
        if i >= MAX_LITERALS:
            return
        value = literal.group(1)
        candidates = [value]
        if obfuscated:
            candidates.append(value.translate(_OBFUSCATOR_ALPHABET))
        for candidate in candidates:
            raw = _b64(candidate)
            if raw is not None and (decoded := _printable(raw)):
                yield decoded
                count += 1
                if count >= MAX_DECODED:
                    return


class KnownSignature:
    """A file carries a known family's signature (`SIGNATURES`), in its text or in strings its
    obfuscation hides. HIGH, weight 6: a repost of confirmed malware is reported first."""

    id: ClassVar[str] = "static.known-signature"
    version: ClassVar[int] = SIGNATURES_VERSION
    severity: ClassVar[Severity] = Severity.HIGH
    weight: ClassVar[float] = 6.0
    title: ClassVar[str] = "Matches a known malware family"

    def __init__(self, signatures: Sequence[Signature] = SIGNATURES) -> None:
        self.signatures = signatures

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        decoded: str | None = None  # computed only when the text alone doesn't decide
        out = []
        for signature in self.signatures:
            where = [p.search(text) for p in signature.patterns]
            if not all(where):
                if decoded is None:
                    decoded = "\n".join(decoded_strings(text))
                if not all(
                    m is not None or p.search(decoded)
                    for m, p in zip(where, signature.patterns, strict=True)
                ):
                    continue
            first = next((m for m in where if m is not None), None)
            line = text.count("\n", 0, first.start()) + 1 if first else 1
            snippet = (
                text[max(0, first.start() - 40) : first.end() + 40]
                if first
                else "(in decoded strings)"
            )
            out.append(
                FileMatch(
                    rule_id=self.id,
                    rule_version=self.version,
                    severity=self.severity,
                    weight=self.weight,
                    title=self.title,
                    explanation=(
                        f"Signature {signature.id}: {signature.family}. Taken from "
                        f"{', '.join(signature.seen_in[:3])}"
                        + (" (in strings the file's obfuscation hides)." if first is None else ".")
                    ),
                    line=line,
                    snippet=snippet[:SNIPPET],
                )
            )
        return out
