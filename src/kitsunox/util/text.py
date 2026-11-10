"""Untrusted text: hidden characters and safe links, shared by the Markdown reports and the
viewer.

Package text (names, versions, explanations quoting manifests, snippets, URLs) may carry
characters that render as nothing or reorder what is around them. Real npm malware has hidden
its payload in them: GlassWorm (2025) encoded code in variation selectors, and
os-info-checker-es6 (2025) in private-use characters; Trojan Source (2021) used bidirectional
overrides to make code read differently from what it is. So `strip_hidden` removes, by
Unicode general category rather than a hand-made list:

- `Cc` controls (C0, DEL, C1), except tab and newline;
- `Cf` format characters: bidi marks, overrides and isolates, zero-width characters, word
  joiners, invisible operators, the BOM, interlinear annotation, tag characters, musical
  formatting, shorthand format controls;
- `Co` private use, `Cs` surrogates (lone ones can't even be encoded), `Zl` and `Zp` line and
  paragraph separators;
- the rest of Unicode's `Default_Ignorable_Code_Point` set, which isn't `Cf`: the combining
  grapheme joiner, Hangul fillers, Khmer inherent vowels, Mongolian free variation selectors,
  variation selectors (`FE00`-`FE0F`, `E0100`-`E01EF`) and the unassigned ignorable ranges.

The carriage return of a CRLF line ending and a byte order mark at the very start are removed
too, but not counted: Windows and BOM-prefixed files are ordinary, and a marker on every such
snippet would be noise. A lone carriage return, or a BOM anywhere else, counts.

It reports how many it removed, so a page can say so: for a reviewer, hidden characters in a
package name or a snippet are a signal in themselves.

`safe_url` decides whether a URL may become a link at all: plain ASCII `https://`, a host name
with no user info (`https://www.npmjs.com@evil.example/` goes to evil.example), an optional
port, and no spaces, controls, quotes, angle brackets, backticks or backslashes.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Final

HIDDEN_CATEGORIES: Final = frozenset({"Cc", "Cf", "Co", "Cs", "Zl", "Zp"})
KEPT: Final = frozenset("\t\n")
BOM: Final = "\ufeff"
# Default_Ignorable_Code_Point (Unicode DerivedCoreProperties) outside `Cf`: these are `Mn`,
# `Lo` or unassigned, so the category test alone would keep them.
DEFAULT_IGNORABLE: Final = (
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x115F, 0x1160),  # Hangul choseong/jungseong fillers
    (0x17B4, 0x17B5),  # Khmer inherent vowels
    (0x180B, 0x180F),  # Mongolian free variation selectors (and the vowel separator)
    (0x2065, 0x2065),  # unassigned, in the invisible-operators block
    (0x3164, 0x3164),  # Hangul filler
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
    (0xFFF0, 0xFFF8),  # unassigned, before the interlinear annotation characters
    (0xE0000, 0xE0FFF),  # tags, variation selectors supplement, unassigned
)
_ASCII_HIDDEN: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_HOST: Final = r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"
_SAFE_URL: Final = re.compile(rf"https://{_HOST}(?::[0-9]{{1,5}})?(?:[/?#][\x21-\x7e]*)?")
_UNSAFE_URL_CHARS: Final = frozenset("\"'<>`\\")


@lru_cache(maxsize=65_536)
def is_hidden(char: str) -> bool:
    """Whether `char` (one code point) renders as nothing or changes how text around it reads.
    Tab and newline are not hidden."""
    if char in KEPT:
        return False
    if unicodedata.category(char) in HIDDEN_CATEGORIES:
        return True
    point = ord(char)
    return any(low <= point <= high for low, high in DEFAULT_IGNORABLE)


def strip_hidden(value: str) -> tuple[str, int]:
    """`value` without hidden characters (see `is_hidden`), and how many were removed.

    Some are removed without being counted, because ordinary files carry them: the `\\r` of a
    CRLF line ending (also one left at the very end, where a snippet was cut at the `\\n`), and
    one byte order mark at the very start. A lone `\\r` elsewhere, or a BOM anywhere else,
    still counts."""
    value = value.removeprefix(BOM).replace("\r\n", "\n").removesuffix("\r")
    if value.isascii():
        stripped = _ASCII_HIDDEN.sub("", value)
    else:
        stripped = "".join(char for char in value if not is_hidden(char))
    return stripped, len(value) - len(stripped)


def hidden_note(count: int) -> str:
    """The plain-text marker for `count` removed characters: "[3 hidden characters removed]"."""
    return f"[{count:,} hidden character{'' if count == 1 else 's'} removed]"


COLLAPSE_RUN: Final = 40
_RUN: Final = re.compile(rf"[ \t]{{{COLLAPSE_RUN},}}")


def collapse_runs(value: str) -> str:
    """`value` with every run of `COLLAPSE_RUN` or more spaces and tabs replaced by a marker
    that counts it (`⟨266 tabs⟩`, `⟨120 spaces⟩`, `⟨130 spaces and tabs⟩`), so a snippet cut to
    a width shows the code a run pushed off screen (`hauntview@0.2.9`: 266 tabs filled the
    whole 200-character diff line, which read as blank)."""
    return _RUN.sub(_run_marker, value)


def _run_marker(match: re.Match[str]) -> str:
    run = match.group(0)
    tabs = run.count("\t")
    kind = "tabs" if tabs == len(run) else "spaces" if not tabs else "spaces and tabs"
    return f"⟨{len(run):,} {kind}⟩"


def safe_url(url: str | None) -> str | None:
    """`url` if it is a plain `https://` URL safe to put in a link, else None."""
    if url is None or not url.isascii() or not _SAFE_URL.fullmatch(url):
        return None
    return None if _UNSAFE_URL_CHARS.intersection(url) else url
