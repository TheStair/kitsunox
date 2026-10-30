"""Hidden characters and safe links in untrusted text."""

from __future__ import annotations

import unicodedata

import pytest

from kitsunox.util.text import (
    DEFAULT_IGNORABLE,
    HIDDEN_CATEGORIES,
    hidden_note,
    is_hidden,
    safe_url,
    strip_hidden,
)

# Each named because real attacks or Unicode's invisible sets use it.
HIDDEN = {
    "\x00": "NUL",
    "\x1b": "escape",
    "\r": "carriage return",
    "\x7f": "DEL",
    "\x85": "C1 next line",
    "\u00ad": "soft hyphen",
    "\u034f": "combining grapheme joiner",
    "\u061c": "Arabic letter mark",
    "\u115f": "Hangul choseong filler",
    "\u1160": "Hangul jungseong filler",
    "\u17b4": "Khmer vowel inherent aq",
    "\u17b5": "Khmer vowel inherent aa",
    "\u180b": "Mongolian FVS1",
    "\u180e": "Mongolian vowel separator",
    "\u180f": "Mongolian FVS4",
    "\u200b": "zero width space",
    "\u200d": "zero width joiner",
    "\u200e": "left-to-right mark",
    "\u2028": "line separator",
    "\u2029": "paragraph separator",
    "\u202e": "right-to-left override",
    "\u2060": "word joiner",
    "\u2064": "invisible plus",
    "\u2066": "left-to-right isolate",
    "\u3164": "Hangul filler",
    "\ufe00": "variation selector 1",
    "\ufe0f": "variation selector 16",
    "\ufeff": "byte order mark",
    "\uffa0": "halfwidth Hangul filler",
    "\ufff9": "interlinear annotation anchor",
    "\ufffb": "interlinear annotation terminator",
    "\ue000": "private use (os-info-checker-es6)",
    "\uf8ff": "private use",
    "\U000f0000": "supplementary private use A",
    "\U0010fffd": "supplementary private use B",
    "\U0001bca0": "shorthand format letter overlap",
    "\U0001d173": "musical symbol begin beam",
    "\U0001d17a": "musical symbol end phrase",
    "\U000e0001": "language tag",
    "\U000e0041": "tag latin capital A",
    "\U000e007f": "cancel tag",
    "\U000e0100": "variation selector 17 (GlassWorm)",
    "\U000e01ef": "variation selector 256",
    "\ud800": "lone surrogate",
}
VISIBLE = "aZ09 ~\t\n\u00a0\u00e9\u0430\u05d0\u4e2d\u00e9\u0301\U0001f600\ufffd"


@pytest.mark.parametrize("char", sorted(HIDDEN))
def test_hidden_characters(char: str) -> None:
    assert is_hidden(char), HIDDEN[char]
    assert strip_hidden(f"a{char}b") == ("ab", 1)


@pytest.mark.parametrize("char", VISIBLE)
def test_visible_characters_are_kept(char: str) -> None:
    assert not is_hidden(char)


def test_counts_and_the_ascii_fast_path() -> None:
    assert strip_hidden("plain ascii\tand\nnewline") == ("plain ascii\tand\nnewline", 0)
    assert strip_hidden("a\x00b\x1fc\x7f") == ("abc", 3)
    assert strip_hidden(VISIBLE) == (VISIBLE, 0)
    assert strip_hidden("".join(HIDDEN)) == ("", len(HIDDEN))
    glassworm = "eval(" + "".join(chr(0xE0100 + i) for i in range(200)) + ")"
    assert strip_hidden(glassworm) == ("eval()", 200)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a\r\nb\r\n", ("a\nb\n", 0)),  # CRLF: the \r goes, uncounted
        ("\ufeffline 1\n", ("line 1\n", 0)),  # a leading BOM goes, uncounted
        ("\ufeffa\r\nb\u00e9\r\n", ("a\nb\u00e9\n", 0)),  # both, on the non-ASCII path
        ("a\rb", ("ab", 1)),  # a lone \r still counts
        ("a\r", ("a", 0)),  # at the very end: a CRLF cut at the \n (Stage 2 snippets)
        ("a\r\r\nb", ("a\nb", 1)),  # only the \r right before \n is a line ending
        ("a\ufeffb", ("ab", 1)),  # a BOM anywhere else still counts
        ("\ufeff\ufeffa", ("a", 1)),  # only one leading BOM is exempt
        ("\r\n\u200b", ("\n", 1)),
    ],
)
def test_line_endings_and_a_leading_bom_are_not_counted(
    value: str, expected: tuple[str, int]
) -> None:
    assert strip_hidden(value) == expected


def test_every_default_ignorable_and_category_member_is_hidden() -> None:
    for low, high in DEFAULT_IGNORABLE:
        assert all(is_hidden(chr(point)) for point in range(low, high + 1))
    for point in range(0x110000):
        char = chr(point)
        if char not in "\t\n" and unicodedata.category(char) in HIDDEN_CATEGORIES:
            assert is_hidden(char), hex(point)


def test_notes() -> None:
    assert hidden_note(1) == "[1 hidden character removed]"
    assert hidden_note(37) == "[37 hidden characters removed]"
    assert hidden_note(1234) == "[1,234 hidden characters removed]"


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "javascript:alert(1)",
        "data:text/html,x",
        "http://example.com/",
        "//example.com/",
        "https://",
        "https://-bad.example/",
        "https://www.npmjs.com@evil.example/",
        "https://user:pass@example.com/",
        'https://example.com/"onmouseover=x',
        "https://example.com/'x",
        "https://example.com/<x>",
        "https://example.com/`x`",
        "https://example.com/a b",
        "https://example.com/a\\b",
        "https://example.com\\@evil.example/",
        "https://example.com/\x01",
        "https://example.com/\x7f",
        "https://example.com/\n",
        "https://exa\u043cple.com/",
        "https://example.com/\u202e",
        "https://example.com:123456/",
        " https://example.com/",
    ],
)
def test_unsafe_urls(url: str | None) -> None:
    assert safe_url(url) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://www.npmjs.com/package/@scope/x/v/1.0.0?activeTab=code",
        "https://npmdiff.dev/x/1.0.0/1.0.1/",
        "https://github.com/a/b/tree/0123abc/packages/x",
        "https://localhost:8443/a#frag",
        "https://example.com",
    ],
)
def test_safe_urls(url: str) -> None:
    assert safe_url(url) == url


def test_the_cache_is_bounded() -> None:
    info = is_hidden.cache_info()
    assert info.maxsize is not None and info.maxsize <= 65_536


def test_a_cr_left_by_a_snippet_cut_at_the_newline_is_not_hidden() -> None:
    assert strip_hidden('require("child_process").exec(x);\r') == (
        'require("child_process").exec(x);',
        0,
    )
    assert strip_hidden("a\rb") == ("ab", 1)  # a lone CR inside the text still counts
