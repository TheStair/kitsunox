"""npm semver ranges: a port of node-semver 7.7.4 plus npm-pick-manifest 11.0.3's version pick.

Stage 5's offline dependency bundle has to choose the dependency versions npm 11.12.1 would
choose inside the sandbox image, so this module follows the exact code npm ships rather than a
reading of the semver spec. Sources (npm/cli tag `v11.12.1`, which commits its `node_modules`;
`NPM` = `https://github.com/npm/cli/blob/v11.12.1/`):

- `NPM/node_modules/semver/internal/re.js`: the token regexes, including the "safe"
  bounded-quantifier rewrite (`#L27-L40`) that every class below actually uses.
- `NPM/node_modules/semver/classes/semver.js`: version parsing (`#L10-L79`) and precedence
  (`#L93-L166`), `internal/identifiers.js` for identifier order.
- `NPM/node_modules/semver/classes/range.js`: range desugaring (`#L100-L168`), carets, tildes,
  x-ranges, hyphens (`#L254-L521`) and the prerelease rule in `testSet` (`#L523-L557`).
- `NPM/node_modules/semver/classes/comparator.js`: comparator parsing (`#L10-L77`).
- `NPM/node_modules/npm-pick-manifest/lib/index.js` (11.0.3): `pick_version`.

The port is literal on purpose. JavaScript behaviour that differs from Python's defaults is
reproduced explicitly: `\\s` and `String.prototype.trim` use JavaScript's whitespace set,
`\\d` is ASCII only, `$` never matches before a trailing newline, and `+M + 1` goes through a
float64 and JavaScript's number-to-string conversion (so a 22-digit major becomes `1e+21`,
which no comparator accepts). Everything here is pure: no I/O, no clock.

Precedence reuses `semver.SemVer` as the value type, but compares with node-semver's
`compareIdentifiers`, which differs from `SemVer.__lt__` in one corner: prerelease identifiers
that are digit strings too large for a safe integer compare numerically (as float64), not as
text.
"""

from __future__ import annotations

import functools
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Final, Literal

from kitsunox.ecosystems.npm.semver import SemVer

__all__ = [
    "MAX_RANGE_LENGTH",
    "NODE_VERSION",
    "NPM_VERSION",
    "Comparator",
    "InvalidRange",
    "InvalidVersion",
    "Pick",
    "Range",
    "clean",
    "compare",
    "engines_ok",
    "max_satisfying",
    "parse_version",
    "pick",
    "pick_version",
    "satisfies",
    "valid",
    "valid_range",
]

# The sandbox image (package-analysis rel-38) ships these; see the offline-dependency-bundle note.
NODE_VERSION: Final = "24.15.0"
NPM_VERSION: Final = "11.12.1"

# semver/internal/constants.js
_MAX_LENGTH: Final = 256
_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_SAFE_BUILD_LENGTH: Final = _MAX_LENGTH - 6
# Kitsunox's own cap on a range string, a deliberate divergence: node-semver has none for
# ranges (versions have `MAX_LENGTH`, 256). The unanchored `comparatorTrim` scan is quadratic
# in a run of `v`, `=` or whitespace (a 16,000-character `vvv...` took 2.4 s), and specs and
# `engines` values are package text. A longer string is an invalid range here: as a spec it
# picks nothing (`invalid-spec`), as `engines.node`/`engines.npm` it fails `engines_ok`.
# Real ranges are far shorter (long `||` lists of carets run to a few hundred characters).
MAX_RANGE_LENGTH: Final = 1024


class InvalidRange(ValueError):
    """A string node-semver's `new Range()` would reject with a TypeError."""


class InvalidVersion(ValueError):
    """A string node-semver's `new SemVer()` would reject with a TypeError."""


# --- JavaScript string and number semantics -------------------------------------------------

# ECMAScript WhiteSpace + LineTerminator: what `\s` matches and what `trim()` strips.
_JS_WS_CODEPOINTS: Final = (
    *(0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680),
    *range(0x2000, 0x200B),
    *(0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF),
)
_JS_WS_CHARS: Final = "".join(map(chr, _JS_WS_CODEPOINTS))
_JS_WS_CLASS: Final = (
    "\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
)
_WS_RUN: Final = re.compile(f"[{_JS_WS_CLASS}]+")
_NUMERIC: Final = re.compile(r"[0-9]+")


def _js_trim(text: str) -> str:
    return text.strip(_JS_WS_CHARS)


def _js_split_ws(text: str) -> list[str]:
    """`text.split(/\\s+/)`."""
    return _WS_RUN.split(text)


def _js_number_to_string(value: float) -> str:
    """`Number.prototype.toString()` for a non-negative number (ECMA-262 Number::toString).

    `repr` gives the shortest round-trip digits, as the ECMAScript algorithm requires."""
    if math.isinf(value):
        return "Infinity"
    if value == 0:
        return "0"
    sign, digit_tuple, exponent = Decimal(repr(value)).as_tuple()
    assert isinstance(exponent, int)  # noqa: S101 - finite by the check above
    digits = "".join(map(str, digit_tuple))
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = k + exponent  # value = 0.<digits> x 10^n
    prefix = "-" if sign else ""
    if k <= n <= 21:
        return prefix + digits + "0" * (n - k)
    if 0 < n <= 21:
        return prefix + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return prefix + "0." + "0" * -n + digits
    mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{prefix}{mantissa}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"


def _js_inc(number: str) -> str:
    """`${+number + 1}` for a string of ASCII digits."""
    return _js_number_to_string(float(number) + 1.0)


def _js_length(text: str) -> int:
    """`text.length`: UTF-16 code units."""
    return len(text.encode("utf-16-le")) // 2


def _js_truthy(value: object) -> bool:
    """JavaScript truthiness of a JSON value (`[]` and `{}` are truthy, `""` and `0` aren't)."""
    if value is None or value is False:
        return False
    if value is True:
        return True
    if isinstance(value, int | float):
        return value != 0 and not math.isnan(value)
    if isinstance(value, str):
        return value != ""
    return True


# --- semver/internal/re.js -------------------------------------------------------------------

_LETTERDASHNUMBER: Final = "[a-zA-Z0-9-]"


def _make_safe(value: str) -> str:
    """`makeSafeRegex` (`re.js#L33-L40`): bound `*` and `+` on three tokens."""
    for token, limit in (
        ("\\s", 1),
        ("\\d", _MAX_LENGTH),
        (_LETTERDASHNUMBER, _MAX_SAFE_BUILD_LENGTH),
    ):
        value = value.replace(f"{token}*", f"{token}{{0,{limit}}}")
        value = value.replace(f"{token}+", f"{token}{{1,{limit}}}")
    return value


def _compile(js_source: str) -> re.Pattern[str]:
    """Compile a node-semver token source as its `safeRe` entry, with JavaScript semantics."""
    source = _make_safe(js_source)
    # Possessive: what follows `[v=\s]*` is always a digit, `x`, `X` or `*`, none of which the
    # class matches, so giving characters back can never lead to a match. Same matches and
    # groups, without the futile backtracking over a long run.
    source = source.replace("[v=\\s]*", f"[v={_JS_WS_CLASS}]*+")
    source = source.replace("[v=\\s]", f"[v={_JS_WS_CLASS}]")
    source = source.replace("\\s", f"[{_JS_WS_CLASS}]").replace("\\d", "[0-9]")
    source = source.replace("$", "\\Z")
    return re.compile(source)


_NUMERICIDENTIFIER: Final = "0|[1-9]\\d*"
_NUMERICIDENTIFIERLOOSE: Final = "\\d+"
_NONNUMERICIDENTIFIER: Final = f"\\d*[a-zA-Z-]{_LETTERDASHNUMBER}*"
_MAINVERSION: Final = f"({_NUMERICIDENTIFIER})\\.({_NUMERICIDENTIFIER})\\.({_NUMERICIDENTIFIER})"
_MAINVERSIONLOOSE: Final = (
    f"({_NUMERICIDENTIFIERLOOSE})\\.({_NUMERICIDENTIFIERLOOSE})\\.({_NUMERICIDENTIFIERLOOSE})"
)
_PRERELEASEIDENTIFIER: Final = f"(?:{_NONNUMERICIDENTIFIER}|{_NUMERICIDENTIFIER})"
_PRERELEASEIDENTIFIERLOOSE: Final = f"(?:{_NONNUMERICIDENTIFIER}|{_NUMERICIDENTIFIERLOOSE})"
_PRERELEASE: Final = f"(?:-({_PRERELEASEIDENTIFIER}(?:\\.{_PRERELEASEIDENTIFIER})*))"
_PRERELEASELOOSE: Final = (
    f"(?:-?({_PRERELEASEIDENTIFIERLOOSE}(?:\\.{_PRERELEASEIDENTIFIERLOOSE})*))"
)
_BUILDIDENTIFIER: Final = f"{_LETTERDASHNUMBER}+"
_BUILD: Final = f"(?:\\+({_BUILDIDENTIFIER}(?:\\.{_BUILDIDENTIFIER})*))"
_FULLPLAIN: Final = f"v?{_MAINVERSION}{_PRERELEASE}?{_BUILD}?"
_LOOSEPLAIN: Final = f"[v=\\s]*{_MAINVERSIONLOOSE}{_PRERELEASELOOSE}?{_BUILD}?"
_GTLT: Final = "((?:<|>)?=?)"
_XRANGEIDENTIFIERLOOSE: Final = f"{_NUMERICIDENTIFIERLOOSE}|x|X|\\*"
_XRANGEIDENTIFIER: Final = f"{_NUMERICIDENTIFIER}|x|X|\\*"
_XRANGEPLAIN: Final = (
    f"[v=\\s]*({_XRANGEIDENTIFIER})"
    f"(?:\\.({_XRANGEIDENTIFIER})"
    f"(?:\\.({_XRANGEIDENTIFIER})"
    f"(?:{_PRERELEASE})?{_BUILD}?"
    ")?)?"
)
_XRANGEPLAINLOOSE: Final = (
    f"[v=\\s]*({_XRANGEIDENTIFIERLOOSE})"
    f"(?:\\.({_XRANGEIDENTIFIERLOOSE})"
    f"(?:\\.({_XRANGEIDENTIFIERLOOSE})"
    f"(?:{_PRERELEASELOOSE})?{_BUILD}?"
    ")?)?"
)
_LONETILDE: Final = "(?:~>?)"
_LONECARET: Final = "(?:\\^)"

_RE_FULL: Final = _compile(f"^{_FULLPLAIN}$")
_RE_LOOSE: Final = _compile(f"^{_LOOSEPLAIN}$")
_RE_BUILD: Final = _compile(_BUILD)
_RE_XRANGE: Final = _compile(f"^{_GTLT}\\s*{_XRANGEPLAIN}$")
_RE_XRANGELOOSE: Final = _compile(f"^{_GTLT}\\s*{_XRANGEPLAINLOOSE}$")
_RE_TILDETRIM: Final = _compile(f"(\\s*){_LONETILDE}\\s+")
_RE_TILDE: Final = _compile(f"^{_LONETILDE}{_XRANGEPLAIN}$")
_RE_TILDELOOSE: Final = _compile(f"^{_LONETILDE}{_XRANGEPLAINLOOSE}$")
_RE_CARETTRIM: Final = _compile(f"(\\s*){_LONECARET}\\s+")
_RE_CARET: Final = _compile(f"^{_LONECARET}{_XRANGEPLAIN}$")
_RE_CARETLOOSE: Final = _compile(f"^{_LONECARET}{_XRANGEPLAINLOOSE}$")
_RE_COMPARATORLOOSE: Final = _compile(f"^{_GTLT}\\s*({_LOOSEPLAIN})$|^$")
_RE_COMPARATOR: Final = _compile(f"^{_GTLT}\\s*({_FULLPLAIN})$|^$")
_RE_COMPARATORTRIM: Final = _compile(f"(\\s*){_GTLT}\\s*({_LOOSEPLAIN}|{_XRANGEPLAIN})")
_RE_HYPHENRANGE: Final = _compile(f"^\\s*({_XRANGEPLAIN})\\s+-\\s+({_XRANGEPLAIN})\\s*$")
_RE_HYPHENRANGELOOSE: Final = _compile(
    f"^\\s*({_XRANGEPLAINLOOSE})\\s+-\\s+({_XRANGEPLAINLOOSE})\\s*$"
)
_RE_STAR: Final = _compile("(<|>)?=?\\s*\\*")
_RE_GTE0: Final = _compile("^\\s*>=\\s*0\\.0\\.0\\s*$")
_RE_GTE0PRE: Final = _compile("^\\s*>=\\s*0\\.0\\.0-0\\s*$")


# --- semver/classes/semver.js ----------------------------------------------------------------


@functools.lru_cache(maxsize=65536)
def _parse(version: str, loose: bool) -> SemVer | None:
    """`new SemVer(version, {loose})`, or None where it throws (`semver.js#L10-L79`)."""
    if _js_length(version) > _MAX_LENGTH:
        return None
    match = (_RE_LOOSE if loose else _RE_FULL).search(_js_trim(version))
    if match is None:
        return None
    major, minor, patch = int(match[1]), int(match[2]), int(match[3])
    if max(major, minor, patch) > _MAX_SAFE_INTEGER:
        return None
    prerelease: list[int | str] = []
    if match[4]:
        for ident in match[4].split("."):
            if _NUMERIC.fullmatch(ident) and int(ident) < _MAX_SAFE_INTEGER:
                prerelease.append(int(ident))
            else:
                prerelease.append(ident)
    return SemVer(major, minor, patch, tuple(prerelease))


def _format(version: SemVer) -> str:
    """`SemVer.format()`: the canonical string, without build metadata."""
    text = f"{version.major}.{version.minor}.{version.patch}"
    if version.prerelease:
        text += "-" + ".".join(str(p) for p in version.prerelease)
    return text


def _compare_identifiers(a: int | str, b: int | str) -> int:
    """`internal/identifiers.js` `compareIdentifiers`."""
    if isinstance(a, int) and isinstance(b, int):
        return 0 if a == b else -1 if a < b else 1
    a_num = isinstance(a, int) or _NUMERIC.fullmatch(a) is not None
    b_num = isinstance(b, int) or _NUMERIC.fullmatch(b) is not None
    if a_num and b_num:
        fa, fb = float(a), float(b)  # `+a`, `+b`: float64, as JavaScript does
        return 0 if fa == fb else -1 if fa < fb else 1
    if a == b:
        return 0
    if a_num:
        return -1
    if b_num:
        return 1
    return -1 if str(a) < str(b) else 1


def _compare(a: SemVer, b: SemVer) -> int:
    """`SemVer.compare` (`semver.js#L93-L166`): main version, then prerelease."""
    if _format(a) == _format(b):
        return 0
    main_a, main_b = (a.major, a.minor, a.patch), (b.major, b.minor, b.patch)
    if main_a != main_b:
        return -1 if main_a < main_b else 1
    if a.prerelease and not b.prerelease:
        return -1
    if b.prerelease and not a.prerelease:
        return 1
    # Both have a prerelease here (equal formats returned above). The first identifiers that
    # differ decide, through compareIdentifiers, which can call two different float-equal
    # numeric strings equal; otherwise the longer list is greater (`comparePre`).
    for x, y in zip(a.prerelease, b.prerelease, strict=False):
        if x != y or type(x) is not type(y):
            return _compare_identifiers(x, y)
    return (len(a.prerelease) > len(b.prerelease)) - (len(a.prerelease) < len(b.prerelease))


def parse_version(version: str, *, loose: bool = False) -> SemVer | None:
    """`semver.parse`: the parsed version, or None if node-semver would reject it."""
    if not isinstance(version, str):
        return None
    return _parse(version, loose)


def valid(version: str, *, loose: bool = False) -> str | None:
    """`semver.valid`: the canonical version string (build metadata dropped), or None."""
    parsed = parse_version(version, loose=loose)
    return None if parsed is None else _format(parsed)


def clean(version: str, *, loose: bool = False) -> str | None:
    """`semver.clean`: `valid` after trimming whitespace and leading `=`/`v` characters."""
    if not isinstance(version, str):
        return None
    stripped = re.sub(r"\A[=v]+", "", _js_trim(version))
    return valid(stripped, loose=loose)


def compare(a: str, b: str, *, loose: bool = False) -> int:
    """`semver.compare`: -1, 0 or 1. Raises InvalidVersion where node-semver throws."""
    parsed_a, parsed_b = parse_version(a, loose=loose), parse_version(b, loose=loose)
    if parsed_a is None or parsed_b is None:
        raise InvalidVersion(f"Invalid Version: {a if parsed_a is None else b}")
    return _compare(parsed_a, parsed_b)


# --- semver/classes/comparator.js ------------------------------------------------------------

Operator = Literal["", "<", "<=", ">", ">="]
# Every string `_GTLT` can capture.
_OPERATORS: Final[dict[str, Operator]] = {
    "": "",
    "=": "",
    "<": "<",
    "<=": "<=",
    ">": ">",
    ">=": ">=",
}


@dataclass(frozen=True)
class Comparator:
    """One `<op><version>` term. `semver` None is node-semver's `Comparator.ANY` (value `""`)."""

    operator: Operator
    semver: SemVer | None

    @property
    def value(self) -> str:
        return "" if self.semver is None else self.operator + _format(self.semver)

    def __str__(self) -> str:
        return self.value

    @classmethod
    def parse(cls, comp: str, *, loose: bool = False) -> Comparator:
        """`new Comparator(comp, {loose})` (`comparator.js#L10-L55`)."""
        comp = " ".join(_js_split_ws(_js_trim(comp)))
        match = (_RE_COMPARATORLOOSE if loose else _RE_COMPARATOR).search(comp)
        if match is None:
            raise InvalidRange(f"Invalid comparator: {comp}")
        operator = _OPERATORS[match[1] or ""]  # `=` is the same as no operator
        if not match[2]:
            return cls("", None)
        version = _parse(match[2], loose)
        if version is None:
            raise InvalidRange(f"Invalid comparator: {comp}")
        return cls(operator, version)

    def test(self, version: SemVer) -> bool:
        if self.semver is None:
            return True
        order = _compare(version, self.semver)
        match self.operator:
            case "":
                return order == 0
            case ">":
                return order > 0
            case ">=":
                return order >= 0
            case "<":
                return order < 0
            case _:
                return order <= 0


# --- semver/classes/range.js -----------------------------------------------------------------

_NULL_SET: Final = "<0.0.0-0"


def _is_x(ident: str | None) -> bool:
    return not ident or ident.lower() == "x" or ident == "*"


def _replace_tilde(comp: str, loose: bool) -> str:
    """`replaceTilde` (`range.js#L288-L314`)."""

    def replace(m: re.Match[str]) -> str:
        major, minor, patch, pre = m[1] or "", m[2] or "", m[3] or "", m[4]
        if _is_x(major):
            return ""
        if _is_x(minor):
            return f">={major}.0.0 <{_js_inc(major)}.0.0-0"
        if _is_x(patch):
            return f">={major}.{minor}.0 <{major}.{_js_inc(minor)}.0-0"
        if pre:
            return f">={major}.{minor}.{patch}-{pre} <{major}.{_js_inc(minor)}.0-0"
        return f">={major}.{minor}.{patch} <{major}.{_js_inc(minor)}.0-0"

    return (_RE_TILDELOOSE if loose else _RE_TILDE).sub(replace, comp, count=1)


def _replace_caret(comp: str, loose: bool, include_prerelease: bool) -> str:
    """`replaceCaret` (`range.js#L332-L383`), including the `^0.x` and `^0.0.x` rules."""
    z = "-0" if include_prerelease else ""

    def replace(m: re.Match[str]) -> str:
        major, minor, patch, pre = m[1] or "", m[2] or "", m[3] or "", m[4]
        if _is_x(major):
            return ""
        if _is_x(minor):
            return f">={major}.0.0{z} <{_js_inc(major)}.0.0-0"
        if _is_x(patch):
            if major == "0":
                return f">={major}.{minor}.0{z} <{major}.{_js_inc(minor)}.0-0"
            return f">={major}.{minor}.0{z} <{_js_inc(major)}.0.0-0"
        low = f">={major}.{minor}.{patch}" + (f"-{pre}" if pre else z)
        if major == "0":
            if minor == "0":
                return f"{low} <{major}.{minor}.{_js_inc(patch)}-0"
            return f"{low} <{major}.{_js_inc(minor)}.0-0"
        # A version without prerelease gets no `-0` here, even with includePrerelease (#L375).
        low = f">={major}.{minor}.{patch}" + (f"-{pre}" if pre else "")
        return f"{low} <{_js_inc(major)}.0.0-0"

    return (_RE_CARETLOOSE if loose else _RE_CARET).sub(replace, comp, count=1)


def _replace_xrange(comp: str, loose: bool, include_prerelease: bool) -> str:
    """`replaceXRange` (`range.js#L393-L466`)."""
    comp = _js_trim(comp)

    def replace(m: re.Match[str]) -> str:
        ret, gtlt = m[0], m[1] or ""
        major, minor, patch = m[2] or "", m[3] or "", m[4] or ""
        x_major = _is_x(m[2])
        x_minor = x_major or _is_x(m[3])
        x_patch = x_minor or _is_x(m[4])
        any_x = x_patch
        if gtlt == "=" and any_x:
            gtlt = ""
        pr = "-0" if include_prerelease else ""
        if x_major:
            return "<0.0.0-0" if gtlt in (">", "<") else "*"
        if gtlt and any_x:
            if x_minor:
                minor = "0"
            patch = "0"
            if gtlt == ">":
                gtlt = ">="
                if x_minor:
                    major, minor, patch = _js_inc(major), "0", "0"
                else:
                    minor, patch = _js_inc(minor), "0"
            elif gtlt == "<=":
                gtlt = "<"
                if x_minor:
                    major = _js_inc(major)
                else:
                    minor = _js_inc(minor)
            if gtlt == "<":
                pr = "-0"
            return f"{gtlt}{major}.{minor}.{patch}{pr}"
        if x_minor:
            return f">={major}.0.0{pr} <{_js_inc(major)}.0.0-0"
        if x_patch:
            return f">={major}.{minor}.0{pr} <{major}.{_js_inc(minor)}.0-0"
        return ret

    return (_RE_XRANGELOOSE if loose else _RE_XRANGE).sub(replace, comp, count=1)


def _hyphen_replace(m: re.Match[str], include_prerelease: bool) -> str:
    """`hyphenReplace` (`range.js#L491-L521`): `1.2 - 3.4` is `>=1.2.0 <3.5.0-0`."""
    from_, f_major, f_minor, f_patch, f_pre = m[1] or "", m[2], m[3], m[4], m[5]
    to, t_major, t_minor, t_patch, t_pre = m[7] or "", m[8], m[9], m[10], m[11]
    z = "-0" if include_prerelease else ""
    if _is_x(f_major):
        low = ""
    elif _is_x(f_minor):
        low = f">={f_major}.0.0{z}"
    elif _is_x(f_patch):
        low = f">={f_major}.{f_minor}.0{z}"
    elif f_pre:
        low = f">={from_}"
    else:
        low = f">={from_}{z}"
    if _is_x(t_major):
        high = ""
    elif _is_x(t_minor):
        high = f"<{_js_inc(t_major or '')}.0.0-0"
    elif _is_x(t_patch):
        high = f"<{t_major}.{_js_inc(t_minor or '')}.0-0"
    elif t_pre:
        high = f"<={t_major}.{t_minor}.{t_patch}-{t_pre}"
    elif include_prerelease:
        high = f"<{t_major}.{t_minor}.{_js_inc(t_patch or '')}-0"
    else:
        high = f"<={to}"
    return _js_trim(f"{low} {high}")


def _map_tokens(comp: str, step: Callable[[str], str], *, trim: bool = True) -> str:
    return " ".join(step(c) for c in _js_split_ws(_js_trim(comp) if trim else comp))


def _parse_comparator(comp: str, loose: bool, include_prerelease: bool) -> str:
    """`parseComparator` (`range.js#L257-L269`): carets, tildes, x-ranges, then stars."""
    comp = _RE_BUILD.sub("", comp, count=1)
    comp = _map_tokens(comp, lambda c: _replace_caret(c, loose, include_prerelease))
    comp = _map_tokens(comp, lambda c: _replace_tilde(c, loose))
    comp = _map_tokens(comp, lambda c: _replace_xrange(c, loose, include_prerelease), trim=False)
    return _RE_STAR.sub("", _js_trim(comp), count=1)


def _parse_set(part: str, loose: bool, include_prerelease: bool) -> tuple[Comparator, ...]:
    """`Range.parseRange` (`range.js#L100-L168`) for one `||` alternative."""
    hyphen = _RE_HYPHENRANGELOOSE if loose else _RE_HYPHENRANGE
    part = hyphen.sub(lambda m: _hyphen_replace(m, include_prerelease), part, count=1)
    part = _RE_COMPARATORTRIM.sub(lambda m: (m[1] or "") + (m[2] or "") + (m[3] or ""), part)
    part = _RE_TILDETRIM.sub(lambda m: (m[1] or "") + "~", part)
    part = _RE_CARETTRIM.sub(lambda m: (m[1] or "") + "^", part)
    desugared = " ".join(_parse_comparator(c, loose, include_prerelease) for c in part.split(" "))
    gte0 = _RE_GTE0PRE if include_prerelease else _RE_GTE0
    terms = [gte0.sub("", _js_trim(c), count=1) for c in _js_split_ws(desugared)]
    if loose:
        terms = [c for c in terms if _RE_COMPARATORLOOSE.search(c)]
    comparators = [Comparator.parse(c, loose=loose) for c in terms]
    unique: dict[str, Comparator] = {}
    for comparator in comparators:
        if comparator.value == _NULL_SET:
            return (comparator,)
        unique[comparator.value] = comparator
    if len(unique) > 1:
        unique.pop("", None)
    return tuple(unique.values())


def _test_set(
    comparators: tuple[Comparator, ...], version: SemVer, include_prerelease: bool
) -> bool:
    """`testSet` (`range.js#L523-L557`). A prerelease version only matches when a comparator in
    the same set has a prerelease on the same major.minor.patch, unless includePrerelease."""
    if not all(c.test(version) for c in comparators):
        return False
    if version.prerelease and not include_prerelease:
        return any(
            c.semver is not None
            and c.semver.prerelease
            and (c.semver.major, c.semver.minor, c.semver.patch)
            == (version.major, version.minor, version.patch)
            for c in comparators
        )
    return True


@dataclass(frozen=True)
class Range:
    """A parsed npm range: an OR of comparator sets (`classes/range.js`)."""

    raw: str
    set: tuple[tuple[Comparator, ...], ...]
    loose: bool = False
    include_prerelease: bool = False

    @classmethod
    def parse(cls, spec: str, *, loose: bool = False, include_prerelease: bool = False) -> Range:
        """`new Range(spec, {loose, includePrerelease})`. Raises InvalidRange where it throws."""
        if not isinstance(spec, str):
            raise InvalidRange(f"Invalid SemVer Range: {spec!r}")
        if len(spec) > MAX_RANGE_LENGTH:
            raise InvalidRange(f"Invalid SemVer Range: over {MAX_RANGE_LENGTH} characters")
        parsed = _parse_range(spec, loose, include_prerelease)
        if isinstance(parsed, str):
            raise InvalidRange(parsed)
        return parsed

    @property
    def range(self) -> str:
        """The desugared form, e.g. `>=1.2.0 <2.0.0-0`; `""` for `*`."""
        return "||".join(" ".join(_js_trim(c.value) for c in comps) for comps in self.set)

    def __str__(self) -> str:
        return self.range

    def test(self, version: str) -> bool:
        """`Range.test`: whether the version satisfies any comparator set. Invalid versions
        never do, and never raise."""
        if not isinstance(version, str) or not version:
            return False
        parsed = _parse(version, self.loose)
        if parsed is None:
            return False
        return any(_test_set(s, parsed, self.include_prerelease) for s in self.set)


@functools.lru_cache(maxsize=16384)
def _parse_range(spec: str, loose: bool, include_prerelease: bool) -> Range | str:
    """The Range constructor (`range.js#L7-L71`), or the error message where it throws: a
    failure is cached too, so an invalid range (an `engines` value compared once per sort
    step in `pick`) is parsed once."""
    try:
        return _construct_range(spec, loose, include_prerelease)
    except InvalidRange as exc:
        return str(exc)


def _construct_range(spec: str, loose: bool, include_prerelease: bool) -> Range:
    raw = _WS_RUN.sub(" ", _js_trim(spec))
    sets = [
        comps
        for comps in (_parse_set(_js_trim(p), loose, include_prerelease) for p in raw.split("||"))
        if comps
    ]
    if not sets:
        raise InvalidRange(f"Invalid SemVer Range: {raw}")
    if len(sets) > 1:
        first = sets[0]
        sets = [comps for comps in sets if comps[0].value != _NULL_SET]
        if not sets:
            sets = [first]
        elif len(sets) > 1:
            for comps in sets:
                if len(comps) == 1 and comps[0].semver is None:
                    sets = [comps]
                    break
    return Range(raw, tuple(sets), loose, include_prerelease)


def satisfies(
    version: str, spec: str, *, loose: bool = False, include_prerelease: bool = False
) -> bool:
    """`semver.satisfies`: False for an invalid range or version, never raises."""
    try:
        parsed = Range.parse(spec, loose=loose, include_prerelease=include_prerelease)
    except InvalidRange:
        return False
    return parsed.test(version)


def valid_range(spec: str, *, loose: bool = False) -> str | None:
    """`semver.validRange`: the desugared range (`*` when it desugars to nothing), or None."""
    try:
        return Range.parse(spec, loose=loose).range or "*"
    except InvalidRange:
        return None


def max_satisfying(versions: Iterable[str], spec: str, *, loose: bool = False) -> str | None:
    """`semver.maxSatisfying` (`ranges/max-satisfying.js`): the highest version that satisfies
    `spec`, the first one seen among equals, or None (also for an invalid range)."""
    try:
        parsed = Range.parse(spec, loose=loose)
    except InvalidRange:
        return None
    best: str | None = None
    best_sv: SemVer | None = None
    for version in versions:
        if not parsed.test(version):
            continue
        current = _parse(version, loose)
        assert current is not None  # noqa: S101 - test() parsed it with the same options
        if best_sv is None or _compare(best_sv, current) == -1:
            best, best_sv = version, current
    return best


# --- npm-pick-manifest 11.0.3 ----------------------------------------------------------------

# encodeURIComponent leaves exactly these unescaped; npa refuses other tag names
# (`NPM/node_modules/npm-package-arg/lib/npa.js#L468-L470`).
_TAG_SAFE: Final = re.compile(r"[A-Za-z0-9\-_.!~*'()]*")

PickReason = Literal[
    "invalid-spec",
    "unknown-tag",
    "tag-not-candidate",
    "version-not-candidate",
    "no-versions-by-as-of",
    "no-match",
]


@dataclass(frozen=True)
class Pick:
    """The outcome of `pick`. `version` None comes with a `reason`.

    - `spec_type`: how npm-package-arg classifies the spec (`tag`, `version` or `range`).
    - `latest_after_as_of`: the `latest`-first step was skipped because `dist-tags.latest`
      satisfies the range but was published after `as_of` (or has no publish time).
    - `untimed`: versions excluded because they have no publish time to compare with `as_of`.
    """

    version: str | None
    spec_type: Literal["tag", "version", "range"]
    reason: PickReason | None = None
    latest_after_as_of: bool = False
    untimed: int = 0


def engines_ok(
    manifest: Mapping[str, Any], *, node: str = NODE_VERSION, npm: str = NPM_VERSION
) -> bool:
    """npm-install-checks 8.0.0 `checkEngine` (`lib/index.js#L5-L23`), as pick-manifest's
    `engineOk` (`lib/index.js#L8-L15`) calls it: `engines.node` must accept `node` and
    `engines.npm` must accept `npm`, prereleases included. An absent or non-object `engines`
    passes; a truthy value that isn't a valid range fails, as `satisfies` returns false."""
    engines = manifest.get("engines")
    if not isinstance(engines, Mapping):
        return True
    for key, current in (("node", node), ("npm", npm)):
        wanted = engines.get(key)
        if _js_truthy(wanted) and not (
            isinstance(wanted, str) and satisfies(current, wanted, include_prerelease=True)
        ):
            return False
    return True


def pick(
    packument_versions: Mapping[str, Any],
    dist_tags: Mapping[str, Any],
    spec: str,
    *,
    published: Mapping[str, datetime],
    as_of: datetime,
    node: str = NODE_VERSION,
    npm: str = NPM_VERSION,
) -> Pick:
    """The version npm 11.12.1 would install for `spec` at `as_of`, with the reason when none.

    A port of `NPM/node_modules/npm-pick-manifest/lib/index.js` (11.0.3) with Kitsunox's
    `as_of` rules from `docs/proposals/offline-dependency-bundle.md` ("Version pick"):

    - **Candidates** are versions whose manifest is an object, that aren't stub placeholders
      (`"stub": true`), and whose `published` time is at or before `as_of`. npm's `isBefore`
      (`#L17-L18`) lets a version with no time through; here it can't be shown to predate
      `as_of`, so it is excluded and counted in `untimed`.
    - **Spec type** follows npm-package-arg 13.0.2 `fromRegistry` (`npa.js#L454-L474`): the
      spec is trimmed, then a loose valid version is `version`, else a loose valid range is
      `range`, else a `tag`. An empty spec means the default tag, which npm treats as the
      range `*` (`#L88`, `#L115`).
    - **Tag** (`#L96-L105`): `dist-tags[spec]`, if it is a candidate. npm falls back to
      `<=tag` when the tag postdates `before`; the design note makes it unresolved instead.
    - **Exact version** (`#L107-L112`): `clean(spec, loose)` if it is a candidate, without the
      deprecation or engines checks.
    - **Range, `latest` first** (`#L117-L132`): `dist-tags.latest` wins if it is a candidate,
      satisfies the range (any `latest`, even a prerelease, when the spec is literally `*`),
      passes `engines_ok` and isn't deprecated.
    - **Range, otherwise** (`#L134-L184`): the satisfying candidates (`satisfies`, loose,
      prereleases excluded) sorted by: not deprecated and engines OK, then engines OK, then
      not deprecated, then highest version, ties kept in packument order (stable sort, as
      V8's). npm's avoid, restricted and staged keys never apply to public packuments.

    A spec longer than `MAX_RANGE_LENGTH` is `invalid-spec` (Kitsunox's cap, not npm's).
    `deprecated` uses JavaScript truthiness, as `!mani.deprecated` does. `spec` must be a
    registry spec: npa sends `file:`, `npm:` aliases, git, hosted-git shorthands and URLs to
    other fetchers before `fromRegistry` (`npa.js#L79-L113`), so callers classify those first
    (here they would just come back as an unknown or invalid tag).
    """
    # pacote 21.5.0 passes npa's `fetchSpec` (`lib/registry.js#L130`), which `fromRegistry`
    # trims (`npa.js#L456-L460`); every step below sees the trimmed spec.
    spec = _js_trim(spec)
    untimed = sum(
        1 for v, m in packument_versions.items() if isinstance(m, Mapping) and v not in published
    )
    if len(spec) > MAX_RANGE_LENGTH:  # npm would read it as a range or a tag; see the cap
        return Pick(None, "range", "invalid-spec", untimed=untimed)
    is_range_spec = not spec
    spec_type: Literal["tag", "version", "range"]
    if is_range_spec:
        spec_type = "range"
    elif valid(spec, loose=True) is not None:
        spec_type = "version"
    elif valid_range(spec, loose=True) is not None:
        spec_type = "range"
    else:
        spec_type = "tag"

    def candidate(version: str) -> bool:
        manifest = packument_versions.get(version)
        if not isinstance(manifest, Mapping) or manifest.get("stub") is True:
            return False
        time = published.get(version)
        return time is not None and time <= as_of

    if spec_type == "tag":
        if _TAG_SAFE.fullmatch(spec) is None:
            return Pick(None, "tag", "invalid-spec", untimed=untimed)
        tagged = dist_tags.get(spec)
        if not isinstance(tagged, str) or tagged not in packument_versions:
            return Pick(None, "tag", "unknown-tag", untimed=untimed)
        if not candidate(tagged):
            return Pick(None, "tag", "tag-not-candidate", untimed=untimed)
        return Pick(tagged, "tag", untimed=untimed)

    if spec_type == "version":
        exact = clean(spec, loose=True)
        if exact is None or not candidate(exact):
            return Pick(None, "version", "version-not-candidate", untimed=untimed)
        return Pick(exact, "version", untimed=untimed)

    range_spec = "*" if is_range_spec else spec

    def deprecated(manifest: Mapping[str, Any]) -> bool:
        return _js_truthy(manifest.get("deprecated"))

    latest = dist_tags.get("latest")
    latest_after = False
    if (
        isinstance(latest, str)
        and latest
        and (range_spec == "*" or satisfies(latest, range_spec, loose=True))
    ):
        manifest = packument_versions.get(latest)
        if candidate(latest):
            assert isinstance(manifest, Mapping)  # noqa: S101 - candidate() checked it
            if engines_ok(manifest, node=node, npm=npm) and not deprecated(manifest):
                return Pick(latest, "range", untimed=untimed)
        elif isinstance(manifest, Mapping) and manifest.get("stub") is not True:
            latest_after = True

    pool = [(v, m) for v, m in packument_versions.items() if candidate(v)]
    if not pool:
        return Pick(None, "range", "no-versions-by-as-of", latest_after, untimed)
    # (version, engines OK, not deprecated, parsed): each manifest's checks run once, not
    # once per comparison (npm's comparator calls `engineOk` on every step).
    matching: list[tuple[str, bool, bool, SemVer]] = []
    for version, manifest in pool:
        parsed = _parse(version, True)
        if parsed is not None and satisfies(version, range_spec, loose=True):
            ok = engines_ok(manifest, node=node, npm=npm)
            matching.append((version, ok, not deprecated(manifest), parsed))
    if not matching:
        return Pick(None, "range", "no-match", latest_after, untimed)

    def order(a: tuple[str, bool, bool, SemVer], b: tuple[str, bool, bool, SemVer]) -> int:
        _, ok_a, fresh_a, parsed_a = a
        _, ok_b, fresh_b, parsed_b = b
        return (
            int(fresh_b and ok_b) - int(fresh_a and ok_a)
            or int(ok_b) - int(ok_a)
            or int(fresh_b) - int(fresh_a)
            or _compare(parsed_b, parsed_a)
        )

    best = sorted(matching, key=functools.cmp_to_key(order))[0]
    return Pick(best[0], "range", None, latest_after, untimed)


def pick_version(
    packument_versions: Mapping[str, Any],
    dist_tags: Mapping[str, Any],
    spec: str,
    *,
    published: Mapping[str, datetime],
    as_of: datetime,
    node: str = NODE_VERSION,
    npm: str = NPM_VERSION,
) -> str | None:
    """The version npm would pick for `spec` at `as_of`, or None. See `pick` for the rules and
    for why a pick failed."""
    return pick(
        packument_versions,
        dist_tags,
        spec,
        published=published,
        as_of=as_of,
        node=node,
        npm=npm,
    ).version
