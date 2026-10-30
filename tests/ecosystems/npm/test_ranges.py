"""Tests for `ecosystems/npm/ranges.py`: node-semver 7.7.4 ranges and npm-pick-manifest's pick.

The fixture tables below are node-semver's own test data, transcribed as plain data from tag
`v7.7.4` of https://github.com/npm/node-semver (the version npm 11.12.1 ships):
`test/fixtures/range-include.js`, `range-exclude.js`, `range-parse.js`, `comparisons.js`,
`equality.js`, `invalid-versions.js` and `valid-versions.js`, plus the cases inline in
`test/ranges/max-satisfying.js`, `test/classes/comparator.js`, `test/classes/range.js`,
`test/functions/satisfies.js`, `valid.js` and `clean.js`. node-semver is under the ISC licence:

    Copyright (c) Isaac Z. Schlueter and Contributors

    Permission to use, copy, modify, and/or distribute this software for any purpose with or
    without fee is hereby granted, provided that the above copyright notice and this permission
    notice appear in all copies.

Options are written as `(loose, include_prerelease)` booleans: node-semver's `true`,
`{ loose: 123 }` and other truthy `loose` values are `loose=True`; `{}`, `/asdf/`,
`{ loose: null }`, `0`, `NaN` and `undefined` are `False`.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import semver as reference
from hypothesis import assume, given
from hypothesis import strategies as st

from kitsunox.ecosystems.npm import ranges
from kitsunox.ecosystems.npm.ranges import (
    Comparator,
    InvalidRange,
    InvalidVersion,
    Range,
    clean,
    compare,
    engines_ok,
    max_satisfying,
    parse_version,
    pick,
    pick_version,
    satisfies,
    valid,
    valid_range,
)
from kitsunox.ecosystems.npm.semver import SemVer

MAX_SAFE_INTEGER = 2**53 - 1

# --- node-semver v7.7.4 fixtures (ISC licence, see the module docstring) ----------------------
# (range, version, loose, include_prerelease): the version satisfies / doesn't satisfy the range.
# RANGE_PARSE: (range, desugared `.range || "*"`, loose, include_prerelease); None means
# `new Range()` throws.
# COMPARISONS: (a, b, loose) with a > b. EQUALITY: (a, b, loose) with a == b.

RANGE_INCLUDE: list[tuple[str, str, bool, bool]] = [
    ("1.0.0 - 2.0.0", "1.2.3", False, False),
    ("^1.2.3+build", "1.2.3", False, False),
    ("^1.2.3+build", "1.3.0", False, False),
    ("1.2.3-pre+asdf - 2.4.3-pre+asdf", "1.2.3", False, False),
    ("1.2.3pre+asdf - 2.4.3-pre+asdf", "1.2.3", True, False),
    ("1.2.3-pre+asdf - 2.4.3pre+asdf", "1.2.3", True, False),
    ("1.2.3pre+asdf - 2.4.3pre+asdf", "1.2.3", True, False),
    ("1.2.3-pre+asdf - 2.4.3-pre+asdf", "1.2.3-pre.2", False, False),
    ("1.2.3-pre+asdf - 2.4.3-pre+asdf", "2.4.3-alpha", False, False),
    ("1.2.3+asdf - 2.4.3+asdf", "1.2.3", False, False),
    ("1.0.0", "1.0.0", False, False),
    (">=*", "0.2.4", False, False),
    ("", "1.0.0", False, False),
    ("*", "1.2.3", False, False),
    ("*", "v1.2.3", True, False),
    (">=1.0.0", "1.0.0", False, False),
    (">=1.0.0", "1.0.1", False, False),
    (">=1.0.0", "1.1.0", False, False),
    (">1.0.0", "1.0.1", False, False),
    (">1.0.0", "1.1.0", False, False),
    ("<=2.0.0", "2.0.0", False, False),
    ("<=2.0.0", "1.9999.9999", False, False),
    ("<=2.0.0", "0.2.9", False, False),
    ("<2.0.0", "1.9999.9999", False, False),
    ("<2.0.0", "0.2.9", False, False),
    (">= 1.0.0", "1.0.0", False, False),
    (">=  1.0.0", "1.0.1", False, False),
    (">=   1.0.0", "1.1.0", False, False),
    ("> 1.0.0", "1.0.1", False, False),
    (">  1.0.0", "1.1.0", False, False),
    ("<=   2.0.0", "2.0.0", False, False),
    ("<= 2.0.0", "1.9999.9999", False, False),
    ("<=  2.0.0", "0.2.9", False, False),
    ("<    2.0.0", "1.9999.9999", False, False),
    ("<\t2.0.0", "0.2.9", False, False),
    (">=0.1.97", "v0.1.97", True, False),
    (">=0.1.97", "0.1.97", False, False),
    ("0.1.20 || 1.2.4", "1.2.4", False, False),
    (">=0.2.3 || <0.0.1", "0.0.0", False, False),
    (">=0.2.3 || <0.0.1", "0.2.3", False, False),
    (">=0.2.3 || <0.0.1", "0.2.4", False, False),
    ("||", "1.3.4", False, False),
    ("2.x.x", "2.1.3", False, False),
    ("1.2.x", "1.2.3", False, False),
    ("1.2.x || 2.x", "2.1.3", False, False),
    ("1.2.x || 2.x", "1.2.3", False, False),
    ("x", "1.2.3", False, False),
    ("2.*.*", "2.1.3", False, False),
    ("1.2.*", "1.2.3", False, False),
    ("1.2.* || 2.*", "2.1.3", False, False),
    ("1.2.* || 2.*", "1.2.3", False, False),
    ("*", "1.2.3", False, False),
    ("2", "2.1.2", False, False),
    ("2.3", "2.3.1", False, False),
    ("~0.0.1", "0.0.1", False, False),
    ("~0.0.1", "0.0.2", False, False),
    ("~x", "0.0.9", False, False),
    ("~2", "2.0.9", False, False),
    ("~2.4", "2.4.0", False, False),
    ("~2.4", "2.4.5", False, False),
    ("~>3.2.1", "3.2.2", False, False),
    ("~1", "1.2.3", False, False),
    ("~>1", "1.2.3", False, False),
    ("~> 1", "1.2.3", False, False),
    ("~1.0", "1.0.2", False, False),
    ("~ 1.0", "1.0.2", False, False),
    ("~ 1.0.3", "1.0.12", False, False),
    ("~ 1.0.3alpha", "1.0.12", True, False),
    (">=1", "1.0.0", False, False),
    (">= 1", "1.0.0", False, False),
    ("<1.2", "1.1.1", False, False),
    ("< 1.2", "1.1.1", False, False),
    ("~v0.5.4-pre", "0.5.5", False, False),
    ("~v0.5.4-pre", "0.5.4", False, False),
    ("=0.7.x", "0.7.2", False, False),
    ("<=0.7.x", "0.7.2", False, False),
    (">=0.7.x", "0.7.2", False, False),
    ("<=0.7.x", "0.6.2", False, False),
    ("~1.2.1 >=1.2.3", "1.2.3", False, False),
    ("~1.2.1 =1.2.3", "1.2.3", False, False),
    ("~1.2.1 1.2.3", "1.2.3", False, False),
    ("~1.2.1 >=1.2.3 1.2.3", "1.2.3", False, False),
    ("~1.2.1 1.2.3 >=1.2.3", "1.2.3", False, False),
    (">=1.2.1 1.2.3", "1.2.3", False, False),
    ("1.2.3 >=1.2.1", "1.2.3", False, False),
    (">=1.2.3 >=1.2.1", "1.2.3", False, False),
    (">=1.2.1 >=1.2.3", "1.2.3", False, False),
    (">=1.2", "1.2.8", False, False),
    ("^1.2.3", "1.8.1", False, False),
    ("^0.1.2", "0.1.2", False, False),
    ("^0.1", "0.1.2", False, False),
    ("^0.0.1", "0.0.1", False, False),
    ("^1.2", "1.4.2", False, False),
    ("^1.2 ^1", "1.4.2", False, False),
    ("^1.2.3-alpha", "1.2.3-pre", False, False),
    ("^1.2.0-alpha", "1.2.0-pre", False, False),
    ("^0.0.1-alpha", "0.0.1-beta", False, False),
    ("^0.0.1-alpha", "0.0.1", False, False),
    ("^0.1.1-alpha", "0.1.1-beta", False, False),
    ("^x", "1.2.3", False, False),
    ("x - 1.0.0", "0.9.7", False, False),
    ("x - 1.x", "0.9.7", False, False),
    ("1.0.0 - x", "1.9.7", False, False),
    ("1.x - x", "1.9.7", False, False),
    ("<=7.x", "7.9.9", False, False),
    ("2.x", "2.0.0-pre.0", False, True),
    ("2.x", "2.1.0-pre.0", False, True),
    ("1.1.x", "1.1.0-a", False, True),
    ("1.1.x", "1.1.1-a", False, True),
    ("*", "1.0.0-rc1", False, True),
    ("^1.0.0-0", "1.0.1-rc1", False, True),
    ("^1.0.0-rc2", "1.0.1-rc1", False, True),
    ("^1.0.0", "1.0.1-rc1", False, True),
    ("^1.0.0", "1.1.0-rc1", False, True),
    ("1 - 2", "2.0.0-pre", False, True),
    ("1 - 2", "1.0.0-pre", False, True),
    ("1.0 - 2", "1.0.0-pre", False, True),
    ("=0.7.x", "0.7.0-asdf", False, True),
    (">=0.7.x", "0.7.0-asdf", False, True),
    ("<=0.7.x", "0.7.0-asdf", False, True),
    (">=1.0.0 <=1.1.0", "1.1.0-pre", False, True),
]

RANGE_EXCLUDE: list[tuple[str, str, bool, bool]] = [
    ("1.0.0 - 2.0.0", "2.2.3", False, False),
    ("1.2.3+asdf - 2.4.3+asdf", "1.2.3-pre.2", False, False),
    ("1.2.3+asdf - 2.4.3+asdf", "2.4.3-alpha", False, False),
    ("^1.2.3+build", "2.0.0", False, False),
    ("^1.2.3+build", "1.2.0", False, False),
    ("^1.2.3", "1.2.3-pre", False, False),
    ("^1.2", "1.2.0-pre", False, False),
    (">1.2", "1.3.0-beta", False, False),
    ("<=1.2.3", "1.2.3-beta", False, False),
    ("^1.2.3", "1.2.3-beta", False, False),
    ("=0.7.x", "0.7.0-asdf", False, False),
    (">=0.7.x", "0.7.0-asdf", False, False),
    ("<=0.7.x", "0.7.0-asdf", False, False),
    ("1", "1.0.0beta", True, False),
    ("<1", "1.0.0beta", True, False),
    ("< 1", "1.0.0beta", True, False),
    ("1.0.0", "1.0.1", False, False),
    (">=1.0.0", "0.0.0", False, False),
    (">=1.0.0", "0.0.1", False, False),
    (">=1.0.0", "0.1.0", False, False),
    (">1.0.0", "0.0.1", False, False),
    (">1.0.0", "0.1.0", False, False),
    ("<=2.0.0", "3.0.0", False, False),
    ("<=2.0.0", "2.9999.9999", False, False),
    ("<=2.0.0", "2.2.9", False, False),
    ("<2.0.0", "2.9999.9999", False, False),
    ("<2.0.0", "2.2.9", False, False),
    (">=0.1.97", "v0.1.93", True, False),
    (">=0.1.97", "0.1.93", False, False),
    ("0.1.20 || 1.2.4", "1.2.3", False, False),
    (">=0.2.3 || <0.0.1", "0.0.3", False, False),
    (">=0.2.3 || <0.0.1", "0.2.2", False, False),
    ("2.x.x", "1.1.3", False, False),
    ("2.x.x", "3.1.3", False, False),
    ("1.2.x", "1.3.3", False, False),
    ("1.2.x || 2.x", "3.1.3", False, False),
    ("1.2.x || 2.x", "1.1.3", False, False),
    ("2.*.*", "1.1.3", False, False),
    ("2.*.*", "3.1.3", False, False),
    ("1.2.*", "1.3.3", False, False),
    ("1.2.* || 2.*", "3.1.3", False, False),
    ("1.2.* || 2.*", "1.1.3", False, False),
    ("2", "1.1.2", False, False),
    ("2.3", "2.4.1", False, False),
    ("~0.0.1", "0.1.0-alpha", False, False),
    ("~0.0.1", "0.1.0", False, False),
    ("~2.4", "2.5.0", False, False),
    ("~2.4", "2.3.9", False, False),
    ("~>3.2.1", "3.3.2", False, False),
    ("~>3.2.1", "3.2.0", False, False),
    ("~1", "0.2.3", False, False),
    ("~>1", "2.2.3", False, False),
    ("~1.0", "1.1.0", False, False),
    ("<1", "1.0.0", False, False),
    (">=1.2", "1.1.1", False, False),
    ("1", "2.0.0beta", True, False),
    ("~v0.5.4-beta", "0.5.4-alpha", False, False),
    ("=0.7.x", "0.8.2", False, False),
    (">=0.7.x", "0.6.2", False, False),
    ("<0.7.x", "0.7.2", False, False),
    ("<1.2.3", "1.2.3-beta", False, False),
    ("=1.2.3", "1.2.3-beta", False, False),
    (">1.2", "1.2.8", False, False),
    ("^0.0.1", "0.0.2-alpha", False, False),
    ("^0.0.1", "0.0.2", False, False),
    ("^1.2.3", "2.0.0-alpha", False, False),
    ("^1.2.3", "1.2.2", False, False),
    ("^1.2", "1.1.9", False, False),
    ("*", "v1.2.3-foo", True, False),
    ("*", "not a version", False, False),
    (">=2", "glorp", False, False),
    (">=2", "", False, False),  # node-semver passes `false`; Range.test treats it like ""
    ("2.x", "3.0.0-pre.0", False, True),
    ("^1.0.0", "1.0.0-rc1", False, True),
    ("^1.0.0", "2.0.0-rc1", False, True),
    ("^1.2.3-rc2", "2.0.0", False, True),
    ("^1.0.0", "2.0.0-rc1", False, False),
    ("1 - 2", "3.0.0-pre", False, True),
    ("1 - 2", "2.0.0-pre", False, False),
    ("1 - 2", "1.0.0-pre", False, False),
    ("1.0 - 2", "1.0.0-pre", False, False),
    ("1.1.x", "1.0.0-a", False, False),
    ("1.1.x", "1.1.0-a", False, False),
    ("1.1.x", "1.2.0-a", False, False),
    ("1.1.x", "1.2.0-a", False, True),
    ("1.1.x", "1.0.0-a", False, True),
    ("1.x", "1.0.0-a", False, False),
    ("1.x", "1.1.0-a", False, False),
    ("1.x", "1.2.0-a", False, False),
    ("1.x", "0.0.0-a", False, True),
    ("1.x", "2.0.0-a", False, True),
    (">=1.0.0 <1.1.0", "1.1.0", False, False),
    (">=1.0.0 <1.1.0", "1.1.0", False, True),
    (">=1.0.0 <1.1.0", "1.1.0-pre", False, False),
    (">=1.0.0 <1.1.0-pre", "1.1.0-pre", False, False),
    ("== 1.0.0 || foo", "2.0.0", True, False),
]

RANGE_PARSE: list[tuple[str, str | None, bool, bool]] = [
    ("1.0.0 - 2.0.0", ">=1.0.0 <=2.0.0", False, False),
    ("1.0.0 - 2.0.0", ">=1.0.0-0 <2.0.1-0", False, True),
    ("1 - 2", ">=1.0.0 <3.0.0-0", False, False),
    ("1 - 2", ">=1.0.0-0 <3.0.0-0", False, True),
    ("1.0 - 2.0", ">=1.0.0 <2.1.0-0", False, False),
    ("1.0 - 2.0", ">=1.0.0-0 <2.1.0-0", False, True),
    ("1.0.0", "1.0.0", False, False),
    (">=*", "*", False, False),
    ("", "*", False, False),
    ("*", "*", False, False),
    (">=1.0.0", ">=1.0.0", False, False),
    (">1.0.0", ">1.0.0", False, False),
    ("<=2.0.0", "<=2.0.0", False, False),
    ("1", ">=1.0.0 <2.0.0-0", False, False),
    ("<2.0.0", "<2.0.0", False, False),
    (">= 1.0.0", ">=1.0.0", False, False),
    (">=  1.0.0", ">=1.0.0", False, False),
    (">=   1.0.0", ">=1.0.0", False, False),
    ("> 1.0.0", ">1.0.0", False, False),
    (">  1.0.0", ">1.0.0", False, False),
    ("<=   2.0.0", "<=2.0.0", False, False),
    ("<= 2.0.0", "<=2.0.0", False, False),
    ("<=  2.0.0", "<=2.0.0", False, False),
    ("<    2.0.0", "<2.0.0", False, False),
    ("<\t2.0.0", "<2.0.0", False, False),
    (">=0.1.97", ">=0.1.97", False, False),
    ("0.1.20 || 1.2.4", "0.1.20||1.2.4", False, False),
    (">=0.2.3 || <0.0.1", ">=0.2.3||<0.0.1", False, False),
    ("||", "*", False, False),
    ("2.x.x", ">=2.0.0 <3.0.0-0", False, False),
    ("1.2.x", ">=1.2.0 <1.3.0-0", False, False),
    ("1.2.x || 2.x", ">=1.2.0 <1.3.0-0||>=2.0.0 <3.0.0-0", False, False),
    ("x", "*", False, False),
    ("2.*.*", ">=2.0.0 <3.0.0-0", False, False),
    ("1.2.*", ">=1.2.0 <1.3.0-0", False, False),
    ("1.2.* || 2.*", ">=1.2.0 <1.3.0-0||>=2.0.0 <3.0.0-0", False, False),
    ("2", ">=2.0.0 <3.0.0-0", False, False),
    ("2.3", ">=2.3.0 <2.4.0-0", False, False),
    ("~2.4", ">=2.4.0 <2.5.0-0", False, False),
    ("~>3.2.1", ">=3.2.1 <3.3.0-0", False, False),
    ("~1", ">=1.0.0 <2.0.0-0", False, False),
    ("~>1", ">=1.0.0 <2.0.0-0", False, False),
    ("~> 1", ">=1.0.0 <2.0.0-0", False, False),
    ("~1.0", ">=1.0.0 <1.1.0-0", False, False),
    ("~ 1.0", ">=1.0.0 <1.1.0-0", False, False),
    ("^0", "<1.0.0-0", False, False),
    ("^ 1", ">=1.0.0 <2.0.0-0", False, False),
    ("^0.1", ">=0.1.0 <0.2.0-0", False, False),
    ("^1.0", ">=1.0.0 <2.0.0-0", False, False),
    ("^1.2", ">=1.2.0 <2.0.0-0", False, False),
    ("^0.0.1", ">=0.0.1 <0.0.2-0", False, False),
    ("^0.0.1-beta", ">=0.0.1-beta <0.0.2-0", False, False),
    ("^0.1.2", ">=0.1.2 <0.2.0-0", False, False),
    ("^1.2.3", ">=1.2.3 <2.0.0-0", False, False),
    ("^1.2.3-beta.4", ">=1.2.3-beta.4 <2.0.0-0", False, False),
    ("<1", "<1.0.0-0", False, False),
    ("< 1", "<1.0.0-0", False, False),
    (">=1", ">=1.0.0", False, False),
    (">= 1", ">=1.0.0", False, False),
    ("<1.2", "<1.2.0-0", False, False),
    ("< 1.2", "<1.2.0-0", False, False),
    (">01.02.03", ">1.2.3", True, False),
    (">01.02.03", None, False, False),
    ("~1.2.3beta", ">=1.2.3-beta <1.3.0-0", True, False),
    ("~1.2.3beta", None, False, False),
    ("^ 1.2 ^ 1", ">=1.2.0 <2.0.0-0 >=1.0.0", False, False),
    ("1.2 - 3.4.5", ">=1.2.0 <=3.4.5", False, False),
    ("1.2.3 - 3.4", ">=1.2.3 <3.5.0-0", False, False),
    ("1.2 - 3.4", ">=1.2.0 <3.5.0-0", False, False),
    (">1", ">=2.0.0", False, False),
    (">1.2", ">=1.3.0", False, False),
    (">X", "<0.0.0-0", False, False),
    ("<X", "<0.0.0-0", False, False),
    ("<x <* || >* 2.x", "<0.0.0-0", False, False),
    (">x 2.x || * || <x", "*", False, False),
    (">=09090", None, False, False),
    (">=09090", ">=9090.0.0", True, False),
    (">=09090-0", None, False, True),
    (">=09090-0", None, True, True),
    ("^9007199254740991.0.0", None, False, False),
    ("=9007199254740991.0.0", "9007199254740991.0.0", False, False),
    ("^9007199254740990.0.0", ">=9007199254740990.0.0 <9007199254740991.0.0-0", False, False),
    ("1.x.x+build >2.x+build", ">=1.0.0 <2.0.0-0 >=3.0.0", False, False),
    (">=1.x+build <2.x.x+build", ">=1.0.0 <2.0.0-0", False, False),
    ("1.x.x+build || 2.x.x+build", ">=1.0.0 <2.0.0-0||>=2.0.0 <3.0.0-0", False, False),
    ("1.x+build.123", ">=1.0.0 <2.0.0-0", False, False),
    ("1.x.x+meta-data", ">=1.0.0 <2.0.0-0", False, False),
    ("1.x.x+build.123 >2.x.x+meta-data", ">=1.0.0 <2.0.0-0 >=3.0.0", False, False),
    ("1.x.x+build <2.x.x+meta", ">=1.0.0 <2.0.0-0", False, False),
    (">1.x+build <=2.x.x+meta", ">=2.0.0 <3.0.0-0", False, False),
    (" 1.x.x+build   >2.x.x+build  ", ">=1.0.0 <2.0.0-0 >=3.0.0", False, False),
    ("^1.x+build", ">=1.0.0 <2.0.0-0", False, False),
    ("^1.x.x+build", ">=1.0.0 <2.0.0-0", False, False),
    ("^1.2.x+build", ">=1.2.0 <2.0.0-0", False, False),
    ("^1.x+meta-data", ">=1.0.0 <2.0.0-0", False, False),
    ("^1.x.x+build.123", ">=1.0.0 <2.0.0-0", False, False),
    ("~1.x+build", ">=1.0.0 <2.0.0-0", False, False),
    ("~1.x.x+build", ">=1.0.0 <2.0.0-0", False, False),
    ("~1.2.x+build", ">=1.2.0 <1.3.0-0", False, False),
    ("~1.x+meta-data", ">=1.0.0 <2.0.0-0", False, False),
    ("~1.x.x+build.123", ">=1.0.0 <2.0.0-0", False, False),
    ("^1.x.x+build || ~2.x.x+meta", ">=1.0.0 <2.0.0-0||>=2.0.0 <3.0.0-0", False, False),
    ("~1.x.x+build >2.x+meta", ">=1.0.0 <2.0.0-0 >=3.0.0", False, False),
    ("^1.x+build.123 <2.x.x+meta-data", ">=1.0.0 <2.0.0-0", False, False),
    ("1.x.x-alpha+build", ">=1.0.0 <2.0.0-0", False, False),
    (">1.x.x-alpha+build", ">=2.0.0", False, False),
    (">=1.x.x-alpha+build <2.x.x+build", ">=1.0.0 <2.0.0-0", False, False),
    ("1.x.x-alpha+build || 2.x.x+build", ">=1.0.0 <2.0.0-0||>=2.0.0 <3.0.0-0", False, False),
]

COMPARISONS: list[tuple[str, str, bool]] = [
    ("0.0.0", "0.0.0-foo", False),
    ("0.0.1", "0.0.0", False),
    ("1.0.0", "0.9.9", False),
    ("0.10.0", "0.9.0", False),
    ("0.99.0", "0.10.0", False),
    ("2.0.0", "1.2.3", False),
    ("v0.0.0", "0.0.0-foo", True),
    ("v0.0.1", "0.0.0", True),
    ("v1.0.0", "0.9.9", True),
    ("v0.10.0", "0.9.0", True),
    ("v0.99.0", "0.10.0", True),
    ("v2.0.0", "1.2.3", True),
    ("0.0.0", "v0.0.0-foo", True),
    ("0.0.1", "v0.0.0", True),
    ("1.0.0", "v0.9.9", True),
    ("0.10.0", "v0.9.0", True),
    ("0.99.0", "v0.10.0", True),
    ("2.0.0", "v1.2.3", True),
    ("1.2.3", "1.2.3-asdf", False),
    ("1.2.3", "1.2.3-4", False),
    ("1.2.3", "1.2.3-4-foo", False),
    ("1.2.3-5-foo", "1.2.3-5", False),
    ("1.2.3-5", "1.2.3-4", False),
    ("1.2.3-5-foo", "1.2.3-5-Foo", False),
    ("3.0.0", "2.7.2+asdf", False),
    ("1.2.3-a.10", "1.2.3-a.5", False),
    ("1.2.3-a.b", "1.2.3-a.5", False),
    ("1.2.3-a.b", "1.2.3-a", False),
    ("1.2.3-a.b.c.10.d.5", "1.2.3-a.b.c.5.d.100", False),
    ("1.2.3-r2", "1.2.3-r100", False),
    ("1.2.3-r100", "1.2.3-R2", False),
]

EQUALITY: list[tuple[str, str, bool]] = [
    ("1.2.3", "v1.2.3", True),
    ("1.2.3", "=1.2.3", True),
    ("1.2.3", "v 1.2.3", True),
    ("1.2.3", "= 1.2.3", True),
    ("1.2.3", " v1.2.3", True),
    ("1.2.3", " =1.2.3", True),
    ("1.2.3", " v 1.2.3", True),
    ("1.2.3", " = 1.2.3", True),
    ("1.2.3-0", "v1.2.3-0", True),
    ("1.2.3-0", "=1.2.3-0", True),
    ("1.2.3-0", "v 1.2.3-0", True),
    ("1.2.3-0", "= 1.2.3-0", True),
    ("1.2.3-0", " v1.2.3-0", True),
    ("1.2.3-0", " =1.2.3-0", True),
    ("1.2.3-0", " v 1.2.3-0", True),
    ("1.2.3-0", " = 1.2.3-0", True),
    ("1.2.3-1", "v1.2.3-1", True),
    ("1.2.3-1", "=1.2.3-1", True),
    ("1.2.3-1", "v 1.2.3-1", True),
    ("1.2.3-1", "= 1.2.3-1", True),
    ("1.2.3-1", " v1.2.3-1", True),
    ("1.2.3-1", " =1.2.3-1", True),
    ("1.2.3-1", " v 1.2.3-1", True),
    ("1.2.3-1", " = 1.2.3-1", True),
    ("1.2.3-beta", "v1.2.3-beta", True),
    ("1.2.3-beta", "=1.2.3-beta", True),
    ("1.2.3-beta", "v 1.2.3-beta", True),
    ("1.2.3-beta", "= 1.2.3-beta", True),
    ("1.2.3-beta", " v1.2.3-beta", True),
    ("1.2.3-beta", " =1.2.3-beta", True),
    ("1.2.3-beta", " v 1.2.3-beta", True),
    ("1.2.3-beta", " = 1.2.3-beta", True),
    ("1.2.3-beta+build", " = 1.2.3-beta+otherbuild", True),
    ("1.2.3+build", " = 1.2.3+otherbuild", True),
    ("1.2.3-beta+build", "1.2.3-beta+otherbuild", False),
    ("1.2.3+build", "1.2.3+otherbuild", False),
    ("  v1.2.3+build", "1.2.3+otherbuild", False),
]


# test/fixtures/invalid-versions.js (the non-string entries can't be typed in Python).
INVALID_VERSIONS: list[tuple[str, bool]] = [
    ("1" * 255 + ".0.0", False),  # too long: `new Array(MAX_LENGTH).join('1')`
    (f"{MAX_SAFE_INTEGER}0.0.0", False),  # too big
    (f"0.{MAX_SAFE_INTEGER}0.0", False),
    (f"0.0.{MAX_SAFE_INTEGER}0", False),
    ("hello, world", False),
    ("hello, world", True),
    ("xyz", True),
]

# test/fixtures/valid-versions.js: (version, major, minor, patch, prerelease). Build metadata
# is parsed but not kept, as node-semver's `version` string doesn't keep it either.
VALID_VERSIONS: list[tuple[str, int, int, int, tuple[int | str, ...]]] = [
    ("1.0.0", 1, 0, 0, ()),
    ("2.1.0", 2, 1, 0, ()),
    ("3.2.1", 3, 2, 1, ()),
    ("v1.2.3", 1, 2, 3, ()),
    ("1.2.3-0", 1, 2, 3, (0,)),
    ("1.2.3-123", 1, 2, 3, (123,)),
    ("1.2.3-1.2.3", 1, 2, 3, (1, 2, 3)),
    ("1.2.3-1a", 1, 2, 3, ("1a",)),
    ("1.2.3-a1", 1, 2, 3, ("a1",)),
    ("1.2.3-alpha", 1, 2, 3, ("alpha",)),
    ("1.2.3-alpha.1", 1, 2, 3, ("alpha", 1)),
    ("1.2.3-alpha-1", 1, 2, 3, ("alpha-1",)),
    ("1.2.3-alpha-.-beta", 1, 2, 3, ("alpha-", "-beta")),
    ("1.2.3+456", 1, 2, 3, ()),
    ("1.2.3+build", 1, 2, 3, ()),
    ("1.2.3+new-build", 1, 2, 3, ()),
    ("1.2.3+build.1", 1, 2, 3, ()),
    ("1.2.3+build.1a", 1, 2, 3, ()),
    ("1.2.3+build.a1", 1, 2, 3, ()),
    ("1.2.3+build.alpha", 1, 2, 3, ()),
    ("1.2.3+build.alpha.beta", 1, 2, 3, ()),
    ("1.2.3-alpha+build", 1, 2, 3, ("alpha",)),
]

# test/functions/clean.js
CLEAN: list[tuple[str, str | None]] = [
    ("1.2.3", "1.2.3"),
    (" 1.2.3 ", "1.2.3"),
    (" 1.2.3-4 ", "1.2.3-4"),
    (" 1.2.3-pre ", "1.2.3-pre"),
    ("  =v1.2.3   ", "1.2.3"),
    ("v1.2.3", "1.2.3"),
    (" v1.2.3 ", "1.2.3"),
    ("\t1.2.3", "1.2.3"),
    (">1.2.3", None),
    ("~1.2.3", None),
    ("<=1.2.3", None),
    ("1.2.x", None),
    ("0.12.0-dev.1150+3c22cecee", "0.12.0-dev.1150"),
]

# test/ranges/max-satisfying.js: (versions, range, expected, loose)
MAX_SATISFYING: list[tuple[list[str], str, str | None, bool]] = [
    (["1.2.3", "1.2.4"], "1.2", "1.2.4", False),
    (["1.2.4", "1.2.3"], "1.2", "1.2.4", False),
    (["1.2.3", "1.2.4", "1.2.5", "1.2.6"], "~1.2.3", "1.2.6", False),
    (
        ["1.1.0", "1.2.0", "1.2.1", "1.3.0", "2.0.0b1", "2.0.0b2", "2.0.0b3", "2.0.0", "2.1.0"],
        "~2.0.0",
        "2.0.0",
        True,
    ),
    ([], "some frogs and sneks-v2.5.6", None, False),
]

# node-semver README, "Advanced Range Syntax": each pair desugars to the same comparator sets.
README_EQUIVALENT: list[tuple[str, str]] = [
    ("1.2.3 - 2.3.4", ">=1.2.3 <=2.3.4"),
    ("1.2 - 2.3.4", ">=1.2.0 <=2.3.4"),
    ("1.2.3 - 2.3", ">=1.2.3 <2.4.0-0"),
    ("1.2.3 - 2", ">=1.2.3 <3.0.0-0"),
    ("*", ">=0.0.0"),
    ("1.x", ">=1.0.0 <2.0.0-0"),
    ("1.2.x", ">=1.2.0 <1.3.0-0"),
    ("", "*"),
    ("1", "1.x.x"),
    ("1", ">=1.0.0 <2.0.0-0"),
    ("1.2", "1.2.x"),
    ("1.2", ">=1.2.0 <1.3.0-0"),
    ("~1.2.3", ">=1.2.3 <1.3.0-0"),
    ("~1.2", ">=1.2.0 <1.3.0-0"),
    ("~1", ">=1.0.0 <2.0.0-0"),
    ("~0.2.3", ">=0.2.3 <0.3.0-0"),
    ("~0.2", ">=0.2.0 <0.3.0-0"),
    ("~0", ">=0.0.0 <1.0.0-0"),
    ("~1.2.3-beta.2", ">=1.2.3-beta.2 <1.3.0-0"),
    ("^1.2.3", ">=1.2.3 <2.0.0-0"),
    ("^0.2.3", ">=0.2.3 <0.3.0-0"),
    ("^0.0.3", ">=0.0.3 <0.0.4-0"),
    ("^1.2.3-beta.2", ">=1.2.3-beta.2 <2.0.0-0"),
    ("^0.0.3-beta", ">=0.0.3-beta <0.0.4-0"),
    ("^1.2.x", ">=1.2.0 <2.0.0-0"),
    ("^0.0.x", ">=0.0.0 <0.1.0-0"),
    ("^0.0", ">=0.0.0 <0.1.0-0"),
    ("^1.x", ">=1.0.0 <2.0.0-0"),
    ("^0.x", ">=0.0.0 <1.0.0-0"),
    # npm docs, package.json `dependencies`: `version1 - version2` is `>=version1 <=version2`.
    ("1.0.0 - 2.9999.9999", ">=1.0.0 <=2.9999.9999"),
    ("<1.0.0 || >=2.3.1 <2.4.5 || >=2.5.2 <3.0.0", "<1.0.0||>=2.3.1 <2.4.5||>=2.5.2 <3.0.0"),
]


# --- node-semver fixture tests ---------------------------------------------------------------


@pytest.mark.parametrize(("spec", "version", "loose", "include_prerelease"), RANGE_INCLUDE)
def test_range_include(spec: str, version: str, loose: bool, include_prerelease: bool) -> None:
    parsed = Range.parse(spec, loose=loose, include_prerelease=include_prerelease)
    assert parsed.test(version)
    assert satisfies(version, spec, loose=loose, include_prerelease=include_prerelease)


@pytest.mark.parametrize(("spec", "version", "loose", "include_prerelease"), RANGE_EXCLUDE)
def test_range_exclude(spec: str, version: str, loose: bool, include_prerelease: bool) -> None:
    parsed = Range.parse(spec, loose=loose, include_prerelease=include_prerelease)
    assert not parsed.test(version)
    assert not satisfies(version, spec, loose=loose, include_prerelease=include_prerelease)


@pytest.mark.parametrize(("spec", "expected", "loose", "include_prerelease"), RANGE_PARSE)
def test_range_parse(
    spec: str, expected: str | None, loose: bool, include_prerelease: bool
) -> None:
    if expected is None:
        with pytest.raises(InvalidRange):
            Range.parse(spec, loose=loose, include_prerelease=include_prerelease)
        return
    parsed = Range.parse(spec, loose=loose, include_prerelease=include_prerelease)
    assert (parsed.range or "*") == expected
    assert parsed.range == Range.parse(expected).range  # "parsing both yields same result"


def test_empty_comparator_set_throws_even_in_loose_mode() -> None:
    with pytest.raises(InvalidRange, match="Invalid SemVer Range: sadf\\|\\|asdf"):
        Range.parse("sadf||asdf", loose=True)


@pytest.mark.parametrize(
    ("loose_spec", "desugared"),
    [(">=01.02.03", ">=1.2.3"), ("~1.02.03beta", ">=1.2.3-beta <1.3.0-0")],
)
def test_strict_vs_loose_ranges(loose_spec: str, desugared: str) -> None:
    with pytest.raises(InvalidRange):
        Range.parse(loose_spec)
    assert Range.parse(loose_spec, loose=True).range == desugared


def test_range_tostring() -> None:
    assert str(Range.parse(">= v1.2.3")) == ">=1.2.3"


@pytest.mark.parametrize(
    ("spec", "version", "loose"),
    [
        ("blerg", "1.2.3", False),
        ("git+https://user:password0123@github.com/foo", "123.0.0", True),
        ("^1.2.3", "2.0.0-pre", False),
    ],
)
def test_invalid_ranges_never_satisfied(spec: str, version: str, loose: bool) -> None:
    assert not satisfies(version, spec, loose=loose)


def test_comparator_cases() -> None:
    comparator = Comparator.parse(">=1.2.3")
    version = parse_version("1.2.4")
    assert version is not None
    assert comparator.test(version)
    assert str(Comparator.parse(">= v1.2.3")) == ">=1.2.3"
    assert Comparator.parse("=1.2.3") == Comparator.parse("1.2.3")
    assert Comparator.parse("").semver is None  # ANY
    assert Comparator.parse("").test(version)
    with pytest.raises(InvalidRange, match="Invalid comparator: foo bar baz"):
        Comparator.parse("foo bar baz")


@pytest.mark.parametrize(("bigger", "smaller", "loose"), COMPARISONS)
def test_comparisons(bigger: str, smaller: str, loose: bool) -> None:
    assert compare(bigger, smaller, loose=loose) == 1
    assert compare(smaller, bigger, loose=loose) == -1
    assert compare(bigger, bigger, loose=loose) == 0


@pytest.mark.parametrize(("a", "b", "loose"), EQUALITY)
def test_equality(a: str, b: str, loose: bool) -> None:
    assert compare(a, b, loose=loose) == 0
    assert compare(b, a, loose=loose) == 0


@pytest.mark.parametrize(("version", "loose"), INVALID_VERSIONS)
def test_invalid_versions(version: str, loose: bool) -> None:
    assert valid(version, loose=loose) is None
    with pytest.raises(InvalidVersion):
        compare(version, "1.0.0", loose=loose)


@pytest.mark.parametrize(("version", "major", "minor", "patch", "prerelease"), VALID_VERSIONS)
def test_valid_versions(
    version: str, major: int, minor: int, patch: int, prerelease: tuple[int | str, ...]
) -> None:
    assert parse_version(version) == SemVer(major, minor, patch, prerelease)


def test_valid() -> None:
    assert valid("1.2.3") == "1.2.3"
    assert valid("4.2.0foo") is None
    assert valid("4.2.0foo", loose=True) == "4.2.0-foo"
    long_build = "-928490632884417731e7af463c92b034d6a78268fc993bcb88a57944"
    assert valid("1.1.1" + long_build) == "1.1.1" + long_build
    long_version = f"{MAX_SAFE_INTEGER}.{MAX_SAFE_INTEGER}.{MAX_SAFE_INTEGER}"
    assert valid(long_version + long_build) == long_version + long_build


@pytest.mark.parametrize(("dirty", "expected"), CLEAN)
def test_clean(dirty: str, expected: str | None) -> None:
    assert clean(dirty) == expected


@pytest.mark.parametrize(("versions", "spec", "expected", "loose"), MAX_SATISFYING)
def test_max_satisfying(versions: list[str], spec: str, expected: str | None, loose: bool) -> None:
    assert max_satisfying(versions, spec, loose=loose) == expected


@pytest.mark.parametrize(("spec", "equivalent"), README_EQUIVALENT)
def test_readme_equivalences(spec: str, equivalent: str) -> None:
    assert Range.parse(spec).range == Range.parse(equivalent).range


def test_readme_prerelease_example() -> None:
    # README "Prerelease Tags": >1.2.3-alpha.3 admits prereleases of 1.2.3 only.
    assert satisfies("1.2.3-alpha.7", ">1.2.3-alpha.3")
    assert not satisfies("3.4.5-alpha.9", ">1.2.3-alpha.3")
    assert satisfies("3.4.5", ">1.2.3-alpha.3")
    assert satisfies("3.4.5-alpha.9", ">1.2.3-alpha.3", include_prerelease=True)


# --- JavaScript semantics the port reproduces (from reading the source, not node fixtures) ----


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1.0, "1"),
        (2.0**53, "9007199254740992"),
        (2.0**60, "1152921504606847000"),  # shortest round-trip digits, zero padded
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1.5e300, "1.5e+300"),
        (float("inf"), "Infinity"),
        (0.0, "0"),
        (0.5, "0.5"),
        (1.5, "1.5"),
        (1e-7, "1e-7"),
    ],
)
def test_js_number_to_string(value: float, expected: str) -> None:
    assert ranges._js_number_to_string(value) == expected


def test_huge_majors_follow_javascript_number_formatting() -> None:
    # `>1000000000000000000000` desugars to `>=1e+21.0.0`, which loose mode drops as not a
    # comparator, so only the other alternative is left. One digit less, `+M + 1` still prints
    # as digits, the comparator parses, and SemVer rejects the major: the whole range throws.
    assert Range.parse(">1000000000000000000000 || 1.x", loose=True).range == ">=1.0.0 <2.0.0-0"
    with pytest.raises(InvalidRange):
        Range.parse(">99999999999999999999 || 1.x", loose=True)
    with pytest.raises(InvalidRange):
        Range.parse(">1000000000000000000000 || 1.x")


NBSP, BOM, ARABIC_THREE = chr(0xA0), chr(0xFEFF), chr(0x663)


def test_javascript_whitespace_and_digits() -> None:
    # `\s` and trim() are JavaScript's: NBSP and BOM are whitespace, U+001C is not.
    assert Range.parse(f"{NBSP}>={NBSP}1.2.3{BOM}").range == ">=1.2.3"
    assert valid(f"{BOM}1.2.3{NBSP}") == "1.2.3"
    assert valid("\x1c1.2.3") is None
    # `\d` is ASCII only, and `$` doesn't match before a trailing newline inside a comparator.
    assert valid(f"1.2.{ARABIC_THREE}") is None
    with pytest.raises(InvalidRange):
        Range.parse(f"1.2.{ARABIC_THREE}")
    assert valid("1.2.3\n") == "1.2.3"  # trimmed first, as in JavaScript


def test_huge_numeric_prerelease_identifiers_compare_as_float64() -> None:
    # Identifiers past MAX_SAFE_INTEGER stay strings; `+a` makes these two equal in node-semver,
    # where SemVer.__lt__ would order them as text.
    a = f"1.0.0-{MAX_SAFE_INTEGER + 2}"
    b = f"1.0.0-{MAX_SAFE_INTEGER + 1}"
    assert compare(a, b) == 0
    # A numeric identifier sorts before an alphanumeric one, even one starting with "-".
    assert compare(f"1.0.0-{MAX_SAFE_INTEGER + 1}", "1.0.0--x") == -1
    assert compare("1.0.0-01", "1.0.0-1", loose=True) == 0  # loose numberifies "01"


def test_version_length_counts_utf16_units() -> None:
    assert parse_version("1.0.0+" + "a" * 250) is not None
    assert parse_version("1.0.0+" + "a" * 251) is None


def test_range_rejects_non_strings() -> None:
    value: Any = 5
    with pytest.raises(InvalidRange):
        Range.parse(value)
    assert not Range.parse("*").test(value)
    assert valid(value) is None
    assert clean(value) is None


def test_valid_range() -> None:
    assert valid_range("") == "*"
    assert valid_range("^1.2.3") == ">=1.2.3 <2.0.0-0"
    assert valid_range("latest") is None
    assert valid_range("v2", loose=True) == ">=2.0.0 <3.0.0-0"


# --- Hypothesis properties -------------------------------------------------------------------

NUMS = st.sampled_from(["0", "1", "2", "3", "10"])
PRE = st.sampled_from(["", "-0", "-alpha", "-alpha.1", "-beta.2", "-rc.10", "-1"])
VERSION = st.builds(lambda a, b, c, p: f"{a}.{b}.{c}{p}", NUMS, NUMS, NUMS, PRE)
PART = st.sampled_from(["0", "1", "2", "3", "10", "x", "X", "*"])
PARTIAL = st.one_of(
    PART,
    st.builds(lambda a, b: f"{a}.{b}", PART, PART),
    st.builds(lambda a, b, c, p: f"{a}.{b}.{c}{p}", PART, PART, PART, PRE),
)
OPERATOR = st.sampled_from(["", "=", "<", "<=", ">", ">=", "~", "~>", "^", "v", "> ", "^ "])
TERM = st.builds(lambda o, p: o + p, OPERATOR, PARTIAL) | st.builds(
    lambda a, b: f"{a} - {b}", PARTIAL, PARTIAL
)
RANGE = st.lists(st.lists(TERM, min_size=1, max_size=3).map(" ".join), min_size=1, max_size=3).map(
    " || ".join
)
FIXTURE_RANGES = sorted(
    {r for r, *_ in RANGE_INCLUDE} | {r for r, *_ in RANGE_EXCLUDE} | {r for r, *_ in RANGE_PARSE}
)


@given(st.lists(VERSION, max_size=12), RANGE)
def test_max_satisfying_is_the_satisfying_maximum(versions: list[str], spec: str) -> None:
    best = max_satisfying(versions, spec)
    matching = [v for v in versions if satisfies(v, spec)]
    if best is None:
        assert not matching
        return
    assert best in matching
    assert all(compare(best, v) >= 0 for v in matching)


@given(
    st.sampled_from(FIXTURE_RANGES) | RANGE | st.text(max_size=30),
    st.booleans(),
    st.booleans(),
    VERSION,
)
def test_parse_is_total_and_desugaring_agrees(
    spec: str, loose: bool, include_prerelease: bool, version: str
) -> None:
    try:
        parsed = Range.parse(spec, loose=loose, include_prerelease=include_prerelease)
    except InvalidRange:
        return
    # The desugared form is a strict range that matches exactly the same versions.
    again = Range.parse(parsed.range, include_prerelease=include_prerelease)
    assert again.range == parsed.range
    if parse_version(version) is not None:
        assert again.test(version) == parsed.test(version)


@given(RANGE, VERSION)
def test_prerelease_needs_a_comparator_on_the_same_tuple(spec: str, version: str) -> None:
    parsed_version = parse_version(version)
    assert parsed_version is not None
    assume(parsed_version.prerelease)
    try:
        parsed = Range.parse(spec)
    except InvalidRange:
        return
    triple = (parsed_version.major, parsed_version.minor, parsed_version.patch)
    allowed = any(
        c.semver is not None
        and bool(c.semver.prerelease)
        and (c.semver.major, c.semver.minor, c.semver.patch) == triple
        for comps in parsed.set
        for c in comps
    )
    if parsed.test(version):
        assert allowed
    loose = Range.parse(spec, include_prerelease=True)
    if parsed.test(version):
        assert loose.test(version)


@given(VERSION, VERSION)
def test_compare_matches_semver_spec_reference(a: str, b: str) -> None:
    assert compare(a, b) == reference.Version.parse(a).compare(b)


# --- npm-pick-manifest ------------------------------------------------------------------------

AS_OF = datetime(2026, 10, 29, 12, tzinfo=UTC)
BEFORE = AS_OF - timedelta(days=1)
AFTER = AS_OF + timedelta(days=1)


def packument(
    *versions: tuple[str, datetime | None, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, datetime]]:
    manifests = {v: {"name": "p", "version": v, **extra} for v, _, extra in versions}
    published = {v: t for v, t, _ in versions if t is not None}
    return manifests, published


def test_pick_prefers_latest_when_it_satisfies() -> None:
    manifests, published = packument(
        ("1.0.0", BEFORE, {}), ("1.1.0", BEFORE, {}), ("1.2.0", BEFORE, {})
    )
    tags = {"latest": "1.1.0"}
    assert pick_version(manifests, tags, "^1.0.0", published=published, as_of=AS_OF) == "1.1.0"
    # Not satisfied: the highest satisfying version.
    assert pick_version(manifests, tags, "~1.2.0", published=published, as_of=AS_OF) == "1.2.0"
    # Empty spec is the default tag, treated as the range `*`.
    assert pick_version(manifests, tags, "", published=published, as_of=AS_OF) == "1.1.0"


def test_pick_skips_latest_published_after_as_of() -> None:
    manifests, published = packument(("1.0.0", BEFORE, {}), ("1.1.0", AFTER, {}))
    result = pick(manifests, {"latest": "1.1.0"}, "^1.0.0", published=published, as_of=AS_OF)
    assert result.version == "1.0.0"
    assert result.latest_after_as_of
    assert result.spec_type == "range"


def test_pick_star_accepts_prerelease_latest_but_other_ranges_do_not() -> None:
    manifests, published = packument(("1.0.0", BEFORE, {}), ("2.0.0-rc.1", BEFORE, {}))
    tags = {"latest": "2.0.0-rc.1"}
    assert pick_version(manifests, tags, "*", published=published, as_of=AS_OF) == "2.0.0-rc.1"
    assert pick_version(manifests, tags, "", published=published, as_of=AS_OF) == "2.0.0-rc.1"
    assert pick_version(manifests, tags, ">=0", published=published, as_of=AS_OF) == "1.0.0"
    # npm hands pick-manifest the trimmed spec, so " *" is "*" and "  " is "".
    assert pick_version(manifests, tags, " * ", published=published, as_of=AS_OF) == "2.0.0-rc.1"
    assert pick_version(manifests, tags, "  ", published=published, as_of=AS_OF) == "2.0.0-rc.1"


def test_pick_orders_deprecated_and_engines() -> None:
    manifests, published = packument(
        ("1.0.0", BEFORE, {}),
        ("1.1.0", BEFORE, {"engines": {"node": ">=99"}}),
        ("1.2.0", BEFORE, {"deprecated": "use 2"}),
        ("1.3.0", BEFORE, {"deprecated": "bad", "engines": {"node": "<1"}}),
    )
    args: dict[str, Any] = {"published": published, "as_of": AS_OF}
    # latest is deprecated, so the sort runs: good versions first.
    assert pick_version(manifests, {"latest": "1.2.0"}, "^1.0.0", **args) == "1.0.0"
    # Engines OK beats not deprecated.
    assert pick_version(manifests, {}, "^1.1.0", **args) == "1.2.0"
    # Only an engines failure left: it is still picked.
    assert pick_version(manifests, {}, ">=1.3.0", **args) == "1.3.0"
    manifests["1.0.0"]["deprecated"] = ""  # JavaScript: "" is falsy, so not deprecated
    assert pick_version(manifests, {}, "^1.0.0", **args) == "1.0.0"
    manifests["1.0.0"]["deprecated"] = {}  # and {} is truthy
    assert pick_version(manifests, {}, "^1.0.0", **args) == "1.2.0"
    manifests["1.0.0"]["deprecated"] = True
    assert pick_version(manifests, {}, "^1.0.0", **args) == "1.2.0"


def test_pick_excludes_untimed_stub_and_late_versions() -> None:
    manifests, published = packument(
        ("1.0.0", BEFORE, {}),
        ("1.1.0", None, {}),
        ("1.2.0", BEFORE, {"stub": True}),
        ("1.3.0", AFTER, {}),
    )
    result = pick(manifests, {}, "^1.0.0", published=published, as_of=AS_OF)
    assert result.version == "1.0.0"
    assert result.untimed == 1
    nothing = pick(manifests, {}, "^1.0.0", published=published, as_of=BEFORE - timedelta(1))
    assert nothing.version is None
    assert nothing.reason == "no-versions-by-as-of"
    assert pick(manifests, {}, "^2", published=published, as_of=AS_OF).reason == "no-match"


def test_pick_tags_and_exact_versions() -> None:
    manifests, published = packument(("1.0.0", BEFORE, {"deprecated": "x"}), ("2.0.0", AFTER, {}))
    tags = {"latest": "1.0.0", "next": "2.0.0", "gone": "3.0.0"}
    args: dict[str, Any] = {"published": published, "as_of": AS_OF}
    assert pick(manifests, tags, "latest", **args) == ranges.Pick("1.0.0", "tag")
    assert pick(manifests, tags, " latest ", **args) == ranges.Pick("1.0.0", "tag")
    assert pick(manifests, tags, "next", **args).reason == "tag-not-candidate"
    assert pick(manifests, tags, "gone", **args).reason == "unknown-tag"
    assert pick(manifests, tags, "missing", **args).reason == "unknown-tag"
    assert pick(manifests, tags, "bad tag", **args).reason == "invalid-spec"
    # Exact versions are cleaned loosely and skip the deprecation check.
    assert pick(manifests, tags, "=v1.0.0", **args) == ranges.Pick("1.0.0", "version")
    assert pick(manifests, tags, "2.0.0", **args).reason == "version-not-candidate"
    assert pick(manifests, tags, "1.0.0+build", **args).version == "1.0.0"


def test_pick_latest_stub_is_not_reported_as_late() -> None:
    manifests, published = packument(("1.0.0", BEFORE, {}), ("1.1.0", BEFORE, {"stub": True}))
    result = pick(manifests, {"latest": "1.1.0"}, "^1", published=published, as_of=AS_OF)
    assert result == ranges.Pick("1.0.0", "range")


def test_pick_ignores_hostile_manifests() -> None:
    manifests: dict[str, Any] = {"1.0.0": "not an object", "1.0.1": {"engines": ["node 0.4"]}}
    published = {"1.0.0": BEFORE, "1.0.1": BEFORE}
    assert pick_version(manifests, {"latest": 5}, "1", published=published, as_of=AS_OF) == "1.0.1"


@pytest.mark.parametrize(
    ("engines", "ok"),
    [
        (None, True),
        (["node >= 0.4"], True),  # legacy array form: `eng.node` is undefined
        ({}, True),
        ({"node": ">=18"}, True),
        ({"node": ">=25"}, False),
        ({"node": ">=24.15.0-0"}, True),
        ({"node": "^24.0.0-rc.1"}, True),  # prereleases included, so the range desugars wider
        ({"node": ""}, True),  # falsy: not checked
        ({"node": 0}, True),
        ({"node": 18}, False),  # truthy non-string: `new Range(18)` throws, satisfies is false
        ({"node": "not a range"}, False),
        ({"npm": ">=11"}, True),
        ({"npm": "<11"}, False),
        ({"node": ">=18", "npm": "^10"}, False),
    ],
)
def test_engines_ok(engines: object, ok: bool) -> None:
    assert engines_ok({"engines": engines}) is ok


# --- hostile input -----------------------------------------------------------------------------


def test_long_ranges_are_invalid_and_cheap() -> None:
    """`[v=\\s]*` in comparatorTrim made a run of `v` quadratic (16,000 characters took 2.4 s).
    Over `MAX_RANGE_LENGTH` a range is invalid (Kitsunox's cap; node-semver has none), so a
    megabyte of it costs nothing, and the possessive class keeps a capped one fast."""
    huge = "v" * 1_000_000
    capped = "v " * (ranges.MAX_RANGE_LENGTH // 2)
    start = time.perf_counter()
    assert valid_range(huge, loose=True) is None
    assert not satisfies("1.2.3", huge, loose=True)
    assert not engines_ok({"engines": {"node": huge}})
    assert pick({"1.0.0": {}}, {}, huge, published={}, as_of=AS_OF).reason == "invalid-spec"
    ranges._parse_range.cache_clear()
    assert valid_range(capped, loose=True) is None
    assert valid_range(capped + "1.2.3", loose=True) is None  # over the cap by five
    assert time.perf_counter() - start < 1.0
    at_cap = " " * (ranges.MAX_RANGE_LENGTH - 6) + "^1.2.3"
    assert valid_range(at_cap) == ">=1.2.3 <2.0.0-0"


def test_invalid_ranges_are_parsed_once() -> None:
    ranges._parse_range.cache_clear()
    for _ in range(3):
        assert not satisfies("1.0.0", "vvv not a range")
    info = ranges._parse_range.cache_info()
    assert (info.misses, info.hits) == (1, 2)
    with pytest.raises(InvalidRange, match="Invalid comparator: vvv"):  # the cached message
        Range.parse("vvv not a range")


def test_pick_checks_each_manifests_engines_once() -> None:
    """npm's comparator calls `engineOk` on every step; here each manifest is checked once,
    so many versions with distinct, slow `engines` values cost one parse each."""
    entries = [(f"1.0.{i}", BEFORE, {"engines": {"node": "v " * 400 + str(i)}}) for i in range(60)]
    manifests, published = packument(*entries)
    ranges._parse_range.cache_clear()
    result = pick(manifests, {}, "^1.0.0", published=published, as_of=AS_OF)
    assert result.version == "1.0.59"  # every engines value is invalid: highest version wins
    assert ranges._parse_range.cache_info().misses == 61  # 60 engines values and the spec
