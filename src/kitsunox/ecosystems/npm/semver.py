"""Minimal SemVer 2.0.0 parsing and precedence, enough to order npm versions.

npm only accepts valid semver on publish, but packuments are untrusted input, so anything that
doesn't parse returns None and callers fall back to publish-time ordering.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@total_ordering
@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[int | str, ...] = ()

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        core_self = (self.major, self.minor, self.patch)
        core_other = (other.major, other.minor, other.patch)
        if core_self != core_other:
            return core_self < core_other
        # A version without prerelease has higher precedence than one with.
        if not self.prerelease or not other.prerelease:
            return bool(self.prerelease) and not other.prerelease
        for a, b in zip(self.prerelease, other.prerelease, strict=False):
            if a == b:
                continue
            if isinstance(a, int) and isinstance(b, int):
                return a < b
            if isinstance(a, int) != isinstance(b, int):
                return isinstance(a, int)  # numeric identifiers sort before alphanumeric
            return str(a) < str(b)
        return len(self.prerelease) < len(other.prerelease)


def parse(version: str) -> SemVer | None:
    match = _SEMVER.match(version.strip())
    if match is None:
        return None
    major, minor, patch, pre, _build = match.groups()
    prerelease = tuple(int(p) if p.isdigit() else p for p in pre.split(".")) if pre else ()
    return SemVer(int(major), int(minor), int(patch), prerelease)
