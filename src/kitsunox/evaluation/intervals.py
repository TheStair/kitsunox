"""Proportions with 95% intervals, for live evaluation."""

from __future__ import annotations

import math
from typing import Final

from kitsunox.core.models import Record

Z95: Final = 1.959963984540054


class Rate(Record):
    k: int
    n: int
    value: float | None
    low: float | None
    high: float | None


def wilson(k: int, n: int, z: float = Z95) -> Rate:
    """A proportion with its Wilson score interval (95% by default)."""
    if n == 0:
        return Rate(k=k, n=n, value=None, low=None, high=None)
    p = k / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return Rate(k=k, n=n, value=p, low=max(0.0, centre - half), high=min(1.0, centre + half))


def zero_bound(n: int, alpha: float = 0.05) -> float | None:
    """Exact one-sided upper bound on a rate when none of `n` draws was positive (≈ 3/n)."""
    return 1 - alpha ** (1 / n) if n else None
