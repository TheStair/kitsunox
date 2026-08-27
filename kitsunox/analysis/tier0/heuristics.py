"""Tier 0 — structural heuristics on the version-to-version diff.   [USER-OWNED]

Contract
--------
``check(file_diffs, prev_meta, cur_meta) -> list[Finding]``

``prev_meta`` is ``None`` for a package's first publish.

Heuristics to cover (see plan):
  - new binary blob added (esp. ``.node`` / ``.wasm`` / executables / archives)
  - Shannon entropy of an added/modified text file above threshold (packed payload)
  - an install script (preinstall/install/postinstall) appears where the previous
    version had NONE  — the single highest-value Tier 0 heuristic
  - a dependency newly points at a git URL / tarball URL instead of a registry range
  - previously pinned dependency ranges widened (``^1.2.3`` / exact -> ``*`` / ``latest``)
  - ``unpacked_size`` jump disproportionate to the semver delta

Helpers you may want:
  - ``shannon_entropy(data: bytes) -> float`` is provided below.
  - ``kitsunox.ir.VersionMeta.has_install_script`` for the install-script check.

``tests/test_tier0_heuristics.py`` pins expectations and currently fails.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence

from kitsunox.ir import FileDiff, Finding, VersionMeta

RULE_NEW_BINARY = "tier0.heuristic.new_binary_blob"
RULE_ENTROPY_SPIKE = "tier0.heuristic.entropy_spike"
RULE_NEW_INSTALL_SCRIPT = "tier0.heuristic.new_install_script"
RULE_NONREGISTRY_DEP = "tier0.heuristic.nonregistry_dependency"
RULE_PINNING_LOSS = "tier0.heuristic.dependency_pinning_loss"
RULE_SIZE_JUMP = "tier0.heuristic.unpacked_size_jump"

ENTROPY_THRESHOLD = 4.8  # bits/byte; tune against the control sample later


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def check(
    file_diffs: Sequence[FileDiff],
    prev_meta: VersionMeta | None,
    cur_meta: VersionMeta,
) -> list[Finding]:
    """USER: implement. Return [] for clean input; never raise on malformed diffs."""
    raise NotImplementedError("TODO(user): Tier 0 heuristics — see module docstring")
