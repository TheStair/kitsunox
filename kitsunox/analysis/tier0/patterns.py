"""Tier 0 — known-bad code-construct scanner.   [USER-OWNED — implement `scan()`]

Contract
--------
``scan(file_diffs, version_meta) -> list[Finding]``

Run signatures over **added/modified text files only** (never whole repos) and, with
elevated severity, over the **install-script surface**: ``version_meta.install_scripts``
plus any first-party file those scripts invoke.

Signature families to cover (see plan for the full list):
  - dynamic code exec: ``eval(`` / ``new Function(`` on non-literal input
  - base64/hex blob -> ``eval`` / ``exec`` / ``Function`` (``Buffer.from(x,'base64')``, ``atob(``)
  - ``child_process`` (exec/execSync/spawn) — HIGH inside an install script
  - network egress inside an install script (http/https/net/dns, ``fetch(``, curl/wget),
    especially to a raw IP or a non-registry host
  - obfuscation signatures where source is otherwise readable (``_0x`` identifiers,
    very long single lines, ``String.fromCharCode`` chains, high hex-escape density)
  - credential/secret exfil (``process.env`` sweep + outbound request, ``.npmrc``,
    ``~/.aws``, ``/etc/passwd``, ``NPM_TOKEN``, ``GITHUB_TOKEN``)

Each ``Finding``: ``tier=0``, a stable dotted ``rule_id`` under ``tier0.pattern.``,
a ``Severity``, ``file_path`` + ``line`` where locatable, a bounded ``evidence`` snippet
(≤ ~200 chars — never a whole file), and a plain-language ``rationale``.

``tests/test_tier0_patterns.py`` pins the expected ``rule_id`` / ``file_path`` / ``line``
for crafted inputs and currently fails.
"""

from __future__ import annotations

from collections.abc import Sequence

from kitsunox.ir import FileDiff, Finding, VersionMeta

# Suggested rule ids — keep stable once tests reference them.
RULE_DYNAMIC_EVAL = "tier0.pattern.dynamic_eval"
RULE_BASE64_EXEC = "tier0.pattern.base64_to_exec"
RULE_CHILD_PROCESS = "tier0.pattern.child_process"
RULE_INSTALL_NET = "tier0.pattern.install_script_network"
RULE_OBFUSCATION = "tier0.pattern.obfuscation"
RULE_SECRET_EXFIL = "tier0.pattern.secret_exfil"

EVIDENCE_MAX_CHARS = 200


def scan(file_diffs: Sequence[FileDiff], version_meta: VersionMeta) -> list[Finding]:
    """USER: implement. Return [] for clean input; never raise on malformed diffs."""
    raise NotImplementedError("TODO(user): Tier 0 pattern scanner — see module docstring")
