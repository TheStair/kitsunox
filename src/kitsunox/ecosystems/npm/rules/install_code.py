"""What the files an npm install script runs can do (Stage 3).

Install scripts run on `npm install` with the user's privileges. `npm.install-hook` (Stage 1)
sees the hook's command line change; this rule sees the code behind it, including when the
command stays `node setup.js` and only `setup.js` changes.

`day1` (2026-10-28): an install-script file using network, process, the whole environment or
dynamic code: benign 0.9% of updates and 0.2% of new packages; malicious 70.2% and 33.7%.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from kitsunox.core.models import Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.lang.javascript import Capability
from kitsunox.rules.capabilities import evidence
from kitsunox.stages.ast import CodeChange

C = Capability
RISKY: Final = frozenset({C.NETWORK, C.PROCESS, C.ENV_ALL, C.DYNAMIC_CODE, C.DYNAMIC_REQUIRE})


class InstallScriptCode(BaseRule):
    """The code an install hook runs reaches the network, runs processes, takes the whole
    environment or runs dynamic code. For an update, only capabilities the install code didn't
    have before count."""

    id = "npm.install-script-code"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Install script runs risky code"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        if change.install is None:
            return ()
        risky = change.install.capabilities & RISKY
        if change.before is not None:
            risky -= change.install_before.capabilities if change.install_before else frozenset()
        if not risky:
            return ()
        files = ", ".join(sorted({u.path for u in change.install.uses}))
        names = ", ".join(sorted(c.value for c in risky))
        return (
            self.finding(
                f"`npm install` runs {files}, which uses {names}"
                + (" (new to the install code)." if change.before is not None else "."),
                *evidence(change.install, risky),
            ),
        )


RULES: Final = (InstallScriptCode(),)
