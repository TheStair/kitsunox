"""Stage 3 wiring for npm: the rule set and install-entry finder `kitsunox ast` and `collect`
use. Kept apart from `stages/ast.py`, which is ecosystem-agnostic."""

from __future__ import annotations

from typing import Final

import httpx

from kitsunox.core.models import PackageBatch
from kitsunox.core.run import DataDir
from kitsunox.ecosystems.npm.install import gyp_commands, install_sources
from kitsunox.ecosystems.npm.registry import NpmEcosystem
from kitsunox.ecosystems.npm.rules.install_code import RULES as NPM_CODE_RULES
from kitsunox.ecosystems.npm.rules.install_shapes import RULES as NPM_SHAPE_RULES
from kitsunox.ecosystems.npm.rules.undeclared import RULES as NPM_UNDECLARED_RULES
from kitsunox.rules.agents import RULES as AGENT_RULES
from kitsunox.rules.capabilities import RULES as GENERIC_CODE_RULES
from kitsunox.stages.ast import CodeRule, record_ast

CODE_RULES: Final[tuple[CodeRule, ...]] = (
    *GENERIC_CODE_RULES,
    *AGENT_RULES,
    *NPM_CODE_RULES,
    *NPM_SHAPE_RULES,
    *NPM_UNDECLARED_RULES,
)


def run_code_stage(
    data: DataDir, run_id: str, *, workers: int = 8, client: httpx.Client | None = None
) -> tuple[PackageBatch, ...]:
    return record_ast(
        data,
        run_id,
        NpmEcosystem,
        CODE_RULES,
        install_entries=install_sources,
        build_commands=gyp_commands,
        workers=workers,
        client=client,
    )
