"""Settings and secrets from the environment or the project's `.env` (gitignored).

Values are never logged or echoed: callers get the value and decide what to say about it.
"""

from __future__ import annotations

import os
from pathlib import Path

DOTENV = Path(".env")


def env_value(name: str, dotenv: Path = DOTENV) -> str | None:
    """`name` from the process environment, else from `dotenv`, else None. Empty counts as
    unset. `.env` lines are `KEY=VALUE`, optionally prefixed with `export `, with `#` comment
    lines and optional matching quotes around the value; the last assignment wins, as in a
    shell."""
    value = os.environ.get(name)
    if value:
        return value
    try:
        lines = dotenv.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return None
    found: str | None = None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").lstrip()
        key, sep, rest = line.partition("=")
        if not sep or key.strip() != name:
            continue
        rest = rest.strip()
        if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in "\"'":
            rest = rest[1:-1]
        found = rest
    return found or None
