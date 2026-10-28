"""Schema-version check for JSON files written by Kitsunox.

Every persisted record carries `schema_version`. Loaders check it *before* validation so an old
or foreign file fails with a clear message instead of a wall of field errors. Bump a record's
version on any incompatible change (renamed/removed/retyped field) and note it in the devlog.
"""

from __future__ import annotations

import json


class SchemaVersionError(ValueError):
    """A file was written with a schema version this build can't read."""


def require_schema_version(data: str | bytes, expected: int, kind: str) -> None:
    try:
        raw = json.loads(data)
    except json.JSONDecodeError as exc:
        raise SchemaVersionError(f"{kind}: not valid JSON ({exc.msg})") from exc
    except UnicodeDecodeError as exc:
        raise SchemaVersionError(f"{kind}: not valid JSON (not UTF-8)") from exc
    found = raw.get("schema_version") if isinstance(raw, dict) else None
    if found != expected:
        shown = "none (unversioned)" if found is None else repr(found)
        raise SchemaVersionError(
            f"{kind}: file has schema_version {shown}, this build reads {expected}. "
            "Re-create it with the current version (or add a migration)."
        )
