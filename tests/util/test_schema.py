import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from kitsunox.core.models import Change, PackageVersionRef, PublishInfo, VersionSnapshot
from kitsunox.util.http import Snapshot
from kitsunox.util.schema import SchemaVersionError, require_schema_version


def a_change() -> Change:
    return Change(
        new=VersionSnapshot(
            ref=PackageVersionRef(ecosystem="npm", name="x", version="1.0.0"),
            publish=PublishInfo(),
            manifest={},
        )
    )


def test_persisted_records_round_trip_with_version() -> None:
    change = a_change()
    data = change.model_dump_json()
    assert json.loads(data)["schema_version"] == 1
    assert Change.load_json(data) == change


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.pop("schema_version"), "none \\(unversioned\\)"),
        (lambda d: d.update(schema_version=2), "schema_version 2"),
    ],
)
def test_other_versions_are_refused_before_validation(mutate, message) -> None:  # type: ignore[no-untyped-def]
    raw = json.loads(a_change().model_dump_json())
    mutate(raw)
    with pytest.raises(SchemaVersionError, match=message):
        Change.load_json(json.dumps(raw))


def test_cannot_construct_with_wrong_version() -> None:
    with pytest.raises(ValidationError):
        Change(new=a_change().new, schema_version=0)


def test_snapshot_version_checked(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.json"
    Snapshot().save(path)
    assert Snapshot.load(path).schema_version == 1
    path.write_text('{"entries": {}}')
    with pytest.raises(SchemaVersionError, match="Snapshot"):
        Snapshot.load(path)


@pytest.mark.parametrize("data", ["not json", "[1, 2]"])
def test_non_object_json_is_refused(data: str) -> None:
    with pytest.raises(SchemaVersionError):
        require_schema_version(data, 1, "Thing")
