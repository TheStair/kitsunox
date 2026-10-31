"""After-the-fact confirmations: registry takedowns found in the runs' feeds, and OSV records."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from conftest import run_manifest
from kitsunox.core.models import Change, PackageVersionRef, PublishInfo, VersionSnapshot
from kitsunox.core.run import DataDir
from kitsunox.ecosystems.npm.packument import is_security_holder
from kitsunox.evaluation.confirmations import (
    Confirmations,
    Takedown,
    read_takedowns,
    scan_takedowns,
    takedowns_path,
)
from kitsunox.evaluation.labels import AffectedRange, LabelSet, MalwareLabel
from kitsunox.stages.ingest import write_jsonl

T = datetime(2026, 10, 30, 18, 0, tzinfo=UTC)


def change(name: str, version: str, publisher: str, at: datetime) -> Change:
    return Change(
        new=VersionSnapshot(
            ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
            publish=PublishInfo(published_at=at, publisher=publisher),
            manifest={},
        )
    )


def save_run(data: DataDir, run_id: str, *changes: Change) -> None:
    run_dir = data.run_dir(run_id)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(run_manifest(run_id).model_dump_json())
    write_jsonl(run_dir / "changes.jsonl", changes)


def test_takedowns_are_found_in_the_feed_once_and_kept(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    holder = change("stealer", "0.0.1-security", "npm", T)
    save_run(
        data,
        "20261030T180000Z-npm",
        change("stealer", "1.0.0", "mallory", T - timedelta(hours=5)),
        holder,
        change("decoy", "0.0.1-security", "mallory", T),  # anyone can publish the version string
    )
    # The next chained run overlaps the first and carries the same takedown, then another.
    save_run(data, "20261030T190000Z-npm", holder, change("probe", "0.0.1-security", "npm", T))
    (data.run_dir("20261030T200000Z-npm")).mkdir(parents=True)  # ingest still running: skipped

    log, runs, added = scan_takedowns(data, "npm", is_security_holder)
    assert (runs, added) == (2, 2)
    assert log.scanned_through == "20261030T190000Z-npm"
    assert [(t.name, t.run_id) for t in log.takedowns] == [
        ("probe", "20261030T190000Z-npm"),
        ("stealer", "20261030T180000Z-npm"),
    ]
    assert read_takedowns(tmp_path, "npm") == log

    assert scan_takedowns(data, "npm", is_security_holder)[1:] == (0, 0)  # nothing new to read
    save_run(data, "20261030T210000Z-npm", change("late", "0.0.1-security", "npm", T))
    log, runs, added = scan_takedowns(data, "npm", is_security_holder)
    assert (runs, added, len(log.takedowns)) == (1, 1, 3)


def test_an_unreadable_log_is_rebuilt_from_the_kept_runs(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save_run(data, "20261030T180000Z-npm", change("stealer", "0.0.1-security", "npm", T))
    path = takedowns_path(tmp_path, "npm")
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    log, runs, _ = scan_takedowns(data, "npm", is_security_holder)
    assert runs == 1
    assert [t.name for t in log.takedowns] == ["stealer"]


def test_a_takedown_confirms_versions_published_before_it_by_as_of() -> None:
    takedown = Takedown(name="p", version="0.0.1-security", published_at=T, run_id="r")
    found = Confirmations([takedown], None, as_of=T).of("p", "1.0.0", T - timedelta(hours=1))
    assert [(c.source, c.id, c.published) for c in found] == [("registry", "0.0.1-security", T)]
    # The name was registered again after the takedown: the new owner's release isn't it.
    assert Confirmations([takedown], None, as_of=T).of("p", "2.0.0", T + timedelta(hours=1)) == ()
    # A takedown later than as_of is not known yet.
    assert Confirmations([takedown], None, as_of=T - timedelta(minutes=1)).of("p", "1", None) == ()


def test_osv_records_confirm_the_versions_they_cover_by_as_of() -> None:
    labels = LabelSet(
        ecosystem="npm",
        source="s",
        fetched_at=T,
        source_sha256="0",
        labels={
            "p": (
                MalwareLabel(id="MAL-1", published=T - timedelta(days=1), versions=("1.0.0",)),
                MalwareLabel(
                    id="MAL-2", published=T, ranges=(AffectedRange(introduced="0"),)
                ),  # every version
                MalwareLabel(id="MAL-3", published=T + timedelta(days=1), versions=("1.0.0",)),
            )
        },
    )
    confirm = Confirmations((), labels, as_of=T)
    assert [c.id for c in confirm.of("p", "1.0.0", None)] == ["MAL-1", "MAL-2"]
    assert [c.id for c in confirm.of("p", "2.0.0", None)] == ["MAL-2"]
    assert confirm.of("q", "1.0.0", None) == ()
