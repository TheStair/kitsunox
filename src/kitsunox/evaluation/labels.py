"""Malware labels from OSV `MAL-` records (mirrored from ossf/malicious-packages).

`kitsunox labels sync` downloads the OSV export for an ecosystem (npm: ~220 MB zip, ~223k MAL
records on 2026-10-27), keeps only malware records, and saves a compact, hash-pinned `LabelSet`.
Labels are evaluation ground truth and, later, a known-bad lookup for Stage 4. Record contents are
untrusted data: only the fields below are kept, and only after type checks.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Final

from kitsunox.core.models import Persisted, Record
from kitsunox.core.run import DataDir
from kitsunox.core.store import RecordStore, timestamp_id
from kitsunox.ecosystems.npm import semver
from kitsunox.util.archive import ExtractLimits, extract_zip
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchError, HttpFetcher

OSV_EXPORT_URL: Final = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
OSV_ECOSYSTEM_NAMES: Final = {"npm": "npm"}
OSV_LIMITS: Final = ExtractLimits(
    max_compressed_bytes=1024 * 1024 * 1024,
    max_total_bytes=4 * 1024 * 1024 * 1024,
    max_file_bytes=8 * 1024 * 1024,
    max_files=5_000_000,
)
OSV_MAX_DOWNLOAD: Final = 1024 * 1024 * 1024


class AffectedRange(Record):
    """One OSV interval. `introduced="0"` means from the first version."""

    introduced: str
    fixed: str | None = None
    last_affected: str | None = None

    def contains(self, version: semver.SemVer) -> bool:
        if self.introduced != "0":
            low = semver.parse(self.introduced)
            if low is None or version < low:
                return False
        if self.fixed is not None:
            high = semver.parse(self.fixed)
            return high is not None and version < high
        if self.last_affected is not None:
            high = semver.parse(self.last_affected)
            return high is not None and version <= high
        return True

    @property
    def open_ended(self) -> bool:
        return self.fixed is None and self.last_affected is None


class MalwareLabel(Record):
    id: str
    published: datetime
    versions: tuple[str, ...] = ()
    ranges: tuple[AffectedRange, ...] = ()

    def affects(self, version: str) -> bool:
        if version in self.versions:
            return True
        parsed = semver.parse(version)
        return parsed is not None and any(r.contains(parsed) for r in self.ranges)

    def observes(self, version: str, published_at: datetime | None) -> bool:
        """Whether the record is evidence about this release, not just a projection onto it.

        An open-ended range ("introduced 0", nothing fixed) says "every version, including future
        ones". For a release published *after* the record, that is a guess: in the first live run
        it labeled two legitimate trusted-publisher builds of `@magda/semantic-indexer-sdk` as
        malware, from a 2025 record about the Shai-Hulud compromise. Listed versions and bounded
        ranges always count; open ranges count only for releases published before the record.
        """
        if version in self.versions:
            return True
        parsed = semver.parse(version)
        if parsed is None:
            return False
        for r in self.ranges:
            if not r.contains(parsed):
                continue
            if not r.open_ended or (published_at is not None and published_at <= self.published):
                return True
        return False

    @property
    def all_versions(self) -> bool:
        return any(r.introduced == "0" and r.open_ended for r in self.ranges)


class LabelSet(Persisted):
    ecosystem: str
    source: str
    fetched_at: datetime
    source_sha256: str
    labels: dict[str, tuple[MalwareLabel, ...]]

    @property
    def id(self) -> str:
        return timestamp_id(self.fetched_at)

    def match(self, name: str, version: str) -> tuple[str, ...]:
        """Ids of malware records covering this exact release."""
        return tuple(label.id for label in self.labels.get(name, ()) if label.affects(version))

    def classify(
        self, name: str, version: str, published_at: datetime | None
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """`(observed, projected)` record ids for a release; see `MalwareLabel.observes`."""
        matched = [label for label in self.labels.get(name, ()) if label.affects(version)]
        observed = tuple(m.id for m in matched if m.observes(version, published_at))
        return observed, tuple(m.id for m in matched if m.id not in observed)

    def known_malware(self, name: str, as_of: datetime) -> tuple[str, ...]:
        """Ids of records, published by `as_of`, that call *every* version of `name` malware.

        Records about some versions of a real package (a compromised `chalk` release) don't
        count: depending on `chalk` is not depending on malware. Measured on `day1` by name
        alone, 11 benign new packages "depended on malware" (`axios`, `chalk`, `debug`)."""
        return tuple(
            label.id
            for label in self.labels.get(name, ())
            if label.all_versions and label.published <= as_of
        )

    @property
    def record_count(self) -> int:
        return sum(len(v) for v in self.labels.values())


def label_store(data: DataDir) -> RecordStore[LabelSet]:
    return RecordStore(data.root / "labels", LabelSet)


def fetch_label_set(fetcher: HttpFetcher, *, ecosystem: str, fetched_at: datetime) -> LabelSet:
    url = OSV_EXPORT_URL.format(ecosystem=OSV_ECOSYSTEM_NAMES[ecosystem])
    response = fetcher.get(url)
    if not response.ok:
        raise FetchError(f"GET {url}: HTTP {response.status}")
    return LabelSet(
        ecosystem=ecosystem,
        source=url,
        fetched_at=fetched_at,
        source_sha256=sha256_hex(response.body),
        labels=parse_osv_export(response.body, ecosystem=OSV_ECOSYSTEM_NAMES[ecosystem]),
    )


def parse_osv_export(data: bytes, *, ecosystem: str) -> dict[str, tuple[MalwareLabel, ...]]:
    """Malware labels by package name. Withdrawn records and records that fail type checks are
    skipped; the result is sorted so identical input gives an identical LabelSet."""
    tree = extract_zip(data, limits=OSV_LIMITS)
    by_name: dict[str, list[MalwareLabel]] = {}
    for path in tree:
        if not (path.startswith("MAL-") and path.endswith(".json")):
            continue
        try:
            record = json.loads(tree[path])
        except ValueError:
            continue
        for name, label in _labels_from_record(record, ecosystem):
            by_name.setdefault(name, []).append(label)
    return {
        name: tuple(sorted(labels, key=lambda label: label.id))
        for name, labels in sorted(by_name.items())
    }


def _labels_from_record(record: object, ecosystem: str) -> list[tuple[str, MalwareLabel]]:
    if not isinstance(record, dict) or record.get("withdrawn"):
        return []
    record_id, published = record.get("id"), record.get("published")
    if not isinstance(record_id, str) or not isinstance(published, str):
        return []
    try:
        published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return []
    out = []
    for affected in _list(record.get("affected")):
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict) or package.get("ecosystem") != ecosystem:
            continue
        name = package.get("name")
        if not isinstance(name, str):
            continue
        versions = tuple(v for v in _list(affected.get("versions")) if isinstance(v, str))
        ranges = tuple(_ranges(affected.get("ranges")))
        if versions or ranges:
            label = MalwareLabel(
                id=record_id, published=published_at, versions=versions, ranges=ranges
            )
            out.append((name, label))
    return out


def _list(value: object) -> list[object]:
    """Untrusted JSON: iterate only real lists (`x or []` crashes on `true`, found by fuzzing)."""
    return value if isinstance(value, list) else []


def _ranges(raw: object) -> list[AffectedRange]:
    """Turn OSV SEMVER/ECOSYSTEM event lists into intervals."""
    if not isinstance(raw, list):
        return []
    result = []
    for entry in raw:
        if not isinstance(entry, dict) or entry.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        introduced: str | None = None
        for event in _list(entry.get("events")):
            if not isinstance(event, dict):
                continue
            if isinstance(event.get("introduced"), str):
                if introduced is not None:
                    result.append(AffectedRange(introduced=introduced))
                introduced = event["introduced"]
            elif introduced is not None and isinstance(event.get("fixed"), str):
                result.append(AffectedRange(introduced=introduced, fixed=event["fixed"]))
                introduced = None
            elif introduced is not None and isinstance(event.get("last_affected"), str):
                result.append(
                    AffectedRange(introduced=introduced, last_affected=event["last_affected"])
                )
                introduced = None
        if introduced is not None:
            result.append(AffectedRange(introduced=introduced))
    return result
