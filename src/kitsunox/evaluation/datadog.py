"""Malicious samples from the DataDog malicious-software-packages dataset (Apache-2.0).

The dataset ships each sample as a ZipCrypto zip (password `infected`) holding the package files
and `package_info-<name>-<version>.json`: the registry packument as DataDog captured it, with
`_npmUser`, maintainers, `dist` and the `time` map, usually including earlier versions. That is
everything Stage 1 reads, so each sample becomes an ordinary `Change` through the same
`Packument` parser Stage 0 uses.

- `compromised_lib/` → shape A (a compromised release of a real package); the previous
  version comes from the same packument.
- `malicious_intent/` → shape B (published to deliver malware).

The dataset's `manifest.json` lists, per package, the malicious versions (`null` = all of them).
A sample whose previous version is also listed is a *follow-on* release: worms such as
Shai-Hulud publish several malicious versions in a row, and only the first one differs from
benign code. Measured on the 2026-10-27 import, 481 of 1,446 shape-A samples are follow-ons.
They are kept, but reported separately (`ExternalSample.previous_malicious`).

Safety: zips are stored **as distributed** (still encrypted) in their own blob store under
`data/eval/malware/`, away from the pipeline's `data/blobs`. Only the `package_info` member is
ever decrypted, in memory, and it is parsed as untrusted JSON. Package code is never extracted
here, and never executed on the host.

Downloads are pinned to one dataset commit, so a sample set rebuilds byte-identically from its
recorded snapshot. Shape-B samples are a deterministic subset (ordered by a hash of the path);
the dataset holds ~25k of them, mostly GuardDog detections, so it leans towards what GuardDog
finds.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from typing import Any, Final

from kitsunox.core.models import Change
from kitsunox.core.watchlist import Watchlist
from kitsunox.ecosystems.npm.packument import Packument, is_registry_placeholder
from kitsunox.evaluation.dataset import ExternalSample, ExternalSampleSet, Shape
from kitsunox.util.archive import ExtractLimits, extract_zip
from kitsunox.util.disk import DiskSpaceError
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchError, HttpFetcher

SOURCE: Final = "datadog"
REPO: Final = "DataDog/malicious-software-packages-dataset"
API_URL: Final = f"https://api.github.com/repos/{REPO}"
RAW_URL: Final = f"https://raw.githubusercontent.com/{REPO}"
ZIP_PASSWORD: Final = b"infected"
CATEGORIES: Final = {"compromised_lib": Shape.A, "malicious_intent": Shape.B}
SAMPLE_LIMITS: Final = ExtractLimits(max_compressed_bytes=256 * 1024 * 1024)
_GITHUB_JSON: Final = {"Accept": "application/vnd.github+json"}


def fetch_datadog(
    fetcher: HttpFetcher,
    *,
    fetched_at: datetime,
    limits: Mapping[str, int | None],
    watchlist: Watchlist | None = None,
    workers: int = 8,
) -> ExternalSampleSet:
    """Download and convert npm samples. `limits` caps each category (None = all of it)."""
    commit = _get_json(fetcher, f"{API_URL}/commits/main").get("sha")
    if not isinstance(commit, str):
        raise FetchError("dataset commit has no sha")
    listing = _get_json(fetcher, f"{API_URL}/contents/samples/npm?ref={commit}")
    trees = {
        e["name"]: e["sha"]
        for e in listing.get("entries", [])
        if isinstance(e, dict) and e.get("type") == "dir"
    }
    selected: list[str] = []
    for category in sorted(limits):
        tree = _get_json(fetcher, f"{API_URL}/git/trees/{trees[category]}?recursive=1")
        if tree.get("truncated"):
            raise FetchError(f"tree listing for {category} was truncated")
        entries = tree.get("tree")
        paths = [
            f"{category}/{e['path']}"
            for e in (entries if isinstance(entries, list) else [])
            if isinstance(e, dict)
            and e.get("type") == "blob"
            and isinstance(e.get("path"), str)
            and e["path"].endswith(".zip")
            and e["path"].count("/") == 2
        ]
        paths.sort(key=lambda p: sha256_hex(p.encode()))
        selected.extend(paths[: limits[category]])

    manifest = _malicious_versions(fetcher, commit)

    def convert(path: str) -> ExternalSample | str:
        try:
            return _convert(fetcher, commit, path, watchlist, manifest)
        except DiskSpaceError:
            raise
        except Exception as exc:  # hostile input: one bad sample must not stop the import
            return f"{type(exc).__name__}: {exc}"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = dict(zip(selected, pool.map(convert, selected), strict=True))
    samples: dict[str, ExternalSample] = {}
    failures: dict[str, str] = {}
    for path in sorted(results):
        result = results[path]
        if isinstance(result, str):
            failures[path] = result
        else:
            samples.setdefault(str(result.change.new.ref), result)  # same release twice: first path
    return ExternalSampleSet(
        source=SOURCE,
        ecosystem="npm",
        commit=commit,
        fetched_at=fetched_at,
        limits=dict(sorted(limits.items())),
        watchlist_id=watchlist.id if watchlist else None,
        samples=tuple(sorted(samples.values(), key=lambda s: s.path)),
        failures=failures,
    )


def parse_sample_path(path: str) -> tuple[Shape, str, str, date | None]:
    """`<category>/<name>/<version>/<YYYY-MM-DD>-<...>.zip`. Scoped names are stored as
    `@scope@name`."""
    category, raw_name, version, filename = path.split("/")
    name = "@" + raw_name[1:].replace("@", "/", 1) if raw_name.startswith("@") else raw_name
    try:
        discovered: date | None = date.fromisoformat(filename[:10])
    except ValueError:
        discovered = None
    return CATEGORIES[category], name, version, discovered


def _malicious_versions(fetcher: HttpFetcher, commit: str) -> dict[str, frozenset[str] | None]:
    """Package -> malicious versions; None means every version."""
    response = fetcher.get(f"{RAW_URL}/{commit}/samples/npm/manifest.json", immutable=True)
    if not response.ok:
        raise FetchError(f"manifest.json: HTTP {response.status}")
    raw = json.loads(response.body)
    if not isinstance(raw, dict):
        raise FetchError("manifest.json: not an object")
    return {
        name: None if versions is None else frozenset(v for v in versions if isinstance(v, str))
        for name, versions in raw.items()
        if isinstance(name, str) and (versions is None or isinstance(versions, list))
    }


def _convert(
    fetcher: HttpFetcher,
    commit: str,
    path: str,
    watchlist: Watchlist | None,
    manifest: Mapping[str, frozenset[str] | None],
) -> ExternalSample:
    shape, name, version, discovered = parse_sample_path(path)
    response = fetcher.get(f"{RAW_URL}/{commit}/samples/npm/{path}", immutable=True)
    if not response.ok:
        raise FetchError(f"HTTP {response.status}")
    tree = extract_zip(
        response.body,
        limits=SAMPLE_LIMITS,
        password=ZIP_PASSWORD,
        include=lambda p: p.rsplit("/", 1)[-1].startswith("package_info"),
    )
    if len(tree.files) != 1:
        raise ValueError(f"expected one package_info file, found {len(tree.files)}")
    (raw,) = tree.files.values()
    packument = Packument(json.loads(raw), expected_name=name)
    if version not in packument.versions:
        raise ValueError(f"version {version} not in package_info")
    if is_registry_placeholder(packument.snapshot(version)):
        raise ValueError("registry placeholder, not attacker content")
    previous = packument.previous_version(version)
    change = Change(
        new=packument.snapshot(version),
        previous=packument.snapshot(previous) if previous is not None else None,
        repository_url=packument.repository_url(version),
        popularity=watchlist.lookup([name])[name] if watchlist else None,
    )
    previous_malicious: bool | None = None
    if previous is None:
        previous_malicious = False
    elif name in manifest:
        listed = manifest[name]
        previous_malicious = listed is None or previous in listed
    return ExternalSample(
        path=path,
        shape=shape,
        discovered=discovered,
        change=change,
        previous_malicious=previous_malicious,
    )


def _get_json(fetcher: HttpFetcher, url: str) -> dict[str, Any]:
    """A GitHub API object. A top-level list (directory listings) is wrapped as `entries`."""
    response = fetcher.get(url, headers=_GITHUB_JSON)
    if not response.ok:
        raise FetchError(f"GET {url}: HTTP {response.status}")
    data = json.loads(response.body)
    if isinstance(data, list):
        return {"entries": data}
    if not isinstance(data, dict):
        raise FetchError(f"GET {url}: unexpected JSON")
    return data
