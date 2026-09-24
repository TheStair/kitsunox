"""Adapter for external package-artifact corpora (docs/Plan.md §7a).

The ground-truth set in `incidents.py` is commit-shaped: diffs, authors, review state.
Published benchmark corpora are package-shaped: a directory of files as npm would install
them, with no commit, no author and no review history. This module bridges the two so the
Tier 0 content rules can be measured against an external, peer-reviewed corpus.

The corpus in use is the replication package for "How Effective Are NPM Malicious Package
Detectors? A Large-Scale Empirical Study" (ASE 2026), CC BY 4.0, from
https://doi.org/10.6084/m9.figshare.31869370 — 6,420 malicious versions across 4,286
packages plus 7,288 benign, each malicious sample annotated with behaviour categories and
evasion techniques and reviewed by three security experts. It also ships per-tool results
for 11 detectors, which is where the comparison numbers in the write-up come from.

**What this measures, and what it does not.** A package carries no commit metadata, so
every `context.*` rule is inert here — tenure, direct-push, review and CI signals included,
and with them the AV-800 combo. Only the content patterns are exercised. Results from this
corpus therefore speak to the pattern-matching half of Tier 0 and nothing else; the
commit-level half is measured on the git corpus, where package-level tools cannot reach
(neither tj-actions nor reviewdog ever produced an npm artifact at all).

One further caveat that must survive into the write-up: the corpus's own
`malware_snippets` were extracted from GuardDog's output, so scoring against *those*
would measure agreement with GuardDog rather than ground truth. This module deliberately
reads whole package files and uses the corpus's expert `malicious_files` labels instead.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from kitsunox.model import Change, FileDiff, GroundTruth

# Extensions worth reading as text. Everything else is recorded as a binary FileDiff so
# `content.binary_added` still sees it, without pulling megabytes of images into memory.
TEXT_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".sh", ".bash", ".py",
    ".yml", ".yaml", ".ps1", ".bat", ".cmd", ".map", ".txt", ".md",
}

# A single vendored bundle can be tens of MB; past this we keep the head, which is where
# install-time payloads live, rather than skipping the file entirely.
MAX_FILE_BYTES = 2_000_000


@dataclass(frozen=True)
class CorpusEntry:
    """One package version from an external corpus."""

    name: str
    version: str
    root: Path
    ground_truth: GroundTruth
    malicious_files: tuple[str, ...] = ()  # expert-labelled, relative to `root`

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


def _as_patch(text: str) -> str:
    """Render a whole file as an all-added unified diff hunk.

    The rules read added lines, so a package file is presented as if every line had just
    been introduced. That is exactly what a first publish is, and it keeps one code path
    in `rules.py` rather than a second scanner for package mode.
    """
    lines = text.split("\n")
    return f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + ln for ln in lines)


def _read_file(path: Path) -> FileDiff | None:
    rel = path.name
    try:
        size = path.stat().st_size
    except OSError:
        return None

    if path.suffix.lower() not in TEXT_SUFFIXES:
        return FileDiff(path=rel, change_type="added", is_binary=True)

    try:
        raw = path.read_bytes()[:MAX_FILE_BYTES]
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return None

    return FileDiff(
        path=rel,
        change_type="added",
        is_binary=False,
        additions=text.count("\n") + 1,
        patch=_as_patch(text),
        truncated=size > MAX_FILE_BYTES,
    )


def to_change(entry: CorpusEntry) -> Change:
    """Turn a package directory into a `Change` the Tier 0 rules can scan.

    `source` is "push" because a publish has no pull request, but every review-related
    field stays at its default of None/0 rather than being invented — an absent signal
    must never be scored as a clean one.
    """
    files: list[FileDiff] = []
    for path in sorted(entry.root.rglob("*")):
        if not path.is_file():
            continue
        diff = _read_file(path)
        if diff is None:
            continue
        diff.path = str(path.relative_to(entry.root)).replace("\\", "/")
        files.append(diff)

    return Change(
        repo=entry.key,
        source="push",
        sha=entry.key,
        shas=[],
        author=None,
        committed_at=None,
        files=files,
        ground_truth=entry.ground_truth,
    )


def load_labels(package_label_dir: Path) -> dict[str, tuple[str, ...]]:
    """Read the corpus's expert `malicious_files` annotations.

    Layout is `<pkg>/<version>/<pkg>-<version>-analysis.json`, each holding absolute
    paths from the authors' own machine, so only the part after `/package/` is kept.
    """
    labels: dict[str, tuple[str, ...]] = {}
    for meta in package_label_dir.rglob("*-analysis.json"):
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        name, version = data.get("package_name"), data.get("version")
        if not name or not version:
            continue
        rels = tuple(
            f.split("/package/", 1)[1]
            for f in data.get("malicious_files", [])
            if "/package/" in f
        )
        labels[f"{name}@{version}"] = rels
    return labels


def discover(root: Path, ground_truth: GroundTruth, labels: dict | None = None) -> list[CorpusEntry]:
    """Find `<name>/<version>/` package directories beneath `root`."""
    labels = labels or {}
    entries = []
    for version_dir in sorted(root.glob("*/*")):
        if not version_dir.is_dir():
            continue
        name, version = version_dir.parent.name, version_dir.name
        # npm tarballs unpack into a `package/` wrapper; descend when it is there.
        inner = version_dir / "package"
        entries.append(
            CorpusEntry(
                name=name,
                version=version,
                root=inner if inner.is_dir() else version_dir,
                ground_truth=ground_truth,
                malicious_files=labels.get(f"{name}@{version}", ()),
            )
        )
    return entries
