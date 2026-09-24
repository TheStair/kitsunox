"""The ground-truth incident set (docs/Plan.md §5) — five known source-level supply
chain attacks, hardcoded here rather than discovered dynamically.

Four are fetched live from the GitHub API; `tj-actions/changed-files` is the one
exception — its commit object was force-pushed out of the repo and every mirror checked,
so its diff lives in `fixtures/tj_actions_changed_files_2025.json` (recovered byte-exact
from a fork's revert commit, not reconstructed by hand).

All five are direct pushes, no PR involved — which is itself a finding worth keeping in
mind for rules.py: the most severe git-level attacks tend to come from an account that
already has push rights, not from sneaking something past review.

Adding a sixth incident means appending one `Incident` here and nothing else. Before
assuming a new one needs a fixture, actually call `fetch.fetch_commit` on it — and if
the original commit is gone, look for a "clone-then-revert" fork before settling for a
lossy reconstruction. Every SHA below was confirmed against the live API rather than
recalled.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from kitsunox import fetch
from kitsunox.model import Change, FileDiff

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@dataclass(frozen=True)
class Incident:
    """One known-malicious change. `fixture` names a file under `fixtures/` when the
    commit can't be fetched live; otherwise it's None and the SHA is fetched."""

    key: str  # short slug — how the incident is named on the CLI and in reports
    label: str
    repo: str  # "owner/name"
    sha: str
    year: int
    summary: str
    fixture: str | None = None

    @property
    def is_live(self) -> bool:
        return self.fixture is None


INCIDENTS: list[Incident] = [
    Incident(
        key="xz-utils",
        label="xz-utils backdoor (CVE-2024-3094)",
        repo="tukaani-project/xz",
        sha="cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0",
        year=2024,
        summary=(
            "JiaT75 adds five binary blobs under tests/files/ — 'bad-3-corrupt_lzma2.xz' "
            "and 'good-large_compressed.lzma' carry the backdoor payload, extracted at "
            "build time by a tampered m4 script. The m4 tampering itself only ever "
            "shipped in the release tarball, never in git, so this commit is the "
            "git-visible half of the attack."
        ),
    ),
    Incident(
        key="event-stream",
        label="event-stream / flatmap-stream",
        repo="dominictarr/event-stream",
        sha="e3163361fed01384c986b9b4c18feb1fc42b8285",
        year=2018,
        summary=(
            "right9ctrl, having been handed maintainership weeks earlier, adds a "
            "'flatmap-stream' dependency to package.json alongside a plausible feature "
            "and its tests. The malicious code lived in the dependency, not here — the "
            "only git-visible signal is who added the dep and how recently they were "
            "granted trust."
        ),
    ),
    Incident(
        key="reviewdog",
        label="reviewdog/action-setup compromise (CVE-2025-30154)",
        repo="reviewdog/action-setup",
        sha="f0d342d24037bb11d26b9bd8496e0808ba32e9ec",
        year=2025,
        summary=(
            "install.sh gains a base64-encoded payload that scrapes the Actions runner's "
            "memory for secrets. First stage of the chain that went on to compromise "
            "tj-actions. The commit is off every branch and tag but still reachable by "
            "SHA."
        ),
    ),
    Incident(
        key="tj-actions",
        label="tj-actions/changed-files compromise (CVE-2025-30066)",
        repo="tj-actions/changed-files",
        sha="0e58ed8671d6b60d0890c21b07f8835ace038e67",
        year=2025,
        summary=(
            "dist/index.js gains a curl-to-gist memory scraper that dumps CI secrets "
            "into public workflow logs. Every version tag was retroactively rewritten to "
            "point at this one commit, so pinning a tag was no defense."
        ),
        fixture="tj_actions_changed_files_2025.json",
    ),
    Incident(
        key="colors.js",
        label="colors.js sabotage",
        repo="Marak/colors.js",
        sha="074a0f8ed0c31c35d13d28632bd8a049ff136fb6",
        year=2022,
        summary=(
            "The maintainer pushes an 'American flag module' containing a "
            "`for (let i = 666; i < Infinity; i++)` loop that hangs every consuming app. "
            "Self-sabotage rather than an external compromise — useful as a case where "
            "author trust signals are all clean and only the diff itself is damning."
        ),
    ),
]

INCIDENTS_BY_KEY = {inc.key: inc for inc in INCIDENTS}


def _load_fixture(incident: Incident) -> Change:
    """Build a Change from a hardcoded fixture JSON. Its `files` entries are already
    FileDiff-shaped; the rest of the file is provenance metadata that doesn't belong on
    the Change."""
    assert incident.fixture is not None
    data = json.loads((FIXTURE_DIR / incident.fixture).read_text(encoding="utf-8"))
    return Change(
        repo=data["repo"],
        source=data["source"],
        sha=data["sha"],
        shas=[data["sha"]],
        author=data["author"],
        committed_at=datetime.fromisoformat(data["committed_at"]),
        files=[FileDiff(**f) for f in data["files"]],
        checks_passed=None,  # unknowable after the fact; the repo's history is gone
        ground_truth="malicious",
    )


def load_incident(incident: Incident) -> Change:
    """Fetch or load one incident as a labelled Change.

    A live fetch that fails raises `fetch.FetchError` rather than being skipped — a
    silently-dropped incident would quietly shrink the denominator of the detection rate
    in §7, which is worse than a loud failure.
    """
    if not incident.is_live:
        return _load_fixture(incident)

    owner, name = incident.repo.split("/", 1)
    try:
        change = fetch.fetch_commit(owner, name, incident.sha)
    except fetch.FetchError as exc:
        raise fetch.FetchError(f"incident {incident.key!r} ({incident.repo}@{incident.sha[:8]}): {exc}") from exc
    change.ground_truth = "malicious"
    return change


def load_incidents() -> list[Change]:
    """All five incidents as labelled Changes, in INCIDENTS order."""
    return [load_incident(inc) for inc in INCIDENTS]
