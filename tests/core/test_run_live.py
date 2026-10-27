"""Live npm check. Opt-in: `uv run pytest -m network`."""

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from kitsunox.core.run import DataDir, IngestRequest, changes_digest, record_ingest, replay_ingest
from kitsunox.ecosystems.npm.registry import REPLICATE_URL, NpmEcosystem


@pytest.mark.network
def test_live_record_and_replay(tmp_path: Path) -> None:
    head = httpx.get(f"{REPLICATE_URL}/", timeout=30).json()["update_seq"]
    data = DataDir(tmp_path)
    request = IngestRequest(as_of=datetime.now(UTC), window_hours=2, since=head - 200, until=head)
    manifest = record_ingest(data, NpmEcosystem, request)
    assert manifest.packages_seen > 0
    assert manifest.change_count > 0
    assert changes_digest(replay_ingest(data, NpmEcosystem, manifest.run_id)) == (
        manifest.changes_sha256
    )
