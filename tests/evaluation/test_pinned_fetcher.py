from datetime import UTC, datetime
from pathlib import Path

from conftest import Router
from kitsunox.evaluation.static_eval import PinnedFetcher
from kitsunox.util.http import BlobStore, FetchMode, HttpFetcher, Snapshot

URL = "https://registry.example/missing-payload"
FIXED = datetime(2026, 11, 8, tzinfo=UTC)


def fetcher(cls: type[HttpFetcher], tmp_path: Path, router: Router) -> HttpFetcher:
    """A fresh fetcher (a new evaluation run) sharing the store and the immutable index."""
    return cls(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        immutable_index=tmp_path / "immutable",
        client=router.client(),
        clock=lambda: FIXED,
    )


def test_pinned_fetcher_keeps_a_404_once_the_name_is_published(
    tmp_path: Path, router: Router
) -> None:
    assert fetcher(PinnedFetcher, tmp_path, router).get(URL).status == 404
    router.add_json(URL, {"name": "missing-payload"})  # published after the first evaluation
    assert fetcher(PinnedFetcher, tmp_path, router).get(URL).status == 404
    assert len(router.requests) == 1


def test_plain_fetcher_does_not_pin_a_404(tmp_path: Path, router: Router) -> None:
    assert fetcher(HttpFetcher, tmp_path, router).get(URL, immutable=True).status == 404
    router.add_json(URL, {"name": "missing-payload"})
    assert fetcher(HttpFetcher, tmp_path, router).get(URL, immutable=True).status == 200


def test_pinned_fetcher_asks_again_after_a_server_error(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"teapot", status=418)
    assert fetcher(PinnedFetcher, tmp_path, router).get(URL).status == 418
    router.add_json(URL, {"name": "missing-payload"})
    assert fetcher(PinnedFetcher, tmp_path, router).get(URL).status == 200
