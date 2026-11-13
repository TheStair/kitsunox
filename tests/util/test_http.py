import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from conftest import Router
from kitsunox.util.http import (
    BlobStore,
    FetchedResponse,
    FetchError,
    FetchMode,
    HttpFetcher,
    RetryPolicy,
    Snapshot,
    TransientFetchError,
    derived_key,
    request_key,
)

URL = "https://registry.example/pkg"
FIXED = datetime(2026, 10, 27, tzinfo=UTC)


def make_fetcher(
    tmp_path: Path,
    client: httpx.Client,
    *,
    mode: FetchMode = FetchMode.RECORD,
    snapshot: Snapshot | None = None,
    sleeps: list[float] | None = None,
    **kwargs: object,
) -> HttpFetcher:
    return HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=snapshot if snapshot is not None else Snapshot(),
        mode=mode,
        immutable_index=tmp_path / "immutable",
        client=client,
        sleep=(sleeps if sleeps is not None else []).append,
        clock=lambda: FIXED,
        **kwargs,  # type: ignore[arg-type]
    )


def test_record_then_replay_offline(tmp_path: Path, router: Router) -> None:
    router.add_json(URL, {"v": 1})
    snapshot = Snapshot()
    fetcher = make_fetcher(tmp_path, router.client(), snapshot=snapshot)
    assert fetcher.get(URL).json() == {"v": 1}
    assert fetcher.get(URL).json() == {"v": 1}
    assert len(router.requests) == 1  # second call served from the snapshot

    snapshot.save(tmp_path / "snap.json")
    offline = httpx.Client(transport=httpx.MockTransport(lambda r: pytest.fail("network used")))
    replay = make_fetcher(
        tmp_path, offline, mode=FetchMode.REPLAY, snapshot=Snapshot.load(tmp_path / "snap.json")
    )
    response = replay.get(URL)
    assert response.json() == {"v": 1}
    assert response.fetched_at == FIXED


def test_replay_miss_is_an_error(tmp_path: Path, router: Router) -> None:
    fetcher = make_fetcher(tmp_path, router.client(), mode=FetchMode.REPLAY)
    with pytest.raises(FetchError, match="replay miss"):
        fetcher.get(URL)
    assert router.requests == []


def test_non_retryable_errors_are_recorded(tmp_path: Path, router: Router) -> None:
    fetcher = make_fetcher(tmp_path, router.client())
    response = fetcher.get(URL)
    assert response.status == 404
    assert fetcher.snapshot.entries[request_key(URL, None)].status == 404


def test_retries_with_backoff_and_retry_after(tmp_path: Path) -> None:
    responses = iter(
        [
            httpx.Response(503),
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(200, content=b"ok"),
        ]
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda r: next(responses)))
    sleeps: list[float] = []
    fetcher = make_fetcher(tmp_path, client, sleeps=sleeps)
    assert fetcher.get(URL).body == b"ok"
    assert sleeps == [1.0, 7.0]


def test_retry_after_is_capped_by_max_delay(tmp_path: Path) -> None:
    responses = iter(
        [
            httpx.Response(429, headers={"Retry-After": "86400"}),  # a day: honoured up to 30 s
            httpx.Response(200, content=b"ok"),
        ]
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda r: next(responses)))
    sleeps: list[float] = []
    fetcher = make_fetcher(tmp_path, client, sleeps=sleeps, retry=RetryPolicy(max_delay=30.0))
    assert fetcher.get(URL).body == b"ok"
    assert sleeps == [30.0]


def test_gives_up_after_max_attempts(tmp_path: Path) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    client = httpx.Client(transport=httpx.MockTransport(fail))
    fetcher = make_fetcher(tmp_path, client, retry=RetryPolicy(max_attempts=3))
    with pytest.raises(TransientFetchError, match="after 3 attempts: ConnectError"):
        fetcher.get(URL)
    assert fetcher.snapshot.entries == {}


def test_only_exhausted_retries_are_transient(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"x" * 100)
    fetcher = make_fetcher(tmp_path, router.client(), max_bytes=10)
    with pytest.raises(FetchError) as caught:
        fetcher.get(URL)
    assert not isinstance(caught.value, TransientFetchError)


def test_response_size_limit(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"x" * 100)
    fetcher = make_fetcher(tmp_path, router.client(), max_bytes=10)
    with pytest.raises(FetchError, match="exceeds"):
        fetcher.get(URL)


def test_immutable_responses_are_reused_across_runs(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"tarball")
    make_fetcher(tmp_path, router.client()).get(URL, immutable=True)
    second = make_fetcher(tmp_path, router.client())
    assert second.get(URL, immutable=True).body == b"tarball"
    assert len(router.requests) == 1
    assert request_key(URL, None) in second.snapshot.entries  # still recorded for replay


def test_an_index_entry_whose_blob_is_gone_is_fetched_again(tmp_path: Path, router: Router) -> None:
    """Blobs deleted by hand to free disk (2026-11-04) must mean a refetch, not a failure."""
    router.add_bytes(URL, b"tarball")
    first = make_fetcher(tmp_path, router.client())
    first.get(URL, immutable=True)
    for blob in (tmp_path / "blobs").rglob("*.zst"):
        blob.unlink()
    second = make_fetcher(tmp_path, router.client())
    assert second.needs_network(URL, immutable=True)
    assert second.get(URL, immutable=True).body == b"tarball"
    assert len(router.requests) == 2
    assert make_fetcher(tmp_path, router.client()).get(URL, immutable=True).body == b"tarball"
    assert len(router.requests) == 2  # stored again, so the third run reuses it


def test_an_index_entry_whose_blob_is_empty_is_fetched_again(
    tmp_path: Path, router: Router
) -> None:
    """A crash left 211 tarball blobs empty (2026-11-07) while their index entries survived;
    the rerun served the entries and Stage 3 failed on the empty blobs."""
    router.add_bytes(URL, b"tarball")
    make_fetcher(tmp_path, router.client()).get(URL, immutable=True)
    (blob,) = (tmp_path / "blobs").rglob("*.zst")
    blob.write_bytes(b"")
    second = make_fetcher(tmp_path, router.client())
    assert second.needs_network(URL, immutable=True)
    assert second.get(URL, immutable=True).body == b"tarball"
    assert len(router.requests) == 2
    assert blob.stat().st_size > 0  # rewritten, so the next run reuses it


def test_needs_network_says_whether_get_would_send(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"tarball")
    other = "https://registry.example/other"
    router.add_bytes(other, b"mutable")
    first = make_fetcher(tmp_path, router.client())
    assert first.needs_network(URL, immutable=True) and first.needs_network(other)
    first.get(URL, immutable=True)
    first.get(other)
    assert not first.needs_network(URL) and not first.needs_network(other)  # this run's snapshot
    assert first.needs_network(other, headers={"Accept": "x"})  # another request
    second = make_fetcher(tmp_path, router.client())
    assert not second.needs_network(URL, immutable=True)  # the immutable index holds it
    assert second.needs_network(URL)  # not asked as immutable, so `get` would send it
    assert second.needs_network(other, immutable=True)  # never stored in the index
    replay = make_fetcher(tmp_path, router.client(), mode=FetchMode.REPLAY)
    assert not replay.needs_network("https://registry.example/missing")  # a miss, not a request
    assert len(router.requests) == 2  # asking never fetches


def test_damaged_immutable_entry_is_refetched(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"tarball")
    make_fetcher(tmp_path, router.client()).get(URL, immutable=True)
    (entry,) = (tmp_path / "immutable").rglob("*.json")
    entry.write_bytes(b'{"sche\xf8ma"')  # not UTF-8: seen live, 2026-10-28
    assert make_fetcher(tmp_path, router.client()).get(URL, immutable=True).body == b"tarball"
    assert len(router.requests) == 2


def test_accept_header_is_part_of_the_key() -> None:
    assert request_key(URL, {"Accept": "a"}) != request_key(URL, {"accept": "b"})
    assert request_key(URL, {"User-Agent": "x"}) == request_key(URL, None)


def test_blob_store_detects_corruption(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    sha = store.put(b"content")
    assert store.get(sha) == b"content"
    other = store.put(b"different")
    store._path(sha).write_bytes(store._path(other).read_bytes())
    with pytest.raises(FetchError, match="corrupt"):
        store.get(sha)


def test_an_empty_blob_is_absent_and_rewritten(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    sha = store.put(b"content")
    store._path(sha).write_bytes(b"")
    assert not store.exists(sha)
    assert store.put(b"content") == sha
    assert store.exists(sha)
    assert store.get(sha) == b"content"


def test_min_interval_paces_network_requests_per_host(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"a")
    router.add_bytes(URL + "2", b"b")
    router.add_bytes("https://other.example/x", b"c")
    now = [100.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    fetcher = make_fetcher(tmp_path, router.client(), monotonic=lambda: now[0])
    fetcher._sleep = sleep
    fetcher.set_min_interval("registry.example", 0.5)
    fetcher.get(URL)
    fetcher.get(URL)  # snapshot hit: not paced
    fetcher.get(URL + "2")
    fetcher.get("https://other.example/x")  # different host: not paced
    assert sleeps == [0.5]


def test_redirect_to_plain_http_is_refused(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            return httpx.Response(302, headers={"Location": "http://evil.example/x"})
        return httpx.Response(200, content=b"tampered")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    with pytest.raises(FetchError, match="non-HTTPS"):
        make_fetcher(tmp_path, client).get(URL)


def test_non_transport_http_errors_become_fetch_errors(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=b"not gzip")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(FetchError, match="DecodingError"):
        make_fetcher(tmp_path, client).get(URL)


# --- derived responses (decision 0021: partial reads) -------------------------------------------


def upper(chunks: Iterator[bytes]) -> bytes:
    """A derivation: what a partial read does with the stream, in miniature."""
    return b"".join(chunks).upper()


def derived(fetcher: HttpFetcher, **kwargs: Any) -> FetchedResponse:
    kwargs.setdefault("max_bytes", 1000)
    return fetcher.get_derived(
        URL, upper, variant="partial=1", content_type="application/x-test", **kwargs
    )


def test_derived_responses_are_recorded_under_their_own_key(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"tarball")
    fetcher = make_fetcher(tmp_path, router.client())
    response = derived(fetcher)
    assert response.body == b"TARBALL"
    assert response.content_type == "application/x-test"
    key = derived_key(URL, "partial=1")
    assert list(fetcher.snapshot.entries) == [key] != [request_key(URL, None)]
    entry = fetcher.snapshot.entries[key]
    assert (entry.url, entry.size) == (URL, 7)
    assert fetcher.store.get(entry.sha256) == b"TARBALL"  # the original body is not stored
    assert not fetcher.store.exists(hashlib.sha256(b"tarball").hexdigest())


def test_derived_responses_replay_offline_and_are_reused_across_runs(
    tmp_path: Path, router: Router
) -> None:
    router.add_bytes(URL, b"tarball")
    snapshot = Snapshot()
    derived(make_fetcher(tmp_path, router.client(), snapshot=snapshot))
    snapshot.save(tmp_path / "snap.json")
    offline = httpx.Client(transport=httpx.MockTransport(lambda r: pytest.fail("network used")))
    replay = make_fetcher(
        tmp_path, offline, mode=FetchMode.REPLAY, snapshot=Snapshot.load(tmp_path / "snap.json")
    )
    assert derived(replay).body == b"TARBALL"
    later = make_fetcher(tmp_path, offline)  # another run: the immutable index serves it
    assert derived(later).body == b"TARBALL"
    assert derive_miss(make_fetcher(tmp_path, offline, mode=FetchMode.REPLAY))


def derive_miss(fetcher: HttpFetcher) -> bool:
    with pytest.raises(FetchError, match="replay miss"):
        derived(fetcher)
    return True


class _Broken(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        yield b"tar"
        raise httpx.ReadError("connection reset")


def test_a_stream_cut_mid_body_is_downloaded_again(tmp_path: Path) -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(200, stream=_Broken())
        return httpx.Response(200, content=b"tarball")

    fetcher = make_fetcher(tmp_path, httpx.Client(transport=httpx.MockTransport(handler)))
    assert derived(fetcher).body == b"TARBALL"
    assert len(calls) == 2


def test_a_stream_cut_every_time_is_transient(tmp_path: Path) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, stream=_Broken()))
    )
    fetcher = make_fetcher(tmp_path, client, retry=RetryPolicy(max_attempts=2))
    with pytest.raises(TransientFetchError, match="ReadError"):
        derived(fetcher)
    assert fetcher.snapshot.entries == {}


def test_what_the_derivation_raises_is_not_retried_or_recorded(
    tmp_path: Path, router: Router
) -> None:
    router.add_bytes(URL, b"tarball")

    def refuse(chunks: Iterator[bytes]) -> bytes:
        raise ValueError("integrity mismatch")

    fetcher = make_fetcher(tmp_path, router.client())
    with pytest.raises(ValueError, match="integrity"):
        fetcher.get_derived(
            URL, refuse, variant="partial=1", content_type="application/x-test", max_bytes=100
        )
    assert len(router.requests) == 1
    assert fetcher.snapshot.entries == {}


def test_a_failed_status_is_recorded_without_deriving(tmp_path: Path, router: Router) -> None:
    fetcher = make_fetcher(tmp_path, router.client())
    response = derived(fetcher)
    assert response.status == 404
    assert fetcher.snapshot.entries[derived_key(URL, "partial=1")].status == 404
    assert not (tmp_path / "immutable").exists()  # only a success is reused across runs


def test_the_derived_stream_has_a_size_limit(tmp_path: Path, router: Router) -> None:
    router.add_bytes(URL, b"x" * 100)
    fetcher = make_fetcher(tmp_path, router.client())
    with pytest.raises(FetchError, match="exceeds 10 bytes"):
        derived(fetcher, max_bytes=10)
