"""npm ``_changes`` feed consumer.

The feed no longer streams (``feed=continuous`` / ``longpoll`` / ``eventsource`` were
removed May 2025). This is a **poll loop**: request a page of changes after a stored
sequence, persist the new cursor, repeat; sleep briefly when caught up.

    GET {replicate}/_changes?since=<seq>&limit=<=10000     header: npm-replication-opt-in: true
    -> {"results":[{"seq":int,"id":"pkg","changes":[{"rev":"<n>-<hash>"}],"deleted":bool?}],
        "last_seq":int}

The leading integer of ``rev`` is the CouchDB revision count: ``"1-..."`` (or a low
number) means a brand-new package document; a high number means a long-established one.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass

import httpx
import structlog
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from kitsunox.config import Settings, get_settings

log = structlog.get_logger(__name__)


@dataclass
class ChangeRow:
    seq: int
    package_name: str
    rev: str | None
    deleted: bool

    @property
    def revision_count(self) -> int | None:
        if not self.rev or "-" not in self.rev:
            return None
        head = self.rev.split("-", 1)[0]
        return int(head) if head.isdigit() else None

    @property
    def looks_new_package(self) -> bool:
        rc = self.revision_count
        return rc is not None and rc <= 2


class ChangesFeedClient:
    def __init__(self, settings: Settings | None = None, client: httpx.Client | None = None):
        self.settings = settings or get_settings()
        headers = {"User-Agent": self.settings.user_agent}
        if self.settings.replication_opt_in:
            headers["npm-replication-opt-in"] = "true"
        self._client = client or httpx.Client(
            timeout=self.settings.http_timeout_seconds, headers=headers, follow_redirects=True
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ChangesFeedClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @retry(
        retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
        wait=wait_exponential(multiplier=1, min=1, max=60),
        stop=stop_after_attempt(6),
        reraise=True,
    )
    def _get(self, url: str, params: dict) -> dict:
        resp = self._client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def current_update_seq(self) -> int:
        data = self._get(f"{self.settings.replicate_base_url}/", params={})
        return int(data["update_seq"])

    def resolve_start_seq(self, stored_cursor: int) -> int:
        """Decide where to begin when there is no usable stored cursor."""
        if stored_cursor > 0:
            return stored_cursor
        spec = self.settings.feed_start.strip().lower()
        if spec in {"0", ""}:
            return 0
        head = self.current_update_seq()
        if spec == "now":
            return head
        if spec.startswith("now-"):
            back = spec[4:]
            return max(0, head - int(back)) if back.isdigit() else head
        log.warning("unrecognized feed_start, defaulting to now", feed_start=spec)
        return head

    def fetch_page(self, since: int, limit: int | None = None) -> tuple[list[ChangeRow], int]:
        limit = limit or self.settings.changes_page_limit
        data = self._get(
            f"{self.settings.replicate_base_url}/_changes",
            params={"since": since, "limit": limit},
        )
        rows: list[ChangeRow] = []
        for r in data.get("results", []):
            changes = r.get("changes") or []
            rev = changes[0].get("rev") if changes else None
            rows.append(
                ChangeRow(
                    seq=int(r["seq"]),
                    package_name=r["id"],
                    rev=rev,
                    deleted=bool(r.get("deleted", False)),
                )
            )
        last_seq = int(data.get("last_seq", since))
        return rows, last_seq


def iter_changes(
    *,
    start_seq: int,
    feed: ChangesFeedClient,
    on_cursor,  # callable(last_seq: int) -> None   (persist the cursor)
    stop_when_caught_up: bool = False,
) -> Iterator[ChangeRow]:
    """Yield ``ChangeRow``s forever (or until caught up, if requested).

    ``on_cursor`` is invoked with ``last_seq`` after each page so a crash resumes without
    reprocessing. Callers should also persist their own progress per row if row handling
    is expensive and non-idempotent.
    """
    since = start_seq
    settings = feed.settings
    while True:
        rows, last_seq = feed.fetch_page(since)
        yield from rows
        if last_seq != since:
            on_cursor(last_seq)
            since = last_seq
        if len(rows) < settings.changes_page_limit:
            if stop_when_caught_up:
                return
            time.sleep(settings.poll_interval_seconds)
