"""_changes poll loop + cursor resume (Claude-owned scaffolding — should pass)."""

from __future__ import annotations

import httpx
import respx

from kitsunox.ingest.changes_feed import ChangeRow, ChangesFeedClient, iter_changes


def test_change_row_revision_heuristics():
    new_pkg = ChangeRow(seq=1, package_name="x", rev="1-abc", deleted=False)
    old_pkg = ChangeRow(seq=2, package_name="y", rev="412-def", deleted=False)
    assert new_pkg.revision_count == 1 and new_pkg.looks_new_package
    assert old_pkg.revision_count == 412 and not old_pkg.looks_new_package


@respx.mock
def test_fetch_page_parses_results(settings):
    respx.get("https://replicate.npmjs.com/registry/_changes").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"seq": 10, "id": "left-pad", "changes": [{"rev": "5-aaa"}]},
                    {"seq": 11, "id": "gone-pkg", "changes": [{"rev": "9-bbb"}], "deleted": True},
                ],
                "last_seq": 11,
            },
        )
    )
    with ChangesFeedClient(settings) as feed:
        rows, last_seq = feed.fetch_page(since=0)
    assert last_seq == 11
    assert rows[0].package_name == "left-pad" and not rows[0].deleted
    assert rows[1].deleted


@respx.mock
def test_iter_changes_advances_cursor_and_stops_when_caught_up(settings):
    # Page 1 full (limit defaults to 1000, so give one row and mark caught up via short page).
    route = respx.get("https://replicate.npmjs.com/registry/_changes")
    route.side_effect = [
        httpx.Response(
            200,
            json={"results": [{"seq": 1, "id": "a", "changes": [{"rev": "1-x"}]}], "last_seq": 1},
        ),
    ]
    cursors: list[int] = []
    with ChangesFeedClient(settings) as feed:
        rows = list(
            iter_changes(
                start_seq=0,
                feed=feed,
                on_cursor=cursors.append,
                stop_when_caught_up=True,
            )
        )
    assert [r.package_name for r in rows] == ["a"]
    assert cursors == [1]


@respx.mock
def test_resolve_start_seq_uses_update_seq_for_now(settings, monkeypatch):
    monkeypatch.setenv("KITSUNOX_FEED_START", "now")
    import kitsunox.config as config

    config.get_settings.cache_clear()
    respx.get("https://replicate.npmjs.com/registry/").mock(
        return_value=httpx.Response(200, json={"update_seq": 999, "doc_count": 1})
    )
    with ChangesFeedClient(config.get_settings()) as feed:
        assert feed.resolve_start_seq(stored_cursor=0) == 999
        assert feed.resolve_start_seq(stored_cursor=42) == 42
