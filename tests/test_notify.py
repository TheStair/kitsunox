"""Discord run updates: brief, inert for untrusted names, and never leaking the webhook URL."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from conftest import make_report as report
from conftest import report_entry as entry
from conftest import run_manifest as manifest
from kitsunox import notify
from kitsunox.core.models import Severity
from kitsunox.notify import (
    MAX_CONTENT,
    NotifyError,
    NotifyState,
    Tick,
    TickRecord,
    append_tick,
    crash_due,
    escape,
    is_webhook,
    post_update,
    read_ticks,
    render_crash,
    render_daily,
    render_tick,
    send,
    summary_due,
)

T0 = datetime(2026, 10, 29, 21, 5, tzinfo=UTC)
MARKER = "fakeWebhookPart_-x"
URL = f"https://discord.com/api/webhooks/123456789012345678/{MARKER}"


def test_tick_update_is_brief_and_groups_versions_by_package() -> None:
    run = manifest()
    current = report(
        run.run_id,
        entry(1, "evil-pkg", "1.0.3", 14, Severity.HIGH),
        entry(2, "lightdash-cli", "0.2", 9, Severity.MEDIUM),
        entry(3, "lightdash-cli", "0.1", 11, Severity.HIGH),
        entry(4, "evil-pkg", "1.0.2", 6, Severity.MEDIUM),
    )
    caught_up = report("20261029T200500Z-npm", entry(1, "x", "1", 7, Severity.MEDIUM))
    tick = Tick(manifest=run, reports=(caught_up, current), failed=("prune",))
    content = render_tick(tick, started=T0, elapsed=timedelta(minutes=42))
    assert content.splitlines() == [
        "**Kitsunox** tick 2026-10-29 21:05 UTC, 42 min",
        "Run `20261029T210500Z-npm`: 4,812 versions; **4 to review** (2 HIGH, 2 MEDIUM).",
        r"Top: evil\-pkg (score 14, HIGH, 2 versions), lightdash\-cli (score 11, HIGH, 2 versions)",
        "Caught up: `20261029T200500Z-npm` (1 to review)",
        "Failed: prune. See `data/logs/collect.log`.",
    ]


def test_offline_unchained_and_failed_stages_are_said_plainly() -> None:
    offline = render_tick(Tick(manifest=None), started=T0, elapsed=timedelta(hours=3))
    assert "3.0 h" in offline and "nothing written" in offline
    gap = render_tick(
        Tick(manifest=manifest(chained_from=None, transient_skipped=12), failed=("stages",)),
        started=T0,
        elapsed=timedelta(minutes=5),
    )
    assert "NOT chained" in gap
    assert "12 skipped on the network" in gap
    assert "no report this tick (a stage failed" in gap
    uncompared = report(
        manifest().run_id,
        correlation={"repo_network": {"still_failing": 7, "retry_skipped": "outage"}},
    )
    line = render_tick(
        Tick(manifest=manifest(), reports=(uncompared,)), started=T0, elapsed=timedelta(0)
    ).splitlines()[1]
    assert line.endswith("**0 to review**. 7 not compared with their repo (network, outage).")
    both = report(
        manifest().run_id,
        correlation={
            "repo_network": {"still_failing": 1},
            "dependency_lookups": {"still_failing": 3, "retry_skipped": None},
        },
    )
    line = render_tick(
        Tick(manifest=manifest(), reports=(both,)), started=T0, elapsed=timedelta(0)
    ).splitlines()[1]
    assert line.endswith(
        "**0 to review**. 1 not compared with their repo (network). "
        "3 dependency lookups failed (network)."
    )


@pytest.mark.parametrize(
    "name",
    [
        "@everyone",
        "<@123456789>",
        "[click](https://evil.example/x)",
        "`code` **bold** ||spoiler||",
        "a‮evil\nline\x00",
        "https://evil.example",
        ":joy:",
    ],
)
def test_untrusted_names_are_inert(name: str) -> None:
    out = escape(name)
    assert "\n" not in out and "‮" not in out and "\x00" not in out
    # Every markdown, mention and link character is escaped.
    for char in "@<[]()`*|:":
        assert char not in out.replace(f"\\{char}", "")


def test_long_updates_fit_in_one_message() -> None:
    run = manifest()
    entries = [entry(i, "p" * 300 + str(i), "1", 100 - i, Severity.HIGH) for i in range(1, 50)]
    failed = tuple(f"stages (catch-up 2026102{i}T000000Z-npm from Stage 1)" for i in range(60))
    content = render_tick(
        Tick(manifest=run, reports=(report(run.run_id, *entries),), failed=failed),
        started=T0,
        elapsed=timedelta(minutes=1),
    )
    assert len(content) <= MAX_CONTENT
    assert content.endswith("…")


def test_crash_update_has_no_exception_message() -> None:
    try:
        raise RuntimeError(f"GET {URL} failed")
    except RuntimeError as exc:
        content = render_crash(exc, "collect.py:1 collect", started=T0)
    assert "crashed" in content and "RuntimeError" in content
    assert MARKER not in content


def capture(responses: list[httpx.Response]) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responses.pop(0)

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def test_send_disables_mentions_and_previews() -> None:
    client, seen = capture([httpx.Response(204)])
    send(URL, "hello", client=client)
    (request,) = seen
    body = json.loads(request.content)
    assert body == {"content": "hello", "allowed_mentions": {"parse": []}, "flags": 4}


def test_send_retries_a_rate_limit_once() -> None:
    client, seen = capture(
        [httpx.Response(429, headers={"retry-after": "120"}), httpx.Response(204)]
    )
    waits: list[float] = []
    send(URL, "hello", client=client, sleep=waits.append)
    assert len(seen) == 2 and waits == [10.0]  # capped


@pytest.mark.parametrize("value", ["nan", "inf", "-5", "Wed, 21 Oct 2026 07:28:00 GMT"])
def test_odd_retry_after_values_still_retry(value: str) -> None:
    client, seen = capture(
        [httpx.Response(503, headers={"retry-after": value}), httpx.Response(204)]
    )
    waits: list[float] = []
    send(URL, "hello", client=client, sleep=waits.append)
    assert len(seen) == 2 and len(waits) == 1 and 0.0 <= waits[0] <= 10.0


def test_failures_never_include_the_url() -> None:
    client, _ = capture([httpx.Response(404)])
    with pytest.raises(NotifyError) as info:
        send(URL, "hello", client=client)
    assert str(info.value) == "HTTP 404" and MARKER not in str(info.value)

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    log: list[str] = []
    post_update(URL, "x", log.append, client=httpx.Client(transport=httpx.MockTransport(refuse)))
    assert log == ["notify: FAILED (ConnectError)"]


def test_only_discord_webhooks_are_posted_to() -> None:
    assert is_webhook(URL)
    assert not is_webhook("http://discord.com/api/webhooks/1/abc")
    assert not is_webhook("https://discord.com.evil.example/api/webhooks/1/abc")
    assert not is_webhook(URL + "/../x")
    client, seen = capture([])
    log: list[str] = []
    post_update("https://evil.example/hook", "x", log.append, client=client)
    assert seen == [] and log == [
        "notify: FAILED (KITSUNOX_DISCORD_WEBHOOK is not a Discord webhook URL)"
    ]


def test_no_webhook_means_no_post() -> None:
    client, seen = capture([])
    log: list[str] = []
    post_update(None, "x", log.append, client=client)
    assert seen == [] and log == []


DAY = T0.date()


def ticks_of_a_day() -> list[TickRecord]:
    at = datetime(2026, 10, 29, 1, tzinfo=UTC)
    return [
        TickRecord(
            started=at, minutes=40, run_id="a", versions=20000, chained=True, reports=("a",)
        ),
        TickRecord(
            started=at + timedelta(hours=1),
            minutes=9,
            run_id="b",
            versions=5000,
            chained=False,
            transient_skipped=3,
            reports=("b",),
            failed=("prune",),
        ),
        TickRecord(started=at + timedelta(hours=2), minutes=1, crashed="ValueError at x.py:1"),
        TickRecord(started=at + timedelta(hours=3), minutes=0),  # offline
        TickRecord(
            started=at - timedelta(hours=2), minutes=9, run_id="z", versions=7
        ),  # day before
    ]


def test_the_daily_summary_counts_a_version_two_runs_reported_once() -> None:
    a = report(
        "a",
        entry(1, "evil-pkg", "1.0.3", 14, Severity.HIGH),
        entry(2, "lightdash-cli", "0.2", 9, Severity.MEDIUM),
    )
    b = report(
        "b",
        entry(1, "evil-pkg", "1.0.3", 16, Severity.HIGH),  # the 15-min overlap
        entry(2, "lightdash-cli", "0.3", 7, Severity.MEDIUM),
    )
    content = render_daily(DAY, ticks_of_a_day(), [a, b])
    lines = content.splitlines()
    assert lines[0] == "**Kitsunox** daily summary for 2026-10-29 (UTC)"
    assert lines[1] == (
        "4 ticks (**1 crashed**, 1 with failed steps, 1 offline or an outage), 2 runs, "
        "25,000 versions."
    )
    assert lines[2] == "**3 to review** (2 packages) (1 HIGH, 2 MEDIUM)."
    assert lines[3].startswith("Top: evil\\-pkg (score 16, HIGH)")
    assert "lightdash\\-cli (score 9, MEDIUM, 2 versions)" in lines[3]
    assert "**1 runs NOT chained** (coverage gap)." in lines
    assert "3 packages skipped on the network (retried the next tick)." in lines
    assert "Failed steps: prune x1." in lines
    assert "Crashes: ValueError at x\\.py:1 x1" in content.replace("\\:", ":")
    quiet = render_daily(DAY, ticks_of_a_day()[:1], [])
    assert quiet.splitlines()[1:] == ["1 ticks, 1 runs, 20,000 versions."]


def test_the_tick_log_keeps_the_last_two_weeks_and_skips_damage(tmp_path: Path) -> None:
    for i in range(notify.MAX_TICK_LINES + 5):
        append_tick(tmp_path, TickRecord(started=T0 + timedelta(hours=i), minutes=1))
    with (tmp_path / notify.TICKS_FILE).open("ab") as handle:
        handle.write(b"{not json\n")
    records = read_ticks(tmp_path)
    assert len(records) == notify.MAX_TICK_LINES
    assert records[0].started == T0 + timedelta(hours=5)
    assert read_ticks(tmp_path / "absent") == []


def test_a_summary_is_due_once_a_day_and_a_crash_post_once_a_day() -> None:
    ticks = ticks_of_a_day()
    now = datetime(2026, 10, 30, 0, 30, tzinfo=UTC)
    assert summary_due(NotifyState(), ticks, now) == DAY
    assert summary_due(NotifyState(daily_posted=DAY), ticks, now) is None
    assert summary_due(NotifyState(), ticks, now + timedelta(days=2)) is None  # no ticks then
    assert crash_due(NotifyState(), now)
    assert not crash_due(NotifyState(crash_posted=now - timedelta(hours=23)), now)
    assert crash_due(NotifyState(crash_posted=now - timedelta(days=1)), now)
