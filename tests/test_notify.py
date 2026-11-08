"""Discord run updates: embeds that are brief, inert for untrusted names, within Discord's
limits, and never leaking the webhook URL."""

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
    GREEN,
    MAX_MESSAGE,
    RED,
    Message,
    NotifyError,
    NotifyState,
    Tick,
    TickRecord,
    append_tick,
    crash_due,
    disk_alert_due,
    embed_chars,
    escape,
    is_webhook,
    post_update,
    read_ticks,
    render_crash,
    render_daily,
    render_disk,
    render_tick,
    send,
    summary_due,
)
from kitsunox.reporting.queue import Queue
from kitsunox.util.disk import GIB

T0 = datetime(2026, 10, 29, 21, 5, tzinfo=UTC)
MARKER = "fakeWebhookPart_-x"
URL = f"https://discord.com/api/webhooks/123456789012345678/{MARKER}"


def lines(message: Message) -> list[str]:
    """A message as text, one line per title, description line, field line and footer."""
    out: list[str] = []
    for embed in message:
        out.append(f"# {embed['title']}")
        out += str(embed.get("description", "")).splitlines()
        for field in embed.get("fields", []):  # type: ignore[attr-defined]
            out += [f"{field['name']}: {v}" for v in str(field["value"]).splitlines()]
        if "footer" in embed:
            out.append(f"-- {embed['footer']['text']}")  # type: ignore[index]
    return out


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
    message = render_tick(tick, started=T0, elapsed=timedelta(minutes=42))
    assert lines(message) == [
        "# 🦊 Kitsunox tick · 2026-10-29 21:05 UTC · 42 min",
        "Run `20261029T210500Z-npm`: 4,812 versions",
        "**4 to review**.",
        "🔴 HIGH: 2",
        "🟠 MEDIUM: 2",
        r"Top packages: 🔴 **evil\-pkg** · score 14, HIGH, 2 versions",
        r"Top packages: 🔴 **lightdash\-cli** · score 11, HIGH, 2 versions",
        "Caught up: `20261029T200500Z-npm`: 1 to review",
        "⚠️ Failed: prune",
        "-- Details: data/logs/collect.log",
    ]
    assert message[0]["color"] != GREEN  # a failed step


def test_offline_unchained_and_failed_stages_are_said_plainly() -> None:
    offline = render_tick(Tick(manifest=None), started=T0, elapsed=timedelta(hours=3))
    assert "3.0 h" in str(offline[0]["title"]) and "nothing written" in str(offline)
    gap = render_tick(
        Tick(manifest=manifest(chained_from=None, transient_skipped=12), failed=("stages",)),
        started=T0,
        elapsed=timedelta(minutes=5),
    )
    assert gap[0]["color"] == RED
    text = "\n".join(lines(gap))
    assert "NOT chained" in text
    assert "12 skipped on the network" in text
    assert "No report this tick (a stage failed" in text
    uncompared = report(
        manifest().run_id,
        correlation={"repo_network": {"still_failing": 7, "retry_skipped": "outage"}},
    )
    shown = lines(
        render_tick(
            Tick(manifest=manifest(), reports=(uncompared,)), started=T0, elapsed=timedelta(0)
        )
    )
    assert shown[2:4] == ["**0 to review**.", "7 not compared with their repo (network, outage)."]
    both = report(
        manifest().run_id,
        correlation={
            "repo_network": {"still_failing": 1},
            "dependency_lookups": {"still_failing": 3, "retry_skipped": None},
        },
    )
    shown = lines(
        render_tick(Tick(manifest=manifest(), reports=(both,)), started=T0, elapsed=timedelta(0))
    )
    assert shown[3:5] == [
        "1 not compared with their repo (network).",
        "3 dependency lookups failed (network).",
    ]


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
    entries = [entry(i, "@" * 300 + str(i), "1", 100 - i, Severity.HIGH) for i in range(1, 50)]
    failed = tuple(f"stages (catch-up 2026102{i}T000000Z-npm from Stage 1)" for i in range(60))
    caught_up = tuple(report(f"2026102{i}T000000Z-npm") for i in range(80))
    message = render_tick(
        Tick(manifest=run, reports=(*caught_up, report(run.run_id, *entries)), failed=failed),
        started=T0,
        elapsed=timedelta(minutes=1),
    )
    assert embed_chars(message) <= MAX_MESSAGE
    for field in message[0]["fields"]:  # type: ignore[attr-defined]
        assert len(field["value"]) <= 1024
    text = lines(message)
    assert any(line.startswith("⚠️ Failed: … and ") for line in text)
    assert any(line.startswith("Caught up: … and ") for line in text)
    ticks = [
        TickRecord(
            started=datetime(2026, 10, 29, h % 24, tzinfo=UTC),
            minutes=1,
            crashed=f"{'E' * 300}{h} at x",
            failed=tuple(f"step {'s' * 50}{h}" for _ in range(3)),
        )
        for h in range(200)
    ]
    daily = render_daily(DAY, ticks, [report("a", *entries)], [], None)
    assert embed_chars(daily) <= MAX_MESSAGE


def test_crash_update_has_no_exception_message() -> None:
    try:
        raise RuntimeError(f"GET {URL} failed")
    except RuntimeError as exc:
        message = render_crash(exc, "collect.py:1 collect", started=T0)
    assert "crashed" in str(message[0]["title"]) and "RuntimeError" in str(
        message[0]["description"]
    )
    assert message[0]["color"] == RED and MARKER not in str(message)


HELLO: Message = [{"title": "hello"}]


def capture(responses: list[httpx.Response]) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responses.pop(0)

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def test_send_posts_embeds_with_mentions_off_and_no_content() -> None:
    client, seen = capture([httpx.Response(204)])
    send(URL, [{"title": "hello"}], client=client)
    (request,) = seen
    body = json.loads(request.content)
    assert body == {"embeds": [{"title": "hello"}], "allowed_mentions": {"parse": []}}


def test_send_retries_a_rate_limit_once() -> None:
    client, seen = capture(
        [httpx.Response(429, headers={"retry-after": "120"}), httpx.Response(204)]
    )
    waits: list[float] = []
    send(URL, HELLO, client=client, sleep=waits.append)
    assert len(seen) == 2 and waits == [10.0]  # capped


@pytest.mark.parametrize("value", ["nan", "inf", "-5", "Wed, 21 Oct 2026 07:28:00 GMT"])
def test_odd_retry_after_values_still_retry(value: str) -> None:
    client, seen = capture(
        [httpx.Response(503, headers={"retry-after": value}), httpx.Response(204)]
    )
    waits: list[float] = []
    send(URL, HELLO, client=client, sleep=waits.append)
    assert len(seen) == 2 and len(waits) == 1 and 0.0 <= waits[0] <= 10.0


def test_failures_never_include_the_url() -> None:
    client, _ = capture([httpx.Response(404)])
    with pytest.raises(NotifyError) as info:
        send(URL, HELLO, client=client)
    assert str(info.value) == "HTTP 404" and MARKER not in str(info.value)

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    log: list[str] = []
    post_update(URL, HELLO, log.append, client=httpx.Client(transport=httpx.MockTransport(refuse)))
    assert log == ["notify: FAILED (ConnectError)"]


def test_only_discord_webhooks_are_posted_to() -> None:
    assert is_webhook(URL)
    assert not is_webhook("http://discord.com/api/webhooks/1/abc")
    assert not is_webhook("https://discord.com.evil.example/api/webhooks/1/abc")
    assert not is_webhook(URL + "/../x")
    client, seen = capture([])
    log: list[str] = []
    post_update("https://evil.example/hook", HELLO, log.append, client=client)
    assert seen == [] and log == [
        "notify: FAILED (KITSUNOX_DISCORD_WEBHOOK is not a Discord webhook URL)"
    ]


def test_no_webhook_means_no_post() -> None:
    client, seen = capture([])
    log: list[str] = []
    post_update(None, HELLO, log.append, client=client)
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
    message = render_daily(DAY, ticks_of_a_day(), [a, b])
    assert [e["title"] for e in message] == [
        "🦊 Kitsunox daily summary · Thu 29 Oct 2026",
        "Flagged that day",
        "Needs attention",
    ]
    assert message[0]["color"] == RED and message[2]["color"] == RED
    assert lines(message) == [
        "# 🦊 Kitsunox daily summary · Thu 29 Oct 2026",
        "UTC day **2026-10-29**",
        "🛑 **Collection had a problem**: see *Needs attention* below.",
        "Ticks: 4",
        "Runs: 2",
        "Versions checked: 25,000",
        "# Flagged that day",
        "**3 versions to review**, in 2 packages.",
        "🔴 HIGH: 1",
        "🟠 MEDIUM: 2",
        r"Top packages: 🔴 **evil\-pkg** · score 16, HIGH",
        r"Top packages: 🟠 **lightdash\-cli** · score 9, MEDIUM, 2 versions",
        "# Needs attention",
        r"🛑 1 crashed: ValueError at x\.py\:1 x1",
        "🛑 Coverage gap: **1 run not chained** on to the run before: releases between them "
        "were not checked.",
        "⚠️ 1 with failed steps: prune x1",
        "⚠️ Offline: 1 tick: registry offline or an outage, nothing written (the next tick "
        "catches up).",
        "⚠️ Network skips: 3 packages skipped on the network (retried the next tick).",
        "-- Details: data/logs/collect.log",
    ]
    quiet = render_daily(DAY, ticks_of_a_day()[:1], [])
    assert len(quiet) == 1 and quiet[0]["color"] == GREEN
    assert lines(quiet)[1:] == [
        "UTC day **2026-10-29**",
        "✅ Every tick ran, and every run chained on to the one before.",
        "Ticks: 1",
        "Runs: 1",
        "Versions checked: 20,000",
    ]


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


def test_the_daily_summary_carries_the_verdict_tally() -> None:
    from kitsunox.reporting.verdicts import verdict_record

    a = report("a", entry(1, "evil-pkg", "1.0.3", 14, Severity.HIGH))
    at = datetime(2026, 10, 29, 12, tzinfo=UTC)
    earlier = verdict_record(a, a.entries[0], "malicious", by="owner", at=at - timedelta(days=2))
    benign = verdict_record(a, a.entries[0], "benign", by="owner", at=at)
    other = earlier.model_copy(update={"name": "other", "at": at})
    review = render_daily(DAY, ticks_of_a_day(), [a], [earlier, other])[2]
    assert review["title"] == "Review"
    assert lines([review])[1:5] == [
        "☠️ Malicious: **2**",
        "☠️ Malicious: +1 that day",
        "❔ Inconclusive: **0**",
        "❔ Inconclusive: +0 that day",
    ]
    flipped = lines(render_daily(DAY, ticks_of_a_day(), [a], [earlier, benign]))
    assert "☠️ Malicious: **0**" in flipped and "✅ Benign: +1 that day" in flipped
    probe = other.model_copy(update={"tags": ("probe",)})
    tagged = lines(render_daily(DAY, ticks_of_a_day(), [a], [earlier, probe]))
    assert "☠️ Malicious: +1 that day, research probes 1" in tagged


def test_the_daily_summary_shows_the_queue_as_it_is_now() -> None:
    queue = Queue(
        ecosystem="npm",
        as_of=T0,
        since=T0 - timedelta(days=7),
        runs=(),
        skipped=(),
        packages=398,
        versions=529,
        by_severity={"medium": 267, "high": 131},
        entries=(),
    )
    review = render_daily(DAY, ticks_of_a_day()[:1], [], [], queue)[1]
    assert lines([review]) == [
        "# Review",
        "📥 **398 packages awaiting review** (529 versions)",
        "by their highest severity: 🔴 131 HIGH · 🟠 267 MEDIUM",
    ]


def test_disk_space_is_in_the_daily_summary_and_a_low_disk_is_a_problem() -> None:
    at = datetime(2026, 10, 29, 1, tzinfo=UTC)
    ticks = [
        TickRecord(started=at, minutes=5, run_id="a", disk_free_gb=80.0, disk_lowest_gb=61.5),
        TickRecord(
            started=at + timedelta(hours=1),
            minutes=5,
            run_id="b",
            disk_free_gb=30.2,
            disk_lowest_gb=12.0,
            disk_low=True,
        ),
    ]
    message = render_daily(DAY, ticks, [])
    text = lines(message)
    assert "Disk free: 30.2 GB (lowest 12.0)" in text
    assert message[0]["color"] == RED
    assert any(
        line.startswith("🛑 Disk space: **1 tick skipped work** for lack of space (lowest 12.0 GB")
        for line in text
    ), text
    assert "Disk free: 30.2 GB (lowest 12.0)" not in lines(render_daily(DAY, [], []))


def test_a_low_disk_alert_says_how_much_is_left_and_posts_every_six_hours() -> None:
    tick = Tick(manifest=None, disk_free=21 * GIB, disk_lowest=9 * GIB, disk_low=True)
    (embed,) = render_disk(tick, started=T0)
    assert embed["color"] == RED and "**9.0 GB free** at worst, 21.0 GB at the end" in str(
        embed["description"]
    )
    record = notify.tick_record(tick, started=T0, elapsed=timedelta(minutes=1))
    assert (record.disk_free_gb, record.disk_lowest_gb, record.disk_low) == (21.0, 9.0, True)
    now = T0 + timedelta(hours=1)
    assert disk_alert_due(NotifyState(), now)
    assert not disk_alert_due(NotifyState(disk_posted=now - timedelta(hours=5)), now)
    assert disk_alert_due(NotifyState(disk_posted=now - timedelta(hours=6)), now)
    shown = lines(render_tick(tick, started=T0, elapsed=timedelta(minutes=1)))
    assert "Disk free: 21.0 GB" in shown and any("Disk low" in line for line in shown)


def test_the_daily_summary_has_one_live_eval_line() -> None:
    from kitsunox.evaluation.live import LogLine

    live = LogLine(
        built_at=T0,
        dataset="live-20261124T000000Z",
        dataset_sha256="0",
        label_set="20261124T000000Z",
        versions=500_000,
        malicious=190,
        reported_malicious=52,
        recall=52 / 190,
        precision=0.03,
        newly_labeled=4,
        newly_reported=1,
        sample_unreviewed=3,
    )
    review = render_daily(DAY, ticks_of_a_day()[:1], [], [], None, live)[1]
    assert lines([review])[1] == (
        "🧪 Live eval (labels 20261124T000000Z): 52 / 190 malicious reported (27%); "
        "+4 newly labeled, 1 reported; review sample: 3 to review"
    )
    unknown = live.model_copy(update={"recall": None})
    assert "malicious reported;" in lines(render_daily(DAY, [], [], [], None, unknown))[-1]
