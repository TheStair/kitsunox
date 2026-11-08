"""Run updates to a Discord webhook, posted by `kitsunox collect`: one summary a day, plus a
crash at most once a day (`--notify-each-tick` posts after every tick instead).

Each tick appends one line to `data/state/ticks.jsonl` (`TickRecord`). The first tick of a UTC
day posts the summary of the day before from those lines and that day's reports
(`render_daily`); `data/state/notify.json` remembers which day was posted and when a crash was
last posted. The wall clock decides when to post: a notification is about the machine, not
part of any run.

A notification is output, not input: it isn't part of any run's snapshot, so it goes straight
through httpx rather than `HttpFetcher`, and it never affects what a run records. It is
best-effort. A failed post is logged and the tick is unaffected.

Two things are protected:

- **The webhook URL is a credential**: anyone holding it can post to the channel. It comes from
  `KITSUNOX_DISCORD_WEBHOOK` (environment or `.env`). It is never logged: errors name the HTTP
  status or the exception type only, because httpx messages include the URL.
- **Package names are untrusted.** They could carry `@everyone`, a `<@id>` mention, a masked
  link, markdown, or bidirectional overrides. Mentions are disabled for the whole message
  (`allowed_mentions`), control and bidi characters are dropped, and Discord markdown is
  escaped, so a crafted name can't ping the channel, forge a link or reformat the message.
  Names only ever go in embed descriptions and field values, which render markdown (escaped
  here) but never unfurl a link preview; the message has no `content`, the only text Discord
  unfurls.

A message is a list of Discord embeds (`Message`): a coloured bar for health (green, amber,
red), severity-coloured counts and one package per line, each piece cut to Discord's limits
(4,096 per description, 1,024 per field, 6,000 per message).
"""

from __future__ import annotations

import math
import re
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import ClassVar, Final

import httpx
from pydantic import ValidationError

from kitsunox.core.models import Persisted, Record, Severity
from kitsunox.core.run import RunManifest
from kitsunox.evaluation.live import LogLine
from kitsunox.reporting.markdown import strip_controls
from kitsunox.reporting.queue import Queue
from kitsunox.reporting.report import Report, ReportEntry
from kitsunox.reporting.verdicts import Verdict, VerdictRecord, current, probes, tally
from kitsunox.util.disk import GIB
from kitsunox.util.files import atomic_write

WEBHOOK_ENV: Final = "KITSUNOX_DISCORD_WEBHOOK"
MAX_NAME: Final = 80
TOP_PACKAGES: Final = 5
# Discord's embed limits, with a little room: 4,096 per description, 1,024 per field value,
# 25 fields per embed, 6,000 characters per message.
MAX_DESCRIPTION: Final = 4000
MAX_FIELD: Final = 1000
MAX_FIELDS: Final = 25
MAX_MESSAGE: Final = 6000
MORE_ROOM: Final = 20  # for "… and N more"
LOG_HINT: Final = "Details: data/logs/collect.log"
TIMEOUT: Final = 10.0
ATTEMPTS: Final = 2
MAX_RETRY_AFTER: Final = 10.0

_WEBHOOK: Final = re.compile(
    r"^https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+$"
)
_MARKDOWN: Final = re.compile(r"([\\*_~`|>#\-\[\]()<:@!.+=])")


type Field = dict[str, object]
type Embed = dict[str, object]
type Message = list[Embed]

GREEN: Final = 0x2ECC71
AMBER: Final = 0xF1A33C
RED: Final = 0xE74C3C
BLURPLE: Final = 0x5865F2
_SEVERITY_ORDER: Final = tuple(Severity)  # lowest first
SEVERITY_MARK: Final = {
    Severity.CRITICAL.value: "🟣",
    Severity.HIGH.value: "🔴",
    Severity.MEDIUM.value: "🟠",
    Severity.LOW.value: "🟡",
    Severity.INFO.value: "⚪",
}
SEVERITY_COLOUR: Final = {
    Severity.CRITICAL: 0x9B59B6,
    Severity.HIGH: RED,
    Severity.MEDIUM: AMBER,
    Severity.LOW: 0xF1C40F,
    Severity.INFO: 0x95A5A6,
}
VERDICT_LABELS: Final[tuple[tuple[Verdict, str], ...]] = (
    ("malicious", "☠️ Malicious"),
    ("inconclusive", "❔ Inconclusive"),
    ("benign", "✅ Benign"),
)


class NotifyError(Exception):
    """A post that failed. The message never contains the webhook URL."""


@dataclass(frozen=True, slots=True)
class Tick:
    """What one `collect` tick did."""

    manifest: RunManifest | None  # None: registry offline, an outage or no disk space
    reports: tuple[Report, ...] = ()  # reports written this tick (catch-ups first)
    failed: tuple[str, ...] = ()  # best-effort steps that failed
    disk_free: int | None = None  # bytes free at the end of the tick
    disk_lowest: int | None = None  # the least free during the tick
    disk_low: bool = False  # the tick skipped work for lack of space


TICKS_FILE: Final = "ticks.jsonl"  # in data/state/
NOTIFY_STATE: Final = "notify.json"
MAX_TICK_LINES: Final = 24 * 14  # two weeks of hourly ticks
CRASH_EVERY: Final = timedelta(days=1)  # at most one crash post this often
DISK_ALERT_EVERY: Final = timedelta(hours=6)  # at most one low-disk post this often


class TickRecord(Record):
    """One tick, for the daily summary. Package text never goes in here: only run ids, counts
    and fixed step names."""

    started: datetime
    minutes: float
    run_id: str | None = None  # None: offline, an outage or a crash
    versions: int = 0
    chained: bool | None = None
    transient_skipped: int = 0
    reports: tuple[str, ...] = ()  # run ids whose report this tick wrote (catch-ups first)
    failed: tuple[str, ...] = ()
    crashed: str | None = None  # "<exception type> at <where>"
    disk_free_gb: float | None = None
    disk_lowest_gb: float | None = None
    disk_low: bool = False


class NotifyState(Persisted):
    SCHEMA_VERSION: ClassVar[int] = 1
    schema_version: int = 1
    daily_posted: date | None = None  # the last day whose summary was posted
    crash_posted: datetime | None = None
    disk_posted: datetime | None = None


def tick_record(tick: Tick, *, started: datetime, elapsed: timedelta) -> TickRecord:
    manifest = tick.manifest
    return TickRecord(
        started=started,
        minutes=round(elapsed.total_seconds() / 60, 1),
        run_id=manifest.run_id if manifest else None,
        versions=manifest.change_count if manifest else 0,
        chained=manifest.chained_from is not None if manifest else None,
        transient_skipped=manifest.transient_skipped if manifest else 0,
        reports=tuple(r.run_id for r in tick.reports),
        failed=tick.failed,
        disk_free_gb=_gb(tick.disk_free),
        disk_lowest_gb=_gb(tick.disk_lowest),
        disk_low=tick.disk_low,
    )


def crash_record(
    exc: BaseException, where: str, *, started: datetime, elapsed: timedelta
) -> TickRecord:
    return TickRecord(
        started=started,
        minutes=round(elapsed.total_seconds() / 60, 1),
        crashed=f"{type(exc).__name__} at {where}",
    )


def append_tick(state_dir: Path, record: TickRecord) -> None:
    """Add `record` to the tick log, keeping the last MAX_TICK_LINES."""
    path = state_dir / TICKS_FILE
    try:
        lines = path.read_bytes().splitlines()
    except FileNotFoundError:
        lines = []
    lines = [*lines, record.model_dump_json().encode()][-MAX_TICK_LINES:]
    atomic_write(path, b"\n".join(lines) + b"\n")


def read_ticks(state_dir: Path) -> list[TickRecord]:
    """The tick log; unreadable lines are skipped."""
    try:
        raw = (state_dir / TICKS_FILE).read_bytes().splitlines()
    except FileNotFoundError:
        return []
    records = []
    for line in raw:
        try:
            records.append(TickRecord.model_validate_json(line))
        except ValidationError:
            continue
    return records


def load_state(state_dir: Path) -> NotifyState:
    try:
        return NotifyState.load_json((state_dir / NOTIFY_STATE).read_bytes())
    except OSError, ValueError:
        return NotifyState()


def save_state(state_dir: Path, state: NotifyState) -> None:
    atomic_write(state_dir / NOTIFY_STATE, state.model_dump_json(indent=2).encode() + b"\n")


def summary_due(state: NotifyState, ticks: Sequence[TickRecord], now: datetime) -> date | None:
    """The day to summarise now: yesterday (UTC), if it isn't posted yet and a tick ran in it."""
    day = now.date() - timedelta(days=1)
    if state.daily_posted is not None and state.daily_posted >= day:
        return None
    return day if any(t.started.date() == day for t in ticks) else None


def crash_due(state: NotifyState, now: datetime) -> bool:
    return state.crash_posted is None or now - state.crash_posted >= CRASH_EVERY


def disk_alert_due(state: NotifyState, now: datetime) -> bool:
    return state.disk_posted is None or now - state.disk_posted >= DISK_ALERT_EVERY


def render_daily(
    day: date,
    ticks: Sequence[TickRecord],
    reports: Sequence[Report],
    verdicts: Sequence[VerdictRecord] = (),
    queue: Queue | None = None,
    live: LogLine | None = None,
) -> Message:
    """The day's ticks and reports, reviewers' verdicts (the running tally, and how many were
    recorded that day) and the review queue as it is now, as up to four embeds: health, what
    was flagged, review, and what needs attention. A version two overlapping runs both reported
    counts once, at its highest score."""
    today = [t for t in ticks if t.started.date() == day]
    runs = [t for t in today if t.run_id is not None]
    crashed = [t for t in today if t.crashed]
    failed = Counter(step for t in today for step in t.failed)
    offline = sum(1 for t in today if t.run_id is None and not t.crashed)
    gaps = sum(1 for t in runs if t.chained is False)
    skipped = sum(t.transient_skipped for t in runs)
    disk_low = [t for t in today if t.disk_low]
    measured = [t for t in today if t.disk_free_gb is not None]
    serious = bool(crashed or gaps or disk_low)
    if serious:
        status = "🛑 **Collection had a problem**: see *Needs attention* below."
    elif failed or offline or skipped:
        status = "⚠️ Collection ran, with minor problems: see *Needs attention* below."
    else:
        status = "✅ Every tick ran, and every run chained on to the one before."
    embeds: list[Embed] = [
        _embed(
            f"🦊 Kitsunox daily summary · {day:%a %d %b %Y}",
            f"UTC day **{day:%Y-%m-%d}**\n{status}",
            RED if serious else AMBER if failed or offline or skipped else GREEN,
            [
                _field("Ticks", f"{len(today):,}"),
                _field("Runs", f"{len(runs):,}"),
                _field("Versions checked", f"{sum(t.versions for t in runs):,}"),
                *_disk_fields(measured),
            ],
        )
    ]
    best: dict[tuple[str, str], ReportEntry] = {}
    for report in reports:
        for entry in report.entries:
            key = (entry.name, entry.version)
            if key not in best or entry.score > best[key].score:
                best[key] = entry
    if reports:
        embeds.append(_flagged("Flagged that day", list(best.values())))
    review = _review(day, verdicts, queue, live)
    if review is not None:
        embeds.append(review)
    problems: list[Field] = []
    if crashed:
        kinds = Counter(t.crashed for t in crashed)
        problems.append(
            _field(
                f"🛑 {len(crashed)} crashed",
                _lines([f"{escape(c, 200)} x{n}" for c, n in sorted(kinds.items())]),
                inline=False,
            )
        )
    if gaps:
        problems.append(
            _field(
                "🛑 Coverage gap",
                f"**{gaps:,} {_plural(gaps, 'run')} not chained** on to the run before: "
                "releases between them were not checked.",
                inline=False,
            )
        )
    if failed:
        problems.append(
            _field(
                f"⚠️ {sum(1 for t in today if t.failed)} with failed steps",
                _lines([f"{escape(step, 60)} x{n}" for step, n in sorted(failed.items())]),
                inline=False,
            )
        )
    if disk_low:
        lowest = min(t.disk_lowest_gb or 0.0 for t in disk_low)
        problems.append(
            _field(
                "🛑 Disk space",
                f"**{len(disk_low):,} {_plural(len(disk_low), 'tick')} skipped work** for lack "
                f"of space (lowest {lowest:,.1f} GB free); it resumes once a prune frees room.",
                inline=False,
            )
        )
    if offline:
        problems.append(
            _field(
                "⚠️ Offline",
                f"{offline:,} {_plural(offline, 'tick')}: registry offline or an outage, "
                "nothing written (the next tick catches up).",
                inline=False,
            )
        )
    if skipped:
        problems.append(
            _field(
                "⚠️ Network skips",
                f"{skipped:,} {_plural(skipped, 'package')} skipped on the network "
                "(retried the next tick).",
                inline=False,
            )
        )
    if problems:
        embeds.append(
            _embed("Needs attention", None, RED if serious else AMBER, problems, footer=LOG_HINT)
        )
    return embeds


def live_line(live: LogLine) -> str:
    """One line on the newest live evaluation (decision 0019). No package text in it."""
    share = f" ({live.recall:.0%})" if live.recall is not None else ""
    return (
        f"🧪 Live eval (labels {escape(live.label_set, 20)}): {live.reported_malicious:,} / "
        f"{live.malicious:,} malicious reported{share}; +{live.newly_labeled} newly labeled, "
        f"{live.newly_reported} reported; review sample: {live.sample_unreviewed} to review"
    )


def is_webhook(url: str) -> bool:
    return _WEBHOOK.match(url) is not None


def escape(value: object, limit: int = MAX_NAME) -> str:
    """Untrusted text as one line of inert Discord text."""
    flat = " ".join(strip_controls(str(value)).split())
    if len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    return _MARKDOWN.sub(r"\\\1", flat)


def render_tick(tick: Tick, *, started: datetime, elapsed: timedelta) -> Message:
    title = f"🦊 Kitsunox tick · {started:%Y-%m-%d %H:%M} UTC · {_duration(elapsed)}"
    manifest = tick.manifest
    fields: list[Field] = []
    if manifest is None:
        description = "⚠️ Registry offline or an outage: nothing written, the next tick catches up."
        colour = AMBER
    else:
        current = next((r for r in tick.reports if r.run_id == manifest.run_id), None)
        chain = "" if manifest.chained_from else "\n🛑 **NOT chained**: a coverage gap."
        network = (
            f"\n⚠️ {manifest.transient_skipped:,} skipped on the network (retried next tick)."
            if manifest.transient_skipped
            else ""
        )
        description = f"Run `{manifest.run_id}`: {manifest.change_count:,} versions{chain}{network}"
        colour = RED if chain else AMBER if network or tick.failed else GREEN
        if current is None:
            description += "\n⚠️ No report this tick (a stage failed, see the log)."
            colour = RED
        else:
            description += f"\n**{current.reported:,} to review**."
            uncompared, outage = current.network_uncompared()
            if uncompared:
                description += (
                    f"\n{uncompared:,} not compared with their repo (network"
                    f"{', outage' if outage else ''})."
                )
            failed, outage = current.dependency_network_failures()
            if failed:
                why = "network, outage" if outage else "network"
                description += f"\n{failed:,} dependency lookups failed ({why})."
            fields += _severity_fields(current.by_severity)
            top = _top_packages(current.entries)
            if top:
                fields.append(_field("Top packages", top, inline=False))
    if tick.disk_low:
        description += f"\n🛑 Disk low: work skipped ({_gb_text(tick.disk_lowest)} free at worst)."
        colour = RED
    if tick.disk_free is not None:
        fields.append(_field("Disk free", _gb_text(tick.disk_free)))
    caught_up = [r for r in tick.reports if manifest is None or r.run_id != manifest.run_id]
    if caught_up:
        fields.append(
            _field(
                "Caught up",
                _lines([f"`{r.run_id}`: {r.reported:,} to review" for r in caught_up]),
                inline=False,
            )
        )
    if tick.failed:
        fields.append(
            _field("⚠️ Failed", _lines([escape(s, 120) for s in tick.failed]), inline=False)
        )
    footer = LOG_HINT if tick.failed or colour != GREEN else None
    return [_embed(title, description, colour, fields, footer=footer)]


def render_crash(exc: BaseException, where: str, *, started: datetime) -> Message:
    """For a tick that raised: the exception type and location only (no message, which may
    hold a URL or path from the failing request)."""
    return [
        _embed(
            f"🛑 Kitsunox tick crashed · {started:%Y-%m-%d %H:%M} UTC",
            f"**{escape(type(exc).__name__)}** at {escape(where, 300)}",
            RED,
            [],
            footer=LOG_HINT,
        )
    ]


def render_disk(tick: Tick, *, started: datetime) -> Message:
    """A tick that skipped work for lack of disk space: posted at once, not with the day's
    summary, since the next tick may be the one that fills the disk."""
    return [
        _embed(
            f"🛑 Kitsunox disk low · {started:%Y-%m-%d %H:%M} UTC",
            f"The tick skipped work for lack of space: **{_gb_text(tick.disk_lowest)} free** at "
            f"worst, {_gb_text(tick.disk_free)} at the end. Runs resume on a later tick once a "
            "prune frees room; if it stays low, lower retention or add disk.",
            RED,
            [],
            footer=LOG_HINT,
        )
    ]


def embed_chars(message: Message) -> int:
    """The characters Discord counts against its 6,000 per message."""
    total = 0
    for embed in message:
        total += len(str(embed.get("title", ""))) + len(str(embed.get("description", "")))
        footer = embed.get("footer")
        if isinstance(footer, dict):
            total += len(str(footer.get("text", "")))
        fields = embed.get("fields", [])
        if isinstance(fields, list):
            total += sum(len(str(f["name"])) + len(str(f["value"])) for f in fields)
    return total


def send(
    url: str,
    message: Message,
    *,
    client: httpx.Client,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Post `message` once, retrying once on a rate limit, a server error or a network error.
    Raises `NotifyError`."""
    if not is_webhook(url):
        raise NotifyError(f"{WEBHOOK_ENV} is not a Discord webhook URL")
    payload = {"embeds": list(message), "allowed_mentions": {"parse": []}}
    problem = "no attempt"
    for attempt in range(ATTEMPTS):
        try:
            response = client.post(url, json=payload, timeout=TIMEOUT)
        except httpx.HTTPError as exc:
            problem, wait = type(exc).__name__, 1.0
        else:
            if response.is_success:
                return
            problem = f"HTTP {response.status_code}"
            if response.status_code != 429 and response.status_code < 500:
                break
            wait = _retry_after(response)
        if attempt + 1 < ATTEMPTS:
            sleep(wait)
    raise NotifyError(problem)


def post_update(
    url: str | None,
    message: Message,
    log: Callable[[str], None],
    *,
    client: httpx.Client | None = None,
) -> bool:
    """Best-effort: post if a webhook is configured, log the outcome, never raise. Whether it
    was posted."""
    if url is None:
        return False
    try:
        with client or httpx.Client() as http:
            send(url, message, client=http)
    except NotifyError as exc:
        log(f"notify: FAILED ({exc})")
    except Exception as exc:  # a notification must never break a tick
        log(f"notify: FAILED ({type(exc).__name__})")
    else:
        log("notify: posted")
        return True
    return False


def _retry_after(response: httpx.Response) -> float:
    try:
        seconds = float(response.headers.get("retry-after", "1"))
    except ValueError:
        seconds = 1.0
    if not math.isfinite(seconds):  # `nan` would make sleep() raise
        seconds = 1.0
    return min(max(seconds, 0.0), MAX_RETRY_AFTER)


def _embed(
    title: str,
    description: str | None,
    colour: int,
    fields: Sequence[Field],
    *,
    footer: str | None = None,
) -> Embed:
    embed: Embed = {"title": title, "color": colour}
    if description:
        embed["description"] = _cut(description, MAX_DESCRIPTION)
    if fields:
        embed["fields"] = list(fields[:MAX_FIELDS])
    if footer:
        embed["footer"] = {"text": footer}
    return embed


def _field(name: str, value: str, *, inline: bool = True) -> Field:
    return {"name": name, "value": _cut(value, MAX_FIELD) or "-", "inline": inline}


def _flagged(title: str, entries: Sequence[ReportEntry]) -> Embed:
    """Versions to review, by severity, and the top packages."""
    by_severity = Counter(e.severity.value for e in entries)
    packages = len({e.name for e in entries})
    fields = _severity_fields(by_severity)
    top = _top_packages(entries)
    if top:
        fields.append(_field("Top packages", top, inline=False))
    worst = max((e.severity for e in entries), key=_SEVERITY_ORDER.index, default=None)
    return _embed(
        title,
        f"**{len(entries):,} {_plural(len(entries), 'version')} to review**, "
        f"in {packages:,} {_plural(packages, 'package')}.",
        SEVERITY_COLOUR[worst] if worst is not None else GREEN,
        fields,
    )


def _review(
    day: date,
    verdicts: Sequence[VerdictRecord],
    queue: Queue | None,
    live: LogLine | None = None,
) -> Embed | None:
    """The review queue now, the verdict tally and the newest live evaluation."""
    if not verdicts and queue is None and live is None:
        return None
    lines = []
    if queue is not None:
        lines.append(
            f"📥 **{queue.packages:,} {_plural(queue.packages, 'package')} awaiting review** "
            f"({queue.versions:,} {_plural(queue.versions, 'version')})"
        )
        marks = _severity_marks(queue.by_severity)
        if marks:
            lines.append(f"by their highest severity: {marks}")
    if live is not None:
        lines.append(live_line(live))
    fields: list[Field] = []
    if verdicts:
        now = current(verdicts)
        counts = tally(now)
        that_day = Counter(r.verdict for r in now.values() if r.at.date() == day)
        probed = probes(now, "malicious")
        for kind, label in VERDICT_LABELS:
            value = f"**{counts[kind]:,}**\n+{that_day[kind]} that day"
            if kind == "malicious" and probed:
                value += f", research probes {probed}"
            fields.append(_field(label, value))
    footer = "Verdicts are all-time totals." if fields else None
    return _embed("Review", "\n".join(lines) or None, BLURPLE, fields, footer=footer)


def _severity_fields(by_severity: Mapping[str, int]) -> list[Field]:
    return [
        _field(f"{SEVERITY_MARK.get(s, '⚪')} {escape(s.upper())}", f"{n:,}")
        for s, n in _by_rank(by_severity)
    ]


def _severity_marks(by_severity: Mapping[str, int]) -> str:
    return " · ".join(
        f"{SEVERITY_MARK.get(s, '⚪')} {n:,} {escape(s.upper())}" for s, n in _by_rank(by_severity)
    )


def _by_rank(by_severity: Mapping[str, int]) -> list[tuple[str, int]]:
    """Highest severity first; unknown names last."""
    order = [s.value for s in reversed(_SEVERITY_ORDER)]
    return sorted(
        by_severity.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else len(order)
    )


def _top_packages(entries: Sequence[ReportEntry]) -> str:
    """The highest-scoring packages, each once, one per line: a package releasing many flagged
    versions in the window is one item, with the version count."""
    best: dict[str, tuple[float, str, int]] = {}
    for entry in entries:
        score, severity, count = best.get(entry.name, (float("-inf"), "", 0))
        if entry.score > score:
            score, severity = entry.score, entry.severity.value
        best[entry.name] = (score, severity, count + 1)
    ranked = sorted(best.items(), key=lambda kv: (-kv[1][0], kv[0]))[:TOP_PACKAGES]
    return _lines(
        [
            f"{SEVERITY_MARK.get(severity, '⚪')} **{escape(name)}** · score {score:g}, "
            f"{escape(severity.upper())}{f', {count} versions' if count > 1 else ''}"
            for name, (score, severity, count) in ranked
        ]
    )


def _lines(lines: Sequence[str], limit: int = MAX_FIELD) -> str:
    """`lines`, one per line, dropping whole lines that don't fit and saying how many."""
    kept: list[str] = []
    for i, line in enumerate(lines):
        last = i == len(lines) - 1
        if len("\n".join([*kept, line])) > limit - (0 if last else MORE_ROOM):
            kept.append(f"… and {len(lines) - i:,} more")
            break
        kept.append(line)
    return "\n".join(kept)


def _disk_fields(measured: Sequence[TickRecord]) -> list[Field]:
    """Free space at the day's last tick, and the least seen during the day."""
    if not measured:
        return []
    last = measured[-1].disk_free_gb or 0.0
    lowest = min(t.disk_lowest_gb or t.disk_free_gb or 0.0 for t in measured)
    return [_field("Disk free", f"{last:,.1f} GB (lowest {lowest:,.1f})")]


def _gb(n: int | None) -> float | None:
    return None if n is None else round(n / GIB, 1)


def _gb_text(n: int | None) -> str:
    return "unknown" if n is None else f"{n / GIB:,.1f} GB"


def _plural(n: int, word: str) -> str:
    return word if n == 1 else word + "s"


def _duration(elapsed: timedelta) -> str:
    minutes = round(elapsed.total_seconds() / 60)
    return f"{minutes} min" if minutes < 120 else f"{minutes / 60:.1f} h"


def _cut(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    # Cut on a whitespace boundary so an escape (`\x`) is never split from its character.
    cut = text.rfind(" ", 0, limit - 1)
    return text[: cut if cut > 0 else limit - 1] + "…"
