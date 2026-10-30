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
  (`allowed_mentions`), link previews are suppressed, control and bidi characters are dropped,
  and Discord markdown is escaped, so a crafted name can't ping the channel, forge a link or
  reformat the message.
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
from kitsunox.reporting.markdown import strip_controls
from kitsunox.reporting.report import Report, ReportEntry
from kitsunox.reporting.verdicts import VerdictRecord, current, tally
from kitsunox.util.files import atomic_write

WEBHOOK_ENV: Final = "KITSUNOX_DISCORD_WEBHOOK"
MAX_CONTENT: Final = 1900  # Discord's limit is 2,000 characters
MAX_NAME: Final = 80
TOP_PACKAGES: Final = 5
SUPPRESS_EMBEDS: Final = 1 << 2
TIMEOUT: Final = 10.0
ATTEMPTS: Final = 2
MAX_RETRY_AFTER: Final = 10.0

_WEBHOOK: Final = re.compile(
    r"^https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+$"
)
_MARKDOWN: Final = re.compile(r"([\\*_~`|>#\-\[\]()<:@!.+=])")


class NotifyError(Exception):
    """A post that failed. The message never contains the webhook URL."""


@dataclass(frozen=True, slots=True)
class Tick:
    """What one `collect` tick did."""

    manifest: RunManifest | None  # None: registry offline or an outage, nothing written
    reports: tuple[Report, ...] = ()  # reports written this tick (catch-ups first)
    failed: tuple[str, ...] = ()  # best-effort steps that failed


TICKS_FILE: Final = "ticks.jsonl"  # in data/state/
NOTIFY_STATE: Final = "notify.json"
MAX_TICK_LINES: Final = 24 * 14  # two weeks of hourly ticks
CRASH_EVERY: Final = timedelta(days=1)  # at most one crash post this often


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


class NotifyState(Persisted):
    SCHEMA_VERSION: ClassVar[int] = 1
    schema_version: int = 1
    daily_posted: date | None = None  # the last day whose summary was posted
    crash_posted: datetime | None = None


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


def render_daily(
    day: date,
    ticks: Sequence[TickRecord],
    reports: Sequence[Report],
    verdicts: Sequence[VerdictRecord] = (),
) -> str:
    """The day's ticks and reports, and reviewers' verdicts (the running tally, and how many
    were recorded that day). A version two overlapping runs both reported counts once, at its
    highest score."""
    today = [t for t in ticks if t.started.date() == day]
    runs = [t for t in today if t.run_id is not None]
    crashed = [t for t in today if t.crashed]
    failed = Counter(step for t in today for step in t.failed)
    lines = [f"**Kitsunox** daily summary for {day:%Y-%m-%d} (UTC)"]
    status = []
    if crashed:
        status.append(f"**{len(crashed)} crashed**")
    if failed:
        status.append(f"{sum(1 for t in today if t.failed)} with failed steps")
    offline = sum(1 for t in today if t.run_id is None and not t.crashed)
    if offline:
        status.append(f"{offline} offline or an outage")
    versions = sum(t.versions for t in runs)
    head = f"{len(today)} ticks" + (f" ({', '.join(status)})" if status else "")
    lines.append(f"{head}, {len(runs)} runs, {versions:,} versions.")
    best: dict[tuple[str, str], ReportEntry] = {}
    for report in reports:
        for entry in report.entries:
            key = (entry.name, entry.version)
            if key not in best or entry.score > best[key].score:
                best[key] = entry
    if reports:
        severities = Counter(e.severity.value for e in best.values())
        packages = len({name for name, _ in best})
        lines.append(
            f"**{len(best):,} to review** ({packages:,} packages){_severities(severities)}."
        )
        top = _top_packages(list(best.values()))
        if top:
            lines.append(f"Top: {top}")
    if verdicts:
        now = current(verdicts)
        counts = tally(now)
        that_day = Counter(r.verdict for r in now.values() if r.at.date() == day)
        lines.append(
            f"**Verified malicious: {counts['malicious']:,}** "
            f"(+{that_day['malicious']} that day); inconclusive {counts['inconclusive']:,}, "
            f"benign {counts['benign']:,}."
        )
    gaps = [t for t in runs if t.chained is False]
    if gaps:
        lines.append(f"**{len(gaps)} runs NOT chained** (coverage gap).")
    skipped = sum(t.transient_skipped for t in runs)
    if skipped:
        lines.append(f"{skipped:,} packages skipped on the network (retried the next tick).")
    if failed:
        steps = ", ".join(f"{escape(step, 60)} x{n}" for step, n in sorted(failed.items()))
        lines.append(f"Failed steps: {steps}.")
    if crashed:
        kinds = Counter(t.crashed for t in crashed)
        lines.append(
            "Crashes: " + ", ".join(f"{escape(c, 200)} x{n}" for c, n in sorted(kinds.items()))
        )
    if crashed or failed:
        lines.append("See `data/logs/collect.log`.")
    return _fit(lines)


def is_webhook(url: str) -> bool:
    return _WEBHOOK.match(url) is not None


def escape(value: object, limit: int = MAX_NAME) -> str:
    """Untrusted text as one line of inert Discord text."""
    flat = " ".join(strip_controls(str(value)).split())
    if len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    return _MARKDOWN.sub(r"\\\1", flat)


def render_tick(tick: Tick, *, started: datetime, elapsed: timedelta) -> str:
    lines = [f"**Kitsunox** tick {started:%Y-%m-%d %H:%M} UTC, {_duration(elapsed)}"]
    manifest = tick.manifest
    if manifest is None:
        lines.append("Registry offline or an outage: nothing written, the next tick catches up.")
    else:
        current = next((r for r in tick.reports if r.run_id == manifest.run_id), None)
        chain = "" if manifest.chained_from else " (**NOT chained**: coverage gap)"
        network = (
            f", {manifest.transient_skipped:,} skipped on the network (retried next tick)"
            if manifest.transient_skipped
            else ""
        )
        head = f"Run `{manifest.run_id}`{chain}: {manifest.change_count:,} versions{network}"
        if current is None:
            lines.append(f"{head}; no report this tick (a stage failed, see the log).")
        else:
            uncompared, outage = current.network_uncompared()
            repo = (
                f" {uncompared:,} not compared with their repo (network"
                f"{', outage' if outage else ''})."
                if uncompared
                else ""
            )
            failed, outage = current.dependency_network_failures()
            if failed:
                why = "network, outage" if outage else "network"
                repo += f" {failed:,} dependency lookups failed ({why})."
            lines.append(
                f"{head}; **{current.reported:,} to review**"
                f"{_severities(current.by_severity)}.{repo}"
            )
            top = _top_packages(current.entries)
            if top:
                lines.append(f"Top: {top}")
    caught_up = [r for r in tick.reports if manifest is None or r.run_id != manifest.run_id]
    if caught_up:
        runs = ", ".join(f"`{r.run_id}` ({r.reported:,} to review)" for r in caught_up)
        lines.append(f"Caught up: {runs}")
    if tick.failed:
        steps = ", ".join(escape(step, 120) for step in tick.failed)
        lines.append(f"Failed: {steps}. See `data/logs/collect.log`.")
    return _fit(lines)


def render_crash(exc: BaseException, where: str, *, started: datetime) -> str:
    """For a tick that raised: the exception type and location only (no message, which may
    hold a URL or path from the failing request)."""
    return _fit(
        [
            f"**Kitsunox** tick {started:%Y-%m-%d %H:%M} UTC **crashed**: "
            f"{escape(type(exc).__name__)} at {escape(where, 300)}.",
            "See `data/logs/collect.log`.",
        ]
    )


def send(
    url: str,
    content: str,
    *,
    client: httpx.Client,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Post `content` once, retrying once on a rate limit, a server error or a network error.
    Raises `NotifyError`."""
    if not is_webhook(url):
        raise NotifyError(f"{WEBHOOK_ENV} is not a Discord webhook URL")
    payload = {"content": content, "allowed_mentions": {"parse": []}, "flags": SUPPRESS_EMBEDS}
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
    content: str,
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
            send(url, content, client=http)
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


def _severities(by_severity: Mapping[str, int]) -> str:
    if not by_severity:
        return ""
    order = [severity.value for severity in reversed(Severity)]  # highest first
    items = sorted(
        by_severity.items(),
        key=lambda kv: order.index(kv[0]) if kv[0] in order else len(order),
    )
    return " (" + ", ".join(f"{n:,} {escape(s.upper())}" for s, n in items) + ")"


def _top_packages(entries: Sequence[ReportEntry]) -> str:
    """The highest-scoring packages, each once: a package releasing many flagged versions in
    the window is one item, with the version count."""
    best: dict[str, tuple[float, str, int]] = {}
    for entry in entries:
        score, severity, count = best.get(entry.name, (float("-inf"), "", 0))
        if entry.score > score:
            score, severity = entry.score, entry.severity.value.upper()
        best[entry.name] = (score, severity, count + 1)
    ranked = sorted(best.items(), key=lambda kv: (-kv[1][0], kv[0]))[:TOP_PACKAGES]
    return ", ".join(
        f"{escape(name)} (score {score:g}, {escape(severity)}"
        f"{f', {count} versions' if count > 1 else ''})"
        for name, (score, severity, count) in ranked
    )


def _duration(elapsed: timedelta) -> str:
    minutes = round(elapsed.total_seconds() / 60)
    return f"{minutes} min" if minutes < 120 else f"{minutes / 60:.1f} h"


def _fit(lines: list[str]) -> str:
    content = "\n".join(lines)
    if len(content) <= MAX_CONTENT:
        return content
    # Cut on a whitespace boundary so an escape (`\x`) is never split from its character.
    cut = content.rfind(" ", 0, MAX_CONTENT - 1)
    return content[: cut if cut > 0 else MAX_CONTENT - 1] + "…"
