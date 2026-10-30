# 0011: Brief run updates to Discord

**Status:** accepted 2026-10-29

## Context

Collection now runs unattended on a VM (0006 addendum). The user wants a brief update after
each tick in a Discord channel, so they don't have to log in to find out whether collection is
running and what it found. A tick can take hours (the first one covers 24 hours of releases), and
problems such as an outage, a failed stage or a broken chain are only visible in
`data/logs/collect.log`.

## Options

1. **Discord webhook, posted by `kitsunox collect`** after each tick.
2. A separate watcher that tails `collect.log` and posts. It needs no change to `collect`, but
   it would have to parse log lines, which are written for people.
3. Email or desktop notifications. They need a mail account or a logged-in session, and the user
   asked for Discord.

## Decision

Option 1. `kitsunox collect` builds a `Tick` (manifest, reports written, failed steps) and posts
one message (`src/kitsunox/notify.py`):

- the run, its version count, how many to review by severity, and the top 5 packages, each
  once, with the number of its versions flagged in the run;
- catch-ups, failed steps, "NOT chained" (a coverage gap), network skips;
- an outage ("nothing written"); a crash shows only the exception type and location;
- a skipped tick (lock held) posts nothing.

## Rules

- **The webhook URL is a credential.** It lives in `.env` as `KITSUNOX_DISCORD_WEBHOOK` (or in
  the environment). It is never logged. Errors name the HTTP status or the exception type only,
  because httpx messages include the URL. Only `https://discord.com/api/webhooks/<id>/<token>`
  URLs (and the `discordapp.com`, `ptb.` and `canary.` variants) are posted to.
- **Package names are untrusted.** `allowed_mentions: {"parse": []}` disables every ping, link
  previews are suppressed, control and bidi characters are dropped, and Discord markdown,
  mention and link characters are escaped. Names are cut at 80 characters, and the message at
  1,900 (Discord's limit is 2,000).
- **Output, not input.** The post isn't part of a run's snapshot. It goes straight through httpx,
  not `HttpFetcher`, so the invariant "all network access goes through `HttpFetcher`" is about
  what analysis reads. The post never changes what a run records, and the content is derived
  from the run's own outputs. Best-effort: one retry on a rate limit (capped at 10 s), a 5xx
  or a network error. Then it is logged, and the tick goes on.
- `--no-notify` turns it off for manual runs.

## Addendum (2026-10-30): one summary a day

The owner found a post every hour too much. `collect` now posts the day before's summary on the
first tick of each UTC day (`notify.render_daily`, from a tick log in `data/state/ticks.jsonl`
and that day's reports), and a crash at most once a day, so a crash loop posts once. The
summary counts a version once when two overlapping runs reported it. `--notify-each-tick`
keeps the per-tick update for whoever wants it. The wall clock decides when to post; nothing a
run records depends on it.

## Consequences

- Run updates reach a third-party service (Discord). They hold package names and counts that
  are already public on npm, no file content or evidence.
- A post can't change a run. Determinism and replay are unaffected.
