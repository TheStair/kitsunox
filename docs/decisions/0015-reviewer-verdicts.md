# 0015: Reviewer verdicts, recorded in the viewer

**Status:** accepted 2026-10-30 (the owner asked for it). **Supersedes:** the viewer's
"never writes" property ([viewer.md](../viewer.md)).

## Context

The review queue lists every reported version for a week, whether or not someone has looked
at it. The owner wants to review a version and mark it **malicious**, **inconclusive** or
**benign**; have it leave the queue and appear on that verdict's page; and keep a running
tally of verified malicious releases. Until now the viewer was strictly read-only.

## Decision

1. **Per version, append-only.** `data/verdicts/<ecosystem>.jsonl`, one `VerdictRecord` a
   line: the last record is the verdict; `reopened` puts the version back. History is kept.
   Each record copies the entry as reviewed (score, severity, rules, publisher, publish time,
   run and rank), so it outlives the run. A new release of the same package is a new item.
2. **The queue leaves reviewed versions out** (`reporting.queue.build_queue`), and the viewer
   filters again at render time, so a verdict takes effect at once. The tally rides along in
   `queue.json`, the queue page and the daily Discord summary.
3. **The viewer gets exactly one write, `POST /verdict`,** guarded by a per-start token in
   its own forms, `Origin` / `Sec-Fetch-Site` checks, a 16 KiB urlencoded body, and run id and
   rank looked up on disk (the form never supplies package text). CSP `form-action` becomes
   `'self'`. No token, so no writes, on a non-loopback address or with `--read-only`.
4. **`kitsunox verdict` records the same from a shell**, with `--by` naming the reviewer, so an
   analyst's verdicts are told apart from the owner's (`owner`, the viewer's).

## Alternatives

- **A separate review tool or file the owner edits by hand:** no buttons in the place where
  the evidence is; easy to get a key wrong.
- **Per package verdicts:** a package cleared today can be taken over tomorrow; the next
  release must be looked at again.
- **Accounts and TLS for remote review:** not needed for one reviewer; the SSH tunnel keeps
  the loopback guard.

## Consequences

- The viewer can change what the queue shows. Anyone who can reach the loopback port and load
  a page can record a verdict; that is the machine's own user.
- Verdicts are the first labels from live data: a later step can turn them into evaluation
  samples (verified malicious against what the rules caught).
