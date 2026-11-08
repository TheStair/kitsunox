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

## Addendum 2026-11-01: the `probe` tag and what counts as malicious

The owner was unsure whether bug-bounty probes, "likely mass produced legitimate bounties",
should count as malicious, "However, I could see real malware disguising itself as a bounty
placeholder or PoC". Decided (the owner: "Yes for both"):

- **Judge by behaviour.** Malicious if anything identifying leaves the machine or code is
  fetched and run, whatever the package claims; benign if it only acts locally with no network
  ([viewer.md](../viewer.md), "What counts as malicious"). An "authorized test" notice is a
  free string, and npm and OSV classify these probes as malware too.
- **A `probe` tag on the record** (`VerdictRecord.tags`, empty on older lines), set in the
  viewer or with `kitsunox verdict --probe`, any verdict but `reopened`. Tallies count tagged
  versions apart. The tag never feeds a score: like a verdict, it is a label on what the rules
  found.
- **Alternative rejected:** a fourth verdict, "probe". It would hide whether a probe exfiltrates,
  and a disguised attack would get the mild label.

## Addendum 2026-11-08: the Baileys policy, false disclosures, beacon-only probes

Recorded here because the live confusion matrix (decision 0019) uses reviewer verdicts as its
primary truth, so the rules reviewers apply must be written down.

- **WhatsApp forks that follow channels (the owner, 2026-10-31; devlog of that day).** A Baileys
  fork that makes the user's account follow WhatsApp channels is **malicious** when the follow
  is hidden (not mentioned in the README, not an option), **inconclusive** when it is disclosed
  or on by default with a documented way to turn it off, and **benign** when it is opt-in.
- **A disclosure that doesn't exist is no disclosure (the owner, 2026-11-08).** Code comments
  that claim a README or docs mention which isn't there count as hidden: malicious
  (`@leonoremods/baileys@1.10.1`, `@dancihuy/baileys@0.0.1`, 4-day run of 2026-11-07).
- **Beacon-only probes (the owner, 2026-11-08).** An install-time request to the researcher's or
  attacker's host that carries only a marker (no hostname, username, working directory,
  environment or credentials; DNS lookups of a marker host included) is **inconclusive** with
  the `probe` tag. Reviewers had first recorded these as malicious; 11 verdicts were changed the
  same day (`teick`, `lupedsagaces`, `lane-m-snackager-*`, `lane-m2-snackager-probe`,
  `my-unique-pinger@1.0.0`, `dependencykfeg@2.1.3`, `@mobile-platform/magnetic-components`).
  Anything identifying, or code fetched and run, stays malicious (`laneh-prepare-probe`'s other
  commits steal GCP and AWS credentials). A probe that only acts locally stays benign.
- **Vendor telemetry (the owner, 2026-11-08).** Install-time telemetry sent to the package
  vendor's own service is **benign** unless it collects secrets or credentials; the verdict
  note says what is sent (`@ohos-ports/itwcw-package-analytics`, `@wonderwhy-er/desktop-commander`,
  `signetai`).
