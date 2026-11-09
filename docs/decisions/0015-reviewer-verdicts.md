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

## Addendum 2026-11-08 (later): four categories replace "inconclusive"

The owner: "inconclusive" made packages we caught but couldn't call malicious look like
packages we couldn't judge at all. Two different things were behind the one word: behaviour
we saw in full but that is not harmful enough to call malware, and behaviour we never saw.
They now have their own names. A verdict is one of:

| Verdict | Meaning | Examples |
|---|---|---|
| **malicious** | Harmful behaviour shown. | Credential or environment exfiltration, code fetched and run, a worm publishing with stolen tokens. |
| **unwanted** (new) | Behaviour seen in full; covert or intrusive, but not harmful enough to call malicious. Like an antivirus "PUA". | An install-time beacon that carries only a marker (no hostname, user, path, environment or credentials). A WhatsApp Baileys fork that auto-follows, joins or mutes channels (see below). |
| **benign** | Behaviour seen, and legitimate. | Vendor telemetry without secrets; a probe that only acts locally; an opt-in channel follow. |
| **unverified** (new) | We couldn't confirm what it does. Needs a reason tag. | See the tags. |

`reopened` keeps its meaning: the version goes back to the review queue.

**Reason tags** (`VerdictRecord.reason`; required for `unverified`, refused for every other
verdict, in the CLI with `--reason` and in the viewer as one button per tag):

| Tag | When |
|---|---|
| `gone` | The code was unpublished, or never captured (no tarball, run pruned). |
| `remote` | The payload is fetched from a git repository or URL we couldn't see. |
| `obfuscated` | We couldn't decode it. |
| `binary` | An unexplained native or binary payload. |

The `probe` tag still qualifies any verdict but `reopened` (a beacon-only probe is
`unwanted` with `probe`).

**Changes to the rulings above.** The earlier 2026-11-08 addendum is kept as written, with these
changes:

- "Beacon-only probes are **inconclusive** with the `probe` tag" now reads **unwanted** with
  the `probe` tag.
- "Disclosed or on by default with a documented way to turn it off is **inconclusive**" now
  reads **unwanted**, and is itself superseded by the next point.
- **Baileys forks (the owner, 2026-11-08, superseding the 2026-10-31 policy and the same day's
  "a disclosure that doesn't exist is no disclosure" ruling).** A Baileys/WhatsApp fork that
  auto-joins, follows or mutes WhatsApp channels is **unwanted**, hidden or disclosed alike,
  unless there is evidence that the channel follow is a way to spread malware. An opt-in
  follow stays **benign**. Anything else the package does is judged separately: if it
  downloads or runs code, exfiltrates, sends data besides the follow, or tampers with other
  packages, that decides the verdict. The older text above stays in place for the record, and
  verdicts recorded under it are reclassified by new records (the log is append-only).

**Legacy records.** The log is never rewritten. A record written as `inconclusive` still loads,
as `unverified` with no reason tag (the viewer shows "no reason (was inconclusive)", tallies
count it under `none`), until a newer record for the version reclassifies it. The commands
refuse to write `inconclusive`, and refuse `unverified` without a reason, so a reasonless
`unverified` is always a legacy one. The proposed reclassification of the current
`inconclusive` verdicts, and of `malicious` verdicts whose only harm is a channel follow, is
reviewed by the owner before it is applied; each new record's note starts "Reclassified
(owner, 2026-11-08):" followed by the old note.

**Evaluation.** The live matrices count `malicious` and `unwanted` as positives in the headline
("flag-worthy") matrix, show a strict malicious-only matrix beside it, and leave `unverified`
out of both, with best- and worst-case bounds ([0019](0019-live-evaluation.md), addendum).

## Addendum 2026-11-08 (later): AI-agent skills, hooks and settings

- **The owner, 2026-11-08:** a package built for AI-assisted development that installs its own
  skills, hooks or agent settings (`~/.claude/skills`, `~/.claude/settings.json` hooks such as
  `UserPromptSubmit`, `.agents/`, `AGENTS.md`) is **benign**: "developers are aware when
  installing ai specific packages". This matches the explained-install shape "agent-skill
  copier" approved for after the freeze (`docs/proposals/precision-round2.md`).
- Behaviour still decides: a hook or skill that sends data off the machine, fetches and runs
  code, or plants instructions that work against the user (e.g. telling the agent to hide
  activity, exfiltrate, or disable safeguards) is judged on that, as anywhere else.

## Addendum 2026-11-09: user-wide agent installs are unwanted

- **The owner, 2026-11-09**, narrowing the addendum above: install code that silently writes a
  package's skills (and, by the same reasoning, hooks, agent settings or MCP registrations)
  into **user-wide** agent locations (`~/.claude/`, `~/.agents/`, `~/.codex/`, `~/.cursor/`,
  `~/.gemini/`, ...), so that every agent session in every project loads them, is
  **unwanted**: intrusive and persistent beyond the project the user installed into. Code
  obfuscation that hides it makes it covert as well ("the obfuscation is a big part too",
  `sino-bc-cli`, 20 versions decoded offline: same program, no network at install, recorded
  unwanted).
- Still **benign**: writes into the project (`INIT_CWD`, the project's `.claude/`, `AGENTS.md`),
  and user-wide writes the user starts themselves (an `init`/`install-skills` command run by
  hand, not by an install hook).
- Still **malicious**, on behaviour: a skill or hook that sends data off the machine, fetches and
  runs code, or plants instructions against the user, wherever it is written.
- Consequence for the rules: `npm.install-explained`'s S3 shape (agent-skill copier) must not
  explain user-wide copies, since those are now positives.

## Addendum 2026-11-08 (later): the Baileys signatures are retired

The Stage 2 signatures KX-0008, KX-0009 and KX-0011 ("known malware family") were taken from
Baileys forks that follow WhatsApp channels, which this decision's addenda now rule *unwanted*.
`static.channel-follow` says exactly that (MEDIUM, "unwanted, not by itself a sign of malware")
and matched every version they matched (16 of 16 corpus and verdict tarballs, 2 of 2 of 35,544
live tarballs, 1 of 1 in `vm-day1`), so they were retired rather than relabelled (signatures v3,
`rules/signatures.py` `RETIRED`; [static.md](../stages/static.md)). No fork reported before
stops being reported; its severity drops from HIGH to MEDIUM.
