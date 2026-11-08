# Proposal: Stage 2 routing and the 16 MB cap vs. live recall

> **Status:** proposed 2026-11-08; option C (a 32 MB cap for versions with an install hook)
> implemented the same day (`MAX_HOOK_ARTIFACT_BYTES`, `fetch_limit`, decision
> [0008](../decisions/0008-stage2-routing-and-tarball-capture.md) addendum). No new routing
> rule before the 2026-11-12 freeze unless the owner picks option B (section 4).
> **Builds on:** [prospective-labeling.md §1.3](prospective-labeling.md#13-what-each-stage-decided-for-the-134)
> (the 100 live misses), decision [0008](../decisions/0008-stage2-routing-and-tarball-capture.md)
> (routing and the cap), [stages/static.md](../stages/static.md#routing-what-stage-2-reads).
> Measurements are read-only on the VM's `data/` (2026-11-08), with the rules at `5fe01c6`
> (Stage 1 precision merged; the DataDog routing simulation gives the same counts before and
> after it). Scripts: [Reproducing](#reproducing).

## Summary

Live recall against OSV `MAL-` records is 25.4% (34/134). 48 of the 100 misses are updates
Stage 2 never had files for: **35 not routed** (no Stage 1 signal, not watched, no install
hook, grew by less than 64 KiB) and **13 with no files** (12 declared over the 16 MB cap, one
fetch error). The question was whether routing more, or a larger cap, would win them back.

**It would not.** 24 of the 48 are still on the registry. Fetched as data and run through
Stages 2 and 3 with no size cap (Stage 4's `decide`, without its repository and dependency
rules), **none of the 24 is reported**; 22 have no finding at all. The other 24 can't be
fetched any more (taken down); for four of their packages, earlier versions were read live
with no finding above LOW. What the ones we can read do is outside the rules, not outside the
routing:

| Package (versions missed) | What the change does | Why no rule fires |
|---|---|---|
| `@atedone/workspace-context` (14) | appends a `source` line for `~/.workspace-context/shell-init.sh` to `~/.bashrc` / `~/.zshrc` (persistence) | no rule looks for writes to shell start-up files |
| `@ubedsockets/baileys` (4) | a hard-coded "allowed IPs" kill switch in `lib/Socket/socket.js` | IPs not in a URL; no network call added |
| `@sakataa/baileys`, `@axo_cuy/baileyss`, `@bil-rgb/baileys`, `kevinx-baileys` (5, over the cap) | WhatsApp library forks; the one inspected (`@sakataa/baileys@2.0.0`) auto-follows base64-encoded newsletter ids | abuse of the user's account, no install-time or exfiltration pattern |
| `opencode-skills-collection` (6), `calculator-preinstall-chain-demo` (3), `@ifasn/mmdd-doc-mcp` (4), `luna-baileys` (6), 6 others (1 each) | can't be fetched now | earlier versions of `calculator-…`, `@ifasn/…`, `tailwind-animate-test`, `nulio-connector` were read live: nothing above LOW |

On the DataDog `vm-day1` samples the routing gap matters only for **follow-on** releases:
all 34 unrouted malicious first-release updates (shape A) are unflagged by Stage 2 even when
read (0/34, `stage2-rules`). The cap costs more: 97 of 481 shape-A follow-ons (20%) are over
16 MB, all with an install hook, all flagged by Stage 2 when read.

**Recommendation.**

1. **Option C: read versions that declare an install hook up to 32 MB** (Stage 2's
   `fetch_limit`). It recovers none of the live misses, but on DataDog Stage 2 then reads 44
   more malicious shape-A follow-ons (+9.1 points of follow-on recall), 1 first release and 2
   B follow-ons, for ~339 more versions, 2.5–4.8 GB of tarballs and ~6 benign reports a day.
2. **No new routing rule for unrouted updates before the freeze.** Nothing that can be routed
   cheaply is caught by today's rules: 0 of 19 live misses, 0 of 34 DataDog A first releases.
   The cheapest candidate, updates ≤ 64 KiB (option B), costs little in bytes and noise and
   is an owner decision (section 4).
3. **The misses point at rules, not routing.** `@atedone/workspace-context` writes to shell
   start-up files, which no rule looks for. A rule alone would not have been enough either:
   the version that added the code (0.0.12: 6.5 KiB, +2.3 KiB) is not routed, so it needs
   option B (or "≤ 64 KiB and grew") as well.

## 1. Measurements

### 1.1 The 48 live misses

From the prospective-labeling join (`~/kitsunox-scratch/agent-labeling/rows.pkl`), joined to
each run's `triage.jsonl`. Every one is an unwatched package with no Stage 1 finding at
MEDIUM or above.

| | Versions | Packages | Detail |
|---|---|---|---|
| Not routed | 35 | 11 | 25 are follow-ons of a package already missed in the same window (`@atedone` 14, `opencode-skills-collection` 5, `@ubedsockets` 4); 23 are ≤ 64 KiB; size change −58 KiB … +7 KiB, except `nulio-connector` +20 KiB |
| Over the cap | 12 | 6 | 11 forks of `baileys` (17.6–21.8 MB, 10 with an install hook), `opencode-skills-collection` (97 MB) |
| Fetch error | 1 | 1 | `@pcb-dp/qa-commons@1.0.10` (its 1.0.0 was reported HIGH) |

Replayed (fetched now from the registry, in memory, Stages 2–3 with no size cap, Stage 1
findings as recorded, Stage 4 `score`/`decide`):

| | Versions | Files | Any finding | Reported |
|---|---|---|---|---|
| Not routed | 27 | 19 | 1 (`npm.dependency.added` LOW) | **0** |
| Over the cap | 6 | 5 | 1 (`code.capability-gained` LOW) | **0** |
| Not fetchable now (taken down) | 9 fetched + 15 known gone | — | — | — |

Their siblings tell the same story: `calculator-preinstall-chain-demo@1.0.0`,
`tailwind-animate-test@1.0.1`, `nulio-connector@1.1.10` and four `@ifasn/mmdd-doc-mcp`
versions were read live with no finding above LOW.

### 1.2 What separates them from benign unrouted updates

On 2026-11-02 (24 hourly runs, 118,228 versions; Stage 2 read 39,371 and recorded 17.7 GB of
tarballs; 341 reported), 82,051 updates were not routed. Candidate routing rules, over those
updates (declared ≤ 16 MB), against the 35 live misses and the 420 DataDog updates that are
unrouted today:

| Extra route | Versions/day | Est. tarball GB/day (+ base) | Live (35) / packages | DataDog A first (34) | A follow-on (30) | B follow-on (356) |
|---|---|---|---|---|---|---|
| declared size ≤ 16 KiB | 5,313 | 0.02 (0.04) | 8 / 3 | 1 (0 flagged) | 1 (0) | 152 (39) |
| **≤ 64 KiB** | **18,700** | **0.16 (0.33)** | **20 / 4** | 19 (0) | 5 (0) | 215 (**64**) |
| ≤ 256 KiB | 37,632 | 0.82 (1.65) | 23 / 5 | 24 (0) | 5 (0) | 253 (79) |
| ≤ 1 MiB | 55,447 | 3.1 (6.1) | 24 / 6 | 27 (0) | 5 (0) | 302 (103) |
| grew at all | 32,754 | 13.8 (27.5) | 24 / 9 | 24 (0) | 7 (1) | 145 (61) |
| grew ≥ 4 KiB | 12,636 | 6.7 (13.4) | 8 / 5 | 12 (0) | 4 (0) | 39 (17) |
| file count changed | 8,262 | 3.0 (5.9) | 8 / 3 | 7 (0) | 1 (0) | 50 (13) |
| published < 1 h after the previous | 19,350 | 5.4 (10.8) | 16 / 5 | 1 (0) | 28 (**20**) | 237 (76) |
| ≤ 64 KiB and grew | 4,703 | 0.04 (0.09) | 16 / 3 | 16 (0) | 4 (0) | 72 (34) |
| any Stage 1 finding (LOW) | 3,071 | 0.6 (1.3) | 1 / 1 | 15 (0) | 1 (0) | 18 (8) |
| publisher changed | 1,827 | 0.4 (0.7) | 0 | 30 (0) | 0 | 1 (0) |

"(n)" in the DataDog columns: of those routed, how many `stage2-rules` flags. Bytes are
estimated from declared size with the compressed/unpacked ratio of the tarballs Stage 2
recorded that day (by size bucket); "+ base" adds the previous version's tarball, an upper
bound (often already captured). The publisher-change, popularity and provenance features
don't separate: all 48 misses are unwatched, none changed publisher, and 9 had provenance.

**Benign cost of the cheapest rule, measured.** A deterministic 1/40 sample of 11-02's
unrouted updates ≤ 64 KiB (451 versions, by SHA-256 of `name@version`), fetched and run through
Stages 2–3: **0 reported, 0 flagged by Stage 2** (one had no tarball). The live versions Stage 2
read anyway (batched with a routed sibling) agree: 1 of 6,182 such versions ≤ 64 KiB reported
in the 4-day run `20261107T163310Z`.

### 1.3 DataDog (`vm-day1`) with today's routing

Stage 1 at `5fe01c6` on every update sample, joined to the per-sample `stage2-rules` result
(Stage 2 reading everything, 2026-10-30 rules):

| | Stage 1 flags | Routed | Not routed (Stage 2 would flag) | Over 16 MB (Stage 2 would flag) |
|---|---|---|---|---|
| A, first release (965) | 773 | 148 | 34 (**0**) | 10 (3) |
| A, follow-on (481) | 13 | 341 | 30 (20) | **97 (97)**, all install hook |
| B, follow-on (1,093) | 236 | 433 | 356 (117) | 68 (17) |

### 1.4 The cap

On 2026-11-02, 11,318 versions (9.6%) declared more than 16 MB. Of the routed ones:

| Declared | Routed versions/day | Est. new GB/day | Of them with an install hook |
|---|---|---|---|
| 16–24 MB | 1,283 | 8.0 | 229 (1.6 GB) |
| 24–32 MB | 695 | 6.0 | 110 (1.0 GB) |
| 32–64 MB | 1,388 | 19.5 | 263 |
| > 64 MB | 2,283 | 121 | — |

A cap of 32 MB for everyone would add ~2,000 versions and ~14 GB a day (+80% of today's
17.7 GB) for 44 more DataDog A follow-ons. A 32 MB cap **for versions that declare an install
hook** adds 339 versions/day (173 routed for the hook, 160 watched, 6 flagged), 2.5 GB/day of
new tarballs, at most 4.8 GB with bases (+14 to 27%). It gains 44 of the 97 over-cap A
follow-ons, 1 A first release, 2 B follow-ons, and of the live misses 10 versions
(`luna-baileys` 6, `@sakataa` 2, `@axo_cuy`, `@bil-rgb`), none of which is reported when
read (1.1). **Benign cost, measured:** every third of 11-02's hooked 16–32 MB versions that Stage 1
didn't flag (111 of 333), fetched and run through Stages 2–3: Stage 2 flags none, and 2 are
reported, both `npm.install-script-changed` (Stage 3) on `@sandbox-agent/*` platform
packages: 1.8% [Wilson 95% 0.5–6.3%], so about 6 more benign reports a day (+1.8% of 341).

**Reading part of an oversized tarball.** `extract_tar_gz` holds the whole decompressed tar
(`_gunzip_limited`, up to 512 MB) before it reads members, so a partial read would need a
streaming reader (`tarfile` `r|gz`) to bound memory. The download is the cost that matters,
though: a gzip stream can't be entered in the middle, so the whole tarball is fetched and, for
replays, recorded in the blob store. A partial read saves memory and Stage 2/3 time, not disk.
Memory is not the constraint at 32 MB: a version needs about 2× its declared size while Stage 2
holds it, 64 MB × 8 workers.

## 2. Options

| Option | Live misses recovered | DataDog | Cost | Benign reports |
|---|---|---|---|---|
| A. Keep routing and cap as they are | — | — | — | — |
| B. Route updates ≤ 64 KiB | 0 of 19 replayable (20 routed) | +64 B follow-on; 0 A | +18.7k versions/day (+47% read), +0.3 GB/day, ~+37k small requests | 0 of 451 sampled |
| C. 32 MB cap for install-hook versions | 0 of 5 replayable (10 routed) | +44 A follow-on, +1 A first, +2 B follow-on | +339 versions/day, +2.5–4.8 GB/day | 2 of 111 sampled (1.8%): ~6/day |
| D. B + C | 0 | sum | sum | sum |
| E. 32 MB cap for all | 0 | +44 A follow-on, +1 A first | +2,000 versions/day, +14–27 GB/day | not measured |
| F. Partial read of oversized tarballs | 0 | ≤ 97 A follow-on | full download anyway; a streaming extractor | not measured |

C is the only option with measured recall for its cost, and its cost is small next to the
disk (+5 to 10 GB at 2-day retention, 93 GB free). B is nearly free in bytes and noise, but
adds 47% to the versions Stage 2 and 3 process and 37k registry requests a day for a gain
measured only on DataDog follow-ons; it becomes worth it with a rule that fires on what it
routes. E and F buy the same follow-ons as C at several times its cost.

## 3. Rejected, with numbers

- **Growth below 64 KiB** (grew at all / ≥ 1 / ≥ 4 KiB): 12.6k–32.8k versions and up to
  27.5 GB a day, 0 of 34 DataDog A first releases flagged.
- **Fast re-publish (< 1 h)**: catches the worm's follow-ons (20 of 30 unrouted A
  follow-ons) but costs 19.4k versions and up to 10.8 GB a day, and Stage 2 flags 0 of the 1
  A first release it routes.
- **Publisher changed**: 30 of the 34 unrouted DataDog A first releases changed publisher,
  but Stage 2 flags none of them; no live miss changed publisher.
- **Any LOW Stage 1 finding**: 3,071 versions/day, 1 live miss.
- **A cap of 32 MB or more for everyone** (E): +80% of Stage 2's bytes for the same 44
  follow-ons option C gets; at 64 MB, +55 GB/day. The disk can't hold it at 2-day retention.
- **Partial reads** (F): saves memory, not the download, which is the cost.

## 4. Questions for the owner

1. **Keep option C?** It is implemented (the next commit). Undoing it is one constant
   (`MAX_HOOK_ARTIFACT_BYTES = MAX_ARTIFACT_BYTES`).
2. **Option B, route updates ≤ 64 KiB** (or ≤ 64 KiB *and* grew: 4,703 versions/day, 16 of
   the 35 live versions)? It's a two-line change in Stage 1's `code_route`; worth it only
   with a rule that fires on what it routes. Before the freeze or after?
3. **A rule for writes to shell start-up files** (`.bashrc`, `.zshrc`, `.profile`; persistence)
   as a separate Stage 2 task before the freeze? Stage 5's sandbox rules already list these
   paths (`rules/sandbox.py`).
4. **WhatsApp-library forks** that auto-follow channels (11 of the 48) are account abuse, not
   install-time compromise. In scope for the capstone's recall, or excluded like PoCs?

## Reproducing

Scripts in `~/kitsunox-scratch/agent-routing/scripts/` (read-only on `data/`; the replays
fetch tarballs from the registry into `~/kitsunox-scratch/agent-routing/fetch/`):
`miss.py` (the 48 from the labeling join), `feat.py` (their `Change` features), `bench.py` +
`s2.py` (per-version features, Stage 2 status, report status and recorded tarball sizes for a
run; run over the 24 runs of 2026-11-02 and `20261107T163310Z`), `cand.py` (the routing
table), `fp.py` (benign rates from batched reads), `dd.py` (DataDog routing), `cap.py` /
`cap2.py` / `cap3.py` (the cap), `replay.py` (the live misses), `sample.py` + `replay2.py`
(benign samples), `peek.py` (what changed in a missed version).
