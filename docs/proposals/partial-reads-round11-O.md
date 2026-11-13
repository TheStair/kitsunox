# Round 11, agent O: partial reads of large hooked versions

Base: main `d08077a`. Built in this branch ([decision 0021](../decisions/0021-partial-reads-of-large-hook-packages.md),
[stages/static.md](../stages/static.md#partial-reads-of-large-hooked-versions-decision-0021)):
`f5f8546` (the partial read), `c2b4fea` (files the hooks name kept first), `6c9337e` (Stage 4
does not compare partial reads with their repository). Scripts and outputs:
`~/kitsunox-scratch/r11/O/` (`scripts/`, `out/`). Every fetch went through a scratch fetcher
there (re-packs only, tarballs streamed), nothing was written under `data/`, nothing fetched
was run. Measured 2026-11-13 on a shared VM (load average 9 to 20 from other agents' jobs), so
times are upper bounds.

## Why

`ArtifactFiles` skipped every version whose declared unpacked size was over `fetch_limit`
(16 MB, 32 MB with an install hook). On the two days of runs on disk (2026-11-11 01:10Z to
11-13 00:34Z, 47 runs) that left **1,411 hook-bearing versions over 32 MB unread** (311
packages, 183 GB declared: 702 at 32-64 MB, 270 at 64-128 MB, 436 at 128-512 MB, 3 at 659 MB).
`@dcl-regenesislabs/bevy-explorer-web` alone was 248 of them.

## What was built (summary; details in decision 0021)

- `read_mode(snapshot)`: whole up to the cap; **partial** for a hooked version up to 1 GiB
  declared; else not read. The same for a version, its base and its previous release.
- One streamed `GET` per version (`HttpFetcher.get_derived`), decompressed and walked as it
  arrives (`util.archive.stream_tar_gz`) with `extract_tar_gz`'s guards, the SRI digest checked
  over the whole stream (`IntegrityCheck`). Text and code kept (16 MB a file, 64 MB in all,
  ranked: manifest, `binding.gyp`, the files the hooks name and disguise candidates first;
  then own code; then `node_modules/` code and JSON; then the rest). Binaries (NUL in the first
  8 KiB, source extensions excepted): path, size, SHA-256, mode, first 512 bytes.
- Stored as a deterministic tar.gz re-pack + manifest (`util/partial.py`) under
  `GET <url> partial=1`, content type `application/vnd.kitsunox.partial+gzip`; the tarball is
  never stored. `static.partial-read` (INFO) and a decision note say what wasn't read.
- Stage 4 does not compare a partial read with its repository (see owner question 3).

Tests: 3,629 pass (new: `tests/util/test_archive_partial.py`, `test_partial.py`, differential
fuzz in `test_archive_fuzz.py` (60,000 explore examples, the streaming reader agrees with
`extract_tar_gz` on files, modes, skipped entries, duplicates and anomalies or both refuse),
`get_derived` in `test_http.py`, Stage 2 record + offline re-score of a synthesized 33.6 MB
hooked tarball in `test_static.py`, npm, rules, review, evaluation).

## The replay contract on real data

`scripts/stage2_replay_check.py`: `record_static` on the 6 batches of run
`20261111T051353Z-npm` with a partial read (13 re-packs, 128 MB), in a scratch data directory;
then the immutable index deleted and Stage 2 re-run offline (a transport that fails any
request) with the run's `static-snapshot.json` as the seed: **`static.jsonl` byte-identical**
(record 119 s, re-score 11 s). 7 of 7 decisions carry the partial-read note.

## The sample misses and `misses.txt`

Replayed with round 10 G's harness adapted (`scripts/make_replay.py` -> `o_replay.py`: each
SRC's own read rule for every tree, a partial read streamed through the scratch fetcher, git
dependency findings carried from the record), main vs branch:

| Version | Declared | Main | Branch |
|---|---|---|---|
| `@plannotator/opencode@0.28.45` (unwanted) | 63.9 MB | not read, score 0 | **reported**, score 6: `agent.hostile-instructions` MEDIUM (`skills/plannotator/SKILL.md`); 2 files over 16 MB not read |
| `@cgh567/agent@2.6.60` (unwanted) | 44.7 MB | not read, score 0 | read (3 binaries not read), score 3: only LOW generic matches; the Homebrew-bottle download is not matched by `npm.install-download` (a rules gap) |
| `local-operator-ui@0.52.8` (unwanted) | 38.9 MB | not read, score 0 | read (66 binaries not read), score 3: LOW only (a rules gap) |
| `lumen-lib@2.1.8` | 6.5 MB, no hook | not a size case: unrouted by Stage 1 in `20261110T014424Z`, read and clear in `20261110T024424Z` | unchanged |

Of the 82 entries in `misses.txt` marked "not read by Stage 2" or "Stage 2 had no files":
68 are Stage 1 routing (never forwarded; untouched here), 3 are the hooked versions above, 5
are hooked versions of 16-17 MB that main already reads (the 32 MB hook cap, 2026-11-08), and
6 are hookless versions of 18-101 MB (out of scope; 5 are 404 on the registry now, only
`kevinx-baileys@1.2.1` is still fetchable). **+1 of 3 affected misses reported.**

## Live: one day of runs (2026-11-11, 24 runs)

839 versions have a partially read release or base; **832 become readable** (they were
"files unavailable"). Re-decided with Stages 1-4 (`o_replay.py`, main vs branch):

| before -> after | benign | unwanted | unverdicted |
|---|---|---|---|
| reported -> reported | 6 | 2 | 0 |
| not -> not | 4 | 0 | 742 |
| **newly reported** | 0 | 0 | **81** (29 packages) |
| **lost** | 3 | **1** | 0 |

- Newly reported, by rule: `npm.install-download` 75 (install-time platform downloads:
  `instar` x23, `@datalayer/agent-runtimes` x15, `9router-xd` x9, `snyk`, `foundry-local-sdk`,
  `browser4-cli`, ...), `npm.install-persistence` 5 (`dingtalk-workspace-cli`, `tmux-ide`,
  `@leviyuan/lodestar`, `@strvmarv/total-recall`), `static.disguised-file` 1
  (`@rokob/nodedc`'s brotli `dictionary.bin`, likely benign), `npm.install-script-changed` 1,
  and `eroforze@2026.9.6` (`npm.install-script-code`, `static.shell-startup`: its base
  2026.9.2 has data after the gzip stream and is refused, so every file counts as new). None is verdicted yet; under the owner's ruling
  (third-party download at install = unwanted) part of the 75 may be positives, the rest is
  the benign cost: **at most ~81 reports a day, mostly `npm.install-download`**.
- Lost: 3 benign `@lark-codem/codem-core-linux-x64-gnu` and **1 unwanted,
  `doc-detective@5.0.0-v5-rc.16`**. In main it was read whole (32.1 MB) against an unread base
  (rc.15, 98.7 MB), so its unchanged `postinstall` counted as new (`npm.install-script-code`
  MEDIUM). With the base read partially the script is unchanged and LOW. Main itself did not
  report rc.17 or rc.18 (same script, base read): the report was an artifact of the cap, and
  the series' behaviour predates the window. This misses the bar of 0 unwanted lost; see owner
  question 2.
- Stage 4 would have compared 273 of these versions with their repository (266 watched
  updates, 102 of `bevy-explorer-web` at a new commit each): not done (owner question 3).

### Bandwidth, time, disk (the same day)

| | |
|---|---|
| Artifacts streamed (versions and bases) | 994: 985 read, 8 HTTP 404 (`@aiti-ai/pi-web` 0.15.7-0.15.14, deleted), 1 refused (`eroforze`: trailing data after the gzip stream, as `extract_tar_gz` refuses it) |
| Declared / downloaded / kept | 101.9 GB / **28.7 GB** / 36.5 GB of text |
| Not read | 60,655 binaries (51.0 GB), 134 text files over 16 MB (5.2 GB), 1.06 M text files past the budget (9.2 GB, in 121 versions); 483 versions had nothing left out |
| **Re-packs stored** | **5.88 GB a day** (20.5% of the download; largest 20 MB): ~12 GB at the VM's 2-day retention, plus reported versions held 30 days |
| Time | 19,699 worker-seconds (4 workers, shared and overloaded VM; ~690 s per GB): about 41 min a day for Stage 2's 8 workers, ~1.7 min a tick; the real-data check read 13 in 119 s |
| Largest packages | `bevy-explorer-web` x82: 5.6 GB down, 0.08 GB stored; `@paperclipai/server` x17: 1.9 / 0.28 GB; `instar` x20: 0.7 / 0.35 GB |

What the re-packs hold (232 measured): own code 58%, `node_modules/` code and JSON 14%,
the rest 29% (source maps alone 19%).

## Replay set (3,716 verdicted live versions)

108 have a partially read release or base (88 the release, 42 the base; 104 benign, 2
unwanted, 2 unverified, 0 malicious); the other 3,608 are unaffected by construction (their
`read_mode` is main's routing, and every changed rule branch needs a tree with omitted files).
Those 108, main vs branch:

| before -> after | benign | unverified | unwanted |
|---|---|---|---|
| reported -> reported | 69 | 1 | 2 |
| not -> not | 6 | 0 | 0 |
| newly reported | 6 (`signetai` x6, `npm.install-download`) | 0 | 0 |
| lost | 23 | 1 (`@yalehwang/cloudpit@2.0.0`) | 0 |

**0 malicious or unwanted lost.** The 23 benign leave the queue because the files are now
read: once the install code is read, their `npm.install-hook` MEDIUM is explained or lowered
by the install rules (score 5 -> 3 or 1:
`@testmuai/kane-cli-node-*` x4, `tree-sitter-*`, `openmarketing`, `teamfactory`, ...) or their
base is now read, so unchanged install code is no longer "new" (`@lark-codem/*` x3,
`@superblocksteam/cli` x2, `vibelet`/`@vibelet/cli`, `@ia-ccun/idea-plugin-share` x2, ...).
Harness check: on these 108, main through `o_replay.py` agrees with round 10 G's full replay
on 97; the 11 others are versions whose base is over the cap, which G's harness fetched whole
from the registry and the live pipeline never reads (this harness follows the pipeline).

## `vm-day1` (`pipeline+4`)

92 of 4,944 samples are affected (88 malicious: 87 the release, 1 only the base; 4 benign),
run with `scripts/vm_eval.py` (the evaluation's own predictor; a scratch data directory
overlaid on `data/`'s caches, so nothing is written there):

| | main | branch |
|---|---|---|
| Malicious reported (of 88) | 19 | **85** (+66, 0 lost) |
| Benign reported (of 4) | 0 | 1 (`instar@1.3.1505`, `npm.install-download`) |

What the 66 add: `npm.install-script-code` 65, `static.exfil-endpoint` HIGH 43,
`static.obfuscated` 11, `npm.install-download` 11. Still missed: `@bottino/baileys` 1.0.12 and
1.0.14, `@pixelzx/genesis@2026.6.19` (read, score 3). 77 of the 92 had no base tarball in the
evaluation (all files new), as for most DataDog samples. The other 4,852 samples are
unaffected by construction.

## Limits

- A binary payload, text over 16 MB, or text past 64 MB of more important text is not read.
- Hookless versions over 16 MB and anything over 1 GiB declared are still unread.
- The live numbers carry each version's recorded Stage 4 context; the repository comparison
  and the follow-on pass were not re-run (the comparison is off for partial reads anyway).
- The replay set and `vm-day1` were re-run on the affected versions only.

## Owner questions

1. **Disk.** Re-packs add ~5.9 GB a day (~12 GB at 2-day retention) on a VM with ~30-37 GB
   free. Accept, or keep less: a 32 MB budget, or no rank-3 text (documentation, types, source
   maps, tests, data: 29% of kept bytes; source maps 19%). Default kept: 64 MB, everything.
2. **`doc-detective@5.0.0-v5-rc.16`.** Option A (this branch): a partially read base is used
   as the base. Option B: a partial base is not used for a version read whole (main's
   behaviour for every version main already read). Measured: B keeps that unwanted report and
   the 3 benign `@lark-codem` ones a day, and 11 more benign in the replay set (23 -> 12
   benign leave). B is not built; A is the default. B needs Stage 2 and Stage 3 to know which
   kind of read a base is.
3. **Repository comparison of partial reads** (off): ~273 more comparisons a day, each a
   GitHub archive (sizes not measured).
4. **Hookless versions over 16 MB**: 6 OSV-labelled misses (only `kevinx-baileys@1.2.1`
   still fetchable). Extending partial reads to them is the same code with `has_hook` dropped,
   at a much larger volume (about 11,700 hookless versions skipped for size in the two days).
5. **CLAUDE.md**: the invariant "tarballs are only ever extracted with `extract_tar_gz`" now
   has a sibling, `stream_tar_gz` in the same module with the same guards (and re-packs are
   read back with `extract_tar_gz`). The owner edits CLAUDE.md.
6. The 1 GiB ceiling (all 1,411 seen fit; 3 at 659 MB).
