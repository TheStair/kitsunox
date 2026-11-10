# Proposal: round 4, agent F (recall): code hidden behind whitespace

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Agent F's job this round was recall, not precision: catch a shape the pipeline
> missed while adding as little benign noise as possible.
> **Commits:** Stage 2 `static.padded-code` v1 (new rule); Stage 3 report evidence only
> (`npm.install-script-changed`'s diff shows hidden code). Both add findings or text only.
> **Builds on:** [round 3](precision-round3.md) (method, harness), decision
> [0015](../decisions/0015-reviewer-verdicts.md) (what counts as a positive), and the
> investigator's diagnosis of `hauntview@0.2.9` (2026-11-09).

## Summary

| # | Change (stage) | Live: benign newly reported | Live: positives / unverified lost | Recall gained | Kind |
|---|---|---|---|---|---|
| P1 | `static.padded-code` v1, new (2) | **0** of 3,716 (and 0 MEDIUM in a day of 49,733 unreviewed versions but `hauntview@0.2.9`) | 0 / 0 | live: `hauntview@0.2.9` +1 MEDIUM (now also caught where no install rule looks); `vm-day1`: **+17 malicious samples reported** (2,708 → 2,725 of 3,444), 0 lost | zero-loss |
| P2 | `npm.install-script-changed` evidence (3) | 0 (report text only) | 0 / 0 | the hidden line is readable in the report | zero-loss |

Measured with the real code: live replay of all 3,716 verdicted versions, `main` `4cd4e8a` vs.
this branch (1,674 → 1,674 reported, identical decisions), the 27 versions verdicted since, a
day of every Stage 2 read, and `pipeline+4` on every `vm-day1` sample the rule can change;
re-checked on `main` `829dd41` (with agent A's `npm.install-script-code` v3) on the touched
versions. Rejected (section 7): an install-file HIGH variant (A's v3 covers it), the Stage 3
computed-constructor-plus-handoff idea and a cleartext blockchain-C2 rule (both: no recall on
`vm-day1`, benign hits live).

## 1. The case

`hauntview@0.2.9` (run `20261109T224423Z-npm`, rank 5, malicious) added one line to
`scripts/postinstall.mjs` (line 14) and the identical line to `dist/cli.js` (line 20): 266 tabs,
then 12,433 characters of an obfuscated loader. Decoded as data it reads the latest transaction
of an Ethereum sender through blockscout for its C2 address, fetches an XOR-encoded second
stage from `http://<ip>:443/0x/cls`, runs it with `eval` and starts a detached `node -i`.

What saw it before this round:

- **Stage 2: nothing.** No literal `eval`/`Function` (`Function` is reached as
  `d[p.substring(0,11)]`), no `_0x` names (a seeded index-swap string shuffle), and the
  10,358-character literal is shuffled code full of punctuation, so `encoded-blob` never
  matches. Every URL, IP and module name is inside the shuffled strings.
- **Stage 3: no new capability.** `postinstall.mjs` had `process` before and after.
- **Reported only by `npm.install-script-changed` at MEDIUM**, whose diff evidence cut the
  added line to 200 characters, all tabs: the page showed a blank added line and "+3 -1 lines"
  for 12.8 KB of new code.

That catch is fragile: had the loader been only in `dist/cli.js` (it runs on `npx hauntview`),
or in a file the hook loads (counted only when its change adds a risky use, and this one adds
none a parser sees), nothing would have fired. Agent A's `npm.install-script-code` v3 now
flags the same shape in install code; this proposal covers every other file, and the evidence.

## 2. Data and method

- **Shape frequency first** (`padscan.py`): every file content Stage 2 reads (`new_contents`
  against the diff base, the same size and binary limits) in the 3,716 verdicted live versions
  of the shared round-4 candidates plus the 27 verdicted since (`hauntview@0.2.9` among them),
  and in the `vm-day1` samples that matter (the 1,500 benign and the 736 malicious ones
  round4-base leaves unreported): every run of 40 or more spaces or tabs followed by 50 or
  more characters on the same line, with its length, the tail's length and start, and the text
  before it. The diagnosis proposed 100/200; the table (section 3) is what confirmed it.
- **The real rule over one day of everything Stage 2 read** (`livescan.py`): the 24 hourly
  runs from `20261108T233023Z` to `20261109T224423Z`, 49,733 versions Stage 2 read (reviewed
  or not, 39,255 batches), each new file content through Stage 2's own `new_contents` and
  `content_matches` (so the "not new" and documentation demotions apply), tarballs from the
  runs' captured blobs read in memory. This is the unreviewed noise a day of collection would
  see; a MEDIUM outside `WEAK_ALONE` reports a version on its own.
- **Live replay with the real code** (round 3's `replay.py`, unchanged): Stages 1-4 per
  verdicted version, baseline = `main` at `4cd4e8a` (round4-base plus agents C and D), fix =
  this branch on top of it. Same harness on both sides.
- **`vm-day1`**: `pipeline+4` (`dd.py`, round 3's) with `main` and with this branch on every
  malicious sample the shape scan says the rule could change (an added MEDIUM can only add
  reports, so only the 736 samples round4-base leaves unreported, from round 3's
  `ddbase`/`ddfix`, are scanned), plus the scan of the 1,500 benign samples.
  The round-3 scratch data directory had lost its `runs` link, so `mkdata_f.py` builds
  `~/kitsunox-scratch/r4/F/data` from the same hard-linked inputs, a fresh cache and the live
  `runs/` directory by a read-only symlink (vm-day1's changes come from its run).

## 3. `static.padded-code` (Stage 2)

**The shape in the data.** Versions with at least one line holding a run of at least R spaces
or tabs followed by at least T characters, in the 3,743 verdicted live versions (files read:
2,684 benign, 41 malicious, 258 unwanted, 31 unverified; the rest were not routed to Stage 2
or their tarball is gone). "Code" = an executable file (not
`NON_EXECUTING`: docs, Markdown, source maps, tests), a tail that is not a comment, table
cell or markup, and no open quote before the run:

| R ≥ | T ≥ | Any file: benign / malicious / unwanted | Executable, code: benign / malicious / unwanted |
|---|---|---|---|
| 40 | 50 | 373 / 4 / 64 | 250 / 4 / 57 |
| 60 | 100 | 51 / 4 / 6 | 7 / 4 / 1 |
| 80 | 100 | 20 / 4 / 3 | **0** / 4 / 0 |
| **100** | **200** | 8 / 4 / 2 | **0** / 4 / 0 |
| 200 | 200 | 0 / 4 / 1 | 0 / 4 / 0 |

- Benign executable code never has a run over 88 characters (`cortico-world-douyin-live`'s
  vendored obfuscated SDK, 88 spaces then 53 characters), and nothing at 60+ is followed by
  more than 100 characters except JSX alignment (`@helmcms/checkout`, `@mohasinac/appkit`,
  68 spaces). Python and C++ indentation tops out at 48-78.
- Every benign or unwanted hit at 100/200 is a Markdown table (`|` after the run) or a source
  map: `huaweicloud-devkit`'s skill tables (up to 527 spaces), `@sendtry/computer-mcp`'s
  docs, `@dragonshorn-studios/elyseum-cli`'s `index.js.map`. Stage 2 makes those LOW anyway.
- The malicious hits: `hauntview@0.2.9` (266 tabs, 12,433 characters, twice) and one family
  of three (`persona-ai-sdk`, `ai-persona-sdk`, `archetype-index-sdk` 1.0.0), whose payload
  files start line 2 with 2,000 spaces before a `_0x` string array (also `static.obfuscated`).
  15 malicious live versions have no files left to read.

So the rule uses 100 and 200, MEDIUM (weight 3, the weight every precise Stage 2 MEDIUM has),
one finding per file, with three exclusions that are cheap insurance rather than load-bearing
on this data: a tail that opens a comment, table cell or markup (`//`, `/*`, `*`, `#`, `|`,
`<`, `<!--`), an odd count of one quote kind before the run on its line (padding inside a
string literal), and a tail with no code punctuation in its first 1,000 characters (a `(` or
`=`, and a `;`, `{`, `)`, `[` or `,`).

**One exclusion the one-day run forced.** `@motir/cli@0.17.2`'s `dist/index.js` holds
compiled JSON-schema validators nested 106 spaces deep (`validate25.errors = [...]`), a
level at a time. A run that is the line's indentation now counts only when it is at least
100 deeper than the nearest non-blank line before it (20 lines back at most): hidden code jumps
there from the margin (`hauntview`: the line before is `import { createRequire } from
'module';`), generated nesting doesn't. The first version of the punctuation test asked for
`;`, `{` or `)` and missed the persona family (a string array: `=`, `[`, `,` only), found by
the targeted replay; `[` and `,` were added and the one-day run repeated with the final rule.

**Cost.** One finding per file; runs are matched where they start (a lookbehind), line bounds
are shared by the runs of one line, and only 1,000 characters each side are read, so a 2.4 MB
line of 20,000 runs takes milliseconds (`test_many_runs_on_one_long_line_stay_linear`; the first
draft sliced the rest of the line per run and took 12 s on it).

**Snippet.** The run is shown as a counted marker before the tail:
`⟨266 tabs⟩var z = '-c';var NX,SX,spin,splitLane,peel;(function(){var a=["","*",...`.

**Install files** are agent A's: `npm.install-script-code` v3 (Stage 3) flags the same
100-character run in install code, so this round adds no install-specific variant (an
`npm.install-script-padded-code` HIGH was drafted and dropped to avoid two findings for one
line). `static.padded-code` is what sees the line in `dist/cli.js`, an entry point, or a file
loaded at `require`, and it is not one of the install rules `npm.install-explained` lowers.

## 4. Report evidence (Stage 3, `install_code.py`)

- `_diff_evidence`: every run of 40 or more spaces or tabs in a diff line is replaced by a
  counted marker (`util.text.collapse_runs`: `⟨266 tabs⟩`, `⟨120 spaces⟩`) **before** the
  200-character cut, so the code a run pushes off screen is what the reviewer reads:
  `+⟨266 tabs⟩var z = '-c';var NX,SX,spin,splitLane,peel;(function(){var a=["","*",...`.
  Ordinary indentation (under 40) is unchanged.
- The summary names the longest added line when it is longer than the cut:
  `scripts/postinstall.mjs (+3 -1 lines, longest added line 12,699 characters)`.
- Report text only: no severity, weight or decision changes (the replay's decisions are
  identical with and without it; section 5).

## 5. Live result (real code)

All 3,716 versions of the shared candidates, `replay.py`, base = `main` `4cd4e8a`, fix = this
branch (0 errors on either side):

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| base (`main`) | 1,674 | 1,373 | 224 | 47 | 30 | 16.48% |
| fix | 1,674 | 1,373 | 224 | 47 | 30 | 16.48% |

- **Benign newly reported: 0.** `static.padded-code` fires, at any severity, on 3 of the 3,716
  versions, all malicious and already reported: `persona-ai-sdk`, `ai-persona-sdk` (score
  12 → 15) and `archetype-index-sdk` 1.0.0 (8 → 11). No other finding of any version
  changes (checked per version, rule, severity, weight and path).
- **The 27 verdicted since** (`extra.jsonl.zst`, from runs `20261107T163310Z` to
  `20261109T224423Z`): same decisions (20 reported, 15 benign). `hauntview@0.2.9` goes from
  "score 6; medium: npm.install-script-changed" to "score 9; medium:
  npm.install-script-changed, static.padded-code", with `static.padded-code` MEDIUM in both
  `scripts/postinstall.mjs` and `dist/cli.js`. Its other nine versions (0.0.0-stage to 0.1.9,
  benign, no loader) get no finding.
- **What it buys.** A MEDIUM outside `WEAK_ALONE` reports on its own, and Stage 2 findings are
  never cleared by the repository switches or lowered by `npm.install-explained`. So the
  loader is now reported if it sits only in `dist/cli.js` (fragile point 3 of the diagnosis),
  in a file the hook loads without a visible risky use (point 2), or in a package whose install
  code has an explained shape. With agent A's `npm.install-script-code` v3 it is three
  MEDIUMs.
- **Unreviewed live traffic, one day** (24 runs, 49,733 versions Stage 2 read): MEDIUM on
  `hauntview@0.2.9` only; LOW, as documentation, on a source map of `@forgeroute/ui@0.4.82`
  and `tsdmarc@1.0.0` and on `kiss-ssg@2.14.0`'s `GUIDE.md` table. Expected noise: well under
  one report a day. (Before the indentation guard, `@motir/cli@0.17.2`'s schema validators
  matched; LOW there as "not new", but a first release of such a bundle would have been
  MEDIUM.)
- **Evidence text**: 102 of the replay's `npm.install-script-changed` findings now name their
  longest added line (minified or generated install code); report text only.

## 6. DataDog check (`vm-day1`)

- **Which samples can gain.** A new MEDIUM can only add reports, so only the 736 malicious
  samples round4-base leaves unreported (round 3's `ddbase`/`ddfix`) can change. The shape
  scan over them (436 with files to read; 300 have none or aren't routed): 17 have a line with
  100+ spaces or tabs then 200+ characters (24 at 40/50; the 7 between are all below 60/100).
- **`pipeline+4` on those 17, base (`main`) and fix:** base reports **0**, fix reports **all
  17**, each through `static.padded-code` alone (score 3-6):
  - 15 of the `@gluestack-ui` / `@react-native-aria` compromise: `@gluestack-ui/utils` 0.1.16
    and 0.1.17, `@react-native-aria/button` 0.2.11, `checkbox` 0.2.11, `combobox` 0.2.8,
    `disclosure` 0.2.9, `focus` 0.2.10, `interactions` 0.2.17, `listbox` 0.2.10, `radio`
    0.2.14, `separator` 0.2.7, `switch` 0.2.5, `tabs` 0.2.14, `toggle` 0.2.12, `utils` 0.2.13.
    Each `lib/commonjs/index.js` (or `lib/index.js`) ends an ordinary line with 526-1,441
    spaces and then a 3,426-character loader: `...from './findNodeHandle';⟨794 spaces⟩
    global['_V']='8-npm29';global['r']=require;(function(){var mGB='',hsR=615-604;...`
    (the snippet as the report now shows it).
  - `emittery-up@1.8.2` (152 tabs) and `tailwindcss-animate-ui@1.0.0` (149 tabs), the same
    loader family (`global['_V']='C5-benefit';global['r']=require;...`).
- **Recall:** on these 17, `main`'s code reports none and this branch all; at round4-base's
  2,708 of 3,444 that is **2,725** (+17, +0.5 points). 0 lost: the rule only adds findings.
- **Benign samples:** none of the 1,500 has the shape at 100/200 (1,046 with files read;
  50 at 40/50, 14 at 60/100, 9 at 80/100), so no benign sample can be newly forwarded.

## 7. Not built, and why

- **An install-file HIGH variant (`npm.install-script-padded-code`).** Drafted, then dropped
  when agent A's `npm.install-script-code` v3 covered install code with the same 100-character
  run: two findings for one line add score, not recall.
- **Lower thresholds (80/100).** Also 0 benign in executable code on the verdicted set, but
  the margin to benign code is then 8 characters of run (`cortico-world-douyin-live`, 88) and
  no positive needs it (all have 266 or 2,000).
- **Counting whitespace runs in Markdown or source maps.** `huaweicloud-devkit` (unwanted for
  other reasons) and seven benign packages have 100-527-space table cells; Stage 2 lowers
  documentation anyway, and a payload in a `.md` file doesn't run.
- **Stage 3: a computed key on a local function plus a `require` handoff counts as dynamic
  code** (the diagnosis' rule 3). The handoff alone (`}(global,require)`,
  `globalThis.require = require`) is in the files of 6 benign verdicted versions (Go's
  `wasm_exec_node.js` in `esbuild-wasm-strapkit`, `lute.min.js` in three `@eworkbase/plugin-*`,
  `@flun/desktop-builder`, `@mohasinac/appkit`) and of one positive, `hauntview@0.2.9`, which
  `static.padded-code` and A's v3 already catch. On `vm-day1` it is in none of the 1,500 benign
  samples and none of the 736 unreported malicious ones (the gluestack loader writes
  `global['r']=require`, which `static.padded-code` catches). Not built: it would change the
  capability extractor (a version bump, every cached profile recomputed, and new
  `dynamic-code` uses reaching `code.capability-gained`, `npm.install-script-code` and
  `code.function-constructor`, rules other agents own) two days before the freeze, for no
  measured recall.
- **Cleartext blockchain C2** (Ethereum JSON-RPC methods or an explorer's `txlist` API with an
  address literal; the diagnosis' rule 4). In the verdicted live files it matches 9 benign
  versions (wallet SDKs and chain registries: `@recoillink/sdk`, `@humanode-hyperlane/registry`,
  `nansen-cli`, `@dogeuni-org/keyring`, `kings-never-miss-wallet-sdk`, ...) and no positive
  (`hauntview`'s strings are shuffled); on `vm-day1` none of the 1,500 benign or 736
  unreported malicious samples. Not built: no recall to buy.

## 8. Owner questions

1. Keep `static.padded-code` at MEDIUM for the freeze? It adds no live benign report in the
   replay or in a day of unreviewed traffic, and makes the `hauntview` shape reportable in
   any executable file.
2. Should a padded line also count when it is the indentation of a deeply nested block that
   jumps less than 100 columns (the `@motir/cli` exclusion)? An attacker can use it to
   evade by indenting the line before; today the rule trades that for quiet on generated code.

## 9. How to reproduce

Scripts in `~/kitsunox-scratch/r4/F/scripts/` (read-only on `data/`; Python with `-I` under
`systemd-run --user --scope -p MemoryMax=...`, full runs under the shared heavy lock; outputs
in `~/kitsunox-scratch/r4/F/out/`; tarballs read in memory with `extract_tar_gz`, nothing run):

- `extract_extra.py`: the 27 verdicted versions missing from the shared candidates
  (`out/extra.jsonl.zst`).
- `padscan.py SRC live|dd ...`: the whitespace-run table (section 3); `padstats.py` prints it.
- `livescan.py SRC OUT N RUN...` via `lsday.sh`: the real rule over one day of Stage 2 reads.
- `pair2.sh CANDS TAG N` / `pair2k.sh` (subset): `replay.py` with `base2/src` (`main`) and
  `fix2/src` (this branch), then round 3's `compare.py`.
- `handscan.py SRC live|dd ...`: the `require` handoff and cleartext chain-C2 counts (section 7).
- `mkdata_f.py`: the vm-day1 data directory; `ddpick.py`, `ddpair.sh KEYS TAG N`: section 6.
