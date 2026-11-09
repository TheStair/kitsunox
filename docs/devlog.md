# Kitsunox dev log

Reverse-chronological. Newest entry first.

## 2026-11-09: Afternoon review; the user-wide rule measured and left a note

**Stage(s):** evaluation (verdicts, live sample), Stage 3 (`npm.install-agent-user-wide`)
**Context:** Clearing the queue of the 14:39-16:40Z ticks (43 versions), reviewing the
2026-11-08 live sample (55 unreported versions), and the first daily live-eval with the
four-category verdicts and the 2026-11-09 rulings.

### Decisions
- **`npm.install-agent-user-wide` stays INFO, weight 0** (owner): see the evaluation snapshot.
  Scoring it would add dozens of reports a day; the user-wide installers it doesn't report are
  counted as false negatives instead, and the write-up says so (decision 0015 addendum
  2026-11-09, later).
- **Prompt telemetry is unwanted** (owner): `@ciandt-flow/flow-ai-obs` (7 versions; the 6 older
  betas, recorded benign under the 2026-11-08 ruling, were reclassified after checking each has
  the same unconditional `dist/setup.js`) and `toga-ai` 1.0.1318/1319 (the reviewer had said
  malicious; re-recorded unwanted for consistency, then confirmed by the owner).
- **Baileys media tagging recorded unwanted, pending the owner:** `@codexverified/baileys`
  2.19.18/19 attach the author's newsletter id to every image or video sent (no follow).

### Challenges
- **Verdict ranks move when an old run's report is rebuilt.** Re-recording flow-ai-obs at the
  ranks stored in its 2026-10-30 verdicts hit other packages' pages (rank 3 had become 0.16.0-
  beta.122, rank 4 `@tollbit/tollbit-cli`).
  - **Resolution:** the loop checked each page's name@version before recording and refused the
    three mismatches; they were recorded at the current ranks (2, 3, 7).
  - **Why it worked:** the check is the same one the reviewers run; nothing was mis-recorded.
- **`peek.py` shows only the first 6,000 characters a file**, so a grep can miss matches deep in
  bundles. A reviewer's in-memory full-text search (`review10/tools/srch.py`) is now in the brief.
- **Disk falls ~4 GB an hour** (106 GB free at 17:05Z) while retention keeps two days; the next
  run prune is due ~11-10 13:00Z. `data/cache/` is 81 GB and never pruned: AST v1-v8 (~38 GB)
  and 12 stale Stage 2 fingerprints (~40 GB; live: `a650824fea376f88`). Cleanup handed to the
  owner (removals are theirs); a cache-retention fix is for after the freeze.

### Evaluation snapshot
- Live eval `live-20261109T113623Z`, window "all", headline (flag-worthy, behaviour truth):
  recall 28.2% -> 76.4% (133 of 174), precision 1.9% -> 5.7%; with the current rules re-scored
  79.9% / 8.9%. The jump mixes four changes not yet separated: unwanted counted positive (90
  verdicts), miss adjudication, 107 new OSV labels, and the 11-09 rules.
- Queue (43): 39 benign, 4 unwanted. Live sample 2026-11-08 (55): 54 benign, 1 unwanted miss
  (`@aswless_854771076/ai_short_studio_cli@0.1.236`, skills into `~/.codex/skills` on every
  install, score 0).
- `npm.install-agent-user-wide` on today's 9 runs: 67 fires (58 distinct versions). Of the 45
  without a verdict, reviewed label-aware: 21 unwanted (15 silent, 6 global-only), 19 benign
  (11 print/help/comment, 4 user command, 3 interactive opt-in, 1 unrelated), 3 unverified
  (`wkappbot-code`, runs a fetched `install.sh`), 2 `toga-ai`. With the 13 earlier verdicts:
  30 unwanted, 25 benign, 3 unverified, 55% precision on the decided versions. None of the 45 was reported: they are misses.

### Open questions / next steps
- After the freeze: narrow the rule (home reference and agent directory in one path
  expression; skip comments and help text; skip writes only behind an interactive prompt;
  evidence on the write itself). Reviewer estimate ~87% precision, unmeasured.
- Separate the live-eval jump by cause before it goes on a slide.
- Owner calls still open: global-install-only, interactive opt-in, publish-at-load severity,
  shell-rc edits (`@xfe-repo/cli`), Baileys media tagging.

## 2026-11-09: User-wide agent installs relabelled unwanted (verdicts)

**Stage(s):** evaluation (reviewer verdicts), decision 0015
**Context:** Reviewing `sino-bc-cli@1.8.45`, a reviewer decoded its obfuscated `dist/index.js`:
the postinstall's `/init` silently copies the package's skills into `~/.claude/skills` and
`~/.agents/skills`. Under the 2026-11-08 ruling (AI-dev packages installing their own skills are
benign) it was recorded benign, and the 19 older versions moved from unverified to benign. The
owner disagreed: injecting skills user-wide, rather than into the project, is not benign, "the
obfuscation is a big part too".

### Decisions
- **Silent user-wide agent installs are unwanted** (owner, decision 0015 addendum 2026-11-09):
  an install hook writing skills, hooks, settings or MCP registrations into `~/.claude/`,
  `~/.agents/`, `~/.codex/`, `~/.cursor/`, `~/.gemini/` etc. Unwanted rather than malicious
  (offered as alternatives): nothing harmful was seen in the copied content. Project-scoped
  writes and user-run `init` commands stay benign; harmful content stays malicious.
- **Global-install-only copies are recorded unwanted too** (Claude's default, flagged to the owner;
  each such note says "global install only", so they can be flipped mechanically).
- **The `arkcli-probe-*` builds (23, `@volcengine`/`@byteplus`) are unwanted without the probe
  tag:** the vendor's release-channel builds, not research probes. Their postinstall runs
  `arkcli +connect --refresh`, which by the script's own comments downloads the latest skills
  and installs them into every detected agent. Considered `unverified --reason remote` (the
  fetched skills are unseen); rejected because the behaviour that decides the verdict, the silent
  user-wide install, is plain in the script.
- **No `eval` of package text, ever:** the sino-bc-cli reviewer had run Python `eval` on the
  obfuscator's checksum arithmetic. Checked afterwards: both versions' expressions held only hex
  literals, `parseInt(bf(0x..))` and operators. The reviewer brief now requires an `ast`
  walker with a whitelist; the re-review used one.

### Challenges
- **Finding the affected verdicts:** a note-text filter caught 547 benign versions (408
  packages); 181 had no install hook. A reviewer read the install path of the other 224.
  - **Resolution:** 86 versions (57 packages) changed to unwanted: 31 packages write user-wide
    on every install, 26 only on a global install. About 17 project-scoped copiers, opt-in /
    ask-first installers and refresh-only hooks stayed benign. Plus `sino-bc-cli` (20) and
    the arkcli builds (23).
  - **Why it worked:** each change cites the file and line of the user-wide write; none came
    out malicious. Two never-captured versions (`basinfy@1.3.5`, `@saltpub/agent-web@0.1.0`)
    were left unchanged.

### Evaluation snapshot
- Current verdicts (latest per version, 3,483): malicious 54, unwanted 203 (was ~70), benign
  3,155, unverified 71. All relabelled versions had been reported, so they move from FP to TP
  in the headline (flag-worthy) matrix. `npm.install-explained` v2 (entry below) keeps
  user-wide copiers reported from now on.

### Open questions / next steps
- Owner: are global-install-only copies unwanted (default) or benign?
- A positive rule for silent user-wide agent writes at install was not built; today the
  install rules report them and `npm.install-agent-user-wide` (INFO) explains why.

## 2026-11-09: S3 explains only copies into the project (`npm.install-explained` v2)

**Stage(s):** Stage 3 (`npm.install-explained` v2, new INFO `npm.install-agent-user-wide`,
`lang/agent_config.home_references`); Stage 4 reads the shape as before.
**Context:** The owner ruled today (decision 0015, addendum 2026-11-09) that install code
silently writing skills, hooks, agent settings or MCP registrations into user-wide agent
locations (`~/.claude/`, `~/.agents/`, `~/.codex/`, ...) is **unwanted**, a positive;
project-scoped writes stay benign. `sino-bc-cli` (20 versions decoded offline) is being
re-labelled. S3 ("agent-skill copier", 2026-11-08) explained user-wide and project copies
alike, so it now hides positives. Measured first, then narrowed. Details:
[stages/ast.md](stages/ast.md#s3-v2-copies-into-the-project-only-2026-11-09).

### Decisions
- **Project-scoped means "no home reference" in the install code or hook line.** Text over
  the whole install code: `os.homedir()`/`homedir` imports, `process.env.HOME`/`USERPROFILE`/
  `APPDATA`/`XDG_CONFIG_HOME`, agents' `CLAUDE_CONFIG_DIR`/`CODEX_HOME`, `$HOME`, `~/`,
  `path.join("~", ...)`. Alternatives: data flow from the home path to the write call (not
  available: tree-sitter gives syntax only) or requiring a positive project anchor
  (`INIT_CWD`, `process.cwd()`), which would also drop `@inizioevoke/veeva-astroclm-core`
  (a `projectRoot` from `__dirname`) and `@revikornmann/muka-ui` (only mentions `.claude/`).
  Text over-matches comments and messages; that only keeps a version reported.
- **"Undetermined" is install code that loads a package by name.** Where a dependency writes
  can't be seen (`@doist/todoist-cli` refreshes installed skills through `@doist/cli-core`).
  On the measured sets this condition alone removes only `todoist-cli` (3 live versions).
- **A cheap INFO note, no new MEDIUM.** `npm.install-agent-user-wide` (weight 0) shows the
  reviewer where the install code refers to the home directory, so a reported user-wide
  copier says why it isn't explained. It changes no score or decision.
- **No STAGE_VERSION or extractor bump:** only Stage 3's rule set changes (rule version 2 and
  a new rule); Stage 4's code and contract are unchanged.

### Challenges
- **A quoted tilde is not a path.** The first pattern took `"~"` anywhere: `@abblor/agent-os`
  help text (`"+"/"="/"~" lines`) counted as user-wide. Now only `"~",` as an argument
  (`path.join("~", ...)`) counts; a test pins the help-text form.
- **The keys pass collapsed versions seen in two runs**, so the first per-run totals were 19
  short; counts are per unique version (`tools/by_version.py`).

### Evaluation snapshot
- Live, 17 fully captured runs (38 h): today's S3 explains 30 versions (14 packages); v2
  keeps 11, 17 user-wide and 2 undetermined lose it; **0 reports added back** (S3 only lowers
  install findings, and these have none: mostly updates with an unchanged hook). The 4-day catch-up run (partly captured): 39 → 12 kept,
  **+7 reports**, all reviewed benign. About 0 to 2 a day.
- Reviewed: **16 benign versions S3 explains today write (or mention) user-wide** and are
  reported again; 14 are user-wide copiers by hand-reading (the `sino-bc-cli` shape, to be
  relabelled unwanted), 2 only mention home (`@draig/lexis-two`, `opencode-blocker-diverter`).
  No reviewed positive was S3 (22 unwanted + 1 unverified agent-dir versions all have
  network, process or obfuscation), so recall under today's labels is unchanged and becomes
  +14 positives once relabelled.
- `vm-day1`, all 433 malicious samples reported only through the install rules (each read
  in memory from the encrypted zip): S3 explains 0 before and after (v2 can only explain
  less); the note fires on 1, `aicp-tracker@1.0.7` (`os.homedir()` for a LaunchAgent; it
  reaches the network and runs processes, reported as before). No decision changes.

### Open questions / next steps
- Owner: relabel the 14 user-wide copiers listed in ast.md (3 of them only on a global
  install, `npm_config_global`); confirm that a global-install-only copy is unwanted too.
- Comments: stripping comments before the home test would return `@draig/lexis-two` and
  `claude-spotter` (a comment about removed behaviour) to S3; not worth a parser now.
- `npm.install-explained` and `npm.install-build-tool` are labelled "Stage 1" in reports
  (`STAGE_OF_RULE` lacks them); the new rule is listed.

## 2026-11-09: Self-publishing code: `npm.publish-at-load` and extractor v9

**Stage(s):** Stage 3 (`lang/at_load.py` commands, extractor v9, `npm.publish-at-load` v1)
**Context:** The entry below left the `*_z3n` family open: 46 malicious `vm-day1` samples that
no rule reports, whose `main` re-publishes the user's project under random names
(`exec("npm publish --access public")` in a timer loop started at load). Self-propagation is
in the threat model (#9), but `static.npm-publish` only matches text and fires on 350
reviewed benign versions (release tooling). Task: find the malicious code that publishes,
where its publish runs (load, install, or a `bin`/script the user runs), and build a narrow
rule only if it passes the owner's bar for a MEDIUM (under ~5 benign reports a day,
measurable recall gain). Details and tables:
[stages/ast.md](stages/ast.md#self-publishing-at-load-or-install-npmpublish-at-load-extractor-v9).

### Decisions
- **Measure the reach, not the text.** A prototype scan (tree-sitter, data only) recorded
  every publish/token string in the loaded and install files and whether it runs at load
  (`at_load._Reach`). Publish or token text in those files: 574 `vm-day1` malicious, 8
  benign, 185 live versions in 33.7 h (181 unreported, ~129 a day), 52 reviewed benign. A
  publish string that runs, in any use: 106 / 0 / 2 / 5 (the benign ones are help text and a
  changelog). Only as a command passed to a runner at load or install: **105 / 0 / 0 / 0**.
- **Release tooling separates by itself.** No benign version in any set runs a publish at
  load or install: tools publish from an exported function, a CLI command handler, a `bin`
  script or a `scripts` entry that isn't an install hook. The `bin` guard (copied from
  `npm.load-fingerprint`) removed nothing; kept for a CLI whose `main` is its `bin`.
- **Generic extractor, npm rule.** Extractor v9 records every command that runs at load
  (`FileCapabilities.commands_at_load`: runner calls by name, one level of same-file
  wrappers whose first parameter is the command, `const` names, `spawn("npm", ["publish"])`
  lists); `npm.publish-at-load` (MEDIUM 3) matches `npm|pnpm|bun [flags] publish` and
  `yarn [npm] publish` in the load files (not `bin` targets) and the install code; on updates
  only if the base didn't.
- **Not built:** token + registry `PUT` at load or install (fires on nothing: Shai-Hulud's
  bundle publishes from functions the parse doesn't see run, and is reported by the install
  rules), any running publish string (help text), the hook command line itself (none seen).

### Challenges
- **The wrapper over-reached.** The first extractor treated any function containing a runner
  call as a wrapper, so `go()` in `function go() { execSync(CMD) } go();` became a second,
  empty command. Found by `test_commands_that_run_at_load`; a wrapper now must pass its first
  parameter to the runner (`@emilgroup/*`'s `run(cmd)`), which keeps the worm's shape.
- **Live misses need a live directory.** `kitsunox live misses` reads the newest live report;
  `kitsunox live eval --live-dir <scratch>` built one without writing to `data/` (94 misses,
  35 with a tarball, none publishing).

### Evaluation snapshot
- `vm-day1` recall: +46 malicious reported (every `*_z3n` new package, score 2 → 5; one more
  was reported already through `npm.dependency.fresh-foreign`). The rule fires on 105, the
  other 58 (`@emilgroup/*` x28, `@opengov/*`, `@teale.io/eslint-config`, `pgserve`, ...)
  reported already through the install rules. Benign: 0 of 1,452 fire.
- Live: 0 of 37,154 versions in 33.7 h fire (0 benign reports a day); reviewed benign 0 of
  1,434, positives 0 of 108 (none publishes). No live recall gain: no live positive publishes.

### Open questions / next steps
- Owner: the live sets have no self-publishing positive, so the rule's live precision is
  unmeasured beyond "never fires"; the rule freeze week will show whether it stays silent.
- Extractor v9 invalidates the Stage 3 cache (`data/cache/ast/v9`): the first tick after the
  merge reparses every file, as v8 did.
- Cross-file reach and aliases (`const run = cp.execSync`) would widen it; nothing measured
  needs them yet.

## 2026-11-09: Load-time payloads: `npm.load-fingerprint` and extractor v8

**Stage(s):** Stage 3 (`lang/at_load.py`, extractor v8, `npm.load-fingerprint` v1)
**Context:** `archetype-index-sdk@1.0.0` (entry above) was reported on obfuscation alone: a
payload its entry imports, no install hook, nothing from Stage 3. Task: find how many
malicious packages do their harm when loaded, what their load profile (`CodeChange.load`)
shows, and build a narrow rule only if it passes the owner's bar for a MEDIUM (under ~5
benign reports a day, measurable recall gain). Details and tables:
[stages/ast.md](stages/ast.md#load-time-payloads-npmload-fingerprint-extractor-v8).

### Decisions
- **Population first.** `vm-day1`, every sample scanned (archives read in memory): 880 of the
  3,117 routed malicious samples have no install hook; 420 are reported with today's code
  (per-sample `pipeline+4` for the 548 the 2026-10-31 dump missed), 460 missed (279 new
  packages). Their loaded code: no JavaScript 195, no capability 94, process only 67,
  **two host-identity reads plus network 63**, dynamic code 35. Live: 53 of the 108 reviewed
  positives with a tarball have no hook, 27 of them missed when reviewed (mostly
  `@atedone/workspace-context`, whose names are built from split strings, and Baileys forks).
- **At load, not in a loaded file.** The text form of the identity shape fired on 1 of 1,500
  benign `vm-day1` samples but on 33-73 unreported live versions a day (CLI commands, bundled
  playwright, agent plugins: reads inside functions). Extractor v8 follows what runs when a
  file is loaded within the file (top level, in-place calls, callbacks of running calls,
  functions called by name from running code) and records only identity reads there. A
  Python prototype first, then the extractor; the built rule reproduced the prototype's
  `vm-day1` numbers exactly.
- **Built `npm.load-fingerprint` (MEDIUM 3)**: one loaded file reads two of `os.hostname()`,
  `userInfo()`, `networkInterfaces()`, `homedir()` at load and the loaded files use the
  network; not a `bin` target's file; on updates only when the base didn't. npm-specific
  (in `ecosystems/npm/rules/`) because of the `bin` guard; the extractor part is generic.
- **The `bin` guard**: 6 of the 7 reviewed benign versions it fired on were CLIs whose
  `main` is their `bin` (`codeam-cli`, `@mearl/native-host` x5). It costs one `vm-day1`
  follow-on (`@sentry-browser-sdk/profiling-node@1.0.4`).
- **Not built**: a command at load (50 new `vm-day1` packages, but 3 benign samples and 100
  unreported live versions in 33.2 h), with network (1 / 1 / 11), with a file write (46,
  all the `*_z3n` self-publishing spam family / 1 / 76), a detached spawn (1 / 0 / 58), and
  "obfuscated loaded file in a new package" (`static.obfuscated` already reports those).

### Challenges
- **The live scan was slow** (35,734 versions, tarballs from the blob store): ~1 version a
  second while three `vm-day1` scans shared the 4 vCPUs. A byte prefilter on the gunzipped
  tarball (no trigger word, no parse) skipped 19,327 of them.
- **The live reviewed positives were mostly pruned**: 69 of 191 positives and OSV misses had a
  captured tarball; 47 more were downloaded again from npm as data (read in memory), the rest
  are gone from npm.

### Evaluation snapshot
- `vm-day1`: +42 malicious reported (2 new packages: `@twilio-client/twilio-client@0.0.1`,
  `safe-chain-test@1.0.0`; 40 follow-ons, 32 of them `blocks-nextjs`); fires on 310, 268 of
  them reported already. Benign: 0 of 1,500 fire.
- Live, 12 fully captured runs (33.2 h): 4 new reports (~2.9 a day), unreviewed and
  benign-looking (`dsh-session-gallery`, `@saccolabs/questrade-mcp`, `@saccolabs/wave-mcp`,
  `chatbotx-mcp`); `archetype-index-sdk` score 5 → 8. Reviewed: 3 positives and 1 benign
  (`filedrawer`) fire, all reported already; 0 reviewed benign newly reported.

### Open questions / next steps
- Owner: vendor telemetry that reads two identity facts at import would be reported; none
  was seen live. If one appears, a guard for the package's own homepage host would need the
  same trust question as round 2's S2-homepage proposal.
- Owner: the `*_z3n` self-publishing spam (46 `vm-day1` samples, `npm publish` in a loop at
  load) is caught by nothing; a rule for "runs `npm publish` at load" was not measured.
- Cross-file reach (`index.js` calling another file's exported function at load) would see
  `@atedone/workspace-context`, but its names are built from split strings anyway.

## 2026-11-09: `npm.install-script-changed` v4, version strings and printed text

**Stage(s):** Stage 3 (`npm.install-script-changed` v4, `lang.javascript.mask_printed_text`)
**Context:** The rule is the largest benign cluster among reviewed reports (latest verdicts with
it: benign 714, unverified 27, malicious 6, unwanted 3). Reviewers kept clearing generated
installers whose diff was only the pinned release, its digest and a date, and postinstalls
whose only change was a message. Task: characterise, measure narrow fixes against every
positive, every unverified version and `vm-day1`, build only the ones that lose nothing.

### Decisions
- **Measure on today's findings, not the stored ones.** Baseline = round 2's recomputed groups
  plus the explained-install shapes recomputed on the tarballs (371 missing tarballs were
  downloaded again from npm, as data, read in memory); Stage 4's real `explained` and `decide`.
  This moved the "reported only through this rule" set from 457 to 422 benign: 35 were already
  explained by S1-S3 once their tarballs were present.
- **Shapes of the 422** (tree-sitter tokens, comments aside): code changes 283, newly run file 30,
  versions/digests/dates only 52, string literals only 27, shell/Python install files 21,
  comments/formatting only 8, binary 1. 113 download with a checksum but are not S2.
- **Built: LOW when every changed file is the same but for volatile strings or printed text.**
  Volatile = versions in any form (never inside a dotted quad, so a changed IP address stays
  MEDIUM), dates and build stamps, 7-12/32/40/64/96/128-hex digests and commits, SRI values,
  with the same URL hosts. Printed = a string argument of `console.*` or
  `process.std{out,err}.write`, directly or through `+`/parentheses, on a clean parse.
  Textual normalisation matched the token-level measurement exactly (52 = 52), so the version
  part needs no parser. LOW rather than "unchanged": the diff stays in front of a reviewer and
  in the score.
- **Not built, with numbers.** Any string-literal-only change (−27 benign) loses 8 `vm-day1`
  samples (`esoftplay` ×4, `@emilgroup/*` ×3, `fooobar@1.0.14`: strings there are code
  templates and commands). Comments/formatting only (−8) and capability-free install code (−7)
  both lose `hyrox@0.1.6` (unverified; its only install change is reformatting, its reason is an
  obfuscated dependency): owner's call, as round 2's F1 was. S2 for a checksum-verified
  download from the `homepage`'s domain (−17, 5 packages, only `topaz-lang` ×2 beyond v4) trusts
  a field the publisher writes.

### Challenges
- **The first token pass stalled** on `difflib` over 100k-token minified files. Capped the token
  diff at 12k tokens (larger files only get the equal / strings-only test) and made the pass
  resumable.
- **`vm-day1` took ~10 s a sample** (ZipCrypto in Python). First the 612 samples the
  2026-10-31 dump has the rule on, then every other malicious update whose manifest has an
  install hook (a first full pass over 261 samples had found 4 firing outside the dump, which
  only held Stage 3 results for routed samples): 629 fire with today's code.
- **A line-based "log-only" proxy matched `shoal-cli@0.4.5`** (malicious; reported by
  `npm.install-hook` HIGH anyway); the AST masking does not, because its changed line does more
  than print.

### Evaluation snapshot
- Live, the 750 reviewed versions: reported 655 → 591, all 64 benign (27 packages: `workerd`,
  `bun` canaries, `@depot/cli`, `@ejfkdev/*`, `onpod`, `statuz-cli`, `tunlion`, ...); 0 of 6
  malicious, 3 unwanted, 27 unverified lost. Unreviewed live versions with the rule: 2, neither
  reported.
- `vm-day1`: all 629 malicious samples where the rule fires stay MEDIUM; no report changes.

### Open questions / next steps
- Owner: comments/formatting-only changes as LOW (−8 benign, loses unverified `hyrox@0.1.6`).
- The remaining 283 code-change reports have no narrow shape; a "no new capability, URL,
  credential path or blob in the added lines" test is round 2's F1, still the owner's decision.

## 2026-11-09: Queue review of the first ticks on the pre-freeze rules; evaluation pins 404s

**Stage(s):** Review (verdicts), evaluation harness (`PinnedFetcher`)
**Context:** The first ticks with every pre-freeze rule live (22:30 to 00:30 UTC) left 13
versions in the review queue; the undeclared-package work (entry above) was merged as
`83b09f2` + `c75a72b` (a docstring that named the Stage 4 rule wrongly).

### Decisions
- **`PinnedFetcher` keeps 404s** (`2edf8e6`): the evaluation fetcher pinned found packuments
  only, so a dependency or undeclared name that was 404 at an evaluation's first run was asked
  again every run and could turn "found" once the payload was published. Now a 404 is pinned
  like a success (other failures are still asked again; `HttpFetcher._pins`, overridden).
  Collection is unchanged: its fetcher still never pins a 404. Tests:
  `tests/evaluation/test_pinned_fetcher.py`.

### Challenges
- **A load-time dropper reported on obfuscation alone**: `archetype-index-sdk@1.0.0` (new
  package, no install hook) imports `telemetry-info.mjs` from `dist/index.js`; base64 + XOR
  0x4e strings; it sends hostname, user name, cwd, home, MAC address and the names of set env
  variables to `cdn.node-js.dev/report/...`, then writes `~/.cache/build-cache/helper.cjs` and
  spawns it detached. Score 5: two `static.obfuscated` MEDIUMs plus LOWs; Stage 3 saw nothing
  (the module names are hidden). Reported, but one obfuscation finding fewer and it would not
  have been.
  - **Resolution:** none yet; recorded as a recall risk for load-time payloads in new packages.

### Evaluation snapshot
- Queue review, 13 versions (runs `20261108T213001Z` to `T233023Z`): 2 malicious
  (`archetype-index-sdk@1.0.0`; `@gsas/gsas-sdk@99.99.99`, probe: preinstall DNS lookup of
  `<hostname>.<username>.<marker host>`), 3 unwanted (`@axelkalcer/baileys@1.0.3` and
  `@zaiinlin/bails@1.0.2` channel follows, the latter from a base64-hidden list;
  `@promethea-research/sundial@0.2.3` launchers in every writable PATH directory and shell
  start-up edits), 8 benign. Benign clusters: `npm.install-script-changed` on own-binary
  downloaders verified by checksum (`@depot/cli`, `statuz-cli`, `stacklit`) and a print-only
  postinstall (`totemlayer`); new packages with harmless hooks (`@litterthanlit/vyo`, a
  Homebridge fork pip-installing pinned upstream, `claudecode-ms-teams`: AI-plugin ruling).
- Over all reviewed versions, `npm.install-script-changed` fired on 714 benign, 27
  unverified, 6 malicious and 3 unwanted: the largest benign cluster. A measurement of
  narrower shapes (guards: new host, risky use, unverified fetched exec) is running before the
  freeze; it is built only if no reviewed positive stops being reported.

### Open questions / next steps
- Owner: should re-publishes of another scope's code (`@ohos-ports/cms-components`, 21
  `@smallstack/*` names npm lacks) be reported?

## 2026-11-08: Undeclared packages the registry lacks; Baileys signatures retired

**Stage(s):** Stage 3 (`npm.undeclared-package` v2, extractor v7), Stage 4
(`npm.undeclared.missing`, STAGE_VERSION 15), Stage 2 (signatures v3)
**Context:** Two pre-freeze items. (1) The owner asked to "measure a narrower version" of the
undeclared-package signal and build it only if benign stays under ~5 reports a day: four
Tailwind-wrapper misses (`tailwind-animate-engine@1.0.6` and three identical-manifest releases)
`require` their payload `@unipswap/postcss-animate-units` without declaring it, so Stage 4's
`npm.dependency.missing` never looked it up. v1 (INFO) fired on 700-1,150 benign versions a
day. (2) KX-0008/0009/0011 called Baileys channel-follow forks "known malware family" after the
owner ruled channel follows *unwanted*.

### Decisions
- **Count only what loading the package runs**: a load at module load (not in a `try`, not
  deferred inside a function; IIFEs and `.call(this)` count as at load), in the entry files
  (`exports`, `main`, `module`, string `browser`, default `index.js`) or the package files they
  load by constant relative path (`ecosystems/npm/entry.py`, reusing `followed_files` with wider
  limits). On the 29.2 h of unpruned live runs this cut v1's 993 versions to 204 (each filter in
  [ast.md](stages/ast.md)); reachability did most of it (504 -> 204), because it drops shipped
  TypeScript sources, templates, tests and examples without a path list. A path filter on top
  removed nothing more; adding `bin` scripts as entries added 3 versions, none with a missing
  name, so `bin` stays out (it runs when typed, not when required).
- **devDependencies are not "declared"**: excluding them (as the earlier measurement did) cut the
  INFO from 204 to 165 versions but removed no name npm lacks, and an attacker could list a
  payload there to dodge the rule while npm still wouldn't install it for users.
- **Reuse Stage 4's lookup, after the declared names**: `NpmDependencyLookup.plan` adds Stage 3's
  names (minus own scope, watched names and `sibling_reason` siblings, the exemptions
  `npm.dependency.missing` already uses) after every declared dependency of the run, under the
  same limits, so the existing rules never lose a lookup. Same request, snapshot and 404-only
  semantics (decision 0009). The names travel in the Stage 3 finding's evidence (`[name] code`,
  at most 10), parsed by `undeclared_evidence` next to the rule that writes them.
- **Built**: 15 of the 29,470 live versions load a name npm lacks, 14 of them only siblings or
  own-scope names (`@ranujs/*` -> `@ranu/*`, `@gtkx/*`, `chatluna-plugin-*`); one remains
  (`@ohos-ports/cms-components`, 21 `@smallstack/*` names: a dependency-confusion exposure).
  ~0.8 benign reports a day, under the ~5 ceiling.
- **Retire KX-0008/0009/0011 rather than relabel**: every version they match also has a
  non-demoted `static.channel-follow` match (16/16 corpus and verdict tarballs, 2/2 of 35,544
  live tarballs, 1/1 in `vm-day1`), so a MEDIUM "unwanted" relabel would only duplicate it on the
  same file. Reported forks stay reported (HIGH -> MEDIUM, score -6). Decision 0015 addendum.

### Challenges
- **"Missing now" vs. "missing when Stage 4 asked"**: registry status could only be checked on
  2026-11-08. A payload published after its wrapper would read as present now.
  - **Resolution:** for the 18 v2 names that exist and would be looked up, compared npm's
    `time.created` with the release that loaded them: none was created later. The campaign's own
    404 is in run `20261102T083824Z`'s Stage 4 snapshot.
  - **Why it worked:** it bounds the undercount on benign for this window; it says nothing about
    future campaigns, which is the point of the rule.
- **`vm-day1` doesn't fit 4 GB**: `pipeline+4` OOMs, and even a per-sample dump OOM'd with 2
  threads on the malicious slices. Re-ran in 400-sample slices, one thread, with a "started"
  marker so a sample that kills the process is skipped; only `llm-oracle@1.0.2` was.
- **The live runs were being pruned during the measurement** (keep-days 1 on the 4-day run): the
  tarballs of the eight remaining runs were hard-linked into scratch first, then deleted.

### Evaluation snapshot
- Recall: live `tailwind-animate-engine@1.0.6` now reported (MEDIUM) with three
  identical-manifest siblings expected the same (tarballs gone; all four unverified);
  `vm-day1` unchanged (2 malicious get the finding, both reported already). 0 of 56 reviewed
  positives with a captured tarball change.
- Benign: live +~0.8 reports a day; `vm-day1` 0 of 1,500. Item 2: no report gained or lost.

### Open questions / next steps
- `@ohos-ports/cms-components` style re-publishes of another scope's code will report; the owner
  may want them (dependency confusion) or not.
- Loads inside bundler module functions (webpack) count as deferred, and a payload required from
  a `bin` script or a postinstall-only file is missed; revisit with recall data after the freeze.

## 2026-11-08: Pre-freeze recall: shell start-up files, WhatsApp channel follows, small updates

**Stage(s):** Stage 2 (two rules, `ALWAYS_NEW`), Stage 1 routing (small updates)
**Context:** The owner approved three changes before the 2026-11-12 rule freeze, each only if
it doesn't flood benign reports: a rule for writes to shell start-up files (the live miss
`@atedone/workspace-context`), a rule for Baileys forks that make the user follow WhatsApp
channels (KX-0008 missed the base64 + `mexQuery` forms), and routing updates ≤ 64 KiB to
Stage 2 (option B of [stage2-routing-recall](proposals/stage2-routing-recall.md)). Write-up
with every number: [prefreeze-recall](proposals/prefreeze-recall.md).

### Decisions
- **`static.channel-follow`, MEDIUM 3, "unwanted".** A FOLLOW query or `newsletterFollow(...)`
  call outside the library's own methods, in a file that names, hides (base64, char codes),
  fetches or "auto-follows" channels; an explicit `=== true` opt-in doesn't count. Owner
  rulings during the task: channel follows are *unwanted* (positive in the headline matrix,
  not in the strict one), so the title and explanation claim account abuse, not malware.
  Put in `ALWAYS_NEW` (never "not new"): every release of such a fork follows again. The
  alternative, fixing KX-0008, would still be a signature of the forms seen so far.
- **`static.shell-startup` with per-form severity.** `hook` (an install hook appends to a
  start-up file) and `inject` (a command-running prompt under `prompt_subst`, or a line
  sourcing a non-start-up file under `$HOME` next to a start-up file's name) are MEDIUM;
  `shell` (any redirect into one) and `code` (name + nearby write + `HOME`) are LOW evidence.
  At MEDIUM the latter two reported ~8 and ~2 benign CLIs a day (completion and PATH
  installers); the data didn't support a "remote content vs static PATH line" split: nothing
  wrote fetched content into a start-up file directly.
- **Small updates routed** (`small update`, Stage 1 reason 6, decision 0008 addendum): +16.2k
  versions and +0.14 GB a day (≤ 0.5 with bases), ~5 benign reports a day; without it the
  `@atedone` versions that add the persistence are never read.

### Challenges
- **`inject` was noisy as first written.** Any `source ~/...` or `PROMPT=$(` reported at
  least 11 benign versions in 4.6 days: remote-session scripts that reload `~/.profile`,
  "run `source ~/.zshrc`" advice, an AI prompt in a shell variable.
  - **Resolution:** a sourced start-up file doesn't count, a source line needs a start-up
    file's name in the same file, and a prompt needs `prompt_subst`.
  - **Why it worked:** the same replay then reports 1 benign version (`@heyvamz/carry`, a
    completion installer) and still reports `@atedone` 0.0.12 and 0.0.18.
- **The benign replay first read only a third of the files**: 951 of 1,421 candidate versions'
  tarballs had been pruned (2-day retention) between the scan and the replay, so the first
  count was an undercount. Rerun fetching the missing ones from the registry as data.
- **`pipeline+4` doesn't fit the 4 GB cap.** The CLI (8 workers) and then 2 workers were
  OOM-killed; `load_sample_changes` alone peaked at 3.9 GB by listing the 110k-change run.
  - **Resolution:** a runner that streams the run's changes (318 MB) with 2 workers, and
    `pipeline+3`, which decides the same for Stage 2 MEDIUM findings (not `WEAK_ALONE`,
    clearing off). `pipeline+4` itself stayed over the cap.
- **Self-matching waits again** (`pgrep -f smallrep.py` inside the loop's own command line):
  replaced by PID and log-line checks.
- **A file rule sees one file.** `lexzymods-baileys` (benign, opt-in read in another file) is
  reported; `@atedone` 0.0.13+ names the start-up file in one file and writes it in another.
  Left as known limits and an owner question.

### Evaluation snapshot
- Live misses (97 window-A misses, 30 positive versions of 12 packages): **0 → 4 versions
  reported** (`@sakataa/baileys@2.0.0`, `@axo_cuy/baileyss@3.0.1`, `@atedone` 0.0.12 and
  0.0.18), 3 packages; strict (malicious only): 0 of 10.
- DataDog `vm-day1` `pipeline+3`: B follow-on 606 → 669 of 1,093 (+62 routing, +1
  `channel-follow`); A 920, A follow-on 393, B 612 unchanged; benign 13 of 1,500 unchanged.
- Live benign, 4.6 days of Stage 2 reads (190,203 tarballs scanned, 1,421 versions replayed):
  +11 reports from `channel-follow` (all default-on forks: unwanted), +1 from
  `shell-startup`; small-update routing ~5 a day (2 of 6,436 sampled).
- Baileys corpus: `channel-follow` 26 / 26 hidden followers, 4 / 4 disclosed, 1 of 23 benign
  (`@yshtxxproject/baileys@0.0.1`, which does follow by default).

### Open questions / next steps
- Owner: KX-0008/0009/0011 say "known malware family" for what is now ruled unwanted; re-record
  `@yshtxxproject/baileys@0.0.1`; opt-in in another file (`lexzymods`); over-cap forks
  without a hook (`kevinx-baileys`, `@ubedsockets/baileys`) stay unread.
- After the freeze: a host/IP field rule (`"host": "150.136.8.159"` in `@atedone` 0.0.23's
  JSON isn't a URL); `shell` at MEDIUM for files an install hook runs (needs Stage 3's
  install sources).
## 2026-11-08: Undeclared packages: measured, kept as INFO (Stage 3)

**Stage(s):** Stage 3 (extractor v6, `npm.undeclared-package`)
**Context:** Four Tailwind-wrapper campaign misses (`tailwind-animate-engine@1.0.6` and three
releases built from the same template) load their payload, `@unipswap/postcss-animate-units`,
with `require()` without declaring it, so Stage 4's new `npm.dependency.missing` (declared
names that 404) can't see it. The owner approved a rule for undeclared packages on the same
terms as the Function-constructor one: build it only if benign reports stay low.

### Decisions
- **Record the loads, keep the rule INFO.** The extractor now lists the packages each file
  loads by constant name (and whether inside a `try`), and the profile lists what the tarball
  ships under `node_modules/`. The rule names undeclared packages as INFO evidence (weight 0)
  rather than MEDIUM, because the measurement below says MEDIUM would flood the queue. The
  alternatives (dropping it, or a narrower MEDIUM) are in the table in
  [stages/ast.md](stages/ast.md); none is below tens of benign reports a day without a
  registry lookup.
- **Capitalised specifiers are not packages** (npm refuses new capitalised names): they were
  bundler externals and AMD globals (`require("React")`, `GISDK`).

### Challenges
- **Benign releases load undeclared packages all the time.** Live (32,272 versions Stage 3
  read): 700-1,150 a day not otherwise reported. Plugins whose host provides `react` (217
  versions) or `vscode` (38), TypeScript sources and scaffolding templates shipped beside the
  build, path aliases (`@shared/x`). Excluding devDependencies and test/example/template paths
  leaves 440-560 a day; scoped names of another scope only, 60-130.
  - **Resolution:** INFO. With the names npm didn't have (570 of 3,008 when checked) it would
    be 8-47 a day, but only Stage 4 can ask the registry at the release's time.
  - **Why it worked:** INFO scores nothing (`correlate.score`), so no report changes; unproven
    whether the Stage 4 combination is precise enough.
- `.d.cts` / `.d.mts` declaration files were parsed as TypeScript (only `.d.ts` was skipped);
  their `import`s were among the first false hits. Now skipped.

### Evaluation snapshot
- Recall unchanged (INFO). `vm-day1`: fires on 64 of 1,500 benign and 758 of 3,443 malicious
  samples (108 of them with no other Stage 3 MEDIUM finding).
- `tailwind-animate-engine@1.0.6` gets the INFO finding naming `@unipswap/postcss-animate-units`.

### Open questions / next steps
- Owner: should Stage 4 look up the names this rule reports, and raise to MEDIUM on a 404
  (as `npm.dependency.missing` does for declared names)? Measured upper bound 8-47 benign a day
  before excluding path aliases.

## 2026-11-08: The Function constructor through `constructor` (Stage 3)

**Stage(s):** Stage 3 capability analysis (extractor v5, `code.function-constructor`)
**Context:** Two live false negatives of window A, `txnforge@1.0.4` and `mock-datas-lib@1.0.1`
(adjudicated malicious: a Python dropper fetched from a hard-coded host), ran their decoded
payload with the Function constructor taken from `globalThis.constructor.constructor` and
scored 0: Stages 2-3 look for `eval` and `Function` by name. The owner approved a rule for
the pre-freeze window, to be built only if it doesn't flood benign reports.

### Decisions
- **A `dynamic-code` use, not a separate capability**: the alias forms are recorded with
  details `constructor.constructor` / `function.constructor` (suffix `(require)` when the file
  hands `require`, `process` or `module` to code), so `capability-gained` and
  `install-script-code` see them like other dynamic code, and one rule reads the details.
- **MEDIUM only for the strong forms.** The constructor of a constructor is plain `Function`,
  which code that isn't hiding names: 0 benign firings in 32,272 live versions read (two full
  runs and a 1-in-10 sample of the 4-day run) and in 1,500 `vm-day1` benign samples. A function
  literal's constructor (`Object.getPrototypeOf(async function () {}).constructor`) is the
  only way to build an async function from text, and code-mode executors use it: LOW, unless
  the file hands Node's loader over. The first cut made it LOW unconditionally; the live sample
  then showed three unreported `*-util@1.0.1` packages (`jmrwd-gjdob-util`, `smfos-bskdz-util`,
  `tsbwt-hawsi-util`) running an XOR-decoded `package.json` field with
  `(function(){}).constructor("require", "__dirname", code)(require, __dirname)`, so the
  loader condition was added.
- **New packages count** (unlike `capability-gained`): both misses were new packages.

### Challenges
- **Minified names.** Following any variable that holds `x.constructor` fired on 15 of 5,850
  versions of one run (uses in 135): one-letter names are reused across scopes (`t.constructor.name`
  in zod, React's `publicInstance = publicInstance.constructor`).
  - **Resolution:** follow a variable only when it is declared in the same function, and count
    a use only where the value is called, stored, passed or returned (not `.name`, comparisons,
    tests); for a stored value, at least one reference must be such a use.
  - **Why it worked:** the same run then had uses in 15 versions and firings on 2, both function
    literals. `txnforge`'s split form (`const c = g.constructor; const F = c.constructor;
    return F`) is still found.
- **Cost.** A tree-sitter query over every identifier of a scope took 0.4 s on a 7 MB bundle;
  searching the scope's text for the name and mapping hits back to nodes made the extractor's
  cost indistinguishable from v4 on 3-12 MB bundles.

### Evaluation snapshot
- Live: 2 adjudicated misses now MEDIUM, plus 3 unreviewed new catches; reviewed malicious
  versions with captured tarballs (42): no other Stage 3 finding changes.
- `vm-day1`: 4 of 3,443 malicious fire, all LOW (already reported or not routed): recall
  unchanged; benign 2 of 1,500 fire, both LOW (none reported).
- Benign live: about 3 extra reports a day (`@nodegx/backend`, `@muqian/xiangsu-mcp-plus`;
  at most ~8 if two sampled `@tailwindcss/oxide-wasm32-wasi` builds fire live).

### Open questions / next steps
- Review the three `*-util@1.0.1` packages (run `20261108T073127Z-npm`).
- A variable declared in an outer function, an assignment, or a parameter is not followed
  ([stages/ast.md](stages/ast.md#known-limits)).
- Extractor v5 re-parses everything once; `data/cache/ast/v1`-`v4` (36 GB together) are no
  longer read.
## 2026-11-08: Explained install (S1-S3) and agent configuration, built before the freeze

**Stage(s):** Stage 3 AST (`npm.install-explained`, `agent.hostile-instructions`), Stage 4
correlation (`STAGE_VERSION` 14)
**Context:** The owner approved building the "explained install" shapes of
[precision round 2](proposals/precision-round2.md) before the rule freeze, S3 with the three
guards he added the same day (decision 0015 addendum: AI-agent skills, hooks and settings are
benign as verdicts, but the rule may only stay quiet when the code proves the plain shape),
on one hard condition: finish the DataDog check first. The proposal had computed install
features for only 149 of the 433 `vm-day1` malicious samples reported only through install
rules ("the encrypted zips decrypt slowly in pure Python"). Commits: Stage 3 `169499a`, then
Stage 4.

### Decisions
- **Decrypt with `unzip -p`, member by member, into memory.** The zstd blob is decompressed in
  memory, the still-encrypted ZipCrypto zip is written to `/dev/shm` for `unzip`, and only the
  members a rule reads are decrypted, through a pipe into the process (a lazy mapping); nothing
  is extracted to disk or run. Pure-Python ZipCrypto was the bottleneck; after this, the cost
  was tree-sitter parsing 4 MB obfuscated install files (the `@redhat-cloud-services/*` wave),
  cached by content hash in a scratch capability cache.
- **One INFO signal, three shapes, reusing F2's mechanism.** `npm.install-explained` (Stage 3)
  and `EXPLAINED` (Stage 4), which now maps a rule to explanations in order, so
  `npm.install-hook` has two (build tool first). The three install rules become LOW; content
  findings, `code.capability-gained` and the new hostile-instructions rule never do.
- **Stricter than the proposal's table, on purpose.** S1's network only to
  `registry.npmjs.org`; no `dynamic-require` in any shape; for an update nothing new in the
  install code (the owner: "updates keep the normal diff rules"). Each costs little live and
  keeps the shapes from being a hiding place.
- **The guards read the files an agent would read** (`lang/agent_config.py`, ecosystem
  agnostic; `CodeChange.agent_files` only when the install code names an agent directory):
  hook and MCP commands must be a constant `echo` or a shipped script with constant arguments,
  and that script must itself be plain; any allow-list beyond read-only tools, bypass mode or
  remote MCP server is widening; instructions to hide activity, ignore earlier instructions,
  switch off safeguards or send credential files away are a MEDIUM finding of their own.
  Considered and not done: following what the copier actually copies (needs data flow), and
  allowing scoped `Bash(git ...)` entries (the owner said allow-lists are never explained).

### Challenges
- **Guard 3 flagged security reviewers.** On the live verdicts the first version fired on
  `great-cto@3.75.6` (agents that list "Ignore previous instructions" as the attack to catch)
  and `tesseract-agent@0.12.2-beta.2` ("...ignore earlier instructions, is something to
  report..., never something to do"), both benign. On all hooked versions of the retained
  runs it also fired on `@acedatacloud/skills` ("do not tell the user to reconnect") and
  `@finebi/finebi-cli` (Chinese deployment notes naming `.env.local` and, 200 characters
  later, a `POST` endpoint).
  - **Resolution:** quoted phrases, sentences about attacks, negated "ignore"/"disable",
    "tell the user *to*", CJK sentence ends, and a credential within 80 characters of the
    sending verb.
  - **Why it worked:** 0 hostile findings on the 3,244 reported verdicts and 0 on the 3,552 hooked versions with a tarball in the 8 retained runs (`@wowok/skills@3.4.0` and `nameslink` 1.0.5/1.0.6, hits of the first pass, were pruned before they could be read or re-checked);
    tests pin each case.
- **`pkill -f` killed my own shell twice** (its pattern was in the command line), losing a
  half-written patch. Workers are now stopped by PID.

### Evaluation snapshot
- `vm-day1`, all 433 samples reported only through install rules: 0 explained, 0 hostile
  (before: 0 of 149 checked). Only `@nx/key@3.2.0` (the nx compromise) has 2+ platform builds;
  S1 refuses it for `env-all` and network off the registry.
- Live, 3,244 reported verdicts (2,107 reported with today's code): -85 benign (S1 36, S2 34,
  S3 15; 70 packages), 0 malicious, unwanted or unverified lost; precision (malicious +
  unwanted) 4.23% → 4.41%. The guards keep 5 benign S3 candidates reported (allow-lists with
  `Bash`/`Edit`/`Write`, an `npx` hook, hook commands built in code).

### Open questions / next steps
- The live numbers cover the 738 versions with a captured tarball of 1,442 with an install
  finding; with full capture the shapes' share should roughly double. 19 of the 85 are
  updates whose previous tarball is gone, so the "gained" check could not run for them.
- Window B's held tarballs: re-measure after the freeze, including the reviewed queue's
  `agent.hostile-instructions` hits.

## 2026-11-08: Diff base 5, commit-id prereleases follow their own line (round 2 F8)

**Stage(s):** Stage 0 ingest (`Packument.previous_version`, `DIFF_BASE` 5)
**Context:** [Precision round 2](proposals/precision-round2.md) F8: a prerelease named by a
commit hash (`0.7.6-canary.2936b07`) was diffed against the highest semver below it, but
semver compares hashes as strings, so that was an arbitrary canary. The proposal estimated
up to 135 benign reports from it (118 `@astryxdesign/cli`). The owner approved building it
before the freeze if a real measurement held.

### Decisions
- **The line is the core version plus the prerelease text before the commit id**
  (`packument.commit_line`): `0.7.6-canary.` for `0.7.6-canary.2936b07`. The base is the
  latest earlier publish on that line; with none, the usual base. Considered: a channel
  across core versions (would diff `0.7.7-canary.x` against an old `0.7.6` canary rather than
  the `0.7.6` release), and stopping the line at a number (`beta.60.<sha>` would then follow
  `beta.61.<sha>` builds of another branch); keeping the number is narrower and numbers
  already sort. Channels stay apart (`experimental.<sha>` / `next.<sha>`).
- **A commit id is 7-40 lowercase hex digits with a letter and a digit**, a whole dot- or
  hyphen-separated part. All-digit ids are left out: `nightly-8627589-20261104` costs one
  benign report, but a 7+-digit number is as often a build number or date, which already
  sort.
- **Versioned, not retroactive.** `DIFF_BASE` 5 is recorded in each new run's manifest, so
  runs recorded with 4 replay as they were (two unpruned runs replayed "identical" with the
  new code; their manifests say 4, and base 5 differs on 59% of their commit-line changes).

### Challenges
- **The estimate's main case was not caused by the diff base.** Re-running `pipeline+4` with
  today's code on the 199 reported verdicts whose base changes, the recorded base reported
  only 21. The 119 `@astryxdesign/cli` canaries had been reported because their base was
  *unreadable*: the live finding said "uses env-all, process" without "(new to the install
  code)", and Stage 2 had noted "base unavailable: declared unpacked size 18222018 bytes"
  (118 of the 119 bases are over 16 MiB). Stage 2's 32 MB limit for hooked versions
  (`d46ef27`, the same morning) makes those bases readable, so they are gone with either
  base. Found by the control run disagreeing with the proposal's `now_reported`, which kept
  Stage 2/3 findings as recorded.
  - **Resolution:** count F8's effect on top of today's code only (control = recorded base,
    same code), and say so in the proposal.
- **Measuring without packuments.** Most verdict runs are pruned. Their bases were computed
  from the registry's current packument, checked by recomputing base 4: it matched the
  recorded base for 197 of 199 (2 `create-strapi-app` experimental builds differ, unreported
  either way); in unpruned runs it matched 4,859 of 4,859.

### Evaluation snapshot
- Live verdicts (3,032 reported): 242 on a commit line, all benign; base 5 changes 199;
  reported with today's code 21 → 3 (**-18 benign**, 7 packages). Positives on a commit line:
  0 of 137 (malicious, unwanted, unverified), so none can lose a finding.
- `vm-day1`: 94 samples on a commit line, all benign; DataDog 0 of 3,444. OSV: 12 of 53,389
  malicious npm versions are commit-line prereleases (historical, packuments gone, not
  re-runnable); base 5 diffs such a version against the publish just before it on its line,
  the base that shows most of what it added.
- Unverdicted: the six unpruned runs (11-07 22:27Z to 11-08 19:30Z) have 4,859 commit-line
  changes; base 5 changes 2,846 and `pipeline+4` reports none of them with it (0 added).

### Open questions / next steps
- Validate on window B with held tarballs after the freeze, as the proposal planned.

## 2026-11-08: Precision round 2, the pre-freeze fixes (F5, F6b, F7, F2, F3b+F3c, F4b)

**Stage(s):** Stage 1 triage, Stage 2 static, Stage 3 AST, Stage 4 correlation (`STAGE_VERSION` 13)
**Context:** The owner approved the six pre-freeze fixes of
[precision round 2](proposals/precision-round2.md) ("keep cutting down the benign category"),
to be built before the rule freeze of 2026-11-12 and re-measured with the real code rather
than the proposal's simulation. One commit per stage: `2a1d1cd` (Stage 1), `d4bba1a`
(Stage 3), `16676fc` (Stage 4), then Stage 2.

### Decisions
- **F5 (`version.suspicious` v4), narrowed.** Month-day minors (`2026.1107.0`) and `YYMM`
  majors (`2611.5.1`) as proposed; a minor of 0 only in `as_of`'s own year. The proposal's
  "minor 0 in any year" had been checked against OSV only for round 1's shapes; checked now,
  it exempts 15 OSV malware versions (`2000.0.0`, `2000.0.1`, `1999.0.1`, `2001.0.0`,
  `amazonui@2026.0.1` published in 2025). As built: 0 of 53,389. Cost: one benign live report
  (`spain-holidays@2027.0.0`) stays.
- **F6b (`non-registry` v4).** `https://cdn.sheetjs.com/` LOW, one literal origin.
- **F7 (`revived` v3).** LOW with a provenance attestation; only on this rule (no live
  positive), never as an explanation for install code.
- **F2 is a Stage 3 signal plus a Stage 4 explanation, not a Stage 1 rule.** "Every hook is a
  build tool *and binding.gyp runs no command*" needs the tarball, which Stage 1 doesn't have.
  Stage 3 got `CodeChange.build_commands` (npm passes `gyp_commands`) and an INFO rule,
  `npm.install-build-tool`; Stage 4 got `EXPLAINED`/`explained`, which makes the explained
  finding LOW with a note after the rules run (like Stage 2's "not new" notes, so the report
  still shows it). Considered: a Stage 1 rule for the non-gyp tools only (can't see
  `binding.gyp`, whose commands npm runs implicitly), and inferring gyp commands from the
  install files (misses `<!(pkg-config …)` or a `curl` action, which name no package file).
- **F3b/F3c as LOW, not dropped.** A lowered match still counts in the score (weight 1), and
  lowered matches don't use up the rule's cap of three per file, so placeholders first can't
  hide a real endpoint.
- **F4b in Stage 2, not the rule.** File rules see content only (cached by hash); the data-file
  and `package.json` metadata tests need the path, so they sit beside the "doesn't run" note.

### Challenges
- **The first real-code baseline lost a malicious report.** Re-running Stage 2 on tarballs
  with the previous version as base dropped 62 reports, among them `internal-renderers@10.0.0`
  (malicious): its IP was in 1.0.0 too, while the run's Stage 2 had compared it with the
  batch's base. Found by diffing the baseline against the proposal's 2,208.
  - **Resolution:** judge each *stored* MEDIUM/HIGH finding again on its own file (same line
    and match text) with the new code, instead of recomputing Stage 2.
  - **Why it worked:** the baseline then reproduces the proposal's 2,208 reported versions
    exactly, so every difference is the fix.
- **F3b's full window lowered ngrok tables.** With v5's 400-character window instead of the
  snippet, a list check also fires in the Public Suffix List bundled by `@wirecat/*` CLIs
  (correct) and would fire in a table of nothing but a tunnel's region hosts, which v5 kept on
  purpose (`gina`, `cro-pricing`).
  - **Resolution:** the other domains must not be endpoints themselves. The PSL and
    disposable-mail lists still count; region tables stay HIGH (test pinned).
- **A `package.json` cap gap.** The IP rule reports at most 3 matches a file; three metadata
  URLs could hide a hook's IP. When the file has more IP URLs than were reported, none is
  taken for metadata.

### Evaluation snapshot
- Live, the proposal's 3,032 reported verdicts (latest per version; 2,208 reported today,
  127 positives under the four categories), real code: F5 -46, F6b -50, F7 -65, F3b+F3c -43,
  F4b -12, F2 -7; together 2,208 → 1,985 (-223, 153 packages), all benign; precision
  5.8% → 6.4%. Applying the Stage 2/3 rules to stored snippets and manifests where no tarball
  was captured: -253 (6.5%; proposal: -227, 6.5%). Positives lost: 0 malicious, 0 unwanted,
  0 unverified. All 3,211 verdicts: 2,371 → 2,109 reported, 136 positives kept.
- `vm-day1`: the 87 malicious samples at risk through F3/F4/F5/F6/F7 re-run through
  `pipeline+4` with the new code: 87 still reported. None of the 433 reported only through
  install rules has build-tool-only hooks; the 4 other malicious samples that do are decided
  as with the old code (1 reported, 3 not either way).

### Open questions / next steps
- After the freeze (window B): F8 (diff base for commit-hash prereleases) and the S1-S3
  explained-install shapes, which can reuse `EXPLAINED`.
- `pkg.pr.new` previews and other vendors' CDNs (F6b-like) are each an owner decision.

## 2026-11-08: A dependency the registry doesn't have (`npm.dependency.missing`)

**Stage(s):** Stage 4 correlation (`STAGE_VERSION` 12)
**Context:** The adjudicated live misses (review 11) include a campaign of Tailwind/Animate.css
wrappers whose code requires a scoped postcss-style package that did not exist yet when the
wrapper was published; the payload came later (`tailwindcss-animate-bridge@2.0.8` →
`@utilitycraft/tailwindcss-motion-atelier`, MAL-2026-18468). Stage 4 looked those
dependencies up, got 404, and by design said nothing (the proposal had measured 404s as benign
"exposures"). The owner approved a rule on 2026-11-08 if it doesn't flood benign reports.
Details: [stages/correlate.md](stages/correlate.md#missing-dependencies-npmdependencymissing-stage-version-12).

### Decisions
- **MEDIUM on its own, weight 3, not `WEAK_ALONE`.** The brief expected "weak alone, stronger
  combined" (with an install hook, obfuscation, or the code requiring the name). The data say
  otherwise: 8 of the 16 wrappers had no other finding and the rest only LOW ones, so any
  combination reports none of them.
- **Siblings are INFO, by name and version.** Of 121 releases with a 404 dependency, most are a
  project's own packages published one by one: platform builds (`envdoc-cli-linux-x64`),
  monorepo scopes (`@ocean/*` from `@amoree-code/ocean`), release trains (exact specifier =
  the release's version). `sibling_reason` checks those; watched names never make two names
  kin, because the campaign borrows `tailwindcss`/`postcss`. Rejected: "the code requires
  it", since benign siblings are required just the same (38 captured tarballs read).
- **Only a 404.** `FAILED` and `CAPPED` stay "not evaluated" (decision 0009); a 404 is a
  recorded response, so replays agree (`test_dependency_lookup_replays_byte_identically`).

### Challenges
- **Ranges as release trains hid a wrapper.** The first `sibling_reason` treated `^1.0.1` at
  version 1.0.1 as lockstep. That made `fast-deep-thinking@1.0.1` INFO, and it turned out to
  be the campaign's template ("A configurable, namespaced Animate.css integration for Tailwind
  CSS"). Grepping the hits' descriptions for that template found it.
  - **Resolution:** only an exact specifier counts. That made 3 benign releases MEDIUM
    (`monolith-core-cli`, `dsh-fairy-next` x2), so a shared, unwatched first name part became a
    sibling reason too.
  - **Why it worked:** re-simulated over every run: all 16 template releases are MEDIUM, and
    none of the 86 INFO releases has the template.

### Evaluation snapshot
- Live (every recorded run, 10-28 22:18Z to 11-08 15:32Z, 10.7 days, simulated from each run's
  recorded 404s): **16 of 16 campaign wrappers reported** (0 before; 5 have OSV `MAL-` records,
  verdicts 1 malicious, 3 unverified). Extra benign-looking reports: 15 (~1.4/day against
  ~290/day). No report lost (the rule only adds findings).
- DataDog `vm-day1`: unchanged. The rule fires on 1 sample (already reported) and on 0 of 1,500
  benign; none of DataDog's 1,231 added-dependency edges has a dependency published after its
  dependent, so this set can't measure the pattern.

### Open questions / next steps
- 4 of the 8 adjudicated wrapper misses `require` the payload without declaring it
  (`tailwind-animate-engine@1.0.6`): a Stage 3 rule for an undeclared, non-builtin `require`.
- Owner: whether the 15 private/unpublished reports (dependency-confusion exposures) belong in
  the queue or in a separate exposure list; review them in the first live week.
- The eval's `PinnedFetcher` doesn't pin 404s, so a 404 sample is re-asked each run.

## 2026-11-08: Verdicts reclassified into the four categories; WhatsApp channel follow is unwanted

**Stage(s):** Review (verdicts, decisions 0015 and 0019)
**Context:** The owner replaced "inconclusive" with malicious / unwanted / benign / unverified,
then ruled that WhatsApp channel auto-follow is unwanted, not malicious, unless there is
evidence that it distributes malware. The code shipped in 64c03fa/1d12f1d. This entry covers
applying the change to the verdict log.

### Decisions
- **Reclassified 148 records** (`~/kitsunox-scratch/reclass/`: `propose.py`, `proposal.tsv`,
  `apply.sh`):
  - 119 inconclusive became 15 unwanted and 87 unverified (47 obfuscated, 36 gone, 4 remote),
    with 17 left for a human look.
  - 29 malicious Baileys forks became 22 unwanted, with 7 left for a human look.
  - Of the 24 human-look records, 22 became unwanted and 2 benign:
    - **unwanted:** `@atedone/workspace-context` 0.0.12–0.0.22, which stage a backdoor that
      sends nothing off the machine until 0.0.23 (malicious from there); `@ifasn` 1.1.6,
      which ships unwired credential-probe scripts; `@jarvis_1234`, which sends only to
      127.0.0.1; `dsh-model-pipeline`, which hardcodes the author's model server; and the
      Baileys forks.
    - **`charape@1.0.20`:** its postinstall points other Baileys packages in the project at
      itself through shims, which is hijacker-like, and writes only
      `.npmrc legacy-peer-deps=true` (checked).
    - **benign:** `@ohos-ports` analytics (the owner's vendor-telemetry ruling) and
      `@odintest`.
- **No `inconclusive` record is left.** Latest verdict per version: 2,931 benign, 59 unwanted,
  49 malicious, 87 unverified. A reviewer was still recording during the count.

### Challenges
- **Stale ranks:** my first pass on the 24 human-look records took ranks from the proposal file.
  Two runs had since been re-scored, which renumbers their reports, so the reclassification
  landed on `fluxflow-cli@4.44.0` (turning it from benign to unwanted) and on
  `@next2012/aistudio-runtime@0.3.0` (wrong note).
  - **Resolution:** both were restored with their earlier notes, and the intended versions
    (`@jarvis_1234/env-preloader@1.0.6`, now rank 5; `@odintest/astryxdesign-react@0.1.0`,
    now rank 1) were recorded. A check of every proposal row against the latest verdicts finds
    0 mismatches.
  - **Lesson:** look ranks up by name and version in the run's current report. `apply.sh` does;
    my hand-written pass didn't.

## 2026-11-08: Four verdict categories replace "inconclusive"

**Stage(s):** Reviewer verdicts (reporting, viewer, CLI, Discord summary); live evaluation
**Context:** The owner: "inconclusive" made packages we caught but couldn't call malicious look
like packages we couldn't judge. Of 119 current inconclusive verdicts, about a third were fully
seen but grey (disclosed channel follows, marker-only beacons), the rest unseen (code gone,
remote payload, obfuscation). The live confusion matrix (decision 0019) uses verdicts as its
primary truth, so the grey category had to say which it was.

### Decisions
- **Four categories** ([0015](decisions/0015-reviewer-verdicts.md), addendum "four
  categories"): malicious, **unwanted** (seen; covert or intrusive, not harmful enough to call
  malware, like antivirus "PUA"), benign, **unverified** with a required reason tag (`gone`,
  `remote`, `obfuscated`, `binary`). Alternatives: keep "inconclusive" with tags (the label was
  the problem), or a free-text reason (can't be tallied).
- **Baileys forks that auto-follow channels are unwanted, hidden or disclosed** (owner, later
  the same day), superseding the 2026-10-31 policy and the "false disclosure = hidden" ruling;
  malicious only with evidence the follow spreads malware. Old addenda kept, supersession noted.
- **Legacy records load as `unverified` with no reason** (a pydantic before-validator); the log
  stays append-only. New records can't be reasonless unverified, so "no reason" marks legacy.
- **Viewer without script:** unverified is a `<details>` of one submit button per reason
  (`value="unverified:gone"`), so a reason can't be forgotten or attached to another verdict.
- **Live matrices** ([0019](decisions/0019-live-evaluation.md), addendum): headline
  flag-worthy (malicious + unwanted), strict malicious-only, unverified excluded from both with
  best/worst bounds. The bounds are "the pipeline right / wrong about every unverified
  version", not literally "all benign / all malicious": for unreported versions those swap
  (counting one malicious makes it an FN). Only the right/wrong form bounds recall, precision
  and FP rate at once, and the two forms agree for reported versions (nearly all verdicts).
  OSV truth reads unverified as no verdict.

### Challenges
- **Reclassification commands with stale ranks.** A dry run of the generated commands against
  a copy of the data (reports and verdict log) failed on `motionchart-cli@1.0.3`: its run was
  re-scored and rank 17 no longer exists.
  - **Resolution:** the generator looks the version up in the report as it is now and falls
    back to `kitsunox live verdict` (by name, from the ledger) when the report no longer lists it.
  - **Why it worked:** the second dry run applied all 124 commands, each to the intended
    name@version (diffed against the proposal).

### Evaluation snapshot
- No new numbers. The verdict digest in live datasets changes once (records now serialise
  `reason`, and legacy ones as `unverified`), so the next build's input hash differs.

### Open questions / next steps
- Owner review of the reclassification proposal (148 verdicts: 37 unwanted, 87 unverified,
  24 for a human look), then apply it with the generated commands.
- Staged-but-unarmed code (collects data, sends it only to 127.0.0.1) has no clean category.

## 2026-11-08: Stage 2 routing vs. live recall; a 32 MB cap for hooked versions

**Stage(s):** Stage 2 (fetch cap); Stage 1 routing measured, not changed
**Context:** Live recall against OSV `MAL-` records is 25.4% (34/134,
[prospective-labeling](proposals/prospective-labeling.md)). 48 of the 100 misses were updates
Stage 2 had no files for: 35 never routed (no Stage 1 signal, unwatched, no hook, grew
< 64 KiB) and 13 without files (12 over the 16 MB cap, 1 fetch error). Before the 11-12 rule
freeze: would routing more, or a larger cap, win them back? Full write-up:
[stage2-routing-recall](proposals/stage2-routing-recall.md).

### Decisions
- **No new routing rule.** Candidates measured on 2026-11-02 (24 hourly runs, 118k versions)
  against the 35 live misses and the 420 DataDog updates unrouted today: size ≤ 16 KiB to
  1 MiB, any growth, file-count change, re-publish within 1 h, publisher change, any LOW
  Stage 1 finding. None routes a DataDog A first release that Stage 2 flags (0/34), and the
  live ones it routes aren't reported when read (below). The cheapest, updates ≤ 64 KiB, is
  nearly free (+0.3 GB/day; 0 of 451 benign samples reported) but adds 18.7k versions a day for
  64 B follow-ons only; it is left to the owner.
- **A 32 MB cap for versions that declare an install hook** (`MAX_HOOK_ARTIFACT_BYTES`,
  `fetch_limit` in `stages/static.py`; Stages 3 and 4 fetch through the same `ArtifactFiles`,
  and `evaluation/static_eval.py`'s routing now calls `fetch_limit`, a one-line change).
  Alternatives: a flat 32 MB cap (+~2,000 versions and ~14 GB a day for the same follow-ons),
  64 MB for hooks (+~600 versions, 6–12 GB), partial reads (save memory, not the download).
- **No `STAGE_VERSION` bump:** Stage 2 has none, its rules and content-cache fingerprint are
  unchanged, and Stage 4's version describes Stage 4's rules. Old runs keep their "files
  unavailable" decisions; only new ticks fetch the larger hooked versions.

### Challenges
- **Is it routing at all?** Of the 48, 24 are still on the registry. Fetched as data (in
  memory, scratch blob store) and run through Stages 2–3 with no cap plus Stage 4's `decide`:
  **0 reported**, 22 with no finding. `@atedone/workspace-context` (14 versions) appends a
  `source` line to `~/.bashrc`/`~/.zshrc`, which no rule looks for; `@ubedsockets/baileys` adds
  an IP kill switch; `@sakataa/baileys` auto-follows WhatsApp channels.
  - **Resolution:** routing left alone; the persistence rule is an owner question.
  - **Why it worked:** the replay is the evidence; it says nothing about the 24 that are gone.
- **Self-matching wait loops.** `until ! pgrep -f "replay2.py hook"` matched its own shell, so
  the waits never ended; killed by PID. Use the PID, not a pattern that the loop contains.

### Evaluation snapshot
- DataDog `vm-day1` (Stage 1 at `5fe01c6`, `stage2-rules` per-sample results): Stage 2 now
  reads 44 more malicious A follow-ons (of 97 over 16 MB), 1 A first release, 2 B follow-ons,
  all flagged by `stage2-rules` (A follow-on +9.1 points; the `pipeline+4` report was not
  re-run). Live misses recovered: **0** of the 10 the change routes (5 replayable).
- Cost, 2026-11-02: +339 versions/day (today Stage 2 reads 39.4k), +2.5 GB/day of new
  tarballs, at most +4.8 GB with bases (today 17.7 GB recorded); benign reports +~6/day
  (2 of 111 sampled, both `npm.install-script-changed`; 341 reported that day).

### Open questions / next steps
- Owner: keep the hook cap; route updates ≤ 64 KiB (option B); a Stage 2 rule for writes to
  shell start-up files before the freeze (it needs B to see `@atedone`'s 0.0.12); are
  WhatsApp-fork channel hijacks in scope for recall?
- Watch the first ticks' Stage 2 bytes against the estimate (`df -h /`).

## 2026-11-08: Live evaluation built (Phase 9, option B)

**Stage(s):** evaluation (ledger, live dataset, review sample), retention (label hold), collect
**Context:** The capstone needs a confusion matrix measured on what the pipeline decided live,
not only on DataDog samples. The proposal ([prospective-labeling.md](proposals/prospective-labeling.md))
measured window A by hand with throwaway scripts; the owner approved option B and decided the
four open questions ([0019](decisions/0019-live-evaluation.md)).

### Decisions
- **A per-run decision ledger, kept for good** (`evaluation/ledger.py`): one ~150-byte row per
  version (Stage 1 route, Stages 2-3 read/flag, Stage 4 score and decision, report rank,
  `rule_id@version` of every finding, captured tarball digests) plus a header with Stage 4's
  fingerprint and the SHA-256 of every input. Streams `correlate.jsonl`; ~90 KB per hourly run.
  Alternative: re-reading run outputs at each evaluation; rejected because `correlate.jsonl`
  reaches 3 GB a run and blobs are pruned. When `collect` writes it in the tick that ran the
  stages, it also records every stage's rule fingerprint, which is how window B (rule freeze
  11-12 to 11-19) can be shown single-version; a backfill can't know them.
- **Behaviour truth primary, OSV truth alongside** (the owner): a version-level verdict wins; an
  inconclusive verdict falls back to OSV. D = 7 for benign, with D = 3 / 14 rows.
- **Catch-up by capture lag, not by run window**: a version captured more than 6 h after its
  release goes to a separate group. Tried first by run window (> 6 h): that also dropped all of
  the first VM run (24 h window, 110k versions), including versions captured within the hour.
- **Sample verdicts use rank 0** in the ordinary verdict log (`kitsunox live verdict`) rather
  than a new field: no schema change, and the viewer already links only ranks above 0.
- **The hold keeps labeled tarballs in place, for good** (`until` None), instead of copying
  them to `data/eval/live/tarballs/` as the proposal said: one mechanism, no copy.
- **The hold never blocks a prune**: if `hold.json` can't be updated the last one is used; if
  it can't be read the prune goes ahead without it. A full disk crashed the VM twice.

### Challenges
- **Empty matrices crashed the first `collect` test**: a tick whose versions were all
  provisional had no "behaviour" matrix, and the results log looked it up (`KeyError`, found by
  `test_ticks_chain_and_prune_once_a_day`). Every matrix is now created up front.
- **The live-eval disk check consumed a reading in the disk-guard test**, shifting the sequence;
  the step now checks `"disk" not in failed` before measuring.

### Evaluation snapshot (window A, provisional: D not met for 144k versions, misses not adjudicated)
- Behaviour truth: TP 37, FP 1,899 (758 never reviewed), FN 94, TN 224,444: recall 28.2%
  [21.2–36.5], precision 1.9% [1.4–2.6]. OSV truth: 44 / 1,892 / 94: recall 31.9%. By shape:
  A 15.6%, B 40.3%. Misses: 35 never read by Stage 2, 10 without files, 39 read with no
  finding, 10 below the bar; none watched.
- Real run: `live eval` over 109 ledgers (88 runs, 21 re-scored) and label set
  `20261108T151126Z` took 46 s under a 4 GB cap. The backfill took a few minutes.

### Open questions / next steps
- Adjudicate the 94 window-A misses (`kitsunox live misses`, then `kitsunox live verdict`).
- Review the daily sample (~55 versions a day as built: 20 / 20 / 15).
- The owner's blind check of the analyst's verdicts (κ) is not built.
- After the freeze, check window B's rule-set line reads "single rule version: yes".

## 2026-11-08: Streaming, steps 1-2 (`collect`, retention, Stage 0's digest)

**Stage(s):** `collect`, retention (step 1, `cd7c7b1`); Stage 0 ingest, the digest only
(step 2, the commit after it)
**Context:** The owner approved steps 1 and 2 of
[the streaming proposal](proposals/streaming-stages.md). Step 1 was urgent: the 4-day run
`20261107T163310Z-npm` (405,710 changes, 2.9 GB `changes.jsonl`) becomes due for pruning
after 2026-11-09 16:33Z, inside a `collect` tick, and the prune loaded every `Change` and the
whole file: ~16 GB (the proposal's estimate) on the 30 GB VM, next to the tick's own stages.

### Decisions
- **`collect.run_stages` reduces each stage's result to its log counts and `del`s it** before
  the next stage starts (Stage 1's candidates and forwarded batches; Stage 2's batches; Stage
  3's batches; Stage 4's `CandidateFile`, which already streams). Before, triage's `_`
  (the forwarded batches) and every earlier result stayed alive until the function returned.
  The log lines are byte-identical. The stage functions still return whole runs; that is
  steps 3-6.
- **`_resume_from` reads `static.jsonl` a line at a time** (`_static_needs_retry`) and
  parses only lines holding the `WILL_RETRY` text; the parsed decision confirms it, since an
  evidence snippet or explanation can quote the text. Before, it split the whole file into
  lines first (3.3 GB of bytes at 405k), for every pending run, every tick.
- **`retention._prune_run` streams**: one pass of `iter_changes` collects the URLs to pin,
  and `changes.jsonl` is compressed in 1 MiB chunks through `compression.zstd.open(..., "wb",
  level=9)`. The `.zst` bytes may differ from a one-shot compress; nothing hashes them. The
  temp file is now `fsync`ed before the rename (new `util.files.sync_file`, which
  `atomic_write` also uses): before, a crash could keep the rename and the deletion of
  `changes.jsonl` without the compressed data, the failure that left 211 empty blobs on
  2026-11-07. Decision [0006](decisions/0006-scheduled-collection-and-retention.md) addendum.
- **Stage 0's `changes_digest` hashes a line at a time** (step 2): each
  `model_dump_json().encode()`, with `b"\n"` between lines, changes then skipped. These are
  exactly the bytes of the old `"\n".join(lines).encode()` (UTF-8 encodes each character on
  its own, so encoding per line and joining bytes equals encoding the join). Nothing else in
  Stage 0 changed: `IngestResult` still holds every `Change` (~32 KB each as objects), so
  recording or replaying the 4-day run would still need ~13 GB; that is step 4.
- **Alternative not taken:** two passes over the changes (one for metadata URLs, one for
  tarball URLs) as the proposal allowed; one pass gives the same set.

### Challenges
- **Showing the streamed digest is the same bytes.** Tests compare it with the old joined
  formula for changes only, skipped only, both and neither, with a 2-byte, a 3-byte, a line
  separator and an astral (4-byte) character
  (`tests/core/test_run.py::test_the_streamed_digest_equals_the_joined_one`), and check the
  recorded digest against the written files' lines
  (`test_the_recorded_digest_is_the_written_files_lines`). Live, `changes_digest` fed one
  parsed `Change` at a time over the 4-day run's 405,710 lines gives the manifest's
  `00652635...`, and `ingest replay` of two recorded hourly runs prints "identical".
- **Proving the prune is the same without running the old one on the big run** (it would need
  ~16 GB). Resolution: the old and new code on copies of an hourly run give a byte-identical
  `retention.json`; the URL logic is the same expressions in one loop; on the 4-day copy the
  decompressed `.zst` hashes the same as the original.

### Evaluation snapshot
- Not a detection change: no recall or false-positive numbers move. Memory, measured on
  hard-linked copies (details in [validation](validation.md#2026-11-08-streaming-steps-1-2-collect-retention-stage-0-digest)):
  - prune of the 4-day run: 1.19 GB peak RSS in 41 s, 0.74 GB of it the label set loaded
    before pruning (~16 GB before, estimated);
  - the resume check on its 1.67 GB `static.jsonl`: 86 MB;
  - `changes_digest` over its 405,710 changes, parsed and re-dumped one at a time: 128 MB
    peak RSS in 36 s (the joined string: ~18 GB, the proposal's estimate);
  - `ingest replay` of `20261107T222723Z-npm` (16,589 changes): identical, 1.04 GB peak.
- **Not measured:** `run_stages`' saving needs a whole tick; the ~13-21 GB held into Stage 3
  on the 4-day run is the proposal's model, not a new measurement.

### Open questions / next steps
- `retention.json` itself is still written with `write_text`, not atomically; a crash mid-write
  would leave a marker that fails to load (and garbage collection would then raise before
  deleting anything). Unchanged here; worth a one-line `atomic_write` later.
- `ingest replay` of the 4-day run is still not possible: the replay holds every `Change`
  (~13 GB) plus its packuments. Step 4 removes that; the run's blobs go with the prune after
  2026-11-09 16:33Z, so that replay can't be checked later.
- Steps 3-7 of the proposal, each with the owner's go-ahead.

## 2026-11-08: Precision of four rules (downgrade, non-registry, version, revived)

**Stage(s):** Stage 1 rules (`npm.publish-method.downgrade` v4, `npm.dependency.non-registry`
v3, `npm.version.suspicious` v3); Stage 4 `npm.combination.revived-with-new-dependency` v2
(separate commit)
**Context:** The queue review (entry below) found rules that reported only benign versions
when nothing else fired. The owner approved precision changes that the numbers support, with
recall not allowed to drop. Proposal and measurements:
[proposals/stage1-precision.md](proposals/stage1-precision.md).

### Decisions
- **Downgrade needs a co-signal.** Full weight (HIGH watched, MEDIUM 3 otherwise) only when
  another Stage 1 rule fires on the same change (install hook, non-registry or added
  dependency, maintainer added, unfamiliar publisher, suspicious version) or a watched package
  also dropped `gitHead`; otherwise one step lower. Chosen over lowering bursts (93% of
  malicious downgrades are bursts, 55% of benign), "the account published by hand before"
  (loses `axios@1.14.1` and five `@nx/*`), and making it LOW when unwatched (loses `axios`).
  The `gitHead` hedge for watched packages keeps 2 more benign reports than the plain
  co-signal version; all 149 malicious downgrades lack `gitHead`.
- **Non-registry: protocols npm can't fetch don't count** (`backstage:^`). Not adopted: "LOW
  for the package's own GitHub owner", which loses `@opensearch-project/opensearch` 3.7.0 and
  3.8.0, whose payload came from a commit in their own repository.
- **Version: a date-shaped major is not suspicious** (`YYYYMM`/`YYYYMMDD`, real month and day,
  year 1990 to as_of + 1). Asked for after the 4-day run: 314 of its 1,438 reports were
  `@haybarn/*` with versions like `202610.31.30847`.
- **Revived: LOW when the same account comes back with no maintainer added** (Stage 4, its
  own commit after the Stage 1 one; no `STAGE_VERSION` bump, since rule versions are covered by
  the rules fingerprint in `correlate.json`). Not
  adopted: weak-alone, a two-year gap, or own-scope/popular dependencies: each loses
  `xrpl@2.14.2`.

### Challenges
- **The eval can't exercise the watched branch.** The DataDog set was imported without a
  watchlist, so no malicious sample is watched in `vm-day1`. Every check was run twice, the
  second time with popularity from the 2026-10-29 watchlist (60 of the 149 downgrades watched).
  - **Resolution:** both pass; re-importing with a watchlist is an open item for the owner.
- **Simulation vs code.** The proposal's numbers came from a simulation over stored findings.
  - **Resolution:** re-measured with the implemented rules: the old rule classes (from
    `3fa5833`) and the new ones recomputed on every affected live version and re-decided with
    `correlate.decide`; the unmodified `pipeline+4` predictor on the 254 affected `vm-day1`
    samples.
  - **Why it worked:** identical to the simulation for the three proposed changes (1,372 →
    1,218 live).

### Evaluation snapshot
- Recall on known-bad: 254 / 254 affected `vm-day1` samples still reported (so all cells
  unchanged), with and without watchlist popularity; 41 / 41 live malicious verdicts still
  reported. `axios@1.14.1` still reports at exactly score 6 when unwatched.
- False positives, live (87 runs, Oct 28 - Nov 3, every report reviewed): 1,371 → 1,213
  reported versions (1,011 → 868 packages): 157 benign and 1 inconclusive
  (`@fabricorg/cli@0.7.6`, unpublished by its owner before capture) fewer. 4-day run of Nov 7
  (mostly unreviewed): 1,438 → 994 reported, 316 of them through the version change.

### Open questions / next steps
- Known gaps, accepted: a stolen token used for a code-only release that keeps `gitHead`, and a
  dormant account hijacked as itself, now need their content to be seen (Stages 2-3).
- Not done here (integrator to raise with the owner): one queue entry per burst; re-importing
  the DataDog set with a watchlist.

## 2026-11-08: Stage 4 filled the disk on the 4-day run; a per-run comparison budget

**Stage(s):** Stage 4 correlation (repository comparison), collect
**Context:** After the blob repair (entry below), the 4-day catch-up run
(`20261107T163310Z-npm`, 405,710 changes) resumed from Stage 3. Stage 3 finished in about 3
hours (07:39-10:43Z) without running out of memory. Stage 4 then fetched GitHub archives at
~620 MB a minute.

### Challenges
- **Stage 4 can't fit a 4-day run on the disk, and the failure repeats every tick**: the run
  wanted 80,934 comparisons (1,745 flagged, 79,189 watched-package updates; an hourly run wants
  ~500). At 15:07Z the blob store refused a write at its 10 GB floor (`DiskSpaceError`).
  Three things together made it a loop rather than one failure:
  1. Stage 4 saves `correlate-snapshot.json` only on success, so the 108 GB of archives were
     referenced by nothing, and the end-of-tick prune deleted them.
  2. The next tick starts the run's Stage 4 over.
  3. Catch-ups run before the newest run's stages, and low disk skips the rest of the tick,
     so the newer runs' Stage 2 (tarball capture) waits behind it.
  It would have repeated until the run left the 48-hour catch-up window (Nov 9 ~16:33Z).
  - **Resolution:** `MAX_REPO_COMPARISONS` = 2,000 a run, chosen by `plan_comparisons` before
    any request: flagged versions first, then watched-package updates, each in triage order.
    Versions over it carry `BUDGET_UNCOMPARED` on their decision, `collect` logs the count, and
    `correlate.json` has `repo_budget`. Stage version 11. Decision 0010 addendum.
  - **Alternatives:**
    - A byte budget on archives tracks the real limit better, but which versions fit would
      depend on the order threads finish, so it isn't deterministic.
    - Running newer runs' Stages 1-2 before older catch-ups was offered; the owner chose the
      budget alone.
  - **Why it works:** for this run the cap means all 1,745 flagged versions plus 255 watched
    updates. That's ~2,000 comparisons, about 4 hours of normal ticks: ~30-40 GB of archives at
    most, against 111 GB free after the prune. Tests:
    `test_a_run_compares_at_most_its_budget_flagged_versions_first`,
    `test_flagged_versions_over_the_budget_are_noted_too`. Not yet proven on the live run.

### Open questions / next steps
- After a long gap, most watched-package updates go uncompared. A malicious update of a watched
  package with no other finding can then go unreported. That is the trade for not filling the
  disk.
- The resume order (catch-ups before the newest run's Stage 2) is unchanged. If a catch-up
  fails again for another reason, tarball capture for new runs still waits behind it.

## 2026-11-08: A VM crash left 211 empty tarball blobs; writes are now synced

**Stage(s):** Shared storage (`util/files.py`, `util/http.py` `BlobStore`); seen in Stage 3
**Context:** The four-day catch-up run (`20261107T163310Z-npm`) finished Stages 1 and 2 after
eight hours, then Stage 3 failed with `ZstdError: Compressed data ended before the end-of-stream
marker was reached`. Memory was tight (25.3 GB RSS), but this was not the out-of-memory failure
we were watching for.

### Challenges
- **Empty blobs that the store believed were whole**: the VM went down on 2026-11-07 at about
  19:30Z, in the middle of the first Stage 2 attempt on this run. While the owner's host drive
  was full, the VM's journal ends at 19:30:51Z and the next boot is at 22:22Z. `atomic_write`
  wrote a temp file and renamed it, but never synced it. The renames reached disk and the data
  did not, so 211 tarball blobs were left as empty files under their final names; 3 more empty
  ones date from the 2026-11-03 crash. Their `http-immutable` index entries survived. On the
  rerun, Stage 2 reused those entries (`_immutable_lookup` only checked that the blob file
  existed), and `BlobStore.put` would never have rewritten them (also only `exists()`). Stage 3
  then read them.
  - **Found by:** a read-only scan of every file written between 17:00Z and the reboot
    (136,618 blobs decompressed and digest-checked, 32,338 index entries parsed). The only
    damage was the 211 empty blobs, all `.tgz`, for example
    `@credo-ts/core@0.8.0-alpha-20261106144819`. No file was truncated partway.
  - **Repair (data):** blobs are named by the SHA-256 of their content, so each tarball was
    downloaded again, accepted only if its digest matched the blob's name, and written
    atomically over the empty file. All 211 matched (none had been unpublished). Afterwards all
    304,006 blobs the run references verify, and no snapshot or index was edited. Stage 2 had
    no network retries in `static.jsonl`, so the next tick resumes the run from Stage 3.
  - **Resolution (code):** `atomic_write` fsyncs the temp file before the rename (0.82 ms a
    file on the VM, so about 5 minutes over a 400k-blob catch-up). `BlobStore.exists` counts an
    empty file as absent: no zstd frame is empty. So `put` rewrites the file, and an index entry
    whose blob is empty becomes a refetch, the same way a deleted blob already did. The
    directory entry is still not synced: a crash can lose a whole recent file, which every
    caller already treats as never written.
  - **Why it works:** `test_the_data_is_synced_before_the_rename`,
    `test_an_empty_blob_is_absent_and_rewritten` and
    `test_an_index_entry_whose_blob_is_empty_is_fetched_again`. The three empty blobs from
    11-03 are not referenced by any run; the next `put` of the same content rewrites them.

### Open questions / next steps
- Stage 3 on this run peaked at 25.3 GB before the failure. If the resumed run is
  out-of-memory-killed, Stages 1-3 need to stream their results to disk as Stage 4 already
  does. That is a stage change and the owner's call.

## 2026-11-08: Queue review finished (ranks 116-398): three malicious, the downgrade rule is noise

**Stage(s):** Review queue (verdicts), Stage 1 rules (findings only)
**Context:** The owner asked to continue the queue review while the catch-up tick ran. The
queue file is the one built 2026-11-03 (runs of Nov 1-3); ranks 1-115 were reviewed earlier.
Every remaining entry now has a verdict (`data/verdicts/npm.jsonl`, `--by claude`).

### Results
- 283 queue entries, 400 versions: **3 malicious**, 7 inconclusive, 273 benign packages.
- **Malicious:**
  - `@nerxa/socketon@1.21.0` and `lyxe-baileys@1.0.0`: `luna-baileys` copies whose
    `autoJoinChannels()` fetches `raw.githubusercontent.com/noxXza/data/.../noxleys.json` 30 s after
    every WhatsApp connection and follows every channel on it (owner policy 2026-10-31).
  - `tailwindcss-pixel-tools@1.6.1`: a small Tailwind plugin whose `src/motion.js` requires
    `@nexlayerlabs/postcss-keyframe-utils` (MAL-2026-18407, GHSA malware, "fully compromised").
    Caught by `npm.dependency.known-malware`. Still on npm with a 1.6.2 (checked 2026-11-08); reporting
    is the owner's call.
- **Inconclusive:** `sino-bc-cli` (obfuscated postinstall, as before), `@alexiddev/baileys`
  (disclosed default-on auto-follow), `@fabricorg/cli` and `prctls` (unpublished before Stage 2
  captured them), `whybug`, `system-tracker`, `@fcjplugins/hooks` (obfuscated, hidden hosts).

### Challenges
- **Tarballs gone from the blob store:** many Nov 1-3 versions had no captured tarball (the
  hand-deleted blobs of 2026-11-03). Reviewed ones were fetched again from npm as data,
  checked against `dist.integrity`, and read in memory only (`~/kitsunox-scratch/fetched/tgz`).
  Two were unpublished and could only be judged inconclusive.
- **RC4-mode obfuscator strings:** my decoder handled the plain base64 mode (`aurelium`) but not
  the RC4 mode with wrapper offsets (`@autotest/plugin`, `whybug`); those verdicts rest on docs
  and plain strings, and say so.

### Evaluation snapshot (precision, from this batch)
- `npm.publish-method.downgrade` alone flagged **34 packages, all benign** (27 were one
  `@knapsack` release by a maintainer who published 7,694 of its versions). The usual story: a
  sole or listed maintainer publishing by hand, often with CI provenance back on the next release.
- `npm.combination.revived-with-new-dependency` flagged 50 packages, all benign (the new dependency was
  the package's own family or a common library).
- `npm.dependency.non-registry` alone: 8 packages, all benign (own-org GitHub tarballs, SheetJS's
  CDN, uWebSockets.js, Backstage's `backstage:` protocol).

### Open questions / next steps
- Tune `npm.publish-method.downgrade` (owner's decision, Stage 1): e.g. not MEDIUM when the
  publisher has published earlier versions of the package by hand, or when provenance returns on a
  later release (needs a later packument; Stage 1 sees only one). Measure on the verdicts first.
- Teach the review helpers the RC4 string-array mode, or leave those to the sandbox.

## 2026-11-08: Collection restarted; a 4-day catch-up nearly ran out of memory; catch-ups are now sliced

**Stage(s):** Stage 0 (ingest), `collect`
**Context:** The owner restarted the timer on 2026-11-07 after four days off (since the
2026-11-03 disk-full crashes). The first tick chained across the gap, as designed, into one run.

### What happened
- 16:33 UTC: the tick rebuilt the watchlist (64,393 packages) and labels (222,873 records),
  then ingested `20261107T163310Z-npm`: feed (141817767, 142875367], 119,376 packages,
  **405,710 changes** (2.9 GB `changes.jsonl`), 0 skipped, in 95 minutes.
- Stage 0 holds a run's changes in memory until it writes them: peak **27.6 GB RSS** on the
  30 GB VM (`VmHWM`; systemd `MemoryPeak` 28.4 GB), with 2 GB available at the worst sample.
  Triage of the same run held 17 GB, Stage 2 21 GB.
- 22:21 UTC: the VM's kernel panicked when the **host's** boot drive filled (the owner's host;
  the VM disk is preallocated on a separate drive, so not caused by Kitsunox). Nothing was
  lost: the big run had been written and the checkpoint moved. The next tick (22:27) ingested
  16,589 changes and resumed the big run's stages.

### Decisions
- **Slice long catch-ups** ([0006 addendum 2026-11-08](decisions/0006-scheduled-collection-and-retention.md)):
  a chained run reads at most `MAX_RUN_FEED_SPAN` = 250,000 feed positions (~95k changes at
  that gap's 0.38 per position), one slice per tick. Alternatives: streaming Stage 0, triage and
  Stage 2 to disk (three stages at once, and Stage 0 must sort and hash the whole run), or
  splitting the window by time (the feed has no time index, and a past `as_of` would be pruned
  at once under 2-day retention). Slicing by position is safe because the feed lists a package
  once, at its latest change: on that run's 12 recorded feed pages, 119,379 rows were 119,379
  distinct names. Until a slice reaches the head, the checkpoint keeps the old `as_of`, so every
  slice's window starts at the gap's start.
  - **Why it should work:** it bounds each run to the size the stages have handled since
    2026-10-30. Tests: `test_a_long_gap_is_caught_up_in_slices`,
    `test_only_chained_runs_are_sliced`, `test_a_catch_up_slice_is_logged`. Not yet seen live:
    the next long gap will show it.

### Open questions / next steps
- Triage and Stage 2 still load a whole run; slicing bounds the run instead. If runs grow
  (e.g. a busier feed), streaming them is the next fix.
- `20261103T160330Z-npm/triage.jsonl` is still the empty file the 2026-11-03 crash left; the
  run is past retention and will be pruned.

## 2026-11-06: The commits behind each release: two detection rules on, the clearing off

**Stage(s):** Stage 4 (repository comparison, decision)
**Context:** The owner kept 0017's clearing off and asked instead to "check the corresponding
commits and repos for the npm packages being scanned", both to find malicious behaviour and
to cut false positives. That replaced Phase B of [the proposal](proposals/git-path.md), which
would have watched 5,000 popular repositories. Decision:
[0018](decisions/0018-commit-history.md).

### Decisions
- **Measure the ranges before writing rules.** For 904 updates (all 537 reported live
  versions compared at a commit, 400 random unreported ones, the 112 compared malicious
  `vm-day1` updates), we fetched GitHub's compare between the previous release's commit and
  the release's. No errors.
- **What discriminated:**
  - **No new commits** since the previous release: 61 of 102 malicious, 9 of 626 benign.
  - **Commits made after the publish:** 15 of 102 malicious, 2 of 626 benign. With the release
    commit's own date, over 815 live tag-found releases the latest came 1.4 hours after the
    publish, and 14 of 15 malicious came 7 hours to 255 days later.
- **What didn't:** risky workflow edits (1 of 102 malicious against 21 of 261 reported benign),
  behind or diverged history, unverified commits, PR-style messages, and commit age. In almost
  every malicious sample the git range was the maintainers' legitimate work: the attack
  happened on the registry side, after it. None of these were built.
- **Built:**
  - `RepoComparison.history`: the previous release's commit from the refs (free); the compare
    status for flagged versions; the commit date for tag-found commits. About 100 API
    requests an hour, each once per run, recorded for replay.
  - `repo.commit-after-release` (MEDIUM): the tag points to a commit made more than 6 hours
    after the publish.
  - `npm.repo.no-new-commits` (LOW): a stable bump from the same commit or an older one, whose
    code isn't a clean match there.
  - `repo.history-match` (INFO): a clean match at a commit ahead of the previous release's.
- **Clearing with a history match: built, off** (`CLEAR_HISTORY`), for the same reason as
  0017. Live, it would clear 78 of 1,507 reported versions (5.2%), with 60 reviewed benign and
  none reviewed malicious. That is about twice 0017's gain, without stars or age. It loses
  `gina` (Challenges).

### Challenges
- **gina again.** `gina@0.7.1` is 44 commits ahead of 0.7.1-alpha.1, all by the maintainer
  who has run the repository since 2013, ending with "Release v0.7.1" 30 minutes before the
  publish.
  - **Resolution:** no commit-level property separates it from benign releases without
    fitting a threshold to it, so the clearing stays off and the numbers go to the owner.
  - **Why it worked:** n/a; it is a limit of the signal. Code a maintainer commits is the
    maintainer's code.
- **A benign `commit-after-release` on `vm-day1`.** `@mongodb-js/mcp-atlas-telemetry@3.2.2`
  matched the tag `v3.2.2`, which in its monorepo is `mongodb-mcp-server`'s own release, six
  days later.
  - **Resolution:** a version-only tag on a package in a subdirectory doesn't count for the
    rule.
  - **Why it worked:** 0 benign hits left. It costs 2 malicious hits (`@posthog/rrweb-*`),
    which stay reported through other rules.
- **The first eval run had no API.** `env_value` reads `.env` from the working directory, and
  the run started in the scratch folder. Only the rules that need no API changed anything.
  - **Resolution:** the run was repeated from the project root.
- **A test expected the wrong thing.** A version that wasn't flagged read the compare answer
  another version had already asked for.
  - **Resolution:** the code is right not to: `with_history` reads the range only for flagged
    versions, so a version's output never depends on which versions ran first. The test now
    says so (`test_a_history_match_end_to_end`).
- **Fetching 900 ranges serially took 6 seconds each** (page 1 carries up to 300 files with
  patches: median 212 KB, up to 2.3 MB).
  - **Resolution:** the measurement used 6 threads. The built lookups use page 2 at one
    commit a page (18 KB) and the git data API for dates.

### Removed / abandoned
- **Commit-level rules** (workflow edits, new committers, verification): measured above, not
  built.
- **Phase B as proposed** (5,000 watched repositories): superseded by the owner's ask.

### Evaluation snapshot
- `vm-day1` (`pipeline+4`): malicious reported 2,507 → 2,507, benign 14 → 14 (15 before
  the monorepo exception for version-only tags, which took out
  `@mongodb-js/mcp-atlas-telemetry@3.2.2`).
- `no-new-commits` fires on 60 malicious samples and 0 benign; `commit-after-release` on 13
  and 0. None is newly reported: they add evidence only.
- `CLEAR_HISTORY` on: 2,506 malicious (−`gina`), benign unchanged. Live: −78 of 1,507
  reports.

### Open questions / next steps
- The owner decides on `CLEAR_HISTORY` (−5.2% of reports live, −1 `vm-day1` malicious sample:
  `gina`). `CLEAR_ESTABLISHED` stays off by their choice.
- Watch `commit-after-release` on live ticks: its benign rate is 0 of 815 on the sample, not
  yet on a full day.
- The collection timer is still stopped (since 2026-11-03).

## 2026-11-04: Repository trust built; the clearing it enables loses `gina`, so it's off

**Stage(s):** Stage 4 (repository comparison, decision)
**Context:** The owner asked to start the GitHub work: Phase A of
[proposals/git-path.md](proposals/git-path.md). Decision:
[0017](decisions/0017-repository-trust.md).

### Decisions
- **REST API facts with `GITHUB_TOKEN`, only where they can matter.** The facts are fork,
  archived, created, stars and default branch, plus whether the commit is on the default
  branch (the compare API, page 2: status without the file list).
  - They are fetched only for clean comparisons of versions that already have a MEDIUM
    finding. At most two requests per repository and commit per run, recorded for replay.
  - The token is a header that the request key and snapshot never hold. It goes only to
    `api.github.com`, and httpx drops it on a redirect elsewhere (tested).
  - When the API fails, nothing changes for the version, and the request isn't retried.
- **`repo.established-match` (INFO).** It fires on a clean match to a repository that is not
  a fork or archived, is at least 30 days old at the release, has at least 5 stars, and has
  the commit on its default branch.
  - Age is required as well as stars: the attacker's `tavern-labs-ai/persona-ai-sdk` had 197
    stars three days after it was created.
- **Clearing install code with it: built, measured, and left off** (`CLEAR_ESTABLISHED`).
  - The live queue gain: 33 of 1,231 reported versions with a GitHub repository (2.7%), all 20
    reviewed benign, every commit on the default branch.
  - The `vm-day1` cost: 1 of 2,507 reported malicious samples (details under Challenges).
  - Missing an attack is worse than a false positive, and the gain is small, so the owner
    decides.

### Challenges
- **The recall check found exactly the blind spot the proposal predicted.** `gina@0.7.1`
  (DataDog: malicious) is byte for byte its 2013 repository (`gina-io/gina`, 11 stars), at a
  commit on the default branch. The code is in the real repository, so a clean match says
  nothing about it.
  - **Resolution:** the clearing ships off.
  - **Why it worked:** the alternative was a 12-star threshold, which keeps `gina` and still
    clears 26 live reports. It was rejected as fitted to one sample.
  - Watching commits (Phase B) is what would catch this shape.

### Removed / abandoned
- **A.4, commit matching for "no commit or tag".**
  - **Measured:** of 312 reported versions with a repository at least 30 days old, 37 (12%)
    have a commit before publish whose `package.json` has the released version. In
    monorepos, 173 of 217 never commit the released version, because release tools set it
    at publish time.
  - **Not built:** that reach is too low.

### Evaluation snapshot
- `vm-day1` `pipeline+4`: unchanged with the clearing off. With it on: 2,507 → 2,506
  malicious, benign unchanged.

### Open questions / next steps
- The owner: turn `CLEAR_ESTABLISHED` on (-2.7% live reports, -1 `vm-day1` sample) or leave
  it off?
- Phase B (commit watching) size: the proposal suggests the top 5,000 repositories.

## 2026-11-04: GitHub work, measured before designing

**Stage(s):** git path (decision 0004), Stage 4 repository comparison
**Context:** The owner asked to start the GitHub work, and earlier whether GitHub could narrow
the queue. Proposal: [proposals/git-path.md](proposals/git-path.md), for review; nothing built.

### Challenges
- **GH Archive stopped carrying commits.** `PushEvent` and `CreateEvent` vanish from its hourly
  files between 2026-10-24 (23.5k pushes in an hour) and 2026-10-27 (0); total events fell from
  58k to 3-5k an hour. Decision 0004 counted on it to watch ~63k repositories without quota.
  - **Resolution:** the proposal polls smart-HTTP refs (no quota) and uses the REST API (the
    token works, 5,000/hour) only for repositories that moved.

### Evaluation snapshot
- Repository metadata for 723 repositories behind 1,231 reported versions: a clean
  tarball-vs-repo match to a repository that is not a fork, ≥ 30 days old and has ≥ 5 stars
  covers 53 versions; the 34 reviewed are all benign. The one malicious clean match
  (`@finzzcloud/baileys`) is the attacker's own repository, 1 star. Roughly 3% of reported
  versions: a small lever, and only through the report decision (all 53 have a MEDIUM finding).

### Open questions / next steps
- The owner's four questions at the end of the proposal (order, report-decision change, token
  use, Phase B size).

## 2026-11-04: The disk filled and crashed the VM twice; 2-day retention and a disk guard

**Stage(s):** collection (`collect`, retention, notifications)
**Context:** The owner asked whether GitHub monitoring was set up. Checking the logs instead
showed run `20261103T045724Z-npm` with an empty report, a 10-hour gap, and the disk at 99%. The
owner confirmed a full disk crashes the VM and asked to focus on pruning and disk monitoring.

### What happened
- 05:03 UTC: the disk filled during an hourly tick; the VM froze (the journal stops, memory was
  fine: 24 GB available at the last sample). Files renamed into place just before were left
  **empty** (no fsync): that run's Stage 4 outputs, its snapshot and its report.
- 15:14: after a restart, the catch-up tick (55k changes, 10 hours) filled the disk again; the
  VM rebooted. The next tick ran 9 hours at 0 bytes free, every step failing with `ENOSPC`.
- Every prune since 05:03 failed: garbage collection stops when a run's snapshot can't be read
  (so it never deletes a blob a run still needs), and the crashed run's snapshot was empty.
- Root cause: the 0006 estimate (~225 GB at 7/4 days) was low. Data reached 373 GB of 393 GB
  before any run was 7 days old.

### Decisions
- **Repair:** deleted the crashed run's empty Stage 4 files and report (all 0 bytes), so a
  catch-up redoes Stage 4 and the prune can read every snapshot; deleted 1.9 GB of my own
  scratch (an Oct 29 bundle-measurement cache) to give the prune room to write.
- **Retention 2 days** for runs and archives (owner's choice): freed 188 GB, 373 → 194 GB used.
  `schedule systemd`/`plist` gain `--keep-days`; the queue keeps a 7-day window of reports.
- **Disk guard** (decision 0006 addendum 2026-11-04): checks between steps (prune below 60 GB,
  start nothing below 25 GB), a 10 GB floor in the blob store, `DiskSpaceError` passed through
  every per-package handler, free space in the tick log, daily summary and an immediate alert.
- **Blobs deleted by hand (owner, to free more space):** 96 of the 256 `data/blobs/` prefix
  directories, 89,812 of the 239,609 blobs the unpruned runs reference (37%). Disk 188 → 165
  GB used. Those runs can no longer be replayed, and the tarballs among them are gone (npm may
  have deleted malicious ones). `HttpFetcher` now treats an immutable-index entry whose blob is
  missing as a miss (`acfdd59`), so catch-ups fetch again instead of failing.
- **Not done: fsync in `atomic_write`.** It would cost an fsync per cache file (millions); the
  guard keeps the disk from filling, which is what left files empty.

### Evaluation snapshot
- Tests: 2,072 pass. No detection change.

### Open questions / next steps
- The two crashed runs (`045724`, `151412`) and `160330` are caught up by the next ticks.
- Tarballs older than 2 days are gone unless their package has an OSV record, so reviews of
  older queue entries rely on the report evidence.

## 2026-11-03: Queue review (ranks 1-115) and `exfil-endpoint` v5

**Stage(s):** review, Stage 2 (`static.exfil-endpoint`)
**Context:** The queue had grown to 398 packages (529 versions). I reviewed the top 115 by
reading install scripts and code from the captured tarballs (never run).

### Decisions
- **Verdicts (129 versions):** 3 malicious (1 a bug-bounty probe), 3 inconclusive, 123 benign.
  - Malicious: `service-roles-registry@99.0.2` (dependency-confusion PoC posting hostname,
    username and cwd to pipedream; `probe`), `@finzzcloud/baileys@1.0.0` (hidden auto-follow:
    a base64 channel-list URL in `Utils/messages-media.js`, on by default, not in the README),
    `ai-persona-sdk@1.0.0` (tavern stealer, KX-0001/KX-0002).
  - Inconclusive: `@routinecrew/routinecode@2.31.77` (930 KB obfuscated postinstall, no sandbox
    result), and two whose tarball wasn't captured (`@algorithco/algocli`, `@yalehwang/cloudpit`).
- **`exfil-endpoint` v5** (docs/stages/static.md): deny lists of 3+ services and `interact.sh`
  inside an identifier no longer count. `vm-day1`: 0 of 1,176 malicious matches lost.

### Challenges
- **A boundary after every host lost a sample.** `google.fhir.stu3.google@8.8.8` posts to the
  typo `burpcollaborator.nett`.
  - **Resolution:** the boundary is only on `interact.sh`, whose `.sh` starts identifiers.
- **Per-line deny lists missed wrapped lists.** `dsh-security-pack`'s list spans lines.
  - **Resolution:** a 400-character window instead of the line.

### Evaluation snapshot
- `exfil-endpoint` v5: `vm-day1` malicious matches 1,176 → 1,176; live reported versions with
  the finding 116 → 114 (both cleared versions reviewed benign).

### Open questions / next steps
- The biggest benign classes in the queue are not this rule: postinstalls that download the
  package's own binary from its GitHub releases with a checksum (about 15 of 115), and
  opencode-style platform-package launchers. A rule that recognises "downloads only from the
  package's own `repository` releases" could lower those, but it needs a recall measurement
  first (malware can point `repository` anywhere).
- Agent-skill installers (`~/.claude/skills`, `~/.codex/skills`) are a growing benign class
  (6 in 115); their skill text is unreviewed input to an agent and might deserve its own,
  low-weight finding rather than none.

## 2026-11-03: The Discord daily summary as embeds

**Stage(s):** notifications (decision 0011)
**Context:** The owner asked for the daily Discord post to be more visually appealing and easier
to read, using embeds.

### Decisions
- Posts are now up to four embeds (decision 0011, addendum 2026-11-03): health (green, amber or
  red), flagged that day (fields per severity, top packages one per line), review (the queue
  now and the verdict tally) and needs attention (only when something went wrong).
- The daily post now carries the review queue as the tick left it: packages and versions
  awaiting review, by highest severity. The old summary only had the verdict tally, so the
  reviewer couldn't see the backlog from Discord.
- The safety rules are unchanged; the link-preview flag is gone because an embed-only message
  has no `content` to unfurl, and the flag would hide the embeds.

### Evaluation snapshot
- No detection change. Yesterday's summary rendered from real data: four embeds, 678 of
  Discord's 6,000 characters. A test checks adversarial input stays under the limits.

### Next
- The next daily post (first tick after 00:00 UTC) is the first in the new style.

## 2026-11-02: What the sandbox's first day showed, three false-positive shapes tuned, a sinkhole proposed

**Stage(s):** Stage 5 (rules, evaluation), Stage 2 signatures, review
**Context:** The owner asked whether the sandbox has made an impact. I re-applied the Stage 5
rules to all 138 accepted results (`~/kitsunox-scratch/session-scripts/tune/rerules.py`, data
only; it reproduced production's findings exactly) and set them against the verdicts.

### Decisions
- **Answer: not yet, and why.** Stage 5 only exports versions already in the queue, and only
  adds score, so it can't shrink the queue. It added score to 21 versions, every reviewed one
  benign, and missed all three malicious versions it ran (the Discord-webhook squats scored +0:
  offline, the lookup fails and the record shows a failed install). 37 of 45 failed installs
  failed for want of the network. Where it helped was as review evidence.
- **Tuned three false-positive shapes** (`sandbox.download-exec` v5, `sandbox.sensitive-read`
  v5), each measured on the 138 results (exactly the four intended findings changed):
  - A file the tarball doesn't have, never written, run before anything but npm had written a
    file (node's compile cache counted as npm's) can only be a link or rename of shipped files:
    no longer `download-exec` (`devlanes`, `@deadbolt/cli`). A write first, `/tmp` included,
    keeps a renamed dropper HIGH. Rejected: matching the binary's name to a shipped file
    (fuzzy and gameable).
  - `/proc/<pid>/environ` reads in a phase where `ps` ran are MEDIUM, not HIGH: procps-ng's
    `ps -o command` opens every process's environment (measured on the host: 384 opens; none
    with `-o pid=`). Not dropped, because harvesting environments is a stealer's move; any
    other credential path, `/proc/self/environ`, or a `ps` in the package keeps it HIGH
    (`triflux`).
  - `.npmrc` reads in `import` are npm's when npm or npx ran in that phase, as they already
    were in `install` (`cs-devtest` runs its own `npm install`).
  - Left HIGH: `bug-killer` writing its launcher and running it, and `triflux` copying its
    HUD into `~/.claude/hud` and running it. Both are indistinguishable from a dropper in the
    trace.
- **Proposed a sinkhole network** ([proposals/sandbox-sinkhole.md](proposals/sandbox-sinkhole.md)):
  airgapped still, but a sink container owns the network namespace, answers DNS with
  synthetic addresses, and records names, TLS SNI and plaintext HTTP. Awaiting the owner's
  review; it changes decision 0014's network mode.

### Challenges
- **Verdict corrections and new finds this round** (by claude): `triflux@10.93.0`,
  `cs-devtest@1.4.0` benign; `atlassian-wallboard-plugin1@10.0.88` benign and tagged probe
  (JSFuck that decodes to `console.log("a")`; the sandbox confirmed it only printed `a`).
- **pytest silently ran the main checkout's code** from the worktree (the venv's editable
  install wins). A new test "failed" for the old code while 55 others passed.
  - **Resolution:** `PYTHONPATH=src` for every gate in a worktree (already noted for scripts;
    true for pytest too).

### Evaluation snapshot
- Stage 5 on 138 results: malicious versions given a sandbox finding 0 of 3. Versions with a
  HIGH sandbox finding 8 → 5 (all benign; `jive` x2 keep `persistence-write` for a documented
  systemd unit, `bug-killer` x2 and `triflux` keep `download-exec`).

### Open questions / next steps
- The owner's call on the sinkhole proposal (four open questions in it).
- `@deadbolt/cli` dev builds: tarball not captured, code unread; same binary-link shape.

## 2026-11-01 (afternoon): The local sandbox runs; three setup failures on the way

**Stage(s):** Stage 5 (local Docker runner, `tools/sandbox/`)
**Context:** The owner ran `sudo bash tools/sandbox/setup.sh` on the VM (Ubuntu, Docker 29.7.2)
and sent the output of each attempt. I can't run Docker myself (no root, not in the `docker`
group), so every fix was made from their pasted output.

### Challenges
- **`docker save | podman load` lost the image's name.** Docker 29 exports an OCI archive whose
  only ref name is the tag, so podman loaded it as `localhost/rel-38:latest`, and the inspect
  by `gcr.io/ossf-malware-analysis/dynamic-analysis:rel-38` failed. Re-tagging the loaded name
  (0b7122e) failed the same way on the owner's rerun, for a reason I couldn't see without root.
  - **Resolution:** 73f8c1e: the analysis container's podman pulls the sandbox image itself by
    its pinned digest (network for that setup container only), as package-analysis normally
    does, and the setup prints the store's images on any failure.
  - **Why it worked:** the owner's next run printed the image id
    (`ce9afdef4d4e…`) in step 4.
- **The smoke test "passed" with no result.** Docker exited 0 and wrote nothing; the runner
  printed the analyser's output only on a nonzero exit.
  - **Resolution:** ec35f6b: a failed smoke run lists every file the job wrote and the last
    60 lines of output. That showed the real failure: "failed to start packet capture
    (couldn't query interface cni-analysis)". rel-38 starts its pcap on podman's analysis
    bridge even with `-offline`, where the sandbox joins no network and the bridge never
    exists, so every offline run aborted before the install, and `analyze` still exits 0.
  - **Resolution:** ff171b9: the runner starts `analyze` through a fixed `/bin/sh -c` shim that
    adds an empty dummy `cni-analysis` interface in the analysis container's own namespace
    (rel-38's capture opens the interface by name, with no filter or address lookup). Job
    values pass as `"$@"`.
  - **Why it worked:** the smoke run then wrote `1.0.0.json`. The install phase shows
    `npm install` of the tarball and the postinstall `node -e "console.log('kitsunox smoke')"`
    inside gVisor (systrap, no `/dev/kvm` on this VM); the only socket is npm's DNS attempt to
    127.0.0.1:53. Kitsunox's importer accepted it (1,529 observations, bait values masked) and
    the sandbox rules gave only `sandbox.ran` and `sandbox.quiet` (INFO).
- **Review gate:** the owner enabled `kitsunox-sandbox.timer` before I had read the smoke
  result; I read it right after (above), and nothing in it argues against running.

### Open questions / next steps
- First real jobs: the 19:28 UTC tick exported 10 (5 as offline bundles); the timer runs at
  :25. Check the first imported results for false positives from the dummy interface (none
  expected: it carries no packets) and for installs that fail offline.
- Runs collected before `KITSUNOX_SANDBOX_RESULTS` was set exported nothing; their
  inconclusive obfuscated-install versions (`motionchart-cli`, `sppurt`,
  `@routinecrew/routinecode`, `calculatorscool346@1.0.1`) can be exported with
  `kitsunox sandbox <run_id>` while their runs are kept.

## 2026-11-01 (morning): Bug-bounty probes: judged by behaviour, tagged `probe`

**Stage(s):** reviewer verdicts (`reporting.verdicts`, viewer, CLI, daily summary)
**Context:** About a third of the verified-malicious tally is dependency-confusion and
bug-bounty probes. The owner: "I am uncertain whether or not to report those seemingly benign
bug bounty entries as malicious those are likely mass produced legitimate bounties by AI.
However, I could see real malware diguising itself as a bounty placeholder or PoC". They
accepted both proposals: a behaviour rule and a tag
([decision 0015 addendum](decisions/0015-reviewer-verdicts.md)).

### Decisions
- **Malicious if identifying data leaves the machine or code is fetched and run**, whatever the
  "authorized test" notice says; benign if only local (calc.exe, a marker file). The notice is
  free text an attacker can copy, and `claims-ac1` showed a "probe" family moving to fetched
  code. The four packages npm removed after we reported them were all probes that sent machine
  data out, so this matches the registry's own line.
- **A `probe` tag, not a fourth verdict.** A fourth verdict would merge the harmless calc.exe
  PoCs with the ones that send `whoami` to Burp Collaborator, and give disguised malware the
  mild label. The tag is orthogonal: counts can say "26 malicious, 16 of them probes".

### Challenges
- **Earlier verdicts didn't follow one line.** `@mobile-platform/magnetic-components@0.0.1`
  (writes a local marker file only) was malicious, while `calculatorscool346@1.0.0` (spawns
  calc.exe only) was benign.
  - **Resolution:** 0.0.1 re-recorded benign; its 0.0.3, which adds the oast.me DNS beacon,
    stays malicious. 22 verdicts re-recorded with the tag (16 malicious, 6 benign) by a script
    that finds each entry by name and version in its run's current report, since re-scores
    moved ranks (`dependencykfeg@1.5.6`: 368 → 59). Tally: 26 malicious (16 probes),
    27 inconclusive, 976 benign (6 probes).
- **Edge kept benign:** `calculator-preinstall-hook-demo@1.1.1` posts a fixed text to a Discord
  webhook. The post says nothing about the machine, and the webhook owner doesn't see the IP,
  so nothing identifying leaves; its 1.1.2 adds hostname and user name and is malicious.
- **Kept inconclusive:** `@jarvis_1234/env-preloader@1.0.6` collects secret env-var names, user
  and host but sends them only to 127.0.0.1:9; `@atedone/workspace-bootstrap@0.0.1` hides an
  install step in `binding.gyp` but only writes a local file. Both look staged; their next
  versions decide.

### Open questions / next steps
- Turn verdicts into evaluation samples with the tag kept, so recall can be reported with and
  without probes.

## 2026-11-01 (early morning): False-positive cuts that keep the attacks, a local sandbox

**Stage(s):** Stage 4 (report decision, `npm.dependency.known-malware` v3), review queue,
Stage 5 (local runner)
**Context:** The owner: "I feel like 968 benign is a lot. Is there a way we can bring down the
false positives while retaining the true positives?", then asked for sandbox setup scripts and
chose Docker on this VM over a separate airgapped VM, and asked for signatures to classify
reposted malware at once (next entry).

### Decisions
- **Measure every cut against both the eval set and the live verdicts.** Simulated report
  decisions over the `vm-day1` dump and the current reports of all 1,020 verdicts
  (`session-scripts/policy/sim_weak.py`). Of 888 benign verdicts still reported, the big rules
  look benign-only live but carry real attacks in the eval set: demoting
  `revived-with-new-dependency` (-83) loses `xrpl@2.14.2`; `install-script-changed` (-105) loses
  `aicp-tracker`'s last reported release and `fooobar`; requiring two MEDIUM rules (-438) loses
  169 eval samples and 11 of 27 live malicious. Narrowing `revived` to unpopular dependencies
  fails too (`xrpl`, `is@3.3.1`, `vant` added popular ones), and literal-only install-script
  changes are only 24 of 146 and include URL swaps.
- **Adopted: `code.capability-gained` and `static.webhook-placeholder` join `WEAK_ALONE`**
  (Stage 4 v8): -63 live benign, nothing lost anywhere.
- **Adopted: "like a cleared version" in the queue.** 158 of 968 benign verdicts repeated a
  benign version's publisher and rules; the queue now says so next to the version. Not a
  suppressor: `calculator-preinstall-hook-demo` 1.1.1 (benign) and 1.1.2 (malicious) had one
  publisher.
- **`npm.dependency.known-malware` v3**: a Unity (UPM) package's `com.unity.*` dependencies are
  LOW. The 03:12 tick reported 41 `net.dreditor.*` Unity packages HIGH for depending on
  `com.unity.ugui` and friends, which are malware squats on npm but Unity's own modules in
  Unity's registry. With v2 (npm's holder), all four live false-positive kinds are now LOW.
- **package-analysis runs in Docker on this VM** (the owner's decision;
  [0014 addendum](decisions/0014-stage5-uses-ossf-package-analysis.md#addendum-2026-11-01-package-analysis-in-docker-on-the-kitsunox-vm)).
  The risk was put plainly first: the analysis container is privileged, so gVisor is the
  boundary; an escape would hold this VM (a read-only PAT and the webhook, rotatable), not the
  host. `tools/sandbox/` holds a one-time `setup.sh`, a root-owned runner that checks each job
  against the exact export shape and runs it with no network, read-only input and limits, and
  `uninstall.sh`. The owner worried the VM lacks nested virtualisation; package-analysis's
  runsc (gVisor 20260216) uses the systrap platform by default, which needs no `/dev/kvm`.
  The setup leaves the timer off until the smoke result is reviewed (0014's review gate).

### Challenges
- **The re-score lesson again, avoided:** the 03:12 run was re-scored at 03:22, right after
  its tick (50 -> 11 versions in its report).
- **Found while checking permissions:** `.env` was 664 (world-readable); the setup makes it 600.
  The owner's account is in `lxd`, which is root-equivalent on its own.

### Evaluation snapshot
- `vm-day1`: 2,505 malicious and 15 benign reported before and after both Stage 4 changes.
  Live: 888 -> 825 benign verdicts still reported; 27 / 27 malicious and 18 / 18 inconclusive
  kept. Last 26 ticks: 324 reported of 96,550 versions, 307 benign.

### Open questions / next steps
- First sandbox results: confirm bundles install offline (sandbox.md's evaluation step 1).
- **Signatures for reposted malware: `static.known-signature`** (Stage 2; owner: "make
  signatures based on known threats to immediately classify that malware that was re-posted").
  Nine signatures from our malicious verdicts: endpoints, accounts, wallets, and for the tavern
  stealer the API calls every republish decodes to (its four copies share 1,705 of 1,715
  decoded strings; only the XOR key changes). Matching sees through one-byte-XOR string tables,
  javascript-obfuscator arrays and base64 literals. HIGH, weight 6, never demoted as "not new".
  Over 814 benign, 26 inconclusive and 6,004 other captured tarballs it matched only the benign
  `calculator-preinstall-hook-demo@1.1.1` (same webhook as its malicious successor) and
  `dependencykfeg@25.1.9`, an unreported release of a confirmed probe family. Not measured on
  `vm-day1` on purpose: signatures built from our verdicts would only re-find their sources.

## 2026-10-31 (evening): Confirmed after the fact, a Baileys policy, a fourth stealer republish

**Stage(s):** Review queue and viewer (`evaluation/confirmations.py`, `reporting/queue.py`,
`web/pages.py`); `collect`
**Context:** The owner answered three questions from the afternoon: Baileys forks, obfuscated
install code (Stage 5), and the known-malware false positives. For the last they suggested
using npm's removals as evidence that we catch real malware, then refined it: "don't use NPM
removed as a rule, we want to identify our own malware, but we should flag it if it is removed
after the fact".

### Decisions
- **Takedowns and OSV records are a flag, never a score**
  ([decision 0016](decisions/0016-after-the-fact-confirmations.md)). npm replaces a removed
  package with `0.0.1-security` from its own `npm` account, and that publish is in the changes
  feed we already record: 39 takedowns in our runs since 2026-10-29. `collect` now scans each
  new run for them (`data/takedowns/npm.json`), and the queue marks every version a later
  takedown or a covering OSV `MAL-` record confirms, counts verdicts confirmed since, and lists
  benign or inconclusive ones to review again. Alternatives were a scoring rule (rejected by the
  owner: recall must measure our own detection) and polling the registry for every reported
  package (needless requests: the feed already carries every takedown).
- **Baileys forks that make the user's WhatsApp account follow channels are malicious**
  (owner: "if npm flags those forks as malicious we should match their behavior"). The evidence:
  OSV holds about 200 `MAL-` records for Baileys/WhatsApp forks; npm removed four in our feed
  this week (`@chatunitycenter/baileys`, `grizzly-baileys`, `ourin-baileys`, `neuralwhatsapp`),
  and `@sauruslord/baileys` and `sauruslord-baileys` share the `sauruspro-bail` author's
  marker. Re-recorded as malicious: `luna-baileys`, `sauruspro-bail`, `kevinx-baileys`,
  `@bil-rgb/baileys`, `@lekzsync/baileys`; new: `@chatbridgeworld/baileys` (five hard-coded
  channels followed 90 s after connecting). Left inconclusive: `@prasstzymhtrr/baileys`
  (announces the follow and honours `NO_AUTOFOLLOW=1`) and `testbail` (unpublished unread).

### Challenges
- **The fourth tavern-family republish ranked 21st of its run** (`persona-ai-sdk@1.0.0`,
  publisher `gendomidas`, score 6 from `static.obfuscated` alone). Importing `./personas` runs
  `cache-warm.mjs`; its XOR+base64 string tables decode to AWS `GetCallerIdentity` and
  `ListAccountAliases`, Bedrock's `/create-foundation-model-agreement`, a Groq key pattern and a
  filesystem walk: LLM-credential theft, as in `tavern-ai-sdk`, `char-ai-sdk` and
  `character-ai-sdk`. The ranking gap from the afternoon entry is unchanged; a rule for these
  string tables still needs measuring on obfuscated benign packages first.
- **A three-hop dependency chain scored 3** (`claims-ac1`, the `claims-acct-unlock` family):
  its dependency `node-ac2` is a GitHub tarball whose own dependency `node-ac3` (same repo) has
  a preinstall that fetches a C2 hostname from a GitHub text file and POSTs the home directory,
  working directory and platform to it. Stage 4 sees only the first hop
  (`npm.dependency.non-registry`, MEDIUM); the payload is two non-registry tarballs away.
  Reading non-registry dependency tarballs is a possible Stage 4 addition, not started.
- **A re-score skipped the 01:58 tick (again).** Re-scoring the two `sino-bc-cli` runs
  (23k versions each, about 35 minutes) held `DataDir.lock()` when the timer fired, so
  `collect` logged "skipped, data is in use" — the same mistake as the morning's, with a
  smaller job. Nothing was lost: the checkpoint didn't move, and a catch-up tick started by hand
  at 02:12 chained from the 00:57 run. A re-score of a large run has to start right after a
  tick, or go through the driver with its gap check.
- **`npm.dependency.known-malware` fired on `modulus-firewall@0.1.1`**, whose dependency is
  `tree-sitter-dockerfile@^0.0.1-security`: the spec names npm's own holder, which installs
  nothing. Same publisher as the earlier `modulus-security` false positive.

### Evaluation snapshot
- Confirmed since (as of this entry): 7 versions with a malicious verdict (`@pcb-dp/qa-commons`,
  `claims-acct-unlock`, four `dependencykfeg`, `ssite-mock-server`), 0 inconclusive, 0 benign.
  Four benign packages have OSV records about *other* versions (`@builder.io/dev-tools`,
  `@onescience/onecode`, `@vibelet/cli`, `codeam-cli`); none covers a version we cleared.
- Queue: 96 versions from seven ticks reviewed to empty: 3 new malicious (`persona-ai-sdk`,
  `claims-ac1`, `@chatbridgeworld/baileys`), the rest benign (27 Meta `@astryxdesign/cli`
  canaries, 16 `@ejfkdev/*` binary installers, placeholders and fixtures). Four more ticks
  through 02:16 on 2026-11-01: one more malicious, `calculator-preinstall-hook-demo@1.1.2`
  (a "private test fixture" whose preinstall now posts the hostname and username to a Discord
  webhook; 1.1.1 sent fixed text and is benign). Tally: 27 malicious, 25 inconclusive, 968
  benign.
- After re-scoring with `install-script-obfuscated` v2: `motionchart-cli` 1.0.3 and 1.0.4
  (8, 9) and four `sino-bc-cli` betas (7) are HIGH. `whybug` (no hook) and `sppurt` (known
  limit) are not; the earliest `sino-bc-cli` betas and `calculatorscool346` are in the
  110k-version first run, not re-scored.
- One recall miss in hindsight: `tailwindcss-visual-kit@1.3.7` (2026-10-29) added a dependency,
  `@nexlayerlabs/postcss-keyframe-utils`, that npm removed the next day; we scored it 1. Its
  malicious versions predate our feed, so no stage saw the code.

### Open questions / next steps
- Stage 5 for the obfuscated install code (`sppurt`, `motionchart-cli`, `sino-bc-cli`,
  `whybug`, `calculatorscool346`): the owner asked for a sandbox run and to flag such code. The
  airgapped analysis VM is not set up and no results root is configured, so nothing can run
  yet. The flag is a new Stage 3 rule, `npm.install-script-obfuscated` (HIGH, weight 4: a file
  `npm install` runs has javascript-obfuscator identifiers; on updates only new or changed
  ones). `vm-day1`: fires on 96 malicious samples and 0 of 1,500 benign, changes no reporting
  decision; it raises rank, so these versions lead the queue and Stage 5's per-run cap of 30.
  After the re-score of four runs it flagged only `motionchart-cli`: `sino-bc-cli` is
  javascript-obfuscator output with renamed identifiers (no `_0x`), so v2 also recognises the
  tool's string-array rotation prologue (`vm-day1`: 100 malicious samples, was 96; 0 benign);
  `whybug` has no install hook; `sppurt` starts its 3 MB obfuscated CLI through
  `execFileSync(process.execPath, ['dist/cli.js'])` from inline `node -e`, which install-code
  following doesn't trace and whose size is over the followed-file cap (a known limit).
- **`npm.dependency.known-malware` v2: LOW for a specifier only npm's holder satisfies.**
  Skipping them was the first idea (3 of the rule's 4 live false positives pin
  `0.0.1-security`, which installs nothing). `vm-day1` showed why not: 6 of the 12 malicious
  samples the rule fires on have `fs: ^0.0.1-security` too (a tailwind-icon campaign,
  `vite-support-kit`); attackers run `npm install fs` as carelessly as anyone. Neither variant
  changes a reporting decision (2,505 / 17); LOW keeps the evidence and part of the score.

## 2026-10-31 (afternoon): Re-score results, a prerelease downgrade, three skipped ticks

**Stage(s):** Stage 0 (diff base 4), Stage 1 (`npm.publish-method.downgrade` v3), Stage 2
(files with no counterpart)
**Context:** The re-score of the queue finished (two runs are being redone with the morning's
rules). Over the 19 re-scored runs the queue went from 1,944 reported versions to 729 (-62%);
no version with a malicious or inconclusive verdict dropped out. 640 versions in the queue were
still unreviewed. Grouped by the MEDIUM+ rules that carry them, the second-largest group was
`publish-method.downgrade` alone.

### Decisions
- **`publish-method.downgrade` v3: LOW, weight 1, on a prerelease.** 77 of the 101 queue
  versions reported by this rule alone were prereleases (`-dev.`, `-canary.`, `-staging-`),
  mostly watched packages' hand-published dev builds (`@builder.io/dev-tools`,
  `@koda-sl/baker-cli`). npm installs a prerelease only when asked for it by version or tag.
  - **Trade-off:** the rule can't see dist-tags, so a prerelease an attacker also tags
    `latest` is LOW here. Reading dist-tags at ingest would close that.
- **Diff base 4: OpenHarmony builds are platform builds** (`.ohos-arm64`).
  `@bitfun-test/bitfun@0.2.19-daily.20261031` was diffed against
  `0.2.19-daily.20261030.ohos-arm64`, so its postinstall read as changed (HIGH), the case diff
  base 3 fixed for Windows and Linux builds. Recorded runs replay with their own diff base.

- **Stage 2: a file with no counterpart is compared with all of the base's code.** A match is
  "not new" when the base's file at the same path, or its content-hashed chunks of the same
  name, had it. A chunk renamed in a way `unhashed` can't see (Bun's `chunk-eevqxagd.js`, a
  Vite name with no digit such as `main-Zlzlhfga.js`), code moved to a new path, or a versioned
  directory (`gina`'s `framework/v0.7.7/`) read as new in every release. Such a file is now
  compared with what any base code file matched (`BaseFiles.anywhere`; docs, types, source maps
  and tests excluded), computed once per base. A file with a counterpart keeps the stricter
  comparison, so an exfil URL added to a file that didn't have it is still new.
  - **Estimate first** (`exfil_anywhere.py`): of 46 queued exfil-endpoint versions with a base,
    28 already had the literal in another base code file, 27 of them reported by it alone.
  - **Cost:** `esoftplay@0.0.248`, which moved its Telegram code into new files; 8 of the
    family's 22 samples (from 0.0.142-m) are still reported.

### Challenges
- **Three ticks were skipped (06:42, 07:42, 08:42).** The re-score of the first VM day
  (110k changes) was started with no gap before a tick, and held the data lock for 179 minutes.
  The 09:45 tick ingested the whole gap (11,320 changes, window covered), so nothing was lost,
  but three hours were reported late.
  - **Resolution:** later re-scores keep a 20-minute gap and are small.

### Review
- **The queue was reviewed to empty**: 652 unreviewed versions at 13:52, 0 by 14:44 (all 26
  queued runs). Versions scored 5 and above had their install code read (fetched tarballs, or
  Stage 2's captured blob for unpublished ones); below that, most verdicts rest on the
  report's evidence excerpts.
- **Malicious (new):**
  - `tavern-ai-sdk@1.0.0`, a credential stealer posing as a persona loader: XOR+base64 string
    tables decode to AWS SigV4 calls, `gsk_`/`sk-proj`/`secretAccessKey` patterns, SSH keys, an
    ERC-20 `transferFrom` selector and a beacon loop; native `node-vm-detect` binaries for
    sandbox evasion. Reported only at score 5 (four `static.obfuscated`); npm removed it two
    hours after publish.
  - Three dependency-confusion probes from one Bugcrowd researcher account
    (`internal-renderers`, `pandafortunerush`, `ms-client-portal`, 1.0.0 and 10.0.0): install
    hooks send user name, hostname and working directory to a bare IP.
  - `char-ai-sdk@1.0.0` and `character-ai-sdk@1.0.0` (14:46 tick): the same stealer,
    republished by a new account (`character-ai-labs`); still published at 14:55.
  - `dependencykfeg` 2.1.3, 25.0.3, 25.1.3 and `claims-acct-unlock@25.2.1` (publisher `weqwe`):
    DNS and Burp Collaborator beacons, and a payload pulled from a raw GitHub tarball. npm has
    replaced both with `0.0.1-security`.
- **Inconclusive (new):** six more Baileys forks that follow WhatsApp channels with the user's
  account on connect (`sauruspro-bail`, `kevinx-baileys`, `@bil-rgb/baileys`,
  `@lekzsync/baileys`, `@prasstzymhtrr/baileys` (disclosed, opt-out), and `testbail`, by the
  `luna-baileys` publisher, unpublished before it could be read); packages whose install runs
  a fully obfuscated bundle (`sppurt`, `motionchart-cli`, six `sino-bc-cli` betas), Stage 5
  jobs; `whybug` (obfuscated, mentions a relay).
- `modulus-security`'s and `victor-nest-resource`'s known-malware HIGHs were dependencies held
  by npm's `0.0.1-security` placeholder (`tree-sitter-dockerfile`, `fs`); so was
  `com.hidano.shadow-only-shader`'s (a Unity built-in module name).

### Removed / abandoned
- **`install-script-changed` counting a hook's own file only when its change adds a risky
  line** (the criterion v3 applies to files a hook merely loads). On `vm-day1` it lost 9
  malicious samples (8 `esoftplay` releases, `fooobar@1.0.14`), whose payload edits an
  existing hook file without adding a new network or process import, and cleared no benign
  sample. Dropped.

### Evaluation snapshot
- `publish-method.downgrade` v3: `vm-day1` unchanged (2,506 malicious, 17 benign reported by the
  dump); the rule fires on 149 malicious samples, none a prerelease.
- Stage 2 base-wide comparison: 2,506 → 2,505 malicious (`esoftplay@0.0.248`), benign unchanged.
- **Ranking gap:** `tavern-ai-sdk` and its two republications (`char-ai-sdk`,
  `character-ai-sdk`, still live at 14:55) were reported only at score 5-6, through
  `static.obfuscated` alone: their XOR-encoded string tables hide everything the capability and
  exfil rules look for.

### Open questions / next steps
- Read dist-tags at ingest, so a prerelease tagged `latest` keeps the downgrade's weight.
- A dependency npm holds as its `0.0.1-security` placeholder needn't be HIGH (three of three
  live known-malware HIGHs this period). Needs Stage 4's dependency lookup to fetch
  known-malware names: a contract change, so not done in passing.
- `install-script-changed` alone carried 120 queue versions, nearly all ordinary installer
  edits. Reviewing them is still the price of catching edits to an existing hook file (see
  Removed / abandoned).
- Policy question for the owner: should Baileys forks that follow channels with the user's
  account (hidden or disclosed) be malicious rather than inconclusive?

## 2026-10-31 (morning): `binding.gyp` as install code, extractor v4, every chunk compared

**Stage(s):** Stage 2 (hashed chunks), Stage 3 (install code, capability extractor)
**Context:** Two items from the previous entry's review. `@atedone/workspace-bootstrap` ran
code at install with no install script, through a `binding.gyp` action, and avoided the
extractor's tells. Separately, the `@wirecat/*` CLIs reported HIGH in every release (about 10
reports in two ticks) for a bundled ngrok region table the base already had.

### Decisions
- **`binding.gyp` commands are install commands** (`install.gyp_commands`). npm runs
  `node-gyp rebuild` when a package has `binding.gyp` and no install script, and node-gyp runs
  each target's `action` and every command expansion (`<!(...)`, `<!@(...)`). Their `node`
  files are followed like a hook's, and inline `node -e`/`-p` code is read as
  `binding.gyp#commands.js`.
- **Extractor v4:** `process.getBuiltinModule(m)` counts as `require(m)` (a computed name is
  `dynamic-require`), and `Reflect.get(process, 'env')` as `process.env` when the whole object
  is used.
- **Every base chunk with the same unhashed name is compared**, not the first 4. The esbuild
  bundles split one name into many chunks, so the chunk holding the ngrok table was never
  among the 4 compared. Keys are memoised per base, so the cost stays small.

### Evaluation snapshot
- `vm-day1`, against the previous entry: 2,503 → 2,506 malicious reported, benign unchanged.
  The 3 are `awaitly-visualizer` (2.0.2, 13.0.1, 22.0.2), whose `index.js` runs at install
  only through `binding.gyp`.

### Open questions / next steps
- Re-score the queue with these rules once the current re-score finishes.

## 2026-10-31 (early morning): Third precision pass, from the re-scored queue

**Stage(s):** Stage 0 (diff base 3), Stage 2 (`exfil-endpoint` v4, hashed chunks), Stage 3
(`install-script-changed` v3, `capability-gained` v4)
**Context:** Re-scoring the queue (previous entry) took the first eight runs from 211 reports
to 120, with no malicious or inconclusive version dropped. Reviewing what was left, and the
new ticks, showed five causes of noise that recur. Each change below was measured on `vm-day1`
in a separate worktree before the ticks ran it.

### Decisions
- **A file a hook only loads counts as changed only when it adds a risky line**
  (`install-script-changed` v3). Following imports (previous entry) made the rule see ordinary
  library edits: 7 of the 120 re-scored reports came from that alone, all benign, 6 adding no
  risky line. Cost: 3 `aicp-tracker` versions; the family is still reported through 1.0.7.
- **Vite's hashes are recognised** (`static.unhashed`): an 8-character suffix with no digit or
  with `-`/`_` (`settings-panel-Bkki_GMk.js`). Unrecognised, `glimmervoid`'s settings panel
  was a new file each release, so its Telegram help text was HIGH in about 25 queued releases.
- **Written Telegram placeholders are documentation** (`exfil-endpoint` v4): `bot<token>`,
  `botYOUR_...`, `bot...`. A URL built from a variable still matches: dropping that cost 29
  malicious samples last time (see 2026-10-30, second pass).
- **After an empty placeholder base, gaining network plus another capability is LOW**
  (`capability-gained` v4). 11 queued reports were first real releases after
  `0.0.0-placeholder` or `1.0.0-reservation.0`.
- **Diff base 3: a release isn't diffed against a platform build** (`0.5.4-latest-windows-x64`).
  Such builds carry one binary and no postinstall, so the release's postinstall read as added,
  HIGH: 8 reports in two days (`@ozyman42/ozy-cli`, `@kernaut/kernaut`, `@bitfun-test/bitfun`).
  The rule is recorded per run, so older runs replay with diff base 2 and a re-score keeps
  their bases.

### Challenges
- **The first `capability-gained` v4 cost 18 malicious samples.** Making every gain after an
  empty base LOW dropped the `autotel-*` / `awaitly-*` family, which publishes an empty first
  version and then an `eval(` payload: exactly the takeover shape the rule exists for.
  - **Resolution:** `eval` stays MEDIUM after an empty base; only the network combination is
    LOW.
  - **Why it worked:** the final eval loses none of the 18, and the live first releases it
    targets reach network through imports, not `eval`.
- **The first eval run of `install-script-changed` v3 was stopped:** it decided which files the
  hook names from the registry manifest, which eval samples may lack. It now works out loaded
  files from the install files themselves (`install.loaded_files`).
- **The previous commit (7d8333e) failed mypy** on one test (`(finding,) = ... or (None,)`).
  Fixed here; all four gates pass.

### Review
- 56 more verdicts, all benign but one. `@atedone/workspace-bootstrap@0.0.1` is inconclusive:
  no install scripts, but a `binding.gyp` *action* runs `node scripts/write-state.js` during
  npm's implicit `node-gyp rebuild`, and the script avoids common tells
  (`process.getBuiltinModule('fs')`, `Reflect.get(process, 'env')`). Today it only writes a
  state file into the project, so it looks like a probe of what scanners read.
- Large tarballs Stage 2 skips (16 MB cap) were read by hand where an install hook needed it
  (`keyrouter`, a 9router rebrand; `vibelet`; `@safetech/inheriti-cli`).

### Evaluation snapshot
- `vm-day1`, against the previous entry's rules: 2,506 → 2,503 malicious reported (the three
  `aicp-tracker` versions); benign reported 4 fewer (`domain-driver`, `@mastra/e2b`, two
  `glimmervoid` releases).

### Open questions / next steps
- Read `binding.gyp` actions and command expansions (`<!(...)`) as install code, and treat
  `process.getBuiltinModule(...)` and `Reflect.get(process, 'env')` as `require` and
  `process.env` in the capability extractor (`@atedone/workspace-bootstrap`).
- Re-score the runs re-scored before this pass, so the queue reflects it.

## 2026-10-31 (small hours): Faster Stage 4, a missing-base fix, install imports, re-scoring

**Stage(s):** Stage 3 (install profile, previous outside the batch), Stage 4 (worker
processes), reports (`kitsunox rescore`)
**Context:** The owner asked for the queue to be re-scored with the current rules, for Stage 4
to be faster, and for install scripts' imports to be followed.

### Decisions
- **The slow ticks were mostly us.** The tick runs at `Nice=10`; Stage 4 took 24 minutes while
  an eval and a re-analysis ran at normal priority beside it, and 3 minutes for a larger run
  with nothing beside it. Side jobs now run at `nice 19`.
- **Stage 4 extracts and compares in worker processes** (`repo.compare_pool`: three,
  `forkserver`, each replaced after 25 comparisons). A replayed tick's Stage 4: 679 s in
  threads, 325 s with the pool, byte-identical `correlate.jsonl`.
- **Stage 3 fetches a previous that is neither the base nor in the batch.** `@bike4mind/cli`
  publishes snapshots of many branches at once, each following its own branch's last snapshot;
  with no `before`, `npm.install-script-code` counted all of their install code as new (the
  explanation lacked "new to the install code"). 47 queued updates, 40 reported for that alone
  (`@bike4mind/cli`, `@opencode/cli`, `@netlify/agent-runner-cli`).
- **Install code follows what it loads** (`install.followed_files`): constant relative
  `require`/`import`, `path.join(__dirname, ...)`, `new URL(..., import.meta.url)`, two levels,
  20 files of at most 256 KiB. `vm-day1`: 2,506 malicious reported (was 2,494), none lost, 19
  benign (one added).
- **`kitsunox rescore`**: Stages 1-4 and the report again on finished runs, seeded with each
  run's own Stage 2 and 4 snapshots, the tick's outputs kept under `before-rescore/`, the lock
  taken per run. A driver (`session-scripts/rescore_driver.sh`) runs it between ticks.

### Review
- `luna-baileys@1.0.0`, a new Baileys fork: on every connection it fetches a channel list from
  its author's GitHub and silently follows each channel with the user's WhatsApp account, and
  `requestPairingCode` defaults to a fixed code. Inconclusive (covert account use, no
  credential theft found); the owner may want to call it malicious.
- `calculator-preinstall-hook-demo@1.1.0` runs `mshta.exe` on a bundled HTA from its
  preinstall, a self-described harmless test fixture of that technique.

## 2026-10-30 (late night): Second precision pass: what still reports under the current rules

**Stage(s):** Stage 2 (hashed chunks, docs-only matches), Stage 3 (`code.capability-gained`
v3, extractor v3, `npm.install-script-changed` v2), Stage 1 (`npm.dependency.non-registry`
v2), Stage 4 (LOW cap, lazy repository hashing), reports
**Context:** Reviewing two more ticks and the top of the backlog: 49 more benign, none
malicious (83 benign, 5 malicious, 4 inconclusive in all). The queue's 1,761 unreviewed
versions were mostly scored by older rules, which the queue never re-scores.

### How it was measured
- **What still reports:** Stage 2 re-run on every queued version from its run's captured
  tarballs (current code, REPLAY), the other findings re-graded as the current rules would,
  then the current decision (`session-scripts/policy/current_backlog.py`). Of 1,761
  unreviewed versions, 1,078 still reported before this pass.
- **Eval:** each change simulated on the `vm-day1` findings dump first, then a `pipeline+4`
  run with the Stage 2-3 changes, and the Stage 1/4 changes simulated on its findings: 2,494
  malicious reported (72.4%, was 2,496), 18 of 1,500 benign (was 20). The 2 lost
  (`@pixui-dev/pxw@0.1.23`, `securegate-cli-tool@2.1.4`) were caught only by the CRLF
  artefact below: follow-on releases whose install script didn't change but for line endings.

### Decisions
- **`code.capability-gained` v3:** gaining `dynamic-code` alone is MEDIUM only through
  `eval`. 85 of the 90 live reports it made alone that way were `new Function(body)` or `vm`;
  all 35 malicious samples it reported alone were injected `eval(` payloads (`autotel-*`,
  `awaitly-*`). Extractor v3 caps evidence per capability *and detail*, so three
  `new Function` calls can't crowd out a later `eval`.
- **LOW cap (Stage 4 v7):** rules with only LOW findings add at most 3 to the score, so LOW
  findings alone never report. They were 165 of the 1,078 still reported; on `vm-day1` only
  one malicious sample was reported by score alone, and it had a weak MEDIUM, which still
  reaches 6. 1,078 -> 886.
- **Hashed chunks:** Stage 2 compares a bundler's content-hashed chunk with the base's chunk of
  the same name without the hash (`@camstack/*`: a doc comment naming `*.trycloudflare.com`
  was HIGH on every release).
- **Docs-only matches are LOW for every static rule**, not just `exfil-endpoint`.
- **`npm.dependency.non-registry` v2:** a registry tarball URL of the same package is the
  registry; a `file:`/`link:` path is LOW (fetches nothing). Malicious samples all used
  `github:` or `http(s):`. With the docs change: 876 -> about 845.
- **`static.hardcoded-ip` v2** skips public DNS resolvers (`1.1.1.1`, `8.8.8.8`, ...): 29 of
  the 56 MEDIUM live findings were connectivity checks (`apify-cli`), none of the 159 in
  malicious samples. **`catalog:`** dependencies count as registry specs, like `workspace:`.
- **`npm.install-script-changed` v2:** a file whose only change is its line endings is
  unchanged (`@tera-system/pro`: CRLF to LF, reported "+0 -0 lines").
- **Stage 4 speed:** `compare_trees` hashed every file of the repository on every comparison
  to explain missing files; it now does so only when a missing file needs it, and `built_by`
  no longer copies the repository's contents. Stage 4 had grown to 16-40 minutes a tick.
  That wasn't the main cost: a sampling profile of one tick's Stage 4, replayed offline, put
  ~85% in extracting GitHub archives (pure-Python `tarfile` under the GIL, three extraction
  slots), with 373 distinct archives for 404 comparisons, so caching would not help. GitHub
  archives now skip the strict second tar pass that looks for hidden entries (about 16%
  faster on real archives); npm tarballs keep it. Extracting in worker processes is the
  larger fix, left for the owner's decision.

### Rejected or deferred
- **`dynamic-code` alone always LOW:** lost the 35 `eval` samples.
- **`.yaml` as non-executing, placeholder webhooks LOW:** 3 or fewer live reports each, and
  YAML/JSON can be configuration the code loads.
- **Re-scoring the queue:** old runs keep their old reports until they age out (7 days).
  Replaying Stages 2-4 of queued runs with the current rules would remove most of the
  backlog at once; it rewrites past reports, so it waits for the owner.
- **Following an install script's local imports:** `@next2012/aistudio-runtime`'s hook only
  imports `lib/postinstall.js`, which the install-code rules never read. For a new package
  that's a gap; to measure next.

## 2026-10-30 (night): A precision pass from the first live reviews

**Stage(s):** Stage 1 (`npm.publish-method.downgrade`), Stage 2 (not-new and docs-only
matches), Stage 3 (`code.capability-gained`, inline install code, constant code), Stage 4
(report policy, `npm.repo.install-script-not-in-repo`), viewer
**Context:** Reviewing the queue by hand: 31 benign for 5 malicious and 4 inconclusive. The
owner: "the more manual review required, the more likely the human will make mistakes". The
queue held 1,687 reported versions over about two days.

### How it was measured
- **Live:** which rules put each queued version there; then Stage 2 re-run (current code) on
  every reported entry from its run's captured tarballs, read-only, and the report policy
  applied to the result (`kitsunox-scratch/session-scripts/policy/`).
- **Eval:** `pipeline+4` on `vm-day1` with every sample's final findings dumped, so each
  candidate change could be simulated offline before being written, then one real run with
  all of them.

### Decisions (each measured; rejected ones below)
- **Stage 2: a match the previous version's file already had is LOW, weight 1**, and says
  so; an `exfil-endpoint` match only in a file that never runs (docs, `.d.ts`, source maps,
  tests) is LOW too. A changed file was matched whole, so a Telegram bot's endpoint or an
  obfuscated commercial build fired again on every release. Live: -15% of reports on its own
  (136 obfuscated, 93 exfil-endpoint). Eval: -8 malicious, all follow-on releases of a series
  whose first malicious release is still reported (`esoftplay`).
- **`code.capability-gained` v2:** gaining `env-all` alone is LOW. All 35 malicious samples it
  reported alone had gained `dynamic-code`; about 170 live reports were apps starting to read
  `process.env`.
- **Constant code isn't dynamic code** (extractor v2): `eval`/`Function`/`new Function` with
  only short constant strings (120 characters at most). `Function("return this")` was the
  commonest live `dynamic-code`. A long constant can be a payload (`calculatorscool346` passes
  obfuscator output to `Function` as one literal), so it still counts.
- **`npm.publish-method.downgrade` v2:** HIGH for watched packages, MEDIUM weight 3 otherwise,
  and then it doesn't report alone (`correlate.WEAK_ALONE`). 0 malicious lost.
- **`npm.repo.install-script-not-in-repo` v3:** LOW, weight 1, when the previous release
  shipped the same hook (Pulumi's generated hooks).
- **Inline install code is read** (`install_sources`): a `node -e` hook's code is profiled as
  `package.json#scripts.<hook>.js`. `dependencykfeg`'s whole payload was such a one-liner.
- **Package-wide verdicts in the viewer:** one click for every listed version of a package
  (at most 50, all checked to be the same package).

### Rejected after measuring
- "HIGH or score 6" for every rule: -202 malicious (`npm.install-script-code` alone catches
  85, new packages' install hooks 29). Only the unwatched downgrade became weak-alone.
- Capping LOW findings' share of the score at 2: -93 more malicious for -2 benign.
- `exfil-endpoint` HIGH only beside secrets or install-time code: -35 malicious, 0 benign.
- An install hook HIGH only when Stage 3 finds its code risky: -28 malicious, 0 benign.
- `revived-with-new-dependency` weak-alone: it alone catches `xrpl@2.14.2` (April 2025).

### Evaluation snapshot
- **`pipeline+4` on `vm-day1`, all of it: malicious 2,503 -> 2,496 (72.7% -> 72.5%), benign
  24 -> 20 (-17%).** Lost: 8 follow-on releases (above). Gained: `tnactgfds@0.30.5`. The eval's
  1,500 benign samples are too few to show the live effect; on the queue's two days the
  re-analysis gives 1,769 -> 1,160 reported versions (-34%), before the constant-code change.

### Open questions / next steps
- A version of a package with a malicious verdict should report its later releases whatever
  they score (the follow-ons the not-new rule hides); that needs verdicts in Stage 4's context,
  recorded per run for replay.
- `code.capability-gained` on ajv-style code generation (`new Function(names.self, ...)`) is the
  next largest live source.

## 2026-10-30 (evening): Reviewer verdicts in the viewer

**Stage(s):** report, queue, viewer, notifications
**Context:** The owner wants to review a reported version, mark it malicious, inconclusive or
benign, have it leave the queue and land on its verdict's page, and keep a running tally of
verified malicious releases. The viewer was read-only. Decision
[0015](decisions/0015-reviewer-verdicts.md).

### Decisions
- **Per-version verdicts in an append-only log** (`reporting/verdicts.py`,
  `data/verdicts/npm.jsonl`): last record wins, `reopened` returns a version to the queue,
  every record copies the entry as reviewed so it outlives the run's 7 days.
- **The queue leaves reviewed versions out** (`build_queue`; the viewer filters again at
  render time so a click takes effect at once) and carries the tally; so do the queue page and
  the daily Discord summary ("Verified malicious: N (+M that day)").
- **One write in the viewer, `POST /verdict`:** per-start `secrets` token in its own forms,
  `Origin`/`Sec-Fetch-Site` checks, 16 KiB urlencoded body, each field once; the package and
  version come from the report on disk by run id and rank; the redirect must be one of the
  viewer's pages; CSP `form-action 'self'`. No token (no forms, no POST) off loopback or with
  `--read-only`.
- **`kitsunox verdict` / `kitsunox verdicts`** record and list from a shell; `--by` names the
  reviewer, so an analyst's verdicts (mine are `claude`) are told apart from the owner's.

### Open questions / next steps
- Verified verdicts are live labels: turning them into evaluation samples (what the rules
  caught against what was verified) is the obvious next use.

## 2026-10-30 (afternoon): Reviewing the top live results; full previous releases; install-script diffs; daily Discord summary

**Stage(s):** Stage 0 (diff base), Stage 1 (`npm.install-hook`, routing), Stage 3
(`npm.install-script-changed`), Stage 2 (`exfil-endpoint` v4 reverted), notifications
**Context:** The owner asked for a manual check of the first VM day's top results, starting with
rank 1, `@nutui/nutui-react-taro@3.0.24-cpp-beta.4` (score 20), and then for two fixes it
pointed to: compare consecutive full releases, not a partial one; and diff an install script's
file rather than its command (`@pulumi/docker-build`). Also: one Discord post a day.

### What the top results were (every file read as data, nothing run)
- **#1 `@nutui/nutui-react-taro@3.0.24-cpp-beta.4`: benign, scored through a partial publish.**
  `beta.3` (26 minutes earlier) shipped 166 files of the 5,215 in `beta.2` and `beta.4`,
  without the UMD bundle and without `postinstall.js`. Against `beta.2`, `beta.4` has the same
  `package.json` (bar the version) and the same files; the code change is a 3-line popup-layout
  fix that matches the changelog. Per rule:
  - `npm.install-hook`, `npm.dependency.added`, `code.capability-gained`: true against `beta.3`,
    false against `beta.2` (the postinstall and the `@jmfe` dependency shipped in every release
    since `3.0.21-cpp`, May 2026; the `eval` is lottie-web's, in the UMD bundle `beta.3` lacked).
  - `npm.repo.install-script-not-in-repo`, `npm.repo.dependency-not-in-repo`,
    `repo.code-not-in-repo`: true to their wording, false in substance. The repo's build
    script (`scripts/build-taro.mjs`, lines 517-537) adds the hook and the dependency and copies
    `scripts/postinstall.js`, byte-identical to the shipped file.
  - `npm.install-script-code`, `static.dynamic-code`, `static.npm-publish`: accurate and benign.
  - **One real concern, for the maintainers:** the postinstall runs `npm-usage-stats` from the
    optional dependency `@jmfe/npm-usage-stats-tool@latest`, which isn't on the public registry
    (404; no public `@jmfe` packages; whether the npm org is claimed couldn't be checked behind
    Cloudflare). If someone else held that scope on npm, every install of the package's
    `latest` (this beta) would run their code. Today the optional dependency is skipped and the
    hook does nothing.
- **#5 `@pcb-dp/qa-commons@1.0.0`: a true positive.** A new package whose postinstall POSTs the
  hostname, home directory, platform and CI provider to a `webhook.site` URL ("Authorized Test
  Package"): a dependency-confusion probe. All three findings accurate.
- **#2 `open-walnut`**: a native-binary launcher; the postinstall fetches its own
  `@open-walnut/<platform>` package from the configured registry, checked against its sha512.
  Benign. **#3 `@odintest/astryxdesign-react`**: a copy of Meta's `@astryxdesign` under another
  scope (`repository` says `facebook/astryx`), no provenance; its install code only prints a
  hint. Benign code, unverifiable origin.

### Decisions
- **Diff base 2: a partial publish isn't a diff base** (`Packument.previous_version`). A
  candidate with under a quarter of the files (`dist.fileCount`, else `dist.unpackedSize`) of
  both the new version and the release before it is passed over, at most 3 in a row. "Both" is
  the safety: a release only smaller than the new one is kept, so a bloated malicious release
  can't push its diff base back to an older version that already had its install script. The
  rule is recorded per run (`RunManifest.diff_base`, 1 for older runs) and replay uses the run's,
  so old runs still replay identically. First VM day: 41 of 101,232 updates get another base
  (13 reported), `nutui` among them.
  - Alternatives: a minimum file count or "has `main`" (needs the tarball, which Stage 0 doesn't
    read); comparing with several earlier releases (more Stage 2-3 work for every version).
- **`npm.install-hook` v2: a command that changed only its own version string isn't changed.**
  `@pulumi/*` generate `node scripts/install-pulumi-plugin.js resource command <version>`, so
  every release "changed" its hook: 39 of the 52 changed commands on the first VM day.
- **Every update with an install hook goes to the tarball stages** (Stage 1 reason 4). Before,
  an update whose hook was word for word the same reached Stage 3 only when watched or grown, so
  a changed `setup.js` behind an unchanged `node setup.js` went unread in 1,440 of 2,251 hook
  updates (64%).
- **`npm.install-script-changed` (Stage 3, MEDIUM 3):** the files the hooks name, compared byte
  for byte with the previous version's; the evidence is the changed lines as a unified diff,
  rendered as a `diff` block in reports. A file whose only change is its own version string
  doesn't count. First VM day: 47 of the 601 hook updates with both tarballs captured (7.8%);
  not `@pulumi/*`, whose install file didn't change.
- **Discord: one summary a day** (decision 0011 addendum), on the first tick of each UTC day,
  from a tick log in `data/state/ticks.jsonl` and the day's reports; crashes at most once a day;
  `--notify-each-tick` keeps the old post.

### Challenges
- **`difflib` is quadratic on repeated, unjunked lines:** 20,000 lines cycling 150 values took
  45 s, and an attacker chooses an install file's lines. Files over 2,000 lines are reported
  changed without a diff (0.06 s worst case at 2,000).
- **The v4 revert** (entry below): a scan of mine missed 2-letter host labels.

### Evaluation snapshot
- **`pipeline+4` on `vm-day1`: A 90.9% -> 96.4%, A follow-on 29.5% -> 71.7%, B 67.8% ->
  69.0%, B follow-on 22.9% -> 55.3%; benign 1.1% -> 1.4% weighted (22 -> 24 of 1,500).** The
  baseline report is from 2026-10-29, so the `chai-*` rules are in the difference too. Of the 621
  malicious samples gained, 611 are updates with an install hook: mostly worm follow-ons whose
  hook was the previous malicious release's word for word, so Stage 1 never forwarded their
  code. The routing change is most of the gain. The 2 benign added are `glimmervoid`
  prereleases (a `bot${token}` Telegram reference, now read). Lost: `shoal-cli@0.4.3`, whose
  only catch was a `console.log` banner that changed only its version (`npm.install-hook` v2's
  intent). Peak 13.8 GB, 24 min.

### Open questions / next steps
- **Done the same day (owner's go-ahead): a hook the repository's build writes is a note.**
  `npm.repo.install-script-not-in-repo` v2 is INFO when every package file the hook names is in
  the repository byte for byte and another repository file holds the command (the version may
  be a placeholder); `repo.code-not-in-repo` accepts a file whose content is elsewhere in the
  repository. Stage 4 `STAGE_VERSION` 6. Re-run on the first VM day's 41 reported hits: 3
  cleared (`nutui` by `scripts/build-taro.mjs`, `@opencode/cli` x2 by `script/pack.ts`); the
  `@pulumi/*` ones still fire, because Pulumi's code generator writes their hook and nothing in
  their repositories mentions it. A repository that ships more than `REPO_LIMITS` allows
  (`bun`, over 50,000 files) isn't compared at all, as before.
- Whether to tell JD (`jdf2e/nutui-react`) about the unpublished `@jmfe` optional dependency.
- `npm.install-script-changed` alone scores 3, below the report threshold: whether a changed
  install file should be HIGH like a changed command, after a few live days of its rate.

## 2026-10-30 (late morning): Stage 5 downloads the tarballs no earlier stage captured; Stage 5 memory bounded

**Stage(s):** Stage 5 (package-analysis export)
**Context:** 78 of the first VM day's 984 reported versions had no captured tarball, so
Stage 5 could only say `sandbox.not-run` for them (entry below). The owner decided Stage 5
should download them, and that the bundle caps go up only if that doesn't risk memory later.

### Decisions
- **Stage 5 downloads a reported version's tarball when no earlier stage captured it**
  (`stages/sandbox.py: _download`). Only a live call with a results root downloads, only
  plain `https://registry.npmjs.org/` URLs, highest score first, through the stage's recording
  fetcher (`sandbox-snapshot.json` plus the immutable index), within the call's download
  budget. Nothing is run: the tarball is read for `package.json` and `binding.gyp`, as before.
  Stage 5 now reads tarballs up to 128 MiB (the export's limit) and 512 MiB unpacked
  (`spool.TARBALL_LIMITS`) instead of Stage 2's 16 MB.
  - Outcomes that leave nothing usable are recorded in `sandbox.json` (`tarballs`). "pending:
    the tarball is not downloaded yet (retried)" (budget or network) makes the run stale, so
    the next live call renders it again. "tarball download failed" (404, size limit, refused
    redirect) isn't tried again. A replay that misses the snapshot gives the recorded reason,
    or "infra-error: the tarball could not be read from the run's snapshot".
  - Alternatives: let Stage 2 fetch big tarballs without parsing them (it would still not
    cover the 21 versions Stage 1 passed over), or select on the registry metadata's scripts
    (manifest confusion: the tarball is what npm runs).
  - Estimate for the first VM day: 78 downloads, 3.65 GiB unpacked declared (p50 27 MiB,
    max 301 MiB), none over 512 MiB, so likely one or two calls' budget.
- **The bundle caps stay where they are.** Raising the unpacked cap (for `@opencode/cli`)
  raises what one bundle holds in memory, inside a tick that also runs Stage 4 at up to
  ~18 GB. Instead, memory was taken out of the stage:
  - `_render` streamed its input. It used to parse all of `correlate.jsonl` into objects, which
    for a 110k-version catch-up is the ~4 GB that OOM-killed Stage 4. Now it keeps only the
    reported versions (`CandidateFile`).
  - Built bundles wait on disk (`data/sandbox/staging/<run>/`, removed when the call ends),
    and the export writes one job at a time. Before, up to `cap` (30) bundles and tarballs of
    up to 128 MiB each were held until the end of the call: up to ~7.5 GB.
- `STAGE_VERSION` stays 8 (bumped earlier the same day, nothing exported yet).

### Tests
`test_stage5_downloads_a_tarball_no_earlier_stage_captured`,
`test_a_download_over_the_budget_or_offline_waits_for_the_next_call`,
`test_a_failed_download_is_recorded_and_not_tried_again`,
`test_a_refused_download_is_not_tried_again`, `test_without_a_results_root_nothing_is_downloaded`,
`test_a_non_registry_tarball_url_is_never_downloaded`,
`test_a_replay_without_the_recorded_download_says_so`. The Stage 5 test world now routes every
call through a mock registry, so no test can reach npm.

### Open questions / next steps
- After the first live Stage 5 call: download volume and time, and how many of the 78 have
  install hooks.

## 2026-10-30 (morning): First VM day measured; bundle per-file limit; three rules checked against live data

**Stage(s):** Stage 4 (review of live hits), Stage 2 (`static.exfil-endpoint`), Stage 5 bundles
**Context:** The catch-up Stage 4 of `20261029T221803Z-npm` (110,084 versions) finished at
09:37 UTC: 984 reported. With a full live day in hand, I measured what the night's work had
left open (bundle completeness, the tick's time and memory) and went through what makes the
336 HIGH entries HIGH. Numbers are in [validation.md](validation.md).

### Decisions
- **A dependency file may take the bundle's whole unpacked cap** (`BundleCaps.extract_limits`,
  and what is left of it in `fetch_dependencies`). On the live run 12 of 154 bundles were
  `incomplete` only because one file was over `extract_tar_gz`'s default 64 MiB: the native
  binaries of bun, opencode and `@square/cli`. Those CLIs ship their binary through a
  platform package that a postinstall checks, which is the behaviour the sandbox should see.
  Memory is unchanged: a bundle already peaks at the unpacked cap. Offline-installable went
  from 123 to 135 of 154 (87.7%). Stage 5 `STAGE_VERSION` 8. Test:
  `test_one_dependency_file_may_take_what_is_left_of_the_unpacked_cap`.
- **`static.exfil-endpoint` v4 (ngrok's region hosts are not tunnels): adopted, then
  reverted.** `eu.ngrok.io` and its siblings are ngrok's own servers; 9 live reported versions
  (6 packages) had only those. My per-sample scan said no `vm-day1` sample had one, but it only
  counted host labels of 3 or more characters. The confirming `stage2-rules` run lost 11
  malicious samples (`gina`, `cro-pricing`, `edgeone`, ...) caught only through such lists.
  Back to v3; `test_tunnel_suffixes_and_region_hosts_still_count` keeps them firing.
- **Kept as they are, after measuring:**
  - `npm.dependency.known-malware` on `fs`. OSV lists npm's `fs` and `http` names as malware.
    The one live hit (`victor-nest-resource`) adds `fs`, `child_process`, `path` and `util`.
    On `vm-day1`, 20 malicious samples and 2 benign add a dependency named like a Node
    built-in, so it is a malware habit, not noise.
  - `npm.publish-method.downgrade`, the commonest sole reason for HIGH (125 entries). In 120
    of 127 live hits the account had published the package by hand before, in 57 even after
    the package's first CI release. Firing only when it hadn't would clear those 57 but lose 7
    of 149 malicious samples, among them `axios@1.14.1` and five `@nx/*` releases. A stolen
    token of a maintainer who sometimes publishes by hand looks exactly like that.
  - `static.exfil-endpoint`'s Telegram and tunnel forms. Live benign code mostly has
    `api.telegram.org/bot${token}` or a bare `".trycloudflare.com"`. But requiring a literal
    bot token or a concrete tunnel host would drop 30 malicious samples (29 caught by nothing
    else) to clear 4 benign.

### Challenges
- **`pkill -f measure.py` killed its own shell** (the pattern was on its command line too;
  exit 144). Use `pgrep -af` first, or a pattern the shell's command line doesn't contain.
- **The eval's malicious packuments aren't in a snapshot.** DataDog ships each sample's
  packument inside its encrypted zip; the history probe reads only that `package_info` member
  (JSON), as the importer does.

### Evaluation snapshot
- **The bounded Stage 4 holds in a live tick.** The first tick on the slotted code (11:30-12:13
  UTC, 23,807 changes, 43 min) never took available memory below 20.7 GB of 30.7; the old
  code's catch-up took it to 5.5 GB. Hourly ticks since: 8-10 min, 6-7 GB cgroup peak.
- `stage2-rules` with v4: 2,169 -> 2,158 forwarded (11 malicious lost, 0 gained), so v4 was
  reverted; the report on disk is v3's again. (A first run was stopped at 22 min to leave RAM
  for the tick, then rerun at 15:53 UTC: 35 min, 5.4 GB peak.)

### Open questions / next steps
- Whether 984 reported versions a day (336 HIGH) is a queue a reviewer can work. They are
  767 packages, which the cross-run queue groups. The two biggest HIGH sources were checked and
  kept; a precision pass needs labels on live entries, which arrive with OSV over the next
  days.
- (Decided the same day, entry above: Stage 5 downloads them.) 78 of the 984 reported
  versions have no captured tarball, so Stage 5 can only say `sandbox.not-run` for them. 57 were over Stage 2's 16 MB cap (platform binaries, e.g.
  `@builder.io/buildercode-*` at 114-160 MB), and 21 were reported by Stage 4's dependency
  rules after Stage 1 passed them over. Whether Stage 5 should fetch those tarballs itself
  (a download, nothing run) is a question for the owner: it adds disk and bandwidth for
  versions that mostly ship a binary.
- `@opencode/cli`: 6 of the 10 over-cap bundles. Its platform binaries take it past 512 MiB
  unpacked. Raising the cap is a disk and memory question for the owner.

## 2026-10-30: Stage 4 OOM-killed on the first VM day; streaming Stage 4; Stage 5 wired in

**Stage(s):** Stage 4 correlation, report, Stage 5 (package-analysis export/import), retention
**Context:** The VM's first tick (run `20261029T221803Z-npm`, a 24-hour catch-up window:
110,084 changes) finished Stages 0-3 and then died in Stage 4. The same session also finished
Stage 5's airgap-only export and offline dependency bundles (decision
[0014](decisions/0014-stage5-uses-ossf-package-analysis.md),
[proposal](proposals/offline-dependency-bundle.md)), which still had no CLI or `collect` hook.

### Decisions
- **Stage 4 streams its input and output** (`stages/correlate.py`: `RunVersions`,
  `CandidateFile`; `util/files.py`: `LineFile`). It keeps each line's offset and length and
  parses a version again whenever a pass needs it: the dependency plan (two passes, updates
  first), the repository lookups, retries, and the final pass, which writes `correlate.jsonl`
  in windows of 2,048 versions. Only the repository comparisons and dependency records stay
  in memory. `correlate_run` returns the output file read on demand, so callers keep
  iterating it as before. `build_report` now keeps only the reported versions.
  Alternatives: a smaller worker pool or `MALLOC_ARENA_MAX` (they trim the margin, not the
  4 GB of objects); or splitting runs into smaller windows (the catch-up window is decided by
  downtime, so it can always be large). Streaming is the change that bounds memory.
- **Stage 5 wiring.** New command `kitsunox sandbox <run> [--results DIR] [--cap N] [--replay]`.
  `collect` runs Stage 5 after the reports, on each run whose stages ran that tick, only when
  `KITSUNOX_SANDBOX_RESULTS` (environment or `.env`; not a secret) names a results root.
  Without one it skips Stage 5, so nothing is exported until the owner sets up the airgapped
  VM. The daily prune (and `kitsunox data prune`) now drops pruned runs' exports and cached
  results no run refers to (`sandbox/results.py: prune_sandbox`).
- **Reports include Stage 5.** Once Stage 5 has rendered a run, the report takes each reported
  version from `sandbox.jsonl`: Stage 5's findings appear as "Stage 5: sandbox" and count in
  the score, so an analysed package moves up the queue when its results arrive. The reason
  shown stays Stage 4's. After every live Stage 5 call, the reports of the run and of every
  earlier run it refreshed are rebuilt. `Report.sandbox` (network and counts) is a new field
  with a default, so reports written before still load and no schema bump is needed.
- **`sandbox-snapshot.json` is a retained stage snapshot** (`core/run.py: STAGE_SNAPSHOTS`).
  Before this, the daily prune would have deleted the dependency tarballs of live runs'
  bundles, so their replay would have read `BUNDLE_UNREPRODUCIBLE`. Stage 5's own tarball
  index still reads only the Stage 2 and 4 snapshots (`spool.TARBALL_SNAPSHOTS`): its own
  snapshot exists only after a first rendering, and reading it would let a replay see what
  the live call didn't.

### Challenges
- **The OOM kill.** The kernel log: `Out of memory: Killed process 19547 (kitsunox) ...
  anon-rss:21624156kB` at 00:24 local. It took the terminal and the session's agents with it,
  because I had started that tick from the session's shell. Measured on the run's own files:
  `triage.jsonl` is 810 MB (7.2 KiB a line) and becomes 33 KiB of objects a line (x4.6, so
  3.75 GB for 110k versions). `ast.jsonl` (380 MB) was held as objects too, and so were the
  raw lines and the output. Eight threads extracting repository archives added transient peaks
  on top. The next timer tick (old code) resumed the same catch-up and reached 20 GB.
  - **Resolution:** streaming Stage 4 (above). The scheduled tick then running had loaded the
    old code, so it kept going; the next tick loads the new code.
  - **Why it worked:** on `20261029T221803Z-npm`, indexing both files takes 12 s and one full
    pass over all 110,084 versions 22 s, at **0.12 GB peak RSS** (was about 4 GB of
    candidate objects alone). Output is unchanged: the new
    `test_run_streams_in_order_across_write_windows` checks order across window boundaries
    and that a version in two batches takes the later one, and the existing Stage 4 tests
    pass unchanged.
  - **But streaming alone did not bound a live tick.** The restarted tick (streaming code,
    sampled every 30 s) sat at 7 GB in the dependency lookups, dropped to 2.4 GB, then
    climbed to **18 GB** while comparing repositories (all archives already cached, so no
    downloads: pure extraction). Each of 8 workers can hold a compressed archive (up to
    128 MB) and its extracted tree (up to 1 GB, `REPO_LIMITS`) at once. The second fix bounds
    that: `RepoMemory.archive` is now a context manager holding one of
    `ARCHIVES_IN_MEMORY` (3) slots from extraction until the comparison is done. Downloads
    stay parallel and keep their per-request network accounting (`GitHub.archive_body` /
    `extract`). An archive that fails to extract is remembered per (commit, directory), so a
    monorepo's versions don't extract it again. Likewise `PACKUMENTS_IN_MEMORY` (3) bounds the
    dependency lookups' packument parsing (a packument can be 256 MB). Tests:
    `test_archives_are_extracted_a_few_at_a_time_and_a_bad_one_once`. That tick ran on the
    code without the slots and stayed below the 21.6 GB that was killed; the next tick is the
    real measurement.
- **The workflows were cut off mid-run.** The airgap and bundle build had finished its four
  build agents (airgap-only export, rule fixes, the `ranges.py` semver port, `bundle.py`); its
  integrator had run lint and mypy clean and died in the full test run; its two reviews never
  started. The `chai-*` analysis agent had written its rules, and died waiting for the
  "after" Stage 2 evaluation.
  - **Resolution:** gates rerun by hand (1,853 tests, 97% branch coverage); the two bundle
    reviews relaunched as single agents with memory limits (no evals, no `data/` loads); the
    Stage 2 evaluation is to be rerun when the tick is done.
- **`/tmp` is RAM.** It is a tmpfs, and the session scratchpad held 1.7 GB, including a
  half-finished 956 MB bundle-measurement cache. Deleted. Large scratch data goes on disk now.

### Evaluation snapshot
- Stage 4 output is unchanged by streaming (tests), so no eval rerun was needed for it.
- The `chai-*` rules (`static.encoded-url`, `static.function-require`, both MEDIUM 3; written
  by the family-analysis agent before the crash, rerun here): `stage2-rules` on `vm-day1` B
  recall 49.9% -> 52.4%, B follow-on 50.7% -> 53.9%, A 71.5% -> 71.6%: +58 samples, 0 benign
  added, 0 lost. `pipeline+3` (the analyst's run): B 66.0% -> 67.6%, benign unchanged. The
  live day will tell more than 1,500 benign samples can.
- **A ReDoS in the new `static.function-require`**, found while reviewing it: two `\s*`
  around an optional `\)` backtrack quadratically on "Function" plus a long run of
  whitespace (32k spaces: 0.44 s; a 16 MB file would stall Stage 2). Fixed with possessive
  quantifiers (no change to what matches); `test_function_require_is_linear_on_long_whitespace`.

- **Two reviews of the offline bundle (safety and npm fidelity), then a fix round.** Both
  verified their findings with probes (nothing run but Python over inert data).
  - Safety: a quadratic `[v=\s]*` in the semver port (a 16k-char spec took 2.4 s, and failed
    parses weren't cached); dependency trees extracted with the per-tarball default limits
    before the bundle's caps were checked (about 128 GB of RAM reachable with a 128 MB
    download), and a negative `unpackedSize` cancelled the declared total; a package.json
    nested 300 deep crashed all of Stage 5, every tick, until the run was pruned (a pydantic
    `ValidationError` that nothing caught); unbounded packument lookups per bundle.
  - Fidelity: execute bits dropped (every file written 0644, so a `./run.sh` hook would get
    EACCES offline while the record said complete); `1e400` written back as `Infinity`
    (EJSONPARSE in npm, "complete" in Kitsunox); a file where a folder goes; resolution order
    unlike arborist's (different versions than an online install); dependency shrinkwraps
    ignored; a shipped folder satisfying every requirer whatever its version; peer conflicts
    nesting a second copy, possibly of the package itself. Also BOMs, link entries and
    duplicate keys, which npm tolerates, made the bundle opt out: a free evasion.
  - **Resolution:** all fixed, each with a regression test: caps on range length and
    memoised failures, possessive `[v=\s]*+`; extraction within what is left of the bundle's
    caps (`ArchiveLimitError`); `internal-error` as the unbundled outcome for anything
    unexpected; caps on edges, packuments and packument bytes; file modes in `ArtifactTree`;
    numbers kept as written; `path-collision`; arborist's queue order, peer sets and REPLACE
    (not npm's intermediate placement levels, documented); `dependency-shrinkwrap`
    incomplete; npm's readings of BOM, links and duplicate keys, recorded as `normalized`.
    `BUNDLE_FORMAT` 2 and Stage 5 `STAGE_VERSION` 7, so bundled job keys change (nothing was
    exported yet).

- **A ReDoS audit of every regex** (85 patterns, ~2,000 generated inputs each at n and 4n,
  then the worst at 64k and 1M). Three fixed with identical matches (differentials over
  40k-2.3M strings, 0 mismatches): Stage 5's `PIPE_RUN` was cubic (`x/curl/curl/...`, 16k
  chars: 93 s) and `SUBST_RUN` quadratic (`sh -sh -sh ...`, 64k: 5.7 s), rewritten so each
  shell segment's start is tried once; `static.encoded-blob` was linear but slow (16 MB of
  199-char runs: ~10 s), now anchored at run starts (50 ms at 4M). One `PIPE_RUN` shape
  (`curl|sudo -curl|sudo -...`: 128k, 14 s per argv word) had no exact fix: a sudo option now
  stops at `|`, which is what the shell does anyway, so `sandbox.download-run` is v2.
  Everything else measured linear and fast.

### Open questions / next steps
- Measure a whole tick with the archive and packument slots (time and peak RSS), and add a
  `docs/validation.md` section for the first VM day.
- Whether an unbundled reason a package can choose (`original-not-repackable`) together with
  install hooks should score, rather than stay INFO.
- Bundle completeness on live runs (the integrator's measurement died with the session).
- The owner: set up the airgapped analysis VM and `KITSUNOX_SANDBOX_RESULTS`
  ([stages/sandbox.md](stages/sandbox.md#usage)).

## 2026-10-30: Stage 5 becomes an export for OpenSSF package-analysis, airgapped, with offline bundles; viewer and dependency rules

**Stage(s):** Stage 5 dynamic analysis, Stage 4 (dependency reputation), viewer
**Context:** Catching up the log for work done in parallel on 2026-10-29/30. The entries
above and below cover Stage 4's retries and the Stage 2 placeholder fix; this one covers the
rest.

### Decisions
- **Stage 5 is OpenSSF package-analysis (rel-38), run by the owner; Kitsunox only exports and
  imports** ([0014](decisions/0014-stage5-uses-ossf-package-analysis.md), superseding the
  runner part of [0012](decisions/0012-sandbox-design.md)). Our own runner's isolation layer
  could not be produced in this development environment (the tooling's safety checks stopped
  it twice), and the parsers already built had nothing to drive them. package-analysis already
  does the job and is maintained upstream. The owner chose it ("Option 2"). The old runner,
  capture and config code was removed.
- **Airgapped only** (the owner: "Package analysis needs to be airgapped"). By default
  package-analysis gives the sandbox real internet access and runs its outer container
  `--privileged`. Every exported job carries `-fully-offline -nointeractive ... -nopull
  -offline`, checked against the pinned `run_analysis.sh` and `cmd/analyze`. There is no
  online opt-in. Images cross to the analysis VM as `docker save` files, following upstream's
  docs; Kitsunox ships no setup scripts.
- **Offline dependency bundles** (the owner: "move all necessary dependency tarballs along
  with it as a package"; [proposal](proposals/offline-dependency-bundle.md)). Without a
  network, `npm install` fails before any hook runs whenever a registry dependency is
  missing: on `20261029T221803Z-npm`, only 25 of 135 hook-bearing versions (19%) would install
  offline. A selected version whose `package.json` needs dependencies is exported as one
  Kitsunox-built tarball: its own files plus `node_modules/<dep>` for every dependency npm
  would install at the run's `as_of`, with an explicit sorted `bundleDependencies` (npm
  11.12.1 installs bundled dependencies without a registry request and runs their lifecycle
  scripts). Versions are picked by a Python port of node-semver 7.7.4 and npm-pick-manifest
  (`ecosystems/npm/ranges.py`, tested against node-semver's fixtures), and the bytes are
  deterministic. Incomplete bundles are exported unbundled and say so
  (`sandbox.bundle-incomplete`). Why one tarball: package-analysis copies exactly one file into
  the sandbox, so `file:`, shrinkwrap and directory layouts don't work.
- **Importer and rules treat results as hostile.** Strict schema, size caps, `O_NOFOLLOW`, a
  rejection is scored (`sandbox.result-rejected`, HIGH when oversized). The bait credentials
  package-analysis plants are matched by origin (`sandbox.bait-exfil`). Count caps that fire
  (flooding) make `sandbox.truncated` HIGH. A second-stage install (`npm exec --package`, npx,
  yarn/pnpm, a foreign tarball) is `sandbox.nested-install` HIGH. Running a file that wasn't in
  the tarball is `sandbox.download-exec` HIGH.
- **Stage 4 dependency reputation** (`npm.dependency.fresh-foreign` MEDIUM 3,
  `npm.dependency.name-embeds-popular` LOW 1; [correlate.md](stages/correlate.md#evaluation)).
  Registry records of newly added dependencies are fetched through the run's fetcher (capped
  at 1,000 lookups per started day and 40 new names per package) and retried like the
  repository lookups. On `vm-day1`: +1 A and +12 B, benign unchanged at 1.1% weighted
  ([evaluation.md](evaluation.md), with a caveat on a confounded row).
- **Local viewer** (`kitsunox view`, [viewer.md](viewer.md)): standard-library HTTP server, no
  JavaScript, strict CSP, loopback-only bind (checked after binding), Host header check,
  per-connection deadline, 32 concurrent connections, file size caps. All package text goes
  through the same escaping as the Markdown, with hidden characters removed and flagged.

### Challenges
- **The safety checks stopped the runner and setup-script work three times**, the last time
  in a reply to the owner. That forced the change of approach (0014) rather than a rewording.
- **Reviews found real issues before anything ran.** Among them: the driver check accepted
  `npm install /<any>.tgz` (a run that installed `/stage2.tgz` came out quiet); a
  lexicographic observation cap let the package choose what survived; late results were never
  imported after 48 hours. All fixed, with end-to-end probes in the review notes.

### Open questions / next steps
- None of Stage 5 has met a real package-analysis result yet. The first results from the
  owner's VM are the real test, especially of the bundle mechanics, which come from reading
  npm's source.

## 2026-10-30: Webhook placeholders in Stage 2: measured, then labelled rather than dropped

**Stage(s):** Stage 2 static heuristics
**Context:** `static.exfil-endpoint` v2 matched documentation placeholders such as
`discord.com/api/webhooks/123/abc` (in `@waffo/pancake-ts` on the laptop). I wanted to tighten
it, but measured first on `vm-day1`, the VM's first dataset: 3,444 DataDog malware samples and
1,500 provisional benign samples from run `20261029T221803Z-npm`.

### Decisions
- **`exfil-endpoint` v3 + new `static.webhook-placeholder` (MEDIUM, weight 3).**
  - v3 calls a webhook an exfiltration endpoint only when its id looks real: a 17-20-digit
    Discord snowflake, or upper-case Slack `T…/B…` ids that don't repeat or count up.
  - What v2 matched and v3 rejects now gets its own finding, so Stage 2 still forwards it.
  - Rejected: v3 alone (below).

### Challenges
- **The obvious tightening would have cost 42 attacks.** A scan of every webhook mention in
  the malware (shapes only, no URLs) showed that every real Discord webhook has a 19-digit id.
  So the Discord part of v3 cost nothing. The Slack part was different. v2's `[A-Z0-9]` check
  was case-insensitive, so `/services/xxx/xxx/xxx` matched. That placeholder sits in a notifier
  template in 43 shape-B samples, almost all one typosquat family (`chai-as-*`,
  `chai-await-*`). For those samples it was the only Stage 2 match. Through `pipeline+3`, 42 of
  the 43 were then caught by nothing else. v3 alone saved one benign flag (`@zerodot/discord`)
  for 42 missed attacks.
  - **Resolution:** keep the match at MEDIUM under an honest name.
  - **Why it worked:** a per-sample comparison found 0 differences in Stage 2 flags between v2
    and v3 plus the placeholder rule, over all 4,943 samples. Tests:
    `test_placeholder_webhooks_are_labelled_not_dropped` and
    `test_a_real_looking_webhook_is_not_also_a_placeholder`.

### Evaluation snapshot
- `stage2-rules` on `vm-day1`: recall 71.5% A / 49.9% B, 0.8% weighted benign pass-through.
  Unchanged from v2 to v3 plus the placeholder rule; 44 findings relabelled from HIGH 5 to
  MEDIUM 3.

### Open questions / next steps
- The `chai-as-*` family is caught only by accident. What actually gives it away (Stage 3
  shows only LOW `process-exec`, `network` and `dynamic-code`) deserves a look.

## 2026-10-30: Stage 4 retries network failures; sandbox design proposed

**Stage(s):** Stage 4 (correlation), Stage 5 (design only), collection
**Context:** The user asked for more agents where they help. Two jobs were independent of the
Stage 2 measurement that was running: making Stage 4 retry network failures (an open item since
2026-10-29), and the Phase 10 sandbox design that has to come before any sandbox code. Each
went to an agent: Stage 4 in its own git worktree, so it couldn't touch this session's
uncommitted work, followed by an adversarial review and a fix pass. The result was ported as a
patch. The sandbox design is new documents only.

### Decisions
- **Stage 4 retries transient lookups in the same run** (0010 addendum, in line with 0009).
  Only `TransientFetchError` counts as transient, meaning HttpFetcher's 5 attempts ran out on
  connection errors or 429/5xx. A comparison that hits one is retried after the first pass,
  at most twice, and the retries stop early when a pass recovers nothing. Before this,
  `repo_lookup` caught every `FetchError` as "network: ..." and never retried. Permanent
  failures, such as a malformed ref advertisement, were labelled "network" too.
  - Rejected: retrying immediately inside the lookup, which gives the network no time to
    recover.
  - Rejected for now: redoing Stage 4 on a later tick. It would mean a `collect` change and
    redoing every comparison in the run for a few versions.
- **Versions that still fail stay visible.** Their decision reason ends with
  `NETWORK_UNCOMPARED`, and `correlate.json` records
  `repo_network {lookups, first_pass, retry_passes, retry_skipped, still_failing}`. The tick
  log, `report/index.md` and the Discord update all show "N not compared (network)"
  (`Report.network_uncompared()`).
- **Outage guard.** No retry pass runs when at least half the lookups failed on the network,
  with at least 20 failures. This is recorded as `retry_skipped: "outage"`. It is count-based
  on purpose: analysis never reads the clock, so a time budget was out.
- **`correlate.json` gains `stage_version` 2.** `rules_fingerprint` hashes only rule ids and
  versions, so it couldn't tell this output from older output. It stays out of the
  fingerprint because Stage 2 uses that fingerprint as a cache key.
- **Sandbox: gVisor (systrap) under rootless Docker in a dedicated account**
  ([0012](decisions/0012-sandbox-design.md), [stages/sandbox.md](stages/sandbox.md)). The
  status is *proposed*; nothing is installed or run. The VM has no `/dev/kvm`. The user
  confirmed the host is Windows with Hyper-V on and won't turn it off, so nested
  virtualization (Firecracker, Kata, gVisor's KVM platform) is out. The user asked for the
  safest execution possible without nested virtualization: gVisor's user-space kernel plus
  the VM as a second boundary. Decisions D0 and D2-D8 are still the user's: build it at all,
  host isolation, HTTPS capture, what enters, profiles, effect on scores, detonating DataDog
  samples, and the npm version.

### Challenges
- **The first retry design could make an outage take longer than the hourly tick**
  (adversarial review of the agent's first commit). A failed refs request was never
  remembered, so every version of a repository paid the fetcher's full back-off (up to
  ~65 s) in both passes. With ~500 lookups an hour on 8 workers, that is an estimated
  0.5-2.3 h of Stage 4 during a GitHub outage.
  - **Resolution:** `RepoMemory` (`stages/repo.py`) fetches refs once per repository under a
    per-repository lock. For the current pass only, it also remembers repositories that failed
    on the network, so their other versions fail fast. `new_pass()` clears that before each
    retry. Together with the outage guard above, an outage now costs one pass.
  - **Why it worked:** in tests, 3 versions of one repository now take attempts+1 refs
    requests instead of 3×attempts+3 (`test_a_failed_repository_fails_fast_within_a_pass`).
    A repository that stays down costs one fetch per pass, not one per version
    (`test_a_repository_still_down_says_why`). The guard's boundaries are tested: 20 of 40
    failures skip the retries, 20 of 41 are retried. How long a real outage takes is
    unmeasured; the first pass still pays the back-off once per distinct repository.
- **A second review found the retry memory made output depend on thread timing.** The same
  network responses gave two different `correlate.jsonl` files in 30 runs. The worker that
  sent a failing request got "network: GET ... failed after N attempts"; the others got
  "not requested again in this pass". Two more verified defects came from keying the memory by
  repository. One commit's failed archive refused the repository's other commits, even ones
  already cached. The outage guard also counted refused versions, so one blip during a
  30-version monorepo burst was judged an outage and every retry was skipped.
  - **Resolution:** the memory is now per request (refs, or the archive at one commit), and a
    request is refused only if it would really go to the network
    (`HttpFetcher.needs_network`). Every version needing a failed request gets one stable text,
    "network: o/r refs unavailable", while the fetcher's error goes to
    `correlate.json repo_network.errors`. The guard counts distinct failed requests out of
    distinct requests sent. Release tarballs that failed on the network are left to Stage 2's
    next-tick retry, counted as `package_files_network`. `STAGE_VERSION` is 3.
  - **Why it worked:** the reviewer's 7 bug-asserting repros now fail as expected.
    `test_the_output_does_not_depend_on_thread_timing` runs 21 times with delays on 1 or 8
    workers and gets one distinct output. An independent verifier ran the timing case 20+
    times at 8 workers with random delays and checked the guard's boundaries (20 of 40 is an
    outage, 20 of 42 is retried). It also confirmed that an archive served from the immutable
    index is still recorded in the run's snapshot, so replay works.
  - **Still found by the verifier and fixed after:** a permanently rejected archive (over the
    256 MB limit) was downloaded once per version, one after another. Rejections are now
    remembered for the run (`test_a_rejected_archive_is_downloaded_once`). The docs' list of
    fields that reset on replay was also incomplete.
- **Retry-After wasn't capped** (`util/http.py`, older than Stage 4): a server could stall a
  worker for as long as it asked. It is now capped at `max_delay`
  (`test_retry_after_is_capped_by_max_delay`).
- **Replay is exact only for lookups that eventually succeeded.**
  `test_a_recovered_run_replays_identically` records a run with a failing archive and replays
  it offline: `correlate.jsonl` is byte-identical. A lookup that never succeeded has nothing
  recorded, so on replay it is a permanent "replay miss". `repo_network` describes the
  recording run only, and the docs now say so.

### Open questions / next steps
- How often Stage 4 hits the network in live ticks: `repo_network` in `correlate.json` will
  show it from the next ticks on.
- Whether `collect` should redo Stage 4 on a later tick for runs marked
  `retry_skipped: "outage"`.
- Sandbox: the user's answers to D0 and D2-D8, then the Phase 1 spike (rootless Docker +
  gVisor + runtime monitoring together on this VM, which no documentation confirms).

## 2026-10-29: Cross-run review queue, `kitsunox run`, and the first VM tick

**Stage(s):** Report, collection
**Context:** The user asked to move on to development, bug fixing, and running the pipeline
for real. Running it came first: the first VM tick started at 22:18 UTC as a one-off
`kitsunox collect --keep-repo-days 4`, since the systemd timer isn't installed yet. Every stage
uses threads, not processes, so code edited during the run can't leak into it. Meanwhile I built
Phase 8's remaining pieces.

### Decisions
- **Review queue** (`reporting/queue.py`, `kitsunox queue`, step 6 of `collect`): one entry per
  package across every report from the last `keep_days`. Each version counts once, and every
  version links to its page in the run that reported it. Ordered by score, severity, name. See
  [stages/report.md](stages/report.md#review-queue-dataqueue).
- **The strongest sighting wins, not the earliest.** A version in the 15-minute overlap of
  two chained runs is analysed twice. The later run may know more (a tag pushed since, a new
  label set), so the queue keeps the sighting with the higher (severity, score), and the
  earliest on a tie. Evaluation datasets keep the earliest; that rule is about labels, not
  about what a reviewer sees.
- **`kitsunox run`:** ingest, Stages 1-4 and the report, once, through the same `run_stages`
  as `collect`. Like `ingest record` without a feed range, it moves the checkpoint, so demos
  use their own `--data-dir` (`data-*/` is now gitignored).

### Challenges
- **The review (two reviewers and a verifier) confirmed 5 of 8 findings.** Each fix has a
  test:
  - **The queue's cost grew with the whole history.** Runs keep their reports after pruning,
    and every tick parsed all of them before applying the window. A reviewer's synthetic
    benchmark measured 170 reports at 11 s and 781 MB, under the lock, and growing. The
    window is now chosen from the manifests, and reports are read one at a time into small
    sightings.
  - **Unreadable reports were listed forever**, even far outside the window. Now only
    reports in the window count.
  - **Earliest-run dedup hid stronger later sightings.** This is the decision above.
  - **A report whose Markdown write failed was never redone.** The resume check looked only
    for `report.json`, which is written first. It now also requires `index.md` and a
    `report.json` that loads. The same check rebuilds reports written with an old schema.
  - **No test checked that queue links resolve.** Now they are checked against the files
    `write_markdown` writes, with a crafted name.
- **The `--as-of` help text was wrong:** it said "UTC if no offset", but typer rejects
  offsets. Found while testing `kitsunox run`.

### Open questions / next steps
- Measure on the first VM day: tick duration on 4 vCPUs, how often Stage 4 hits network
  failures (it never retries them), and queue build time on real reports.
- Stage 2: placeholder webhooks in documentation. This needs benign samples, which this
  run will provide.

## 2026-10-29: Brief run updates to Discord, and a review of the VM changes

**Stage(s):** collection (`collect`, scheduling)
**Context:** With collection unattended on the VM, the user asked for brief run updates in a
Discord channel through a webhook. Design: [0011](decisions/0011-run-notifications.md).

### Decisions
- **`collect` returns a `Tick`** (manifest, reports written, failed best-effort steps), and
  `kitsunox collect` posts it (`src/kitsunox/notify.py`). Parsing `collect.log` was rejected:
  its lines are written for people.
- **Content:** the run, its versions, how many to review by severity, and the top 5
  packages, each once with its version count. This answers the "27 `@lightdash/cli` entries"
  complaint for the message, not yet for the queue. It also reports catch-ups, failed steps,
  outages and chain gaps. A crash gives the exception type and location only; a skipped tick
  posts nothing.
- **The webhook is a secret, and names are untrusted.** The URL is read from `.env`
  (`util/env.py`, no new dependency), checked against Discord's webhook pattern and never
  logged. Errors give the HTTP status or exception type, because httpx messages carry the URL.
  Mentions are disabled, previews suppressed, and Discord markdown escaped.
- **An exception to "all network access through `HttpFetcher`"**: this is output, not part of
  any run's snapshot, so it doesn't affect replay. CLAUDE.md now scopes that invariant to
  analysis.

### Challenges
- **A review found five real defects** before anything shipped. Three reviewers (security,
  correctness, project rules) and one verifier went over the change; the verifier reproduced
  each finding or refuted it. Results: 11 findings, 5 distinct after merging duplicates, 1
  refuted (a "duplicate helper" point with no failure). Each fix has a test:
  - **A broken `.env` stopped the whole tick** before ingest. Invalid UTF-8, a directory or no
    read permission meant no collection and no tarball capture, every hour. Now it's
    `notify: off, .env unreadable (...)` and the tick runs
    (`test_collect_posts_an_update_or_a_crash`).
  - **systemd quoting was only right for `ExecStart=`.** It was also applied to
    `WorkingDirectory=`, `StandardOutput=append:` and `Environment=`, which take values
    literally. A project path with a space made the unit fatal (`systemd-analyze`: "path is
    not absolute"). Each setting now gets its own encoding, and the test runs `systemd-analyze
    verify` on a unit for `pro ject$x` / `da ta%`.
  - **A newline in a path injected unit directives** (for example an extra `ExecStartPre=`).
    Paths with control characters or edge whitespace are now refused
    (`test_schedule_refuses_paths_that_break_unit_files`).
  - **`Retry-After: nan` turned the retry into a `ValueError`**. Fixed with
    `test_odd_retry_after_values_still_retry`.
  - **"retried next tick" wasn't always true.** A run whose report alone failed isn't
    resumed, so the message no longer promises a retry.
- **Live check:** one test post through the real webhook returned `notify: posted`.

### Open questions / next steps
- Resuming a run whose only missing output is `report/` (today `_resume_from` doesn't look
  for it). Small, but it belongs with the cross-run queue work.

## 2026-10-29: Collection moves to a Linux VM, with a fresh start

**Stage(s):** collection (scheduling, retention), evaluation data
**Context:** The laptop had run out of disk for Stage 4's repository archives (they were cut to
2 days). The planned host, an Ubuntu VM on the user's desktop, is ready: 4 vCPUs, 30 GB RAM,
357 GB free. It is also the planned host for the Stage 5 sandbox (roadmap Phase 10).

### Decisions
- **Start fresh on the VM; don't copy `data/`.** The user chose this over copying everything
  (which would have kept the chain checkpoint) or copying only state and eval data.
  Consequences:
  - The `repo.compared` v1 Stage 4 re-run planned in the previous entry is **dropped**.
  - The `day1` dataset and its results (`pipeline+4`: 91.2% / 66.5% at 0.9%) live only on the
    laptop and can't be reproduced here. They stay in `evaluation.md` as recorded.
  - Tarballs the laptop captured, including malicious ones npm has since deleted, are not
    carried over.
  - DataDog samples are downloaded again (`samples datadog`). The VM's own benign samples stay
    provisional for 30 days.
- **systemd user timer instead of launchd** (`kitsunox schedule systemd`). It shares the
  command line with `schedule plist` (`_collect_job` in `cli.py`).
  - `Type=oneshot` service at `Nice=10` and `IOSchedulingClass=idle`, mirroring launchd's
    `LowPriorityIO`.
  - The timer fires `OnUnitActiveSec=60min` after a tick starts. A long tick isn't started
    twice, and `DataDir.lock()` still guards everything.
  - Arguments are quoted for unit files (spaces, `%` specifiers, `$`). Test:
    `test_schedule_systemd_runs_collect`. The generated units pass `systemd-analyze verify`.
- **Retention on the VM: runs and tarballs 7 days, repository archives 4.** At ~14 + ~31 GB a
  day, this is ~225 GB of 357 GB, with headroom for heavy days (0006 addendum).

### Challenges
- **Nothing in the code assumed macOS except the scheduler.** All four gates passed on the VM
  before any change: 382 tests, ruff, mypy. `fcntl.flock` locking works the same on Linux.
- **Installing the timer is the user's step.** The agent session isn't allowed to install
  persistent services, so the user runs the `systemctl --user` and `loginctl enable-linger`
  commands from `stages/ingest.md`.

### Open questions / next steps
- The first tick has no checkpoint, so it covers a full 24-hour window (~110k versions). The
  laptop needed 11 hours for that on 8 cores; measure it on 4 vCPUs and add a
  `validation.md` section after the first full VM day.
- Stop the laptop agent once the VM has run a few good ticks.
- Next work: a cross-run review queue grouped by package.

## 2026-10-29: First live Stage 4 run: a monorepo bug, and repository archives are too big

**Stage(s):** Stage 4 (correlation, repository comparison), Report
**Context:** The first `collect` tick with Stage 4 caught up the 24-hour run
`20261027T210847Z-npm` (109,497 versions) from Stage 3. It finished at 04:57 UTC after 11.3
hours: Stage 3 took ~3.7 h and Stage 4 ~7.5 h, nearly all of it downloading repository archives.
No stage failed. The report put 1,759 versions (1.6%) up for review: 468 HIGH, 1,231 MEDIUM,
60 reported on score alone. The biggest contributors were `code.capability-gained` (1,058) and
`static.process-exec` (888).

### Challenges
- **`npm.repo.install-script-not-in-repo` fired 43 times live, against 0 of 121 benign updates in
  the evaluation.** Every hit had `directory: ""`: the release doesn't set
  `repository.directory`, so it had been compared with the monorepo's *root* `package.json` (a
  private workspace manifest). This affected Playwright's six browser packages, `workerd`,
  `@tarojs/*`, `@azure/msal-node-extensions` and 27 releases of `@lightdash/cli`.
  - **Resolution:** with no `repository.directory`, the comparison now uses the repository's
    `package.json` whose `name` is the release's (the root if it matches, else the shallowest,
    skipping `node_modules/`). If there is none, the root manifest still counts unless it is a
    workspace (`workspaces` or `private: true`); otherwise the release isn't compared
    (`NpmLocator.package_directory`, `repo.compared` v2, tests
    `test_compare_finds_the_package_in_a_monorepo`, `test_a_renamed_package_keeps_...`).
    A first version without the root fallback cost 7 malicious comparisons on `day1`: forks and
    renamed packages (`wdio-web-reporter` from `wdio-spec-reporter`, `@teselagen/react-list`
    from `coderiety/react-list`) whose repository manifest keeps the old name.
  - **Why it worked:** re-run read-only on the 16 distinct live packages, 13 now find their own
    manifest, whose hooks match the release's, and 1 has no manifest and isn't compared. The
    2 that still fire are accurate: `bun` and `@kilocode/cli` publish manifests generated by a
    release script, so those hooks really aren't in git. On `day1` (comparable updates,
    v1 → v2): install hooks 53/57 → 51/55 malicious, 0/121 → 0/116 benign; code 49/57 → 48/55
    and 9/121 → 3/116; dependencies 30/57 → 7/55 and 14/121 → 2/116. Most of v1's dependency
    hits came from the wrong manifest, too.
- **Archive volume: 31 GB for one day of releases**, against an estimate of 5–15 GB. The run
  downloaded 2,142 archives for 5,637 comparisons. A few monorepos that release many times a
  day dominate: `MaterializeInc/materialize` (2.6 GB, 40 commits), `lightdash/lightdash`,
  `stacksjs/stx`. Capping archives at 32 MB would save 23 GB (75%) but skip 313 archives
  (15%). At 7-day retention this volume needs ~217 GB; 168 GB are free.
  - **Resolution:** the user chose shorter retention for repository archives only, not a size
    cap (a cap would skip 15% of comparisons, biased toward big popular monorepos). New option
    `--keep-repo-days` (default 7, same as runs); this laptop's agent uses 2 until collection
    moves to a VM with more disk in the next day or two. Test:
    `test_repository_archives_can_go_before_the_run`. See the 0006 addendum.

### Open questions / next steps
- On the VM, install the agent without `--keep-repo-days` (7 days).
- Reports list each release separately: 27 `@lightdash/cli` versions were 27 entries. Group by
  package in the queue.
- Re-run Stage 4 (`kitsunox correlate` + `report`) on the runs correlated with `repo.compared`
  v1: `20261027T210847Z-npm` through `20261028T171425Z-npm`. Deferred by the user until after
  the move to the VM: it holds the data lock for hours, and ticks skip meanwhile. They are past
  the 48-hour catch-up window, so it must be done by hand.

## 2026-10-28: Reports, manifest-vs-repo rules, and Stage 4 going live

**Stage(s):** Stage 4 (correlation), Report
**Context:** The user asked whether Stage 4 had run live, and for the `package.json`
comparison with the repository and reporting next.

### Decisions
- **Install hooks compared with the repository's `package.json`** at the compared commit
  (`npm.repo.install-script-not-in-repo`, HIGH): on comparable `day1` updates, 53 of 57
  malicious and 0 of 121 benign. Dependencies the repository doesn't name anywhere
  (`npm.repo.dependency-not-in-repo`) fire on 12% of benign, so LOW, weight 1.
- **Reports per run, `report.json` canonical**, Markdown rendered from it (roadmap decision 4).
  Every package string is untrusted: fences longer than any backtick run, inline escaping,
  `https://`-only links, sanitised file names, bidi-override characters dropped. Findings of
  the same rule are grouped (Stage 2 reports one per file). See [stages/report.md](stages/report.md).

### Challenges
- **Stage 4 hadn't run live yet.** The 12:09 tick spent 4.7 hours on catch-ups and a
  35,275-change run, with the old code loaded, and launchd didn't fire again on its usual
  minute after that. Started the agent's job by hand (`launchctl kickstart`).
- **Every recent `ast.jsonl` came from the buggy Stage 3** (new packages behind placeholders):
  a report preview on `20261028T031447Z-npm` showed 64 versions to review, many of them those
  false flags; with Stage 3 redone, 24. The stale files were deleted under the data-dir lock,
  so the catch-up redoes Stage 3 and then Stage 4 and the report for each run.
- **`@types/*` set off `revived-with-new-dependency`** (4 in that hour): DefinitelyTyped's bot
  republishes long-idle type packages, which add dependencies, without provenance. Exempted
  when the `types` account published both versions.
- **Placeholder webhooks in docs still match `static.exfil-endpoint` v2**
  (`discord.com/api/webhooks/123/abc` in `@waffo/pancake-ts`). Left for Stage 2 tuning.

### Open questions / next steps
- A queue across runs; `kitsunox run` end to end.
- Stage 2: tighten webhook-id matching for documentation placeholders.

## 2026-10-28: Stage 4 correlation, repository comparison and score

**Stage(s):** Stage 4 (correlation), evaluation harness
**Context:** The user asked to start Stage 4 after Stage 3 was verified live. Stage 4's jobs:
combine weak signals, look up outside knowledge, and compare npm releases with their git
repositories. Design and rejected options: [0010](decisions/0010-stage4-correlation-and-repo-comparison.md).

### Decisions
- **Repo comparison scope: flagged versions + watched updates** (the user's choice of three;
  ~500/hour). No GitHub token or API: refs from git's smart-HTTP advertisement, archives from
  codeload by commit, cached through the immutable index.
- **Report on any MEDIUM+ finding, or score ≥ 6; the score orders the queue.** Measured from a
  dump of every stage's findings for all 4,944 `day1` samples: a score bar *instead of* the
  MEDIUM bars is far more precise (0.1% benign updates) but loses 2.2 / 9.5 points of recall, and
  summing Stages 1-3's LOW findings to 3-5 bought almost no recall for 0.4-2.0 points of benign.
  Each rule counts once in the score (Stage 2 reports one finding per file).
- **Stage 4 reads every triaged version**, not only those routed to Stages 2-3: 23 of the first
  24 missed malicious updates examined were never routed, and many had the same two LOW
  Stage 1 findings (`dormant-revived` + `dependency.added`).
- **Eval predictors share one collector** (`SampleFindings`) that gathers every stage's
  findings; each predictor is a decision over it. Regression check: `pipeline+3` re-derived
  exactly (89.7% / 66.0%, benign 0.9% / 1.2%).

### Challenges
- **"Code not in the repo" is noise for most packages.** 57% of sampled benign updates ship
  only build output. A first rule ("package ships its sources, yet has files git lacks") missed
  Shai-Hulud 2.0, whose `setup_bun.js` sits at the root of packages that ship `lib/`.
  - **Resolution:** a missing file counts only if its directory is in the repository and no file
    there shares its stem (`lib/x.js` beside `lib/x.ts` is compiled; ignored `dist/` never
    counts).
  - **Why it worked, partly:** 49 of 57 comparable malicious updates fire, but so do 9 of 121
    comparable benign (generated root files, `@girs/*`), and 43 of the 49 were already flagged.
    The rules were downgraded to LOW. Honest result: the comparison is evidence, not recall,
    until the git path widens its reach. 543 of 965 malicious updates have no commit or tag.
- **Known-malware by name flagged `axios`, `chalk`, `debug`** (11 benign new packages): OSV
  records compromised *versions* of real packages. Only whole-package records count now: 11
  malicious, 0 benign.
- **The combination rule fired on prerelease channels** (`canary`, `experimental`, `pr-`): a
  channel idle for years is "dormant", and its next build adds dependencies. 3 of 4 new benign
  reports; prereleases are skipped now.
- **A slow evaluation looked like a regex hang.** The dump sat on `@sap/generator-fiori` and
  then on `@pilllesss/yorn` for many minutes. Timing every rule on every file found nothing over
  a second; the time was base-tarball fetches for deleted versions. No change needed.

### Evaluation snapshot
- `pipeline+3` → `pipeline+4`: updates 89.7% → **91.1%**, new packages 66.0% → **66.5%**,
  benign 0.8% → **0.9%** weighted (1 extra benign update; nothing lost).

### Open questions / next steps
- Repo archive volume live: estimated 5-15 GB/day (1,000 repos, 1,700+ commits for one day of
  watched updates); measure on the first live day. Archives can be re-fetched by commit, so they
  could be kept for less than 7 days.
- Compare `package.json` install scripts and dependencies with the repository's manifest.
- Reporting (Phase 8): `report.json` + Markdown, ordered by score.

## 2026-10-28: First live hours of Stage 3, two bugs

**Stage(s):** Stage 3 (AST), Stage 2 (static), collection
**Context:** Verifying Stage 3 in hourly collection before starting Stage 4. The first ticks
with Stage 3 ran catch-ups of six earlier runs.

### Challenges
- **Stage 3 flagged 3-4% of the versions it read live, against 0.2% in evaluation.** In
  `20261028T031447Z-npm`, 37 of the 44 flags were new packages, which `code.capability-gained`
  is meant to skip. They had published a staged-publishing placeholder first (`dsh-xiaoqi-pet`:
  `0.0.0-stage`, then `1.4.0`), and Stage 3 compared each version with the one before it *in the
  batch*, so `1.4.0` "gained" everything over the empty placeholder. npm's own `previous` for
  `1.4.0` is None. Evaluation never saw this: it builds each change against `change.previous`.
  - **Resolution:** compare each version with its `change.previous` (base or an earlier batch
    version); none means new package. Test:
    `test_version_without_previous_is_new_even_after_a_placeholder`.
  - **Why it worked:** 7 of the 44 flags remain for that run (all updates). Live rate after the
    fix still to be confirmed over the next ticks.
- **One catch-up failed with `UnicodeDecodeError: byte 0xf8 in position 6`.** Stage 2's code
  hadn't changed since the same run succeeded hours earlier, so the cause was data on disk. A
  scan of 1.73M cache and index files found one content-cache entry holding a 473-byte TLS
  record (`17 03 03 01 d4 ...`) followed by the intended `[]`. Another thread's HTTPS request
  had been written to the file descriptor the temp file reused. It was written at 06:49Z, during
  Stage 2's 8-thread fetching. The Python build has the GIL, so this is a race in the threaded
  HTTPS stack (httpx 0.28.1 / httpcore 1.0.9 / OpenSSL 3.5.9), at about 1 in 1.7M writes.
  - **Resolution:** not chased into third-party code. Instead: `atomic_write` reads the temp
    file back before renaming it into place (retry, then refuse), and the content cache, the
    capability cache and the immutable HTTP index treat a damaged entry as a miss and rewrite
    it (`test_damaged_cache_entry_is_recomputed`, `test_damaged_immutable_entry_is_refetched`,
    `tests/util/test_files.py`). The damaged file was deleted. Blobs were already safe: the
    store checks each blob's SHA-256 on read.
  - **Also:** `collect` logged only the exception's type and message, which is why this took a
    scan to find. Failures now log the innermost frames (`file:line function`).

### Open questions / next steps
- Run outputs (`write_jsonl`) are written without the read-back, after the thread pools have
  finished; if the race shows up there, it will fail loudly on the next read.

## 2026-10-28: Stage 3 capability analysis

**Stage(s):** Stage 3 (AST capabilities)
**Context:** The user asked to start Stage 3 after the resilience work. Stage 2's regular
expressions can't tell a URL in a comment from a network call; a parse can.

### Decisions
- **tree-sitter queries with name filters in the query** (`#any-of?`), so Python only sees
  relevant nodes; per-file results cached by content hash, language and extractor version.
- **Capabilities per version, compared with the previous version in the batch.** The gain is
  attributed to the version that made it, even if the burst reverts it. This is the same burst
  contract as Stage 2.
- **Same input as Stage 2, no narrowing.** Measured cost: about 760 MB of distinct JS/TS per
  hourly run parses in 81 s on 8 threads. Narrowing would repeat the recall loss in 0008.
- **Two rules, chosen from measured signal rates** (see [stages/ast.md](stages/ast.md)):
  - `code.capability-gained`: updates only. New packages "gain" everything, and 34% of benign
    new packages would fire.
  - `npm.install-script-code`: profiles the files an install hook runs. That covers an
    unchanged `node setup.js` whose `setup.js` changed, which Stage 1 can't see.
- **`env-all` means the whole environment as a value.** Reading `process.env.HOME`, or
  destructuring `{HOME}`, doesn't count. Gaining `env-all` is the strongest single signal:
  0.2% of benign updates vs 70.9% of malicious ones.

### Challenges
- **tree-sitter 0.26.0 corrupts the heap.** The cost measurement segfaulted inside Python's
  GC.
  - First cause found: a `Parser` shared across threads (bus error). Fixed with per-thread
    parsers.
  - The segfault remained single-threaded. I bisected it to one 14 KB TypeScript file from a
    live run. Parsing alone was fine, but using nodes from query matches crashed it (the
    symptom moved with allocation timing).
  - The same script passes on 0.25.2, so the pin is `<0.26` with a comment in
    `pyproject.toml`.
  - **Why it worked:** the minimal repro crashes on 0.26.0 and passes on 0.25.2, and the full
    run over 53,503 files completes.

### Evaluation snapshot
- `stage3-rules`: A 80.6%, B 33.7%, benign 0.2%.
- End to end: `pipeline` 86.0% / 66.0% / 0.7% → `pipeline+3` **89.7% / 66.0% / 0.8%**.

### Open questions / next steps
- Stage 3 adds nothing on new packages yet. Candidates: capability *combinations* in the
  main entry file, or obfuscation measured on the AST.
- No data flow: `const m = "child_process"; require(m)` reads as `dynamic-require`.
- Stage 4 (correlation and scoring) is next. Many LOW findings across stages are waiting to
  be combined.

## 2026-10-28: Metadata-vs-tarball rules, and surviving network failures

**Stage(s):** Stage 2 (npm artifact rules), Stage 0 and `collect` (resilience)
**Context:** The user asked for a rule closing the "declared size is publisher-controlled" gap
from [0008](decisions/0008-stage2-routing-and-tarball-capture.md). Then they asked for
protection against network drops, choosing that over renting cloud compute. From Stage 5 on,
the whole pipeline is planned to move into a VM on their desktop.

### Decisions
- **Compare metadata with the tarball, two rules** (`ecosystems/npm/rules/artifact.py`):
  `hidden-install-script` (HIGH: an install hook the registry metadata doesn't show; npm runs
  the tarball's) and `size-mismatch` (MEDIUM: files bigger than `dist.unpackedSize`). The first
  is the documented "manifest confusion" weakness, found while looking at the size question.
- **Flag understated sizes only.** Overstating doesn't help an attacker, and the two-sided
  version fired on 236 DataDog samples, all from files missing in the dataset's zips.
- **Network failures are retried, not skipped** ([0009](decisions/0009-network-failure-handling.md)):
  - `TransientFetchError`, a retry list in the checkpoint, and an outage threshold that
    writes nothing.
  - Stage 1–2 catch-up for recent runs.
  - A chain gap of 7 days instead of 48 hours.
- **Not cloud, for now:** resilience is needed anyway, and the sandbox may break providers'
  terms. The planned VM host is recorded in the roadmap.

### Challenges
- **Stage 0 turned network failures into permanent data loss.** Found by reading the error
  path while answering the user's question. A failed packument fetch was a "skipped package",
  and the checkpoint moved past it.
  - **Resolution / why it worked:** transient skips are carried in the checkpoint and fetched
    over their original window next run. Tested by `test_network_skips_are_retried_by_the_next_run`
    (offline package, then back online) and `test_an_outage_writes_nothing`.
- **The size rule can't catch the evasion it was asked for, in full.** A version that
  understates its growth below 64 KiB is never downloaded, so no post-download check sees it.
  The rule covers routed versions only. Recorded as a limit, with an untried idea: the
  tarball's `Content-Length`, which the publisher doesn't declare.

### Evaluation snapshot
- Artifact rules on `day1`: 0 of 1,468 benign samples flagged. On live data (1,069 versions)
  declared and real sizes matched exactly every time. No malicious sample hid an install
  script, so there is no recall evidence either way: these rules guard against evasions the
  dataset doesn't contain.

### Open questions / next steps
- `Content-Length` (HEAD request) as a publisher-independent growth signal for routing.
- Stage 3 (capabilities) has started; see the next entry.

## 2026-10-27: Hybrid routing to Stage 2, tarball capture in `collect`

**Stage(s):** Stage 1 forward policy, Stage 2 pipeline wiring, retention
**Context:** Stage 2 only adds recall if it reads code Stage 1 has no reason to forward. The
user chose a hybrid between "behind the Stage 1 gate" and "every release". See
[0008](decisions/0008-stage2-routing-and-tarball-capture.md).

### Decisions
- **Route by size growth, not by small size.** I had proposed adding updates *below* a size
  limit. Simulating from the saved per-sample eval results showed that adds nothing under 5 MB:
  malicious updates are large because the payload is added code. A growth of ≥ 64 KiB in
  declared unpacked size routes 71% of malicious updates and 8.3% of benign ones.
- **16 MB download cap per version.** About 10x less volume for 0.3 points of recall.
- **Keep watched packages routed** even though DataDog shows little gain from them: its
  samples are mostly unpopular packages, while popular-package takeovers are the
  highest-impact attacks.
- **Run Stages 1 and 2 inside the hourly `collect`.** Malicious tarballs are deleted quickly,
  so they must be fetched in the same tick.

### Challenges
- **Retention would never have deleted a tarball.** Garbage collection treated every
  immutable-index entry as a live reference, and tarballs are fetched as immutable. Found while
  checking how captured tarballs would be pruned, before the hourly agent picked up the change.
  - **Resolution:** the index is now a cache: entries whose blob no run references are deleted
    first, then the blobs. Pruning pins OSV-named packages' tarballs from `static-snapshot.json`.
  - **Why it worked:** `test_tarballs_follow_retention` (labeled and unlabeled cases).
- **Live false positives.** The first live Stage 2 run flagged 6 versions, all benign. Two were
  rule bugs: a Slack webhook placeholder in docs, and `requestbin` inside the identifier
  `OscoreRequestBinding`. `exfil-endpoint` v2 requires a webhook id and a dot after `requestbin`.
  - **Why it worked:** `pipeline` benign pass-through 0.9% → 0.7%, recall unchanged.

### Evaluation snapshot
- End to end (`pipeline`, `day1`): A 86.0%, B 66.0%, benign 0.9% weighted. Before (Stage 1
  rules alone): 80.1% / 58.2% / 0.6%. The old gate would have given 83.5% / 58.2% / 1.0%.
- Simulation and real run agreed to the decimal, so the per-sample reports are a reliable,
  fast way to compare routings.

### Open questions / next steps
- Disk: about 14 GB/day of tarballs, about 100 GB at steady state (263 GB free).
- `dist.unpackedSize` is publisher-declared; compare it with the real size after download.
- Content-cache hit rate across hourly runs is still unmeasured.
- Next stage: Stage 3 (AST capabilities), after asking.

## 2026-10-27: Stage 2 static heuristics, first evaluation and tuning

**Stage(s):** Stage 2 static diff heuristics
**Context:** Stage 1 misses 42% of first-release malicious packages (shape B) because their
metadata looks normal. Stage 2 reads the code each release adds, with regular expressions only.

### Decisions
- **Analyse new file contents, not diffs of lines.** Every content (by SHA-256) that is in a
  version of the batch but not in the base is analysed once and cached on disk by content and
  rule fingerprint. Alternative: line diffs per file. Rejected because payloads are often
  appended to bundled files, and a whole-file rule result is cacheable across packages.
- **Evaluate with the DataDog files decrypted in memory only.** The package files are read from
  the encrypted zip with `include="/package/"` and never written out.
- **Five rules downgraded MEDIUM → LOW** (`npm-publish`, `dynamic-code`, `encoded-blob`,
  `env-harvest`, `sensitive-path`). Each fired on 1–8% of benign releases, close to its rate on
  malicious ones. Kept as LOW evidence for Stage 4 combination scoring instead of being
  removed: together they may still separate the classes.
- **File cap 2 MB → 16 MB.** See below.

### Challenges
- **First run: 19.5% recall on shape A.** Per-sample inspection showed 698 of 965 shape-A
  samples had a new file over the 2 MB cap: the payload is appended to an existing large
  bundle, so the file was skipped.
  - **Resolution:** cap raised to 16 MB (Shai-Hulud's payload is ~10 MB).
  - **Why it worked:** A recall 19.5% → 71.5% on the same dataset.
- **Benign pass-through 11.5%.** Per-rule counts: `npm-publish` alone hit 6.4% / 8.0% of
  benign A / B (release tooling mentions `NPM_TOKEN`).
  - **Resolution:** the five downgrades above.
  - **Why it worked:** 11.5% → 1.0%. Cost: B recall 74.4% → 49.9%.
- **A 95 MB zip member aborted a 17-minute evaluation**, and a cache temp-file race crashed
  another. Fixed with `skip_oversize`, a per-sample catch-all that counts errors in `notes`,
  and a shared `util/files.atomic_write`. See [validation.md](validation.md).
- **Follow-on numbers are inflated.** Stage 2 gets 84% on shape-A follow-ons vs Stage 1's 2.7%,
  but mostly because the malicious base is gone from npm (1,542 samples), so all files count
  as new. Recorded as optimistic, not as a win.

### Evaluation snapshot
- `stage2-rules`: A 19.5% → 71.5%, B 74.4% → 49.9%; benign 11.5% → 1.0%.
- `stage1+2-rules` (either stage): A 91.4%, B 66.1%, benign 1.5%, vs Stage 1 alone 80.1% /
  58.2% / 0.6%.

### Open questions / next steps
- **The union number assumes Stage 2 sees every release.** Behind the Stage 1 gate, the
  samples only Stage 2 catches are mostly dropped first (unwatched, no metadata signal).
  Running it on everything means ~109k tarballs a day (mean 2.1 MB, median 62 KB in the eval
  store). Needs a decision with the user: gated, all releases, or all new packages plus gated
  updates, possibly with a size cap from `dist.unpackedSize`.
- Pipeline command over `batches.jsonl`, tarball capture in `collect`, content-cache hit rate.
- Evaluation is slow (~37 min per predictor; pure-Python ZipCrypto under the GIL).

## 2026-10-27: Burst handling between Stage 1 and Stage 2

**Stage(s):** Stage 1 output contract, Stage 2 design
**Context:** Stage 1 forwards ~15k versions a day, 96% only because the package is watched.
The user chose to handle bursty packages (option 1 of three; the other two were deprioritising
prereleases and raising the popularity bar).

### Decisions
- **Batch per package per run, but never reduce a batch to its newest version.** My first
  description of option 1 ("analyse the latest, diffed against the last analysed version")
  was wrong: a malicious version reverted within the burst would never be inspected. The
  corrected contract (`PackageBatch`, [stages/triage.md](stages/triage.md)) is that Stage 2
  analyses every distinct file content in any version of the batch, once.
- **Content-hash analysis cache across runs** for Stage 2, keyed on content SHA-256 plus rule
  versions. It is deterministic because analysis is pure.

### Challenges
- **The estimated saving didn't hold.** I had estimated ~5k packages a day. That is true for
  daily batching (5,634), but at the hourly collection cadence bursts spread across hours: the
  simulation gives ~11,800 batches (−20%). The content cache is where the real saving should
  come from. It is unmeasured until Stage 2 downloads tarballs.

### Open questions / next steps
- Measure distinct-content ratios once tarballs are fetched (Stage 2).

## 2026-10-27: Stage 1 metadata triage, DataDog samples, and the stub bug

**Stage(s):** Stage 1 (new), evaluation, plus one Stage 0 fix (flagged below)
**Context:** The user approved Stage 1. With 0 prospective malicious samples, they also approved
downloading malware as long as it is only executed in the sandbox
([0007](decisions/0007-datadog-samples-and-follow-on-releases.md)).

### Decisions
- **Rule contract** (`core/rules.py`): `evaluate(change, ctx)`, with `RuleContext` holding only
  `as_of`. Rule versions are recorded on findings.
- **Forward policy:** MEDIUM or above, or a watched package. LOW findings only score.
- **DataDog samples as metadata only:** the zips stay encrypted; only `package_info` (the
  captured packument) is decrypted, in memory. It goes through the same `Packument` parser as
  Stage 0.
- **Follow-on releases in their own cell.** Recall measured against a malicious diff base is
  meaningless for change-based rules.

### Challenges
- **A Stage 0 bug found through Stage 1's numbers.** The install-hook rule fired on 0 of 4,124
  new packages. 98% of them were npm staged-publishing stubs (`0.0.0-stage`), and real first
  releases diffed against those stubs.
  - **Resolution:** the npm `Packument` skips stubs as a diff base (tool 0.2.0); evaluation
    rebases old runs. This touches Stage 0 inside a Stage 1 task. It is a correctness fix in
    the npm adapter with no contract change, and is flagged here and in
    [validation.md](validation.md).
  - **Trap avoided:** skipping stub *releases* outright would let an attacker hide a release
    by setting `"stub": true` in package.json. Stubs are still emitted.
- **Shape-A recall looked like 55%.** Splitting by whether the previous version was also
  malicious gave 81% on first releases and 3% on follow-ons. Most "misses" were the 2nd–nth
  versions of the same worm wave (Shai-Hulud, 2025-09/11).
- **One rule was most of the noise.** `npm.publisher.unfamiliar` caused ~90% of benign forwards
  for 10 unique catches. Downgraded to LOW: pass-through went from 2.6% to 0.6%, and A recall
  from 81.1% to 80.1%.
- **Smaller tunings:** CalVer exempted from `npm.version.suspicious`; `workspace:` specs
  treated as registry specs.

### Evaluation snapshot
- `stage1-rules` on `day1`, first releases: recall A **80.1%**, B **58.2%**; benign
  pass-through **0.6%** (weighted; labels provisional).
- `stage1` (with watched packages): A 85.6%, B 58.2%, pass-through 14.5%.
- Baseline `popularity-only`: A 21.8%, B 0%, pass-through 13.9%.

### Open questions / next steps
- **42% of shape-B first releases have no metadata signal** (payload runs on import), so Stage
  2 is needed.
- **Tarball capture at ingest** for forwarded changes, before npm removes them.
- **The DataDog bias** towards GuardDog-detectable patterns needs checking against prospective
  samples.
- **Watched-package forwarding is 96% of Stage 1's output** (14.7k/day). Is that budget right
  for Stage 2?

## 2026-10-27: Hourly chained collection and retention (Phase 9 started)

**Stage(s):** Stage 0 orchestration (`core/run.py`, `core/retention.py`, `collect.py`, CLI)
**Context:** The first 24h run found no malicious samples, because everything malicious was
removed before the run fetched it. The user chose hourly collection with retention, ahead of
Stage 1, so samples accumulate while Stage 1 is built.

### Decisions
- **`kitsunox collect` under launchd, hourly**:
  - The watchlist is refreshed weekly and labels daily. Both are best-effort: a failure is
    logged and the previous one is kept.
  - Each tick records one chained ingest run. A failed ingest fails the tick and leaves the
    checkpoint where it was.
  - Pruning runs daily. See [0006](decisions/0006-scheduled-collection-and-retention.md).
- **Chained runs instead of fixed 24h windows.** The checkpoint now records the previous run's
  id and `as_of`. The next window starts 15 minutes before that, and coverage holds because
  the feed ranges are contiguous. Alternatives were a fixed 1h window (it loses releases whose
  feed entry lands after the run that should have seen them) and a 24h window every hour
  (re-emits every release 24 times).
- **7-day retention, not 30** (roadmap decision 5, resolved). Datasets need only the
  `Change` records, which are kept forever and compressed. Raw packuments are pinned only for
  packages named in OSV records.
- **A data-directory lock** (`flock`), because pruning deletes unreferenced blobs and a
  recording run's blobs aren't referenced yet.

### Challenges
- **A coverage false alarm in the design.** The coverage estimate of an hourly run (1st
  percentile of last-modified times) always falls just after the window start once the window
  overlaps the previous run. Every tick would have warned. **Resolution:** chained runs are
  covered by contiguity of the feed, recorded as `chained_from` in the manifest.
- **Crash-safety of pruning.** If the process died after compressing `changes.jsonl` but before
  writing `retention.json`, the retry would have found no plain `changes.jsonl` and pinned
  nothing. Caught while writing the code. **Resolution:** read through `changes_file()`, and
  write the marker last. Test: `test_crash_after_compressing_still_pins`.
- **Each step closes its HTTP client**, so a single injected client failed after the first
  step in tests. `collect` now takes a client factory.

### Evaluation snapshot
- First real tick (foreground): 70 minutes of feed, 3,502 packages, 4,704 changes, 2m23s,
  chained from the 24h run, replay identical. First launchd tick: 178 packages in 9s, exit 0,
  no macOS privacy (TCC) problems from running inside `~/Documents`.

### Open questions / next steps
- **Tarballs are not captured at ingest**, so malicious samples will have metadata but no code.
  That needs solving with the forward policy (Stage 1/2).
- **Dataset rebuilds are still manual** (`eval build`). They could join `collect` once Stage 1
  has a predictor worth tracking.
- Next: Phase 4, Stage 1.

## 2026-10-27: Phase 3 (light) evaluation harness, and the first real 24h run

**Stage(s):** evaluation harness (`evaluation/`), Stage 0 at full scale
**Context:** Build the light harness chosen by the user: OSV labels, datasets from our own runs,
and baselines, with no malware tarballs. Then run the whole chain for real over 24 hours. Harness
code: `b325b72`. Label fixes: the commit after it.

### Decisions
- **Ground truth comes from our own runs** (prospective labeling), not from downloaded malware.
  A release becomes a sample only if we recorded it, so samples always have the metadata the
  pipeline actually sees.
- **Label hygiene** ([0005](decisions/0005-label-hygiene.md)): npm takedown placeholders are
  never malicious. An open-ended OSV range counts only for releases published no later than the
  record.
- **Re-weighted pass-through:** benign strata are sampled equally (500 each) but differ hugely
  in size, so reports weight each stratum's rate by its population.

### Challenges
- **Every "malicious" match in the first run was a label artifact.** The run matched 29
  releases. 27 were npm placeholder stubs (`0.0.1-security`, `0.0.0-stage`, published by the
  `npm` account) matched by "all versions" ranges. 2 were legitimate GitLab-CI trusted-publisher
  builds of `@magda/semantic-indexer-sdk`, matched by a 2025 Shai-Hulud record. Found by reading
  the 29 samples before writing up the numbers.
  - **Resolution:** exclude placeholders and open-range projections, counting both
    (`excluded: {registry-placeholder: 41, label-projected: 2}`). Tests:
    `test_placeholders_and_projected_labels_are_excluded`,
    `test_open_ranges_only_observe_earlier_releases`, `test_security_placeholder`.
  - **Why it worked:** 0 malicious samples remain. That is correct for a single run: every
    malicious package in the window was taken down before the run fetched its packument.
- **Popularity-only pass-through read 50.0%, which was meaningless.** It is exactly the share
  of watched samples, because the sampler takes 500 per stratum.
  - **Resolution:** record stratum populations and weight by them. The population had 14,743
    watched and 90,607 unwatched shape-A releases, so the weighted rate is **13.5%**
    (A: 14.0%, B: 0%).
  - **Why it worked:** checked by hand against the population counts, and by
    `test_pass_through_is_reweighted_to_population`.
- **Dataset rebuilds were not byte-identical**, because `built_at` is the current time. The
  samples are identical, so this was left as provenance metadata and documented.

### Evaluation snapshot
- Run `20261027T210847Z-npm` (offline replay identical, 7.4 min): 24h window, feed `(139752494, 140152494]`, 63,143 packages,
  109,497 changes, 0 skipped, 0 popularity failures. Window covered: the feed start estimate is
  2026-10-26T14:28Z, 6.7h before the window start.
- Timing: watchlist 12.2 min (63,172 packages); labels sync 14 s (222,516 records, 222,515
  packages); 24h ingest 46.5 min (~23 packages/s). Disk: blobs 5.5 GB, runs 792 MB.
- Baselines on `first-24h` (benign labels all provisional, since labels are less than 30 days
  newer): forward-all 100% pass-through; popularity-only 13.5% weighted. Recall is n/a with no
  malicious samples.

### Open questions / next steps
- **Malicious samples need repeated ingest runs** to catch releases before takedown. A scheduled
  hourly run (launchd) needs the user's go-ahead.
- **Blob store growth:** 5.5 GB per day of packuments. This needs a retention policy before
  scheduling.
- **Next:** Phase 4, Stage 1 metadata triage. Ask before starting.

## 2026-10-27: Scope correction: git-commit path planned alongside npm

**Stage(s):** architecture (no code)
**Context:** The user pointed out that they had intended a git-first pipeline (commits → filter →
full repo → compare to npm). The npm-only focus came from my recommendation in
[0002](decisions/0002-data-sources.md), which was approved in a bundle of recommendations. The
git-first option was never presented as an explicit choice.

### Decisions
- **Parallel paths** (user's proposal): keep the npm registry path, and add a path that watches
  commits on the GitHub/GitLab repos of popular npm packages. Releases are joined to repos for
  tarball-vs-repo comparison. See [0004](decisions/0004-git-path-parallel-to-npm.md).
- **Order:** finish the npm workflow first, then build the git path (roadmap 8b).

### Challenges
- **Scope drift from a bundled recommendation**: a direction-setting choice (which source drives
  the pipeline) was accepted without its alternative being visible. **Resolution:** from now on,
  such choices are presented as explicit options with what they exclude.

### Open questions / next steps
- Git phase: polling budget vs. GH Archive, a GitHub token, GitLab coverage.
- Next: Phase 3 (evaluation harness) scope.

## 2026-10-27: Validation pass on Stage 0: fuzzing, live cross-checks, 6 fixes

**Stage(s):** Stage 0 ingest and foundations (`util/`, `core/`, `ecosystems/npm/`)
**Context:** Before building the evaluation harness, the user asked to test and validate what
exists. Full report: [validation.md](validation.md). Also in this session: schema versions on
persisted records (`6b027a1`, see architecture.md).

### Decisions
- **Property-based fuzzing with Hypothesis, deterministic by default** (`derandomize=True`), so
  the normal test run stays reproducible. An `explore` profile with random seeds and 20k
  examples is used for validation passes.
- **Differential testing for semver** against the `semver` library, as an independent oracle
  instead of hand-picked cases.
- **Live validation against independent sources:** ecosyste.ms (releases) for completeness and
  deps.dev for field accuracy. Neither is used in the pipeline itself, which keeps the check
  independent.
- **Lenient tar reading + anomaly flag** instead of strict reading. Analysis must see everything
  any installer might extract. The disagreement between readers is itself evidence.
- **Catch-all per-package error handling in Stage 0**, recorded as `UNEXPECTED ...` in
  `skipped.jsonl`. Normally a broad `except` hides bugs, but here the alternative is an attacker
  being able to halt the scanner with one malformed package. Visibility comes from
  `skipped.jsonl`.

### Challenges
- **Tar parser differential (high severity):** a malicious file after an end-of-archive marker,
  an invalid header, or a zero block was invisible to analysis. Confirmed with crafted archives
  and fixed (F1 in validation.md).
- **Run-wide crash from one packument (high severity):** `"maintainers": 1.0` raised
  `TypeError`. Found by fuzzing, though at first it surfaced only intermittently: the failing
  example had been found by the random-seed run and saved to Hypothesis's database, and the
  deterministic run then replayed it. Fixed (F4).
- **Completeness check looked catastrophic at first:** 823 of 1,015 independently listed
  releases were "absent".
  - **Resolution:** the feed range covered only ~31 minutes of the 3-hour window. Within the
    covered time, 148 of 149 releases were found.
  - **Why this matters:** it revealed that nothing checked coverage (F6, fixed), and that the
    "2h window" smoke runs earlier today had really covered ~12–25 minutes. Their throughput
    numbers are still valid. Their coverage claims weren't.
- **Feed start estimate:** the minimum last-modified time (18:36) badly overstated coverage. The
  1st percentile (19:52) matched the measured start, so that's what is used.
- **Truncated gzip (F2), drive letter after strip (F3, found by deep fuzzing), and HTTP error
  handling (F5)** were smaller fixes.

### Evaluation snapshot
- Not a detection evaluation. Implementation quality, before → after:
  - Tests: 106 → 140.
  - Branch coverage: 94% → 96%.
  - Fuzz failures: 4 distinct bugs → 0 over 240k random cases.
  - Live feed completeness: 99.3% (148/149).
  - Publish-time accuracy: 127/127.
  - Provenance: 127/127 after checking the 2 disagreements against npm (deps.dev lag).

### Open questions / next steps
- **npm feed omissions** (1 in 149 observed; the true rate is unknown). Measure over a larger
  sample, then decide whether to add a supplementary discovery sweep, e.g. periodically
  re-checking ecosyste.ms recent releases against our runs.
- Make the live cross-checks a repeatable `kitsunox validate` command.
- Provenance is the registry's claim, not a verified Sigstore bundle. Decide whether
  verification is worth it for Stage 1.
- Then Phase 3, the evaluation harness.

## 2026-10-27: Popularity: per-change lookups abandoned for a weekly watchlist

**Stage(s):** Stage 0 ingest (popularity enrichment). Closes Phase 2.
**Context:** Stage 1's forward policy needs "is this package popular?" for every change to an
existing package. The plan (roadmap decision 3) was per-change lookups against the npm downloads
API, with a ≥1k weekly or ≥10 dependents cutoff. Full write-up:
[decision 0003](decisions/0003-popularity-watchlist.md).

### Decisions
- **Weekly watchlist from packages.ecosyste.ms** (user-approved): packages ranked by last-month
  downloads, paged until below the cutoff, saved as a small JSON list. Runs record the list's
  id and SHA-256, and replay verifies it. Per-change API lookups are kept as `--popularity api`.
- **Cutoff raised to 10k weekly** (user-approved): ≥43k monthly on the watchlist.
- **Dependents dropped as a criterion for now**: deps.dev only has them via a per-version
  `v3alpha` endpoint. Counts are stored in the watchlist for later.
- **Per-host request pacing in `HttpFetcher`** (`set_min_interval`): generic, so any throttled
  API can use it. Replays and cache hits are never paced.
- **Download counts for a closed period are cached across runs** (immutable), since they're
  final.

### Challenges
- **The npm downloads API throttles hard**: `429` with `retry-after: 0`. The first live run with
  8 threads had 64 of ~1,100 lookups fail after retries, and took 3m22s vs 34s without
  popularity.
  - **Resolution:** a burst test showed sequential requests (~2.4/s) never got a 429 while two
    parallel ones did almost at once, so requests are paced at 0.5 s. The next run had 0
    failures.
  - **Why it wasn't enough:** 88% of changed existing packages were scoped (946 of 1,075), and
    scoped names can't use bulk lookups. That run took 8.5 minutes, which is ~12h for a full day.
- **The planned 1k cutoff was far too low**: 57% of changed existing packages clear it (20% at
  10k, 8% at 100k).
- **ecosyste.ms pages are huge**: ~100–200 MB per 1,000 packages, with no field selection.
  gzip transfer is ~8× smaller. Raw pages go to a temporary blob store and are discarded.
- **Old run files no longer load** after the `Popularity` model changed: models forbid unknown
  fields, so scratch runs recorded earlier fail validation. No real data was affected, but
  records have **no schema version**. This needs fixing before data accumulates.

### Evaluation snapshot
- Watchlist vs API weekly counts on 1,638 packages: 92.2% agreement. The watchlist caught 221 of
  296 packages that the API showed at ≥10k/week (75%). Its misses are mostly fast risers or
  spikes. Mitigated by Stage 1 forwarding anything flagged; not yet measured against attacks.
- Ingest with watchlist: 38 s per ~1,250 packages (vs 8.5 min API mode), replay identical.

### Removed / abandoned
- **Per-change downloads-API popularity as the default**: ~12h/day of paced requests for a full
  day of npm. Kept as an opt-in mode.

### Open questions / next steps
- Add a schema version to persisted records (`Change`, `RunManifest`, `Watchlist`).
- Consider a bulk downloads-API top-up for unscoped packages to catch fast risers.
- Phase 3: evaluation harness.

## 2026-10-27: Phase 2, Stage 0 ingest with record/replay

**Stage(s):** Stage 0 ingest, plus core and util foundations
**Context:** Build the foundation every later stage depends on: data models, a fetch layer that
makes runs reproducible, a safe way to open untrusted tarballs, and the npm adapter. See
[stages/ingest.md](stages/ingest.md).

### Decisions
- **Snapshot fetcher instead of a plain HTTP cache** (`util/http.py`): each run records request
  key → content hash in `snapshot.json`; replay mode answers only from it and fails on a miss.
  A TTL cache was rejected because it gives "probably the same" inputs, not provably the same.
  Integrity-pinned responses (tarballs) are also indexed across runs, so they're downloaded once.
- **In-memory tarball extraction** (`util/archive.py`): no files written means no path-traversal
  or symlink attack surface on the host. Links, devices, FIFOs and unsafe paths are *reported*,
  not silently dropped, because a symlink to `~/.npmrc` inside a tarball is itself a signal.
  Trailing gzip data is rejected, since tools disagree on how to read it.
- **Previous version = highest lower semver published earlier**, falling back to publish order.
  This diffs backports against their own release line (tested: `1.1.1` after `2.0.0` → `1.1.0`).
- **Ecosystem contract uses feed positions, not time**: the npm feed has no timestamps, so
  `list_changes(since, until)` works in sequence numbers and the publish-time window is applied
  to packument `time` entries. This differs from the Phase 1 sketch; architecture.md is updated.
- **Rule/Stage contracts deferred to Stage 1**: there's no consumer yet, and guessing them now
  would mean revising them later.
- **No popularity yet**: deferred within Phase 2, because it isn't needed until the Stage 1
  forward policy.

### Challenges
- **Packument storage blew up**: the first live run stored **1.4 GB for 1,208 packages**, because
  packages with long version histories have multi-MB packuments. At ~100k packages a day that
  would be ~140 GB/day.
  - **Resolution:** zstd-compress blobs (stdlib `compression.zstd`, Python 3.14), still keyed by
    the hash of the uncompressed bytes.
  - **Why it worked:** the second live run stored **119 MB for 1,068 packages** (≈10× smaller),
    and the replay was still byte-identical. The abbreviated packument was considered and
    rejected: it lacks the per-version `time` map and `_npmUser`.
- **Extractor false positive on real tarballs**: a real package's tarball had a bare `package`
  directory entry, which was reported as an "unsafe path".
  - **Resolution:** skip directory entries before path validation. Directories are implied by
    file paths anyway.
- **Monorepo repository URLs** (`github.com/o/repo/sub/pkg.git`) weren't normalized.
  - **Resolution:** drop the sub-path. Covered by a parametrized test.
- **FIFO reported as "device"**: Python's `tarfile.isdev()` is also true for FIFOs. Caught by
  `test_unsafe_and_special_entries_are_reported_not_extracted`; fixed by checking FIFO first.

### Evaluation snapshot
- No detection yet, so no recall/FP numbers. Ingest health on two live runs: 0 skipped packages,
  59 of 60 random tarballs extracted cleanly (1 was a 404, removed after publish), replay
  identical both times.
- Live observations (one 2h sample of 1,821 changes, worth re-measuring):
  - 40% of new versions use trusted publishing and 34% carry provenance.
  - 2.5% are brand-new packages.
  - 1.6% have install scripts.
  - No trusted → manual publish downgrades were seen.

### Open questions / next steps
- Popularity enrichment (downloads API bulk for unscoped names; deps.dev for dependents).
- Blob retention policy (roadmap decision 5).
- Cross-run dedupe of changes re-emitted when a package is touched again.
- Measure npm read rate limits at full-day volume (only ~35 packages/s tried so far, with no 429s).
- Then Phase 3: the evaluation harness.

## 2026-10-27: Planning: threat model, architecture, data sources, evaluation

**Stage(s):** all (design only, no pipeline code)
**Context:** With the scaffold in place, we drafted the Phase 1 planning docs and settled the
four decisions that block Phase 2: [threat-model.md](threat-model.md),
[architecture.md](architecture.md), [evaluation.md](evaluation.md), [roadmap.md](roadmap.md),
and [decisions/0002-data-sources.md](decisions/0002-data-sources.md).

### Decisions
- **Discovery via the npm replication `_changes` feed + full packuments**: GitHub-based discovery
  was rejected because the main attack path (publishing straight to the registry) never touches
  git. Third-party aggregators (deps.dev, ecosyste.ms) were rejected for discovery because of
  lag; commercial feeds because they aren't independent or reproducible. GitHub, deps.dev and
  OSV stay in supporting roles. See [0002](decisions/0002-data-sources.md).
- **Split attacks into shape A (compromised existing package) and shape B (new malicious
  package)**: they need different signals (delta vs. absolute + name similarity). Recall is
  reported per shape so typosquat-heavy public datasets can't hide weak shape-A recall.
- **Publish-method change as a planned Stage 1 signal**: packuments now expose
  `_npmUser.trustedPublisher`, `approver`, and `dist.attestations`. A version published
  manually where earlier ones came through OIDC trusted publishing is cheap to detect. Expected
  to be high-precision, but **unproven until measured**. Provenance alone is not treated as an
  all-clear, since a hijacked CI workflow produces valid attestations.
- **Determinism by snapshot + pure analysis**: all fetches go through a caching client into a
  content-addressed snapshot; stages 1–4 never read the clock and use an explicit `as_of`.
- **Run ledger**: stages record cleared items instead of dropping them, so per-stage recall and
  pass-through can be computed.
- **Eval harness before any detection stage** (roadmap Phase 3), so every rule lands with numbers.
- **User decisions (all accepted as recommended):**
  1. Tarball-vs-repo: three checks (manifest, tarball-only JS, changed shared files) against the
     GitHub repo at `gitHead`/tag, with a build-output allow-list. Rebuilding packages is out of
     scope.
  2. "Recent" = versions published in `[as_of − 24h, as_of]`, with `as_of` explicit.
  3. Coverage: all changes through Stage 1. Tarball stages get packages above a popularity
     cutoff (start ≥1k weekly downloads or ≥10 dependents) **or** anything Stage 1 flagged.
  4. Reports: `report.json` canonical, Markdown per candidate + `index.md` rendered from it.

### Challenges
- **The npm replication API changed in 2025**: the old CouchDB `_changes` endpoint was retired
  on 2025-05-29. The new `replicate.npmjs.com/registry/_changes` has no `include_docs` and no
  streaming. Older tooling and many blog posts still describe the old API.
  - **Resolution:** probed the new endpoint live. Root `update_seq` ≈ 140.1M; a 20k-seq page
    held ~6,000 packages, covering ≈80 minutes. Designed Stage 0 around name-only changes plus a
    packument fetch per package (~100k/day).
  - **Why it worked:** verified directly against the live API, not just docs. The volume figure
    is a single sample and needs re-measuring in Phase 2.
- **Shape-A evaluation samples are scarce**: public datasets are mostly new malicious packages,
  and registries remove malicious versions fast, so the "previous benign + malicious" pair is
  rarely available.
  - **Resolution (planned):** a small curated incident set; **prospective labeling** (cache what
    we ingest, then join later against new `MAL-` records); synthetic injected cases reported
    separately. Unproven until Phase 3/9.

### Open questions / next steps
- Benign-label delay (proposed: 30 days) is still open.
- Which historical compromise samples are actually obtainable has not been checked.
- DataDog dataset license and current npm sample count need confirming before use.
- Real read rate limits for `registry.npmjs.org` at ~100k packuments/day: measure in Phase 2.
- Next: Phase 2, which covers `core/` models and interfaces, the caching HTTP client, the safe
  extractor, and the npm adapter for Stage 0. Ask before starting.

## 2026-10-27: Fresh start and project scaffold

**Stage(s):** none yet (project setup)
**Context:** Kitsunox is being rewritten from scratch as a master's capstone in Cybersecurity
Engineering. The goal is a deterministic, explainable pipeline that flags likely supply chain
attacks in recent npm releases. This session set up the repo and toolchain so later stages have a
working base with lint, type-check and test gates from day one.

### Decisions
- **Fresh rewrite, no code reuse from earlier attempts**: the project needs to be explainable and
  reproducible end to end for the capstone defense. Starting clean means every design choice is
  deliberate and documented here, instead of inherited. The README dropped the earlier "AI
  powered" framing: the pipeline is deterministic, and an LLM stage is an optional future
  extension.
- **Tooling stack**: Python 3.14 via uv, pydantic v2 for inter-stage records, mypy `--strict`
  added to the done gate, ruff including bandit (`S`) rules, network tests opt-in. Full rationale
  is in [decisions/0001-tooling-stack.md](decisions/0001-tooling-stack.md).
  - 3.15 was considered and declined for now: it's a few weeks old, and native wheels
    (pydantic-core, tree-sitter) tend to lag.
- **Scaffold before the planning docs**: CLAUDE.md lists scaffolding last, after the threat
  model, architecture and roadmap. We reordered so the "done" gate (ruff, mypy, pytest) exists
  before any real code is written. The planning docs are the next deliverable. No pipeline code
  was written.
- **Repo hygiene**: `data/` is gitignored before any downloads exist, so malicious samples can't
  be committed by accident. `CLAUDE.md` moved from `.claude/` (gitignored) to the repo root so
  the project instructions are version-controlled.

### Challenges
- **uv wasn't installed**: installed with Homebrew (uv 0.13.6). uv fetched CPython 3.14.10.

### Open questions / next steps
- Draft `docs/threat-model.md`, `docs/architecture.md` (Mermaid pipeline diagram) and
  `docs/roadmap.md`.
- Compare data sources for "recent npm changes" (registry changes feed, GitHub API, others) and
  recommend one.
- Propose the labeled evaluation set (OSV `MAL-` advisories, public malicious-package datasets,
  benign recent changes) and how to store it inertly.
- Decisions for the user:
  - Scope of tarball-vs-repo diffing.
  - How "recent" is defined.
  - All of npm vs. a popularity cutoff.
  - Report format.
