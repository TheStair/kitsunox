# Kitsunox dev log

Reverse-chronological. Newest entry first.

## 2026-10-31 (afternoon): Re-score results, a prerelease downgrade, three skipped ticks

**Stage(s):** Stage 1 (`npm.publish-method.downgrade` v3)
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

### Challenges
- **Three ticks were skipped (06:42, 07:42, 08:42).** The re-score of the first VM day
  (110k changes) was started with no gap before a tick, and held the data lock for 179 minutes.
  The 09:45 tick ingested the whole gap (11,320 changes, window covered), so nothing was lost,
  but three hours were reported late.
  - **Resolution:** later re-scores keep a 20-minute gap and are small.

### Review
- Three dependency-confusion probes from one Bugcrowd researcher account
  (`internal-renderers`, `pandafortunerush`, `ms-client-portal`, 1.0.0 and 10.0.0): install
  hooks send user name, hostname and working directory to a bare IP. Malicious, like earlier
  probes.
- Two more Baileys forks silently follow WhatsApp channels with the user's account on connect,
  now with the channel list's URL or IDs hidden in base64 (`sauruspro-bail`,
  `kevinx-baileys`). Inconclusive, like `luna-baileys`.
- `modulus-security`'s known-malware HIGH was a dependency on `tree-sitter-dockerfile`
  `^0.0.1-security`, npm's empty placeholder for removed malware.

### Evaluation snapshot
- `vm-day1`: unchanged (2,506 malicious, 17 benign reported by the dump); the rule fires on 149
  malicious samples, none a prerelease.

### Open questions / next steps
- Read dist-tags at ingest, so a prerelease tagged `latest` keeps the downgrade's weight.
- A dependency pinned to npm's `0.0.1-security` placeholder needn't be HIGH.
- `install-script-changed` alone still carries 120 unreviewed queue versions.

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
