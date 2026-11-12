# Round 10, agent G: the install code of git dependencies

Base: main `6e67613`. Built in this branch ([decision 0020](../decisions/0020-git-dependency-install-code.md),
[stages/correlate.md](../stages/correlate.md#git-dependencies-npmgit-dependency-stage-version-22)).
Scripts and outputs: `~/kitsunox-scratch/r10/G/` (`measure_live.py`, `vm_eval.py`,
`replay_g.py`, `g_replay.sh`, `vm_repos.py`, `measure_unchanged.py`; every fetch through a
scratch fetcher there, nothing written under `data/`, nothing fetched ever run).

## Why

`web3-mev-error-decoder@0.1.0` (run `20261109T133823Z-npm`, malicious) had a clean npm tarball
and the dependency `"multicall-error-decoder": "github:outgoingyang/multicall-error-decoder"`.
npm installs it from GitHub and runs its `install` hook, `node dist/error-decoder/handlers.js`,
which AES-decrypts its strings, downloads an archive and starts the executable in it, or pipes
a remote script into the shell. Kitsunox raised only `npm.dependency.non-registry` (Stage 1,
MEDIUM, weight 3). Stages 2-4 never saw the dependency's code.

## What was built

Stage 4 reads, for each runtime dependency a version adds or changes that names a GitHub
repository, the code npm runs when it installs it, and runs the install rules on it as if it
were a package of its own (summary; the details are in the decision and the stage page):

1. Resolve the reference (`#commit`, `#tag`, `#branch`, `#semver:`, none) in the repository's
   ref advertisement (`HEAD` now kept), as of the run, through `RepoMemory`.
2. Fetch the archive at that commit through the run's fetcher (recorded, immutable index,
   pruned with `--keep-repo-days`), extract it with `extract_archive` under
   `DEPENDENCY_LIMITS` in the comparison pool, keep only what npm runs.
3. What npm runs for a git dependency: `preinstall`, `install`, `postinstall`, and the root
   lifecycle of `npm install` in the clone (`prepublish`, `preprepare`, `prepare`,
   `postprepare`), shown to the rules in the three install slots; `npm run` expanded. For a
   GitHub archive URL (a remote tarball to npm), the install hooks only.
4. Stage 1's `npm.install-hook`, Stage 2's file rules and Stage 3's code rules on it, explained
   within the dependency; a commit bump in the same repository is compared with the commit the
   previous release pinned.
5. `npm.git-dependency` (Stage 4, v1) shows the findings with their own ids, severities and
   weights (scored like the release's own), evidence under `dep:<name>@<commit12>/`, an INFO
   summary (commit, scripts, `[network]`/`[process]`/`[filesystem]` uses and
   `[decrypt]`/`[download]`/`[write]`/`[start]` lines), INFO notes for what wasn't read and
   for nested non-registry dependencies (not followed).
6. Explanations apply only within their subject (the package, or one dependency); a
   dependency's severe finding is never cleared by the package's repository match.
7. Caps: 200 distinct specs a run, 10 a package, planned in run order. `STAGE_VERSION` 22.

`http(s):` tarball URLs on other hosts are **not fetched** (noted): the host is often the
attacker's (`vm-day1`: `packages.storeartifact.com`, `npm.jpartifacts.com`, bare IPs), a request
tells them the package is being analysed and lets them serve the analyser something else, and
requests to arbitrary hosts from the collection VM are what an SSRF needs. GitHub release
assets and raw files, GitLab, Bitbucket and other git hosts: noted, not read (see owner
questions). `file:` / `link:`: as before.

## How many versions have a git dependency

| Set | Versions with a non-registry runtime dependency | ... with a GitHub dependency | ... added or changed (read) |
|---|---|---|---|
| Live runs on disk (190 runs, 2026-10-29..11-12) | 4,694 | 1,587 (310 packages) | 174 GitHub (175 distinct specs); 273 versions with any added/changed non-registry dependency |
| Replay set (3,716 verdicted) | n/a | n/a | 226 versions with an added/changed non-registry dependency |
| `vm-day1` (4,944 samples) | 151 (143 malicious, 8 benign) | 126 (125 malicious, 1 benign) | 71 malicious + 1 benign |

Live, the 273 versions add or change 335 non-registry dependencies:

| Outcome | Dependencies |
|---|---|
| GitHub repository, read, nothing found | 132 |
| GitHub repository, read, findings | 30 |
| repository deleted (`realvare/libsignal`) | 1 |
| abbreviated commit in no ref (`#ca122da`, `#40febc7`) | 2 |
| archive 404 (a probe's commit, `chimz-max/laneh-prepare-probe`) | 1 |
| tarball URL on another host (not fetched; 2 of 3 `cdn.sheetjs.com`) | 110 |
| GitHub release asset or raw file (not read; `Signet-AI/signetai` platform builds, `GamerD11/ping_test/raw/...tgz`) | 56 |
| another git host (GitLab self-hosted, gitee) | 3 |

115 distinct commits of 70 repositories were read: 191 MB of archives.

## Decisions before and after

**Live runs on disk** (`measure_live2.py`: re-decided from the recorded candidates with
Stage 1 re-run with today's rules, since older runs recorded older `non-registry` versions,
and `npm.git-dependency` added; "before" is the same without it):

| before -> after | benign | positive | unverified | unverdicted |
|---|---|---|---|---|
| reported -> reported | 87 | 21 | 1 | 2 |
| not reported -> not reported | 126 | 2 | 0 | 30 |
| **newly reported** | **4** | 0 | 0 | 0 |
| **lost** | 0 | **0** | 0 | 0 |

(With the recorded Stage 1 findings, i.e. as those runs scored it, nothing changes: all 217
benign were reported by the older `non-registry`.) The 4 newly reported benign versions, all
through the dependency's `npm.install-hook` MEDIUM on a git-only hook, where today's
`non-registry` is LOW (a tag in the package's own account):

| Version | Dependency | Hook npm runs |
|---|---|---|
| `@aimuzov/kaiten-mcp@1.5.2`, `@aimuzov/thinks-mcp@0.11.2` | `github:aimuzov/infra-mcp-kit#v3.4.1` | `prepare: rm -rf build && tsc -p tsconfig.build.json` |
| `@biongff/vizarr@1.4.0` | `github:biongff/zod-ome-ngff#dev` | `prepare: tsc && publint` |
| `@eqtylab/vcomp-verify-js@0.0.8` | `github:eqtylab/node-forge-ec#EQTY-3` | `prepublish: webpack` |

The 2 unreported positives, before and after, are `signetai` 0.238.1 and 1.0.0 (unwanted):
their dependencies are GitHub release assets in their own account (`non-registry` LOW), which
are not read (owner question 2). What else changes is the evidence: 20 versions reported
before gained a MEDIUM or HIGH dependency finding (10 positives, 10 benign); with the recorded
findings' view, 24 (10 positives, 14 benign: the 4 above included), listed here:

- **Positives (10):** `web3-mev-error-decoder@0.1.0`; the `chimz-max/laneh-prepare-probe`
  family (`lane-m-snackager-*`, `lane-m2-*`, `quiet-lantern-*`: `prepare.js` beacons a
  hard-coded IP: `npm.install-hook`, `npm.install-script-code`, `static.hardcoded-ip`), 
  `@expo-probe-ff8e2b/snack-probe-c2a16@1.0.0` (`lordseidon/recon-vps`, same shape),
  `baileys-linius@1.0.0` (its Baileys fork's `preinstall`).
- **Benign (14), the cluster to expect if `non-registry` is ever narrowed:** git dependencies
  built at install by `prepare` / `prepublish`: `tsc` and variants (`@aimuzov/*` x4 via
  `infra-mcp-kit`, `@blopai/cli` x2, `@ultrst-armada/floks`, `@biongff/vizarr`), generators
  (`devhelm`, `@literary-universe/cli`), `webpack` / `uglifyjs` (`@eqtylab/vcomp-verify-js`,
  `@tangram.gl/tangram-renderer`); `polyframes` (`bunli generate`), `trac-peer` (a
  `postinstall` patch script, HIGH: added since the pinned commit). `npm.install-build-tool`
  lists no compiler, so `prepare: tsc` stays MEDIUM.

**Replay set** (3,716 verdicted versions, `g_replay.sh full`; Stage 4 reads git dependencies
from a snapshot `measure_live.py` recorded, so the replay does not touch the network for
them; counted with `relabel.py` against round 9's `full.jsonl`; 0 errors, 0 replay misses;
226 versions carry an `npm.git-dependency` finding, 135 dependencies read):

| replay | reported | benign | unwanted | malicious | unverified | precision |
|---|---|---|---|---|---|---|
| round 9 (main) | 1,424 | 718 | 645 | 49 | 12 | 49.15% |
| this branch | 1,428 | 722 | 645 | 49 | 12 | 49.01% |

4 benign newly reported (the 4 in the live table), 0 benign unreported, **no malicious,
unwanted or unverified version changes decision**.

**`vm-day1`** (`pipeline+4` on the 151 samples with a non-registry dependency, main vs this
branch, stores under scratch; the pinned dependency and API stores copied in):

| | malicious reported | benign reported |
|---|---|---|
| main `6e67613` | 114 of 143 | 1 of 8 |
| this branch | 114 of 143 | 1 of 8 |

No sample changes. Of the 71 malicious samples that add or change a GitHub dependency, 69
can't be read today: the commits the waves pinned are gone from GitHub
(`tanstack/router#79ac49ee…` 40, `antvis/G2` 26 over three commits,
`opensearch-project/opensearch-js#d446803f…` 2: HTTP 404, fork commits GitHub no longer
serves) or the repository is deleted (`opensearch-project/openearch`, 1). The other 2
(`tenka-san/libsignal-node`, `oonlyjs/node-ews`) were read and run nothing at install. 17 more
malicious samples add a tarball on another host (not fetched). The 29
missed malicious samples all keep an unchanged GitHub spec on an update (20 `tanstack/router`,
1 `antvis/G2`, 2 `navaLinh/sysframe` (deleted), 2 `reclaimprotocol/tls`, 2
`bottino-libsignal`, 1 `node-ews`, 1 `libsignal-node`). Read anyway, `reclaimprotocol/tls`'s
`prepare` downloads (`npm.install-download`, MEDIUM): reading unchanged specs would report 2
more (see owner question 1). The benign sample (`@aimuzov/kaiten-mcp`'s `infra-mcp-kit`) gains
a MEDIUM `npm.install-hook` (`prepare: rm -rf build && tsc ...`) and was reported already.

Existence of the `vm-day1` dependency repositories today: of 16 repositories, 2 deleted
(`navaLinh/sysframe`, `opensearch-project/openearch`); of the 4 pinned commits of
`tanstack/router`, `antvis/G2` and `opensearch-project/opensearch-js`, none is served any
more; the 10 default-branch or tagged ones resolve and download.

## `web3-mev-error-decoder@0.1.0`

Reported by the new findings (score 12; `npm.dependency.non-registry`, `npm.install-hook`,
`npm.install-script-code`), the dependency at `outgoingyang/multicall-error-decoder@240aa9b685e2`
(the default branch, resolved 2026-11-12):

- `npm.install-hook` MEDIUM: `dep:multicall-error-decoder@240aa9b685e2/package.json:scripts.install`
  = `node dist/error-decoder/handlers.js`;
- `npm.install-script-code` MEDIUM: `handlers.js:182 [network] globalThis.fetch`,
  `handlers.js:1 [process] import { spawn, execSync } from 'child_process'`;
- `static.process-exec` LOW;
- `npm.git-dependency` INFO: `[decrypt] handlers.js:172 crypto.createDecipheriv('aes-256-cbc', ...)`,
  `[download] handlers.js:181 async function fetchPayload(url, dest)`,
  `[write] handlers.js:189 fs.promises.writeFile(dest, buf)`,
  `[start] handlers.js:361 spawn(exe, [], { detached: true, ... })`, plus the filesystem and
  OS-info uses.

The test fixture (`tests/stages/test_gitdeps.py`) has the same shape with placeholder strings
and no URL.

## Replay harness

`replay.py` (round 5 K) replays Stages 1-4 per version with recorded context findings and no
Stage 4 network. `replay_g.py` adds the git dependency lookup in replay mode: a fetcher over
`G/fetch` (blob store, immutable index and `snapshot.json` recorded once by
`measure_live.py`, which visited every replay-set version with an added non-registry
dependency), so the replay stays offline and every worker reads the same refs and archives.
A version whose dependency is missing from the snapshot would read "not evaluated" (none
did). `g_replay.sh` is `k_replay.sh` with `replay_g.py`, under the same heavy lock.

## Limits

- Resolved as of the run: a later push to a branch, a deleted repository or a garbage-collected
  fork commit (every `vm-day1` wave's) reads differently or not at all. That is also why
  `vm-day1` can't measure recall here: the attacks' git dependencies are gone.
- Unchanged specs on an update were not read at first; they are since Q1 (Owner answers).
- The dependency's own dependencies (the devDependencies npm installs to run `prepare`
  included) are not read; its git dependencies are listed only.
- Release assets, raw files, other git hosts, tarballs on other hosts: noted, not read.
- `prepare: tsc` is not explained (owner question 3).
- Live cost unmeasured beyond the runs on disk: GitHub refs and archives need no token, one
  request each per run.

## Owner questions (answered 2026-11-12: Q1 yes, Q2 no, Q3 yes, Q4 no; see "Owner answers")

1. **Read unchanged specs too?** Today a GitHub dependency is read only when the version adds
   or changes it (as `non-registry` fires). Reading every version's GitHub dependencies would
   catch a push to a dependency's branch between releases, and 2 more `vm-day1` samples
   (`reclaimprotocol/tls`'s downloading `prepare`; the other 27 missed samples' dependencies
   are gone or run nothing). Live cost on the runs on disk (`measure_unchanged.py`: 1,416 versions with a GitHub
   dependency, 1,832 dependencies, 311 commits of 260 repositories read): **108 more versions
   reported (26 packages, all unverdicted:** `@filen/sdk-rs` 16, `@xrpl-utilities/mcp` 15,
   `@kubohiroya/turbowarp-kamishibai-app` 15, `handoff-app-next` 11, `altium-to-circuit-json` 9,
   `@nethesis/phone-island` 9, ...: mostly `prepare` builds of the same dependency in every
   release), about 8 a day, and **no live positive gained** (4 verdicted positives with an
   unchanged spec stay unreported either way). Not done.
2. **GitHub release assets and raw files** (56 live dependencies, `Signet-AI/signetai`'s
   platform tarballs, the `GamerD11/ping_test/raw/*.tgz` probes): they are npm tarballs on
   GitHub's storage (no tip-off to an attacker's host), but their bytes can be replaced under
   the same URL and some are large binaries. Fetch them (one request each, not immutable)?
   With today's Stage 1, `signetai` 0.238.1 and 1.0.0 (unwanted) are not reported: their
   platform tarballs come from their own account's releases (`non-registry` LOW). Whether
   reading them would report those two is not measured (not fetched).
3. **Explain `tsc` in a git dependency's `prepare`** (`tsc`, `tsc -p …`, `tsc -b`, with
   `rm -rf <dir>` / `rimraf` / `publint` around it)? It would remove 3 of the 4 newly reported
   benign versions (`@aimuzov/*` x2, `@biongff/vizarr`; not `webpack`, which runs its config
   file) and 4 of the 10 already-reported benign versions with a severe dependency finding
   (`@aimuzov/veo-mcp`, `@aimuzov/zen-money-mcp`, `@blopai/cli`, `@ultrst-armada/floks`). The compiler
   doesn't run the dependency's code, but `typescript` comes from the dependency's own
   devDependencies, so the explanation would also need that one to be a registry spec. Not
   done: a new explanation shape is the owner's call; the safe default reports.
4. **Narrow `npm.dependency.non-registry` now that the code is read?** E.g. LOW when a GitHub
   dependency was read and its install code found nothing. Live with today's Stage 1: 87
   benign versions reported with a non-registry dependency (not all of them GitHub ones). Not
   measured to the bar here; a precision round could.

## Owner answers (2026-11-12) and what they measured

- **Q2 (release assets): declined.** GitHub release assets and raw files stay noted, not read.
- **Q4 (narrow `non-registry`): declined**, after the freeze at the earliest.

### Q1: unchanged GitHub specs are read too (`STAGE_VERSION` 23, `npm.git-dependency` v2)

`wanted` takes every GitHub dependency of a version, changed or not; an unchanged spec is read
as new. Measured with `measure_live3.py` (live runs on disk, Stage 1 re-run with today's rules,
each run's caps) and `vm_eval.py` (`vm-day1`), the tree frozen as `q1-src`:

| | main | Q1 |
|---|---|---|
| Live: versions measured (a GitHub dependency, or an added non-registry one) | 1,538 | 1,538 |
| Live: newly reported benign | | 4 (the 4 above) |
| Live: newly reported unverdicted | | 108 (26 packages) |
| Live: positives lost / gained | | 0 / 0 |
| `vm-day1`: malicious reported (of 143 with a non-registry dependency) | 114 | **116** |
| `vm-day1`: benign reported (of 8) | 1 | 1 |

- **The 108** come from packages whose every release depends on the same dependency that
  builds itself: `@filen/sdk-rs` 16, `@xrpl-utilities/mcp` 15,
  `@kubohiroya/turbowarp-kamishibai-app` 15, `handoff-app-next` 11, `altium-to-circuit-json` 9,
  `@nethesis/phone-island` 9, `@diffci.com/diffci` 4, 19 more packages with 1-3.
- **`vm-day1` +2:** `trex-proxy-browser-extension-sdk` 0.1.1 and 0.1.11 (malicious), whose
  unchanged `git+https://git@github.com/reclaimprotocol/tls.git#8e0669a2…` dependency's
  `prepare` downloads (`npm.install-download` and `npm.install-hook`, MEDIUM). None lost.
- **Caps.** The biggest live run, the 4-day catch-up `20261107T163310Z-npm` (405k changes),
  wanted 160 distinct specs (428 versions): 151 commits read, 442 MB of archives; 6 specs
  unreadable (`AnthusAI/Vultus#af98d57`, an abbreviated commit in no ref, for 44 versions;
  two deleted repositories; one without `package.json`; one 404). The next runs wanted 63
  (the 24-hour first run, 206 MB) and 20. No run reached the 200-spec cap, no package the
  10-spec one. Over all runs, 3.3 GB of archives were downloaded (688 MB in the scratch blob
  store, compressed and shared between runs).
