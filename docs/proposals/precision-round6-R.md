# Proposal: precision round 6, agent R: install-time downloads (`npm.install-download`)

> **Status:** built 2026-11-10/11, before the rule freeze (moved to 2026-11-16 00:00Z), for
> the owner's review. Stage 3: a new rule `npm.install-download`
> (`ecosystems/npm/rules/install_download.py`, MEDIUM, weight 3), a new parser helper
> `lang.javascript.handed_to_runner`, and `npm.install-explained` v6 (S2 and S6 removed).
> **Result (full live replay, real code, today's verdicts; on `main` `fafd51f`, rebased onto
> `c6e0270`):** 1,248 → 1,458 reported: **+183 unwanted, +1 malicious, +26 benign, 0
> positives or unverified lost**; precision 38.42% → 45.66%. Of the 334 versions the owner's download and Windows-executable
> rulings made positive that are in the replay set, 329 are reported (was 151); the other 5
> are 2 never routed to Stage 3 and 3 whose download the rule can't see. `vm-day1`: the rule
> fires on 862 of the 2,319 malicious samples with an install hook; 0 lost (it only adds a
> finding); `pipeline+4` reports 24 more of them (852 of the 862, was 828).
> **Builds on:** [round 5 H](precision-round5-H.md) (S6 and its host logic, reused through
> `install_shapes._own_kind`), [round 5 M](precision-round5-M.md) and
> [round 4 A](precision-round4-A.md) (`npm.install-persistence`'s reach and masking),
> [round 6 Q](precision-round6-Q.md) (`npm.install-explained` v5, merged first),
> [round 3](precision-round3.md) (method), decision [0015](../decisions/0015-reviewer-verdicts.md)
> with all addenda: on 2026-11-10 the owner ruled install-time downloads of code unwanted, first
> from third-party hosts only, then **strictly** (the package's own binary from its own release
> or CDN too), and an install hook that runs a Windows executable unwanted at best.

## Summary

| # | Commit (Stage 3) | What | Benign added (live) | Positives gained | Positives lost | `vm-day1` lost | Kind |
|---|---|---|---|---|---|---|---|
| R1 | `npm.install-download` v1 (+ `lang.javascript.handed_to_runner`) | names every install-time download of code from outside the npm registry, in forms | 26 | 183 unwanted, 1 malicious | 0 | 0 | gains positives; the 26 benign are listed below (most are downloaders the re-review did not reach) |
| R2 | `npm.install-explained` v6 | S2 (own-release download with a checksum, cargo-dist) and S6 (own-binary download not run) removed | 0 on their own | 0 on their own | 0 | 0 | ruling consequence: every version they explained is reported by R1 |

R2 changes no decision by itself in this replay: every version S2 or S6 explained is a
download R1 names. It is needed anyway so that no future downloader is explained away (and so
that a download R1 misses still keeps its install-rule MEDIUMs).

## 1. Data and method

- **Versions and truth:** the 3,716 verdicted live versions (`~/kitsunox-scratch/r5/shared/
  cands.jsonl.zst`), today's verdicts (last record per version), counted with
  `~/kitsunox-scratch/r5/final/relabel.py`. Five reviewers re-labelled the benign download
  verdicts during this round under the two rulings (note prefixes "Owner ruling 2026-11-10
  (third-party download at install = unwanted" and "(own-binary download at install =
  unwanted, strict)"), and the Windows-executable ruling added a third; the counts below use
  the verdicts as they stood at hand-back.
- **Development:** Stage 3 `CodeChange`s of the 1,620 routed versions with an install hook were
  dumped once (`dump.py`, tarballs read in memory with `extract_tar_gz`, nothing run) and the
  rule evaluated on them in process (`r_fire.py`), against the base replay's decisions and the
  verdicts (`r_new.py`, `r_targets.py`). Final numbers come from the replay harness
  (agent K's `replay.py`, Stages 1-4 with the real code), full, under the heavy lock.
- **`vm-day1`:** the 2,319 malicious samples with an install hook (of 3,444), install code read
  through the `stage2-rules` predictor (decrypted in memory, nothing written or run), no base
  (`dd_dump.py`, as agent M's `m_ddfire.py`); then `pipeline+4` (`dd.py`) with `main` and the
  fix on the samples the rule fires on.

## 2. The rule

What counts is decision 0015's: install code (a hook or a file it runs; a command the user
starts never counts) that fetches files, scripts or binaries that are not in the registry
tarball, whoever hosts them. Benign: the binary in the tarball, the package's own platform
packages on the registry (S1, including a fallback that fetches one from the registry), and a
declared dependency's own install script that npm runs by itself (this rule never reads it).

Reach and masking are `npm.install-persistence`'s (`code_text` over the install files; hook
command lines, here also with multi-line `echo` messages blanked and a fallback that runs only
when a shipped file is missing cut: `test -f dist/index.js || npx tsc`). The forms, each named
in the finding (`[form] snippet` in the evidence), so the owner can weigh them apart:

| Form | Fires on | Live gained (unwanted / malicious / benign) |
|---|---|---|
| `own` | a download from the package's own sources: its repository or any repository of its GitHub owner, its homepage's host (H's `_own_kind`), its vendor's host (`vendor_host`: the host's main domain label is, starts or ends the scope, repository owner or homepage label), the author's GitHub account, a GitHub owner built at run time, cargo-dist's `artifactDownloadUrls` | 147 / 0 / 14 |
| `fetch` | the same from a third-party host | 5 / 0 / 5 |
| `downloader` | network, a write stream and an unpack or `chmod`, with no download URL the rule can name and no registry named (`msedgedriver`, `onpod`, `@ziniao-open/cli`) | 14 / 0 / 1 |
| `tool` | `playwright install`, `@puppeteer/browsers install`, `camoufox fetch`, `pip`/`cargo`/`go`/`gem install`, `skills add`, `huggingface-cli download`; Playwright's `cli.js install chromium` | 8 / 0 / 2 |
| `npx` | `npx`/`bunx`/`pnpm dlx`/... of a package that isn't the package, one npm brings, or a dependency installed with it | 1 / 1 / 2 |
| `guard` | `npx only-allow ...` (separable: `GUARDS_COUNT`) | 5 / 0 / 1 |
| `exe` | a Windows executable or installer run at install (hook line, script `Start-Process`, `msiexec`, or a bundled `.exe` path a runner is given); the shells and system tools are not | 3 / 0 / 0 |
| `prebuilt` | `prebuild-install`, `node-pre-gyp install` | 0 / 0 / 1 |
| `npm` | `npm install` of packages that aren't dependencies | (all already reported) |

(Counted by the first form in each version's evidence; a version can carry several.)

Download URLs: a URL literal counts when it looks like a download (`DOWNLOAD_URL`: release
assets and the release API, raw repository files, `codeload`, `/archive/`, Hugging Face
`/resolve/`, archive/binary/script extensions, `/dist/`, `/dl/`, a `dl.`/`download.`/
`releases.`/`cdn.`/`get.` host) and the install code reaches the network: the capability, or
`curl`/`wget`/PowerShell/`fetch` named in it, or an HTTP client package loaded
(`follow-redirects`, `axios`, ...). Template calls are read as one placeholder
(`https://github.com/${repo()}/releases`). The npm registry and its mirrors, a registry tarball
path (`/-/x.tgz`), the local machine, page links and hosts built at run time are no download.

Command strings in JavaScript count only when they are handed to a runner
(`lang.javascript.handed_to_runner`: an argument or argument list of `exec*`/`spawn*`/
`execa*`/`run*`/`fork`/`sh`/`shell`/`$`, through `+`, templates and ternaries, or a variable such
a call is given). This is stricter than `npm.install-persistence`'s `shown_not_run`, and it
was needed: with `shown_not_run` the first draft added `@whobot/cli@2.0.5` (`npm install -g
failed: ...` in an error class), `cs-devtest` (`pkg.scripts.test = "npx vitest ..."`),
`codeplay-common` (scripts written into a project), `locus-cli` and `vibe-pilot` (`cargo
install` hints in arrays and constants).

`ONLY_WHEN_CHANGED` is off: under the strict ruling every version whose install code
downloads is unwanted, changed or not. Measured on the dump: +10 unwanted versions, the same
26 benign. It also fixes a blind spot for hook-only downloads (an empty install-file set
compares equal to the previous version's even when the hook line is new).

## 3. Live result

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `6137971` (integrator's replay) | 1,269 | 771 | 421 | 47 | 30 | 37.77% |
| `6137971` + R1 + R2 (first full replay) | 1,479 | 797 | 604 | 48 | 30 | 45.00% |
| `main` `fafd51f` (= Q's `final2.jsonl`) | 1,248 | 750 | 421 | 47 | 30 | 38.42% |
| **`fafd51f` + R1 + R2** (second full replay, `full-fix3.jsonl`) | **1,458** | **776** | **604** | **48** | 30 | **45.66%** |

The same 210 versions change in both replays. Main moved during the round (agents Q, U, T);
the harness gives `fafd51f` the same findings and decisions as Q's `final2.jsonl` on the 231
versions any of these changes touch plus 200 random others (subset replay of `fafd51f`), and
`c6e0270` (agent T's Stage 2 rule, the last merge) the same on those 431 versions, with R
adding exactly the same 210 there (subset replays of `c6e0270` with and without R).

**Positives gained (184):** 183 unwanted (147 own-binary downloaders, e.g. `@onreza/nrz` ×8,
`@ejfkdev/*` ×25, `statuz-cli` ×5, `onpod` ×8, `@niuwoai/willdeep`, `@owasp-noir/noir`,
`unbound-paws`, `@abacus-ai/cli`, `@openlatch/client@0.11.7`; third-party:
`@themost/sqlite` ×2, `signal-sdk@0.2.9`, `msedgedriver@156.0.0`, `usingopen@18.8.9`,
`torlnk@1.11.0`, the five `npx only-allow` guards, five `playwright install chromium` hooks,
`@byteplus/mediakit-cli`; Windows executables: `@pro-gram/drumbuddy@1.4.1`,
`rvm-windows@1.1.2-develop.1`), and 1 malicious: `esoftplay@0.0.269-beta96052d3` (`npx expo
install` in its install code). Full list: `relabel.py` output in the reproduce section.

**Positives or unverified lost: none.** The rule only adds a MEDIUM; R2 only removes
explanations.

**Benign newly reported (26), with why** (each fires on code that downloads at install unless
noted; most look like versions the re-review did not reach, since their notes didn't mention a
download):

| Version | Form | What the install code does |
|---|---|---|
| `@bjia56/portable-python-3.9@0.1.37`, `-3.10@0.1.31`, `-3.11@0.1.29`, `-3.12@0.1.42`, `-3.13@0.1.19` | `own` | downloads a CPython build from `bjia56/portable-python` releases (the declared owner's) |
| `node-sword-interface@1.0.127` ... `1.0.131` (5) | `own` | `get_sword_build_win32.js` fetches a prebuilt SWORD library from `ezra-bible-app/sword-build-win32` releases (Windows) |
| `wasm-pack@0.15.1` | `own` | the classic `binary.js` installer: wasm-pack from its GitHub release |
| `locus-cli@0.6.0`, `0.6.1` | `own` | downloads `locus-<target>` from `${REPO}` releases |
| `@cerebrixos/pulselake-experience@0.3.0-rc.5` | `own` | falls back to the vendor's GitHub release when the bundled archive is missing (S6 explained it before) |
| `@aweray/awesun-cli@1.0.9` | `downloader` | downloads and unpacks the vendor's CLI from `d-cdn.oray.com` |
| `@tetsuo-ai/agenc@0.19.23` | `fetch` | a release contract of `cli/cli` (GitHub CLI) assets with SHA-256s |
| `@znmin/claude-remote-cli@0.2.4` | `fetch` | `src/installer.js` (Mutagen from `mutagen-io`) is still among the install files; the note says the hook does nothing in this release: a reach false fire |
| `cs-devtest@1.3.3`, `1.4.0` | `fetch` | `lib/gitleaks.js` downloads gitleaks from its releases; reached from the install code (whether it runs at install is a reach question) |
| `jui-tools-mcp-server@2.20.0` | `fetch` | data files from the author's other repository (`Tai-Kimura/jsonui-cli`); the author check misses (no `author` field naming that account) |
| `anti-slop-engineering@1.2.0` | `tool` | `npx skills add imMamdouhaboammar/anti-slop-engineering` (0.4.0 of the same package is unwanted) |
| `riciplay@1.9.5` | `tool` | `python -m pip install --upgrade <its backend>` at install |
| `esoftplay@0.0.269-beta91d8a14`, `-betaeaa40be` | `npx` | `npx expo install` built into a command in `bin/build.js` (the malicious `-beta96052d3` has the same code) |
| `@ohos-ports/nodejieba@3.5.8-beta.0` | `prebuilt` | `npx @mapbox/node-pre-gyp install --fallback-to-build` (prebuilt from upstream releases) |
| `@orochibraru/ui@0.0.0` | `guard` | `bunx only-allow bun` |

So by the rulings as written, about 21 of the 26 are downloads at install and likely
mislabelled now; `@znmin/claude-remote-cli@0.2.4`, `cs-devtest` ×2 and the two `esoftplay`
betas are reach questions, `jui-tools-mcp-server@2.20.0` an ownership one.

**Targets still unreported (5 of 334 in the set):** `signetai@0.238.1`, `signetai@1.0.0`
(never routed to Stage 3); `meo-skia-canvas@7.0.0`, `7.0.1` (`prebuild.mjs download
--or-compile`: the URL comes from data); `hugo-bin-extended@0.169.0` (`bin-wrapper` builds
the URL from parts). 28 more positives are not in the replay set (verdicted after it was cut).

## 4. DataDog check (`vm-day1`)

The rule fires on **862 of the 2,319** malicious samples with an install hook (evaluated with
no base: `fetch` 812, mostly `curl`/`wget` beacons and downloads in hook lines and scripts;
`npx` 24, `tool` 9, `exe` 7, `prebuilt` 7, `downloader` 6, `npm` 4, `own` 1, `guard` 1). It
only adds a MEDIUM, so **no sample can be lost**. `pipeline+4` (`dd.py`, `main` `6137971` and
the fix) on those 862: 828 → 852 reported, **24 gained, 0 lost**: 20 `esoftplay` versions
(`npx`/`bunx expo install` in `bin/build.js`, the same line that reports the live malicious
beta), `overstock-health-express@1.4.4` (`fetch`: `wget` of `z.wbx.lt` with `whoami` and the
hostname), `n8n-nodes-zalo-fevox@0.6.8` (`guard`), and `aicp-tracker` 1.1.7 and 1.3.4
(`downloader`, for the wrong reason: a log file's write stream next to a `chmod`; see the
limits below).

## 4a. Known limits

- The `downloader` shape is text, not data flow: any write stream plus an unpack or `chmod`
  in network install code counts (`aicp-tracker`'s log stream on `vm-day1`; live it adds
  `@aweray/awesun-cli@1.0.9`, which does download).
- Reach is `install_sources`' (files the hooks run and the files they load by a constant
  path): a downloader reachable only from a user command but loaded at install still counts
  (`@znmin/claude-remote-cli@0.2.4`, `cs-devtest`).
- A URL read from data (a JSON manifest, `bin-wrapper` parts) is not seen
  (`@themost/sqlite` is caught only by the `downloader` shape; `meo-skia-canvas`,
  `hugo-bin-extended` are missed).
- `vendor_host` compares names: a vendor bucket on a cloud host (`*.aliyuncs.com`) reads as
  third-party; under the strict ruling that only changes the form, not the finding.

## 5. Measured and not built

- **`shown_not_run` for commands** (`npm.install-persistence`'s test): fires on help texts
  kept in variables and on scripts written into projects (above); replaced by
  `handed_to_runner`.
- **Generic `/download` paths**: `https://nodejs.org/en/download/` in `@depot/cli`'s messages
  (5 versions) is a page; dropped. `/dl/` and download-host labels kept (`topaz.ooo/dl`,
  `cdn.uniwind.dev`).
- **The `downloader` shape without the registry exclusion:** esbuild-style installers that fall
  back to the registry tarball would fire (`@depot/cli` ×5); excluded when the code names the
  registry.
- **`exe` on any `.exe` string:** `where.exe`, `cargo.exe`, `icacls.exe` and a `case` label
  (`@lifeaitools/build-corpus` ×2, `locus-cli`, `evolcore`, `@dream-encode/wp-build-tools`,
  `wkappbot-code` ×2, unverified) fired; system tools are excluded and a JavaScript `.exe`
  variable must be a package path (`__dirname`, relative).

## 6. Owner questions

1. Take R1 and R2 (+184 positives, +26 benign, 0 lost)?
2. Keep `guard` (`npx only-allow`: 5 unwanted, 1 benign gained)? `GUARDS_COUNT = False` drops
   it alone.
3. The ~21 benign downloaders above: re-review under the strict ruling?
4. `prebuilt` (`prebuild-install`, `node-pre-gyp install`): the classic native-addon path, now
   unwanted by the strict ruling; live it adds 1 benign. Keep?

## 7. Correlate

No change needed in `correlate`: `npm.install-download` is a MEDIUM that is neither
`WEAK_ALONE` nor explained (`EXPLAINED` lists only the three install rules), so it reports on
its own.

## 8. How to reproduce

Scripts in `~/kitsunox-scratch/r6/R/scripts/` (outputs in `../out/`, `../work/`), Python with
`-I` under `systemd-run --user --scope -p MemoryMax=...`:

- `dump.py SRC CANDS BASE OUT` and `dd_dump.py SRC OUT`: Stage 3 `CodeChange`s of the live
  hooked versions and the `vm-day1` hooked malicious samples (pickled, scratch only);
- `r_fire.py SRC DUMP` (the rule on a dump), `r_new.py`, `r_targets.py`, `r_peek.py`,
  `r_diff.py`: sections 2-3;
- `k_replay.sh fix3/src out/full-fix3.jsonl full` and `relabel.py ../Q/final2.jsonl
  out/full-fix3.jsonl` (also `out/full-fix.jsonl` against `../shared/main-6137971.jsonl`):
  section 3; subset checks `out/check-main3.jsonl`, `check-main4.jsonl`, `check-fix4.jsonl` on
  `work/check.keys`; `k_dd.sh SRC OUT work/ddfire2.keys` with `main` and the
  fix: section 4.
