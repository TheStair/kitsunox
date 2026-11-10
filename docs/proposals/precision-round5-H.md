# Proposal: precision round 5, agent H: installers that download their own binary

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Cluster: a new explained-install shape in `ecosystems/npm/rules/install_shapes.py`
> (`npm.install-explained` v4, S6, Stage 3), plus a new parser helper `lang/process_calls.py`.
> **Result on `main` `cde7f12` (rounds 1-4 and agent K), real code (agent K's corrected
> harness), 3,716 verdicted live versions: 1,402 → 1,386 reported, all 16 benign (15
> packages); 0 malicious, unwanted or unverified version stops being reported, and S6 fires on
> none of them.** Precision (malicious + unwanted) 21.57% → 21.83%. On the 52 versions verdicted since the replay set was cut: −1 benign
> (`@ejklock/living-docs@0.26.1`), nothing else changes. `vm-day1`: S6 fires on none of the 2,319 malicious samples with an install hook (1,208 of them with network install code), so no sample can change. Zero-loss.
> **Builds on:** [round 3](precision-round3.md) (method, harness), [round 2](precision-round2.md)
> sections 6-8, decision [0015](../decisions/0015-reviewer-verdicts.md) with all addenda, and
> agent E's S2/S5 in [round 4 E](precision-round4-E.md).

## Summary

| # | Change (Stage 3) | Benign removed | Positives at risk → lost | Unverified lost | `vm-day1` fired → lost |
|---|---|---|---|---|---|
| H1 | `npm.install-explained` v4: **S6 own-binary download, not run** (+ `lang.process_calls`) | **16** (15 packages), +1 on the newer verdicts | 0 → 0 (S6 fires on none of the 53 positives or 6 unverified the install rules alone carry) | 0 | 0 of 2,319 → 0 |

**Commits** (Stage 3, on `worktree-agent-a433c9a71930dec34`, rebased on `fb290b1`):
`837a1a6` (S6 and `lang.process_calls`, tests), `adcbd33` (placement guards: other packages,
system directories, the project), `725beea` (docstring), `383603f` (decoding and
`shell: true` guards, process calls always read); docs in a separate commit. All zero-loss; no trade-off commit.

S2 (round 2; v3 for cargo-dist) explains an own-release download that checks a checksum. The
downloaders reviewers keep clearing (`herozion`, `@ejklock/living-docs`, `translatex`,
`untag-cli`, `@dac-tech-team-tw/gtm-cli`) often check none, or download from a separate
releases repository of the same owner. S6 takes them on a different argument: **what they
download never runs at install**, which is what turns a download into an install-time attack,
and the host is the package's own. A binary written into the package and run when the user
runs the tool is the same as a binary shipped in the tarball (S1).

## 1. Method

Round 3's harness as corrected by agent K (`replayK.py`: Stage 4 with the run's watchlist, no
stale v1 `known-malware` findings), today's verdicts (last record per version). **Baselines:**
`main` `31e96fa` corrected (K's `base.jsonl`: 1,413 reported, 1,087 benign, 249 unwanted, 47
malicious, 30 unverified) and `main` `cde7f12` (K's `fix.jsonl`: 1,402, 1,076 benign). The
work started on the shared `baseline-main.jsonl` (old harness: 1,428 / 1,112); every S6
measurement was repeated with K's harness on `cde7f12` and gives the same 16 versions. An explanation only lowers the three install rules, and none of them is
`WEAK_ALONE`, so S6 can unreport a version only when every severe finding is an install rule:
674 reported versions. For those, Stage 3 was recomputed with the fix (`probe.py`/`fires.py`:
`code_change` on the tarballs read in memory, exactly as the replay does): 180 have
network-capable install code (S6 needs the network), S6 fires on 17; those were replayed end
to end with the fix (`replay.py`). The other 3,699 versions carry no S6 finding, so their
findings and decisions are the baseline's. Holdout: the 52 versions verdicted after
the shared candidate file was cut (`extract_new.py`), replayed with `main` and with the fix.

## 2. Clustering the install buckets

Versions reported only through install rules (current verdicts): 674 (615 benign, 51
unwanted, 6 unverified, 2 malicious). By what the install code can do (Stage 3 capabilities of
the install files):

| Install code | Benign | Positives / unverified | Shape |
|---|---|---|---|
| network, with or without `process` | 149 | 31 | the downloaders (this proposal) |
| `process` only | 176 | 13 | runs tools (`git`, `npm`, `cargo`, `pnpm rebuild`, `codesign`, Electron's installer) or the product's setup; not downloads |
| neither | 249 | 12 | S5 / `npm.install-inert` territory (agents E, B) |
| tarball gone | 41 | 3 | can't be read |

The 180 network rows, from notes and code: own-release binary downloaders (Go, Rust, Zig CLIs,
cargo-dist); vendor-CDN downloaders (Aliyun OSS, `download.whobot.com`, `tiktokcdn`);
third-party tools from their GitHub releases (`mutagen`, `jq`, `txcript`, `vlang`, `ttyd`);
install telemetry; CLIs whose hook runs the product (agent setup, license activation). The 31
positives: 25 `@byteplus`/`@volcengine` `arkcli-probe` builds (download from the vendor's CDN,
then run `arkcli +connect`, which installs skills into every agent), `claudecode-ms-teams@0.1.0`
(`claude plugin install --scope user`), `scarwise` ×2, `@safetech/inheriti-cli`,
`@jarvis_1234/env-preloader` and `dependencykfeg@1.5.6` (malicious: inline DNS exfiltration).
Every one was read for this proposal; none downloads from its own GitHub releases without
running something.

No live version is reported only for a prebuilt-addon download (`prebuild-install`,
`node-pre-gyp install`); the one `node-pre-gyp install --fallback-to-build` hook is beside a
`binding.gyp` build (agent I's).

## 3. S6: the conditions and what each costs

S6 sits after S1/S2 in `explain`, so every shared guard applies first: no shell hook, no
`binding.gyp` command, no `env-all`/dynamic code/dynamic `require`, nothing new in an update's
install code, readable UTF-8. Of the 180 network rows the shared guards refuse 103 (a
whole-environment read 77, dynamic code or `require` 5 more; nothing new in an update 46; some
both), all but 4 benign. Then:

| Condition | Why | Benign it alone keeps (of 180) | Positives it keeps (also kept by others) |
|---|---|---|---|
| a download URL of the package's own: a release or the release API of **any repository of the declared GitHub owner**, the `homepage`'s own host (not a code host), or cargo-dist's `artifactDownloadUrls` | the host is the package's own (`@get-fde/qc` downloads from `getfde-admin/qc-releases`) | 1 (`@ogai/llama.rn`: URLs built from a JSON file) | 25 `arkcli-probe`, `claudecode-ms-teams`, `dependencykfeg` |
| every other URL literal a GitHub asset host, the npm registry, a page link, or a raw file of the owner's repositories | nothing fetched from a stranger | 0 (`vibe-pilot`'s raw `install.sh` hint is allowed) | `claudecode-ms-teams` |
| a literal version in a download URL is the package's or its release's (`0.1.33-trust.1` may fetch `v0.1.33`) | an update can't pin another build silently | 0 | none |
| every `child_process` command an archive, file-mode or platform tool, in every install file (`lang.process_calls`); `shell: true` makes arguments a shell line | what it fetched never runs | 3 (`qdd-framework` runs `"${bin}" consola actualizar`; `kondor`, `sofuu` run commands named by variables) | 25 `arkcli-probe` (run the binary) |
| no other way to run code (workers, `vm`, `module`, WebAssembly, `dlopen`), no `require` of a file the package doesn't ship, no package loaded by name, no inline `node -e`, no decoding (`atob`, `Buffer.from(.., "base64")`) | the same, by other means | 0 | `dependencykfeg` (inline) |
| no home or agent directory named | "written only inside the package"; the owner's user-wide rulings | 0 alone (13 with others: `~/.cache` installs) | 25 `arkcli-probe`, `claudecode-ms-teams` |
| no other installed package (S5's patcher guard), system directory (not the temporary directory) or project path (`INIT_CWD`, git hooks), comments and messages aside | a fetched file placed there runs later, outside the package | 1 (`fluxware@1.1.6` resolves its platform package) | none |
| nothing sent (`method: "POST"`, `.post(`) | a downloader receives | 0 | `claudecode-ms-teams` |

No checksum is required: a checksum shipped in the same release proves nothing about its
author (round 4's argument for cargo-dist), and S2 keeps explaining the checksummed downloads
that do run something.

`lang.process_calls` (new; parse only) is stricter than `lang.at_load.commands`: it lists every
runner call in a file, not only those reached at load, because an exported function another
install file calls runs at install too; and it refuses (`None`) any use of `child_process` it
can't follow: the module or a runner passed on, `promisify(exec)`, a computed member, a default
value or rest element in a destructuring, `module.exports = require("child_process")`, or the
module's name in any other string. Tests: `tests/lang/test_process_calls.py`; the shape:
`test_s6_own_binary_download_not_run` (inert fixtures for each guard).

## 4. Live result

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `31e96fa` (corrected harness) | 1,413 | 1,087 | 249 | 47 | 30 | 21.40% |
| `31e96fa` + H1 | 1,397 | 1,071 | 249 | 47 | 30 | 21.65% |
| `main` `cde7f12` (+ agent K) | 1,402 | 1,076 | 249 | 47 | 30 | 21.57% |
| **`cde7f12` + H1** | **1,386** | **1,060** | 249 | 47 | 30 | **21.83%** |

The at-risk set (674 versions reported only through install rules) is the same on both
baselines; K's changes touch none of S6's versions. **On `main` `fb290b1` (+ agents J and L)**
the same 16 are reported with `main` and unreported with H1 (K's harness on the 17 S6 versions,
`out/J-main-s6.jsonl` / `out/J-fix-s6.jsonl`;
S6 fires on none of the 248 other reported versions with an install MEDIUM, which J's and L's
demotions could leave install-only), so `fb290b1` + H1 = `fb290b1` − 16 benign.

Unreported (all benign): `@autokeren/kancil@0.1.0`, `kancilai@0.1.0`,
`@cerebrixos/pulselake-experience@0.3.0-rc.5`, `@dac-tech-team-tw/gtm-cli@1.6.2`,
`@ejfkdev/ddc@0.1.33-trust.1`, `@ejfkdev/ddc@0.1.34`, `@get-fde/qc@0.1.1`,
`@kurarens/tide@0.1.0`, `@linebridge/engine-neo@1.2.2`, `@owasp-noir/noir@1.5.0`,
`@umutert/cxj@0.3.2`, `figma-mcp-go2@2.0.2`, `fluxware@1.1.1`, `translatex@0.1.0`,
`untag-cli@3.0.0`, `vibe-pilot@0.1.2`. S6 also fires on `simflux-cli@0.1.0` (benign), which
live never reaches Stage 3 (not routed), so it stays reported. **Positives or unverified
versions changed: none.**

Holdout (52 later verdicts; 41 reported on `main`): `@ejklock/living-docs@0.26.1` is
unreported (benign); `herozion@2.0.19` is S6 too but `main` already doesn't report it in the
replay; `agentcam@0.1.0` and `@aswless_854771076/newapi-cli` were S2 already.

## 5. DataDog check (`vm-day1`)

`ddfire6.py` (in memory, through the `stage2-rules` predictor's decrypted files, nothing written
or run) evaluates `explain` with the final code on each of the 2,319 (of 3,444) malicious samples
whose manifest has an install hook, with no base (so the update guard never applies:
a superset of what live would explain). Shapes: S1 7, S5 7, **S6 0**; 1,208 samples have
network-capable install code and every one fails S6. An explanation only lowers the install
rules, so a sample S6 doesn't fire on can't change: **0 lost**, and the `pipeline+4` runs
(`dd.py` with `main` and the fix) had nothing to compare. Most network samples fail several
S6 conditions; among the concerns S6 lists, the commonest blocker is a URL that isn't the
package's own (384 samples show only that one) or no download S6 can name (31: URLs built at
run time, DNS, raw sockets).

## 6. Measured and not built

- **A whole-environment read in a downloader** (`{...process.env}` for `tar` or proxy
  settings): S6 would take 2 more benign (`stacklit@0.5.0`, `lingua-rs@0.2.4`). `env-all` is the
  harvesting capability and a guard of every shape; not worth a carve-out.
- **Lifting "nothing new in an update's install code" for S6** (first releases after a `0.0.0`
  placeholder, new downloads): 6 more benign (`@cipherpay/zipher-cli`, `@inference-gateway/cli`,
  `commitlg`, `fangcun`, `paragma`, `twigsmith`). The owner's rule for every shape (round 4 E,
  section 6); not proposed.
- **Downloads into `~/.cache` or another home directory** (`@fluentci/cli`, six
  `@mateuszwrobel/*`, `@zero-x.live/neuron`, `donsetch`, `usingopen`): about 13 benign, each with
  other concerns too; "written only inside the package" is the shape's point, and the
  `arkcli-probe` builds (unwanted) name the home directory as well. Not built.
- **Third-party tools from their own GitHub releases** (`mutagen`, `jq`, `txcript`, `vlang`,
  `ttyd`, `maestrojeong/*-rs-mcp`): about 10 benign; the host is not the package's own, which is
  the shape's premise. Not built.
- **Templated owners** (`github.com/${repository}/releases`, read from a shipped manifest:
  `@binxgodteli/goon-cli`, `@niuwoai/willdeep`, `@orbit-tools/cli`, `@zhizai/cli`): 4 benign at
  most (`@zhizai/cli` also runs commands named by variables). Needs data flow from a JSON file;
  not built.
- **Subdomains of the homepage's host** (`dl.kx.dev` for `kx.dev`): no live version needs it;
  left strict.
- **Reach analysis for the command test** (only calls reached at install): would also take
  cargo-dist's installer, whose `binary.js` spawns the binary in `run()` (used by the `bin`
  shim, not at install), but cargo-dist's live versions are S2 already or blocked by the update
  guard; and cross-file reach can't be followed. Not built: every call counts.

## 7. Boundary with agent I

Prebuilt *downloads* (`prebuild-install`, `node-pre-gyp install`) are H's, compiling is I's. No
reported live version has a hook that only downloads a prebuilt addon, so S6 does not model
them; `node-gyp-build` (a loader that builds when no prebuilt is shipped) is I's. S6 refuses
any `binding.gyp` command (the shared guard) and any `node-gyp`/`cmake` command (not an
archive tool), so the two never overlap.

## 8. Owner questions

1. Take H1 (16 benign, zero-loss live and on `vm-day1`)?
2. S6 accepts a download from **any repository of the declared owner** and from the
   `homepage`'s own host, both the publisher's own claims (as `repository` is for S2). Keep, or
   require the declared repository itself (−1 live: `@get-fde/qc`; `herozion` and
   `@ejklock/living-docs` on the holdout use a separate releases repository too)?

## 9. How to reproduce

Scripts in `~/kitsunox-scratch/r5/H/scripts/` (outputs in `../out/`, `../work/`), Python with
`-I` under `systemd-run --user --scope -p MemoryMax=...`; code snapshots in `../main/src`
(`31e96fa`) and `../fix6/src` (final):

- `buckets.py`, `dump.py`, `clus.py`, `netrows.py`, `execs.py`, `proccmds.py`, `s6tags.py`:
  section 2 (reported rows, current verdicts, by install capability and shape);
- `probe.py SRC CANDS @KEYS OUTDIR` (Stage 3 `code_change` per version, install files saved as
  data, S6 concerns and shared guards), `fires.py` (the same without saving code),
  `guardcheck.py`: section 3 (`work/f6/fires.jsonl`: the 180 network rows with the final code);
- `replayK.py fixK/src ../shared/cands.jsonl.zst out/K-fix-s6.jsonl 2 @work/keys-s6.txt` and
  `cmp.py ~/kitsunox-scratch/r5/K/out/fix.jsonl out/K-fix-s6.jsonl npm.install-explained`:
  section 4 (`fixK` = this branch on `cde7f12`; the old harness on `31e96fa`,
  `out/fix5-s6.jsonl`, gives the same 16);
- `extract_new.py`: the 52 later-verdicted versions (`work/cands-new.jsonl.zst`), replayed into
  `out/K-new-main.jsonl` and `out/K-new-fix.jsonl` (K's harness);
- `heavy.sh` (under `heavy.lock`): `ddfire6.py SRC OUT` (which `vm-day1` malicious samples with
  an install hook get which shape), `dd.py` (`pipeline+4`) with `main` and the fix on the
  samples S6 fires on: section 5. (Its last step, a full replay with the old harness, was
  stopped after the integrator's harness note; the subset argument of section 1 stands in.)
