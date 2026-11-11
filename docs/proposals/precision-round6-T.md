# Proposal: precision round 6, agent T (`static.disguised-file`, a recall rule)

> **Status:** built 2026-11-10/11, before the rule freeze (2026-11-16 00:00Z), for the owner's
> review, on `main` `fafd51f` (rebased over round 6 Q and U). One rule commit (Stage 2), zero-loss by construction (it only
> adds findings) and measured zero-loss on the live replay and `vm-day1`.
> **Motivating case:** `pdf-html5-page-flip` 2.0.1 and 2.0.2 (run `20261110T205323Z-npm`,
> malicious), a credential stealer shipped as `dist/lib/fonts/fa-solid-400.woff2`.

## Summary

| # | Commit (stage) | What | Positives gained (live) | Benign newly reported (live) | Positives lost | `vm-day1` | Kind |
|---|---|---|---|---|---|---|---|
| T1 | `216085f` `static.disguised-file` v1 (2) | a file named as a binary format whose bytes are a script or a program, in every file of every version read | 1 (`pdf-html5-page-flip@2.0.2`) | 0 | 0 | fires on 0 of 3,444 malicious samples: 0 gained, 0 lost | zero-loss, recall |

**Live, real code, verdicts of 2026-11-11 02:43Z:** 1,249 → 1,250 reported, 750 benign unchanged, malicious 48 → 49 (`pdf-html5-page-flip@2.0.2`), precision 38.47% → 38.52%; no benign version newly reported, no positive or unverified version lost.

## 1. The case

`pdf-html5-page-flip` 2.0.1 and 2.0.2 ship `dist/lib/fonts/fa-solid-400.woff2`, 1.8 KB of
JavaScript, not a font: it reads `~/.aws/credentials`, `.npmrc`, `.git-credentials`, SSH keys,
AI-tool OAuth files and token environment variables, posts them to
`http://193.32.204.199:8080/?c=reinject` and installs a `*/5` crontab `curl | bash`. Nothing in
the package loads it yet. On `main`:

- 2.0.1 (a new package) was reported only through `static.hardcoded-ip` (MEDIUM, score 6). The
  rest of what Stage 2 saw in the font was LOW (`sensitive-path` ×3, `env-harvest`,
  `process-exec`), and Stage 3 doesn't parse a `.woff2`.
- 2.0.2 shipped the font byte for byte. Stage 2's file rules see only contents the base lacks
  (`new_contents`), and Stage 3 found only a LOW `code.capability-gained`: score 3, not
  reported.

## 2. The rule

`src/kitsunox/rules/disguised.py` (ecosystem-agnostic), an `ArtifactRule` registered at the end
of the npm artifact rules (`ecosystems/npm/rules/artifact.py` `RULES`), which Stage 2, the
evaluation predictors, the ledger fingerprint and the replay harness all use. As an artifact
rule it reads every file of every version Stage 2 reads, so a follow-on that still ships the
file fires again (no "not new" demotion: artifact findings don't go through `_demoted`).
`stages/static.py` is untouched.

What it checks and how severe each outcome is: `docs/stages/static.md`,
[Files disguised as a binary format](../stages/static.md#files-disguised-as-a-binary-format-staticdisguised-file-2026-11-11).
In short: magic numbers per claimed format (any binary format is "no disguise", so WebP named
`.png` is fine); short magic (`BM`, `MZ`, MP3 sync) only for content that isn't text; then text
that is markup, an LFS pointer, JSON, base64 of a binary, or not a script is left alone; a script
(two markers of one language or a shebang, also base64-encoded) is HIGH with process, network,
credential or dynamic-code use, MEDIUM when a code file of the package names it, LOW otherwise;
an executable under a non-program name is HIGH; an archive under a font/image/media name LOW; a
script under a program name (`.exe`, `.dll`, `.so`, `.dylib`) is INFO unless it reads
credentials or builds code.

## 3. Data and method

- **Live versions and truth:** the 3,716 verdicted live versions
  (`~/kitsunox-scratch/r5/shared/cands.jsonl.zst`) plus the two `pdf-html5-page-flip` versions
  verdicted today, copied from run `20261110T205323Z-npm`'s `correlate.jsonl`
  (`~/kitsunox-scratch/r6/T/cands-T.jsonl.zst`, `scripts/mkextra.py`); truth re-joined by
  `relabel.py`.
- **Harness:** agent K's corrected `replay.py` (Stages 1-4, real code), my copy in
  `~/kitsunox-scratch/r6/T/scripts/` with the two tarball URLs added to its URL index.
- **Where the rule fires at all:** `candscan.py` (the rule on every live verdicted version's
  tarball as the harness gets it), `survey.py` (the rule on every npm tarball still on disk:
  230,316 distinct blobs, 230,290 readable), `ddscan.py` (the rule on every malicious `vm-day1` sample's
  files, decrypted in memory by the predictor). All in memory with `extract_tar_gz`; nothing
  written or run.
- **Decisions:** the harness on the versions the rule fires on, `main` and fix (`pair.sh`);
  the rule only adds findings and no rule reads them, so every other version's decision is
  unchanged by construction. The table patches those 38 results over the full replay of the
  base (`~/kitsunox-scratch/r6/Q/final2.jsonl`, agent Q's replay of `main` `6bfe0c3`, whose per-version rules are those of `fafd51f`: U's change is a run-level pass the harness doesn't run; the `main` subset was replayed with `fafd51f`; first
  done over `~/kitsunox-scratch/r6/shared/main-6137971.jsonl` before the rebase, same
  outcome) plus the base's own result for the two `pdf-html5-page-flip` versions
  (`scripts/patch.py`). The base subset agrees with the full replay on all 36 versions both
  have. No full fix replay was run (four jobs were queued on the shared lock).

## 4. Live result

The rule fires on 38 of the 3,718 versions (154 have no tarball left):

| Versions | Verdicts | Finding | Decision |
|---|---|---|---|
| `pdf-html5-page-flip@2.0.1` | malicious | HIGH, the font | reported before and after (score 6 → 11) |
| `pdf-html5-page-flip@2.0.2` | malicious | HIGH, the font | **gained** (score 3 → 8) |
| 32 `*/cli@1.0.44` (`@deepseeksi`, `@grokx`, `@kimicode`, ... one publisher's rebrands) | benign | INFO, `bin/dscode.exe` placeholder `#!/bin/sh echo "Error: dscode native binary not installed."` | not reported before or after |
| `glasspane-harness@0.14.5` | benign | INFO, `bin/glasspane-harness.exe` shell resolver | not reported |
| `lockpicks@0.8.0-go.11`, `rlm-harness@0.1.1` | benign | INFO, `.exe` launcher / placeholder | reported before and after (install rules) |
| `@visual-z/xeno@0.13.2` | unwanted | INFO, `bin/xeno.exe` placeholder | reported before and after |

No benign version is newly reported; no positive or unverified version changes except the gain.

`relabel.py`, 3,718 versions, verdicts of 2026-11-11 02:43Z:

| replay | reported | benign | unwanted | malicious | unverified | precision |
|---|---|---|---|---|---|---|
| base (`main`) | 1,249 | 750 | 421 | 48 | 30 | 38.47% |
| fix (T1) | 1,250 | 750 | 421 | 49 | 30 | 38.52% |

`CHANGED malicious pdf-html5-page-flip@2.0.2 reported`; benign unreported 0, benign newly
reported 0.

Before the rebase (base `main-6137971.jsonl`): 1,270 → 1,271 reported, 771 benign unchanged,
malicious 48 → 49, precision 37.82% → 37.87%; the same single change.

## 5. Pass-through on live tarballs

Over all 230,290 distinct npm tarballs on disk (every live run's captures, 2026-10-29 on, with
the 30-day holds), 125,826 files have a claimed binary extension (66,225 `.png`, 17,549
`.woff2`, 6,016 `.webp`, 5,201 `.jpg`, 4,327 `.woff`, 2,951 `.mp3`, 2,886 `.ttf`, 2,618
`.node`, 2,467 `.wasm`, 2,434 `.gz`, 1,365 `.exe`, ...).

- First version (no launcher shape): fired on 133 tarballs, 0.058%: 131 `.exe` launchers in 39
  packages (111 MEDIUM, 20 HIGH by `child_process` or a `curl | bash` hint in an error
  message), and the two `pdf-html5-page-flip` versions. On the live verdicted versions that
  version would have newly reported 33 benign versions (the 32 `*/cli@1.0.44` and
  `glasspane-harness@0.14.5`, not reported on `main`; any MEDIUM outside `WEAK_ALONE` reports
  alone), which is why launchers are INFO now.
- Final version: fires on 135 tarballs (two more `.exe` Node launchers are recognised once
  `#!/usr/bin/env node` counts as a shebang, `commitlg`): **2 HIGH, both
  `pdf-html5-page-flip`; 133 INFO, all `.exe` launchers in 40 packages; no LOW or MEDIUM.**
  Benign pass-through above INFO: 0 of 230,288 tarballs.

Shapes looked for and how each is handled (none fired in the live data except the launchers):

| Shape | Handling |
|---|---|
| SVG or other markup named `.png` / `.ico` | text starting with `<`: nothing |
| a saved HTML error page as a font or image | same |
| Git LFS pointer (`version https://git-lfs.github.com/spec/v1`) | nothing |
| a font or image stored as base64 text, or a `data:` URI | decoded: a binary format → nothing; a script → classified as one |
| WebP/AVIF named `.png`, CFF font named `.ttf`, WOFF named `.ttf` | another binary format: nothing |
| `.node` / `.exe` placeholders (empty, a sentence, a stub) | empty or plain text: nothing; a stub script under `.exe`: INFO |
| test fixtures (a fake `.png` with text) | plain text: nothing; a script fixture with capabilities would be HIGH (none in the data) |
| minified JS stored as `.txt` by build tools | not checked: `.txt` is no binary claim (section 7) |

## 6. `vm-day1`

`ddscan.py` ran the rule (final code) on the files of all 3,444 malicious `vm-day1` samples,
decrypted in memory (9,837 files with a claimed binary extension): **it fires on none**, at
any severity. So `pipeline+4` can't change on any sample: 0 gained, 0 lost, 0 unchanged
samples carrying it. The DataDog set has no payload disguised as a binary file; the rule's
evidence is the live case and the fixtures, its cost is the live pass-through above (the
benign `vm-day1` samples' live runs are pruned from the scratch data dir, so they were not
scanned; the 230,290 live tarballs stand in for them).

## 7. Rejected or not built

- **Text claims (`.txt`, `.md`, `.json`, `.map`, `.css`, `.svg`, `.yml`, `.html`, `.csv`,
  `.xml`).** Measured (`survey_text.py`) on 19,999 tarballs sampled evenly from the 230,290:
  with the same classifier (script markers plus a capability; JSON and maps only when they
  don't parse), 5,696 tarballs (28%) would have a hit, 13,211 of them in `.md` (READMEs with
  code blocks, agent skills), 433 `.html`, 34 `.yml` (CI workflows that `npm publish`), 27
  `.txt` (`llms.txt`, `llms-full.txt`), 32 `.csv` (code-example tables). Even "credentials and
  network or process" leaves 2,258 `.md` hits. No `.json` or `.map` hit at all (every one
  parses or holds no script). Telling a code file from prose that quotes code needs a parser,
  not markers; not built.
- **MEDIUM (HIGH with a capability) for every script under an `.exe` name** (the first
  version): 131 live tarballs in 39 packages, all launchers or placeholders; 36 verdicted live
  versions (35 benign, `@visual-z/xeno@0.13.2` unwanted for other reasons), 33 of the benign
  ones newly reported. INFO now.
- **A "loaded" check through `install_sources` / `load_sources`.** They resolve JavaScript; a
  loader that reads a `.woff2` and evaluates it names the file as a string. The rule asks
  whether any code file names the file's basename, which also catches `readFileSync(...)` and
  `require('./x.woff2')`.

## 8. Routing: is a follow-on read?

The rule fires on any version Stage 2 reads. 2.0.2 was read because its declared size grew by
69,134 bytes, just 3,598 over `MIN_GROWTH_BYTES` (64 KiB). A follow-on that ships the same
payload and changes less (no hook, over 64 KiB, unwatched, no Stage 1 flag) is not routed by
`code_route`, so Stage 2 never reads it and this rule can't fire. Within one run every version
of a package is read whenever one is routed (`analyse_batch` reads the whole batch), so the
gap is across runs only.

**Since round 6 U (`correlate.follow-on`, `main` `fafd51f`)** a Stage 4 pass reads the files of
any release whose previous release was reported (this run or, within 7 days, an earlier one),
routed or not, and carries a reported release's severe evidence when the follow-on still has
the same bytes at the same path. U's part B1 already carries `pdf-html5-page-flip`'s font
(a `hardcoded-ip` in a file that `sensitive-path` also names), so in operation 2.0.2 is
reported either way. The per-version replay above doesn't run that pass, so the gain shown is
this rule's alone. What the rule adds beyond U: the content signal on first sight (2.0.1
HIGH by what the file *is*, not by one IP literal; a disguised payload with no IP, no
webhook and no reported previous release is caught at all), and a follow-on of a release that
was not reported.

**Proposed (not built, U's/the integrator's constant):** add `static.disguised-file` to
`FOLLOW_ON_ALONE` in `stages/correlate.py`. Then a follow-on that keeps a disguised file of a
reported release is carried even when Stage 2 never read it (the routing gap above) and even
when the file holds no IP or endpoint. Cost on the live data: the rule's only severe findings
in 230,290 tarballs are the two `pdf-html5-page-flip` ones (the launchers are INFO and never
carried), so no benign follow-on would gain it.

## 9. Owner questions

1. Should a script under an `.exe` name stay INFO (now), or be LOW so it counts toward the
   score? LOW would add weight 1 to 36 live verdicted versions; the 33 unreported ones are at
   score 3 on `main`, so at most 4 with it, below `REPORT_SCORE` (6): no decision would change
   today.
2. Add `static.disguised-file` to `FOLLOW_ON_ALONE` (section 8)?
3. Check text claims at all (section 7)?

## 10. How to reproduce

```sh
S=~/kitsunox-scratch/r6/T/scripts
python -I $S/mkextra.py                                   # cands-T.jsonl.zst + URL index
python -I $S/candscan.py SRC ~/kitsunox-scratch/r6/T/cands-T.jsonl.zst OUT   # where it fires (live)
bash $S/pair.sh ~/kitsunox-scratch/r6/T/keys-fired.txt fired                 # main vs fix decisions
python -I $S/survey.py SRC OUT 2                          # every tarball on disk
python -I $S/ddscan.py SRC OUT                            # every malicious vm-day1 sample (heavy lock)
python -I ~/kitsunox-scratch/r5/final/relabel.py BASE.jsonl FIX.jsonl
```
