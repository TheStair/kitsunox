# Kitsunox — story notes for the final deck

Raw material for slides: what was built, what went wrong, and how each problem was found
and fixed. Every number here is traceable to a commit, a report under `reports/`, or a
queue under `triage/`. `docs/Plan.md` stays the authoritative design document; this file
is the narrative.

---

## 1. One-slide summary

**Kitsunox triages source-level supply-chain attacks -- malicious commits and tampered
release tags in GitHub Actions and npm repositories -- into a ranked queue for a human
investigator.** Deterministic rules (Tier 0) do the detection; an optional LLM brief
(Tier 2) cuts the investigator's minutes per alert; the human makes the call.

Headline results (details in §4):

| | |
|---|---|
| Ground-truth incidents detected | **5/5** (xz-utils, event-stream, reviewdog, tj-actions, colors.js) |
| False positives, held-out 10-language corpus | **1.15%** (8/695) -- measured before tuning on it |
| LLM recognition ablation | Tier 2 drops **5/5 -> 4/5** with names withheld |
| In-the-wild alerts, first holdout | **17** -> **5** from ~780 changes, re-hunted with the round-2 fixes (in-sample) |
| In-the-wild alerts, holdout-2 (measurement) | **19** from 809 unseen changes (2.3%); 11 of 80 repositories |

---

## 2. Timeline

| When | Phase | Outcome |
|---|---|---|
| Aug | Scope | npm registry monitoring -> source-level attacks in commits and tags |
| Sept wk 1-2 | Ground truth | 5 incidents verified against the live API; tj-actions recovered byte-exact from a fork's revert |
| Sept wk 3-4 | Tier 0 | evidence vs circumstance split; author tenure; capability scoring; 5/5 |
| Sept wk 5 | Held-out control | 695 changes, 25 repos, 10 languages: 1.15% FP |
| Sept wk 6-7 | Tier 2 + ablation | brief works; verdicts contaminated by recognition (5/5 -> 4/5) |
| Sept wk 7 | Tier 3 | investigating agent built, measured, **removed** |
| Oct 8 | Hunting | tag-integrity rules, triage queue, disposition log; calibration round 1 (40 -> 11 alerts) |
| Oct 8 | Holdout | first holdout hunt: 17 alerts |
| Oct 26 | Calibration round 2 | all 17 traced to five deterministic defects; fixed; fresh holdout-2 drawn and hunted |

---

## 3. Architecture (for the diagram slide)

`targets/*.txt` -> **hunt** (recent default-branch commits + release-tag integrity) ->
**Tier 0** rules -> escalated changes -> optional **Tier 2** brief -> ranked
`queue-*.md` -> **human** -> `dispositions.csv` -> `kitsunox tally`.

Seven modules, ~3,900 lines, 459 tests. Grounded in Ladisa et al., *Taxonomy of Attacks
on Open-Source Software Supply Chains* (IEEE S&P 2023): the incidents sit in AV-300
(inject into sources), AV-400 (inject during build) and AV-800 (become a maintainer).

Design decisions worth a slide each:

- **Evidence vs circumstance.** Only what a change *contains* can escalate; where it landed
  and who merged it only ranks. Circumstance rules fire on 11-31% of ordinary changes.
- **Tenure x privilege.** A 5-day-old contributor opening a PR is open source; a 5-day-old
  maintainer pushing straight to main is event-stream.
- **Tags are the Actions attack surface.** Consumers run what `@v4` points at, not main.
- **The LLM writes a brief, not a verdict.** Its explanations are strong; its verdicts were
  the least reliable layer.

---

## 4. Results

### Ground truth and held-out corpus (Tier 0, `kitsunox evaluate`)

| Incident | Attack vector | Evidence score |
|---|---|---|
| xz-utils | opaque binaries under a test-fixture path | 8 |
| event-stream | new maintainer pushes a new dependency | 9 |
| reviewdog | encoded payload in install.sh | 26 |
| tj-actions | encoded payload in dist/ bundle | 51 |
| colors.js | unbounded loop | 8 |

Held-out: 8/695 = 1.15% false positives. Every one of the 8 was in a language absent from
the tuning set (C++ `while (true)`, a zlib version string read as an IP in curl) -- the
argument for a multi-language control, made with evidence.

All round-2 changes re-verified against this: still 5/5 with identical scores, and
dependency findings on the control corpus fell from 62 changes to 6 (all 56 removed were
release version fields, engine constraints or version bumps).

### In the wild

**First holdout, the same 17 changes rescored after round 2** (in-sample -- these alerts
drove the fixes, so this shows the fixes remove what they target, not how the tool performs):

| Alert | Before | After | Why |
|---|---|---|---|
| anonyco/FastestSmallestTextEncoderDecoder `1d75` | 40 | 0 | vendored node_modules no longer "binaries" |
| anonyco/FastestSmallestTextEncoderDecoder `9916` | 23 | **11** | still escalates: a benchmark that fetches remote code and `eval`s it -- a real capability, correctly flagged |
| apisec-inc/AI-Surface `2a44` | 19 | 1 | `env=dict(os.environ)` is pass-through |
| DeLaGuardo/setup-clojure `6d46` | 17 | 0 | one release under two version schemes |
| DoozyX/clang-format-lint-action `c71d` | 15 | **15** | still escalates: 13 tags really were re-pointed -- correct detection, benign intent |
| dkamm/pr-quiz `8843` | 15 | 4 | withheld diffs rebuilt; bundle judged on payload; icons and inlined wasm are assets |
| mheap/github-action-required-labels x5 | 15 each | 0-1 | off-branch release builds are this repo's convention |
| apisec-inc/AI-Surface `dae6` | 11 | **8** | still escalates: a human commit on no branch editing the publish workflow -- worth a look |
| DoozyX/clang-format-lint-action `99a1`, `bcb4` | 8 each | **8** | still escalate: real ELF binaries, escalated by design |
| jidicula/clang-format-action `4329` | 8 | 0 | off-branch tag on a README-only commit whose parent is on a branch |
| snaerth/create-react-component-folder `67a3` | 12 | 0 | `"version"` is not a dependency |
| harikrishna8121999/antigravity-workflows `6f16` | 8 | 0 | empty `.gitkeep` files are not executables |

Every one of the 5 survivors is a correct detection of the behaviour the rule describes;
whether the *intent* is malicious is the reviewer's call, which is the design.

**Re-hunt of the first holdout with every correction** (`triage/calibration/round2/*-fixed/`,
same protocol: 10 commits deep, Actions with tags): Actions 390 changes -> 4 alerts, npm
392 changes -> 1 alert -- the same five survivors as the rescore above. Each survivor is
a correct detection of its behaviour; review time is the remaining cost.

**Holdout-2 (the measurement, Oct 26):** 80 targets drawn by seed 20261026, disjoint by
repository and owner, hunted once with frozen rules after the three policy questions were
settled (all three kept as they were). Queues in `triage/measurement/`.

| | Actions | npm | Total |
|---|---|---|---|
| Changes | 409 | 400 | 809 |
| Alerts | 11 | 8 | **19 (2.3%)** |
| Repositories with an alert | 7 / 40 | 4 / 40 | 11 / 80 |

Six root causes explain all 19 (a description of what matched, not a disposition):

| What fired | Alerts | First read |
|---|---|---|
| Release tags: 1 version collapse, 3 on no branch | 4 | real behaviour; needs review |
| Azure SDK comment bundled into dist/: example address `192.0.0.10` | 5 | precision gap: one library comment |
| Minified bundle named `index.dist.js` (autofix-ci) | 2 | precision gap: not recognised as generated |
| `child_process` in `scripts/` dev scripts (pixi-vn) | 3 | the `scripts/` policy, kept deliberately |
| Opaque binaries: a demo `.zip`, an `.onnx` model, `.js.gz` bundles | 3 | as designed |
| `package.json` homepage is a raw IP address | 2 | as designed |

The two precision gaps are **reported, not fixed**: fixing them would make holdout-2
calibration. Dispositions and minutes per alert are recorded in each queue's
`dispositions.csv`.

**Tier 2 brief on the same 19** (run on request, $1.84, $0.10 per alert; unknown
repositories, so the recognition effect from the ground-truth ablation should not apply):
**16 benign, 3 suspicious, 0 malicious** -- the 3 suspicious are all the bundled Azure SDK
comment. Briefed queues: `triage/measurement/*/queue-20261026-22*.md`.

- *Legwork the rules cannot do:* it found a lockfile silently downgrading a dependency
  (pixi-vn), TLS verification disabled (bulk-mail-cli) and a malformed `action.yml`
  (pullpreview).
- *Inconsistent on identical evidence:* four typst alerts with one cause -> two
  suspicious (0.50), two benign (0.60). The verdict ranks; the investigator decides.
- *A defect in Tier 2 itself, exposed by the measurement:* the prompt names each flagged
  rule and file but not the matched line, and a file over its budget is cut from the top.
  In the typst and PyO3 bundles the flagged line sat past line 53,000, so the model never
  saw `192.0.0.10` and guessed the trigger (wrongly, as the `tunnel` package or a `127.`
  check). The prompt's truncation note also claims flagged files were "kept in full".
  Reported, not fixed: fixing it now would tune Tier 2 on holdout-2.
- *Tags are not a diff question:* for all four tag alerts it cleared the diff and pointed
  the investigator at the tag history -- correctly.

---

## 5. Challenges and how they were solved

Each is a candidate slide: *problem -> how it was found -> fix -> measured effect.*

### 5.1 Recovering ground truth that attackers deleted
- **Problem:** tj-actions' malicious commit is gone from the repo and every mirror;
  node-ipc's 2022 history is scrubbed entirely.
- **Fix:** a legitimate fork (`trmlabs/changed-files`) cloned at the malicious commit and
  reverted it -- diffing the revert reproduces the original byte-exact. node-ipc was
  swapped for colors.js rather than reconstructed; ua-parser-js dropped (never in git).
- **Lesson:** verify every incident against the live API; several "known" facts were wrong.

### 5.2 Circumstance kept accusing ordinary changes
- **Found:** `psf/requests#6968`, a Makefile tweak merged by its author, escalated on
  circumstance alone (CI touched 31%, self-merged 20%, no approvals 18%).
- **Fix:** split evidence from circumstance; only evidence crosses the threshold.
- **Effect:** the whole class gone with no detection lost.

### 5.3 event-stream has nothing malicious in its diff
- The payload lived in a dependency. The only git-visible trace is *who* added it.
- **Fix:** tenure x privilege x new dependency: fired on 1 of 45 benign changes where each
  half alone fired on 56% and 13%.
- **Limitation kept honest:** xz's attacker had 756 days and 431 commits; no tenure rule
  catches the long con.

### 5.4 Our own ground truth could not reveal its blind spot
- Against the ASE 2026 npm benchmark (6,420 malicious), content rules caught 19.1%. 67% of
  malicious packages use install hooks; **none of our five incidents do**.
- **Fix:** install-hook rules graded by what the hook does; detection more than doubled.
- **Lesson:** five incidents cannot show you what five incidents lack.

### 5.5 The LLM was remembering, not reasoning
- Tier 2 cited CVE-2024-3094 by number and decoded a gist URL that only appeared in base64.
- **Fix:** recognition ablation (`--anonymize`): 5/5 -> 4/5. xz flipped to benign -- and
  was *right* to: the extractor lived in a tarball-only m4 file, never in git.
- **Lesson:** an LLM result on famous incidents without an ablation is a memory test. And
  diff-scoped analysis cannot establish intent when payload and trigger are split.

### 5.6 The agent that never finished
- Tier 3 (an investigating agent) exhausted 5,000 GitHub requests in five investigations,
  then never completed a run when narrowed. It sat on the least reliable layer.
- **Decision:** removed. The binding constraint is investigator minutes, not tokens.

### 5.7 Actions attacks never touch main
- reviewdog's commit was on no branch; tj-actions rewrote every tag to one commit. A
  default-branch scan sees neither -- the 5/5 never exposed it because incidents are fed
  by SHA.
- **Fix:** tag-integrity rules (version collapse, moved tag, tag on no branch). First cut
  checked only the default branch: 18 alerts, 10 with no other evidence (`releases/*`
  branches). Checking every branch fixed it.

### 5.8 Calibration round 1 (first hunts, Oct 8)
| Exposed | Share | Fix |
|---|---|---|
| `GITHUB_TOKEN` named in docs/tests | 14 of 40 | naming a token is low; reading a credential store escalates |
| tags on release branches | 10 of 40 | `tag.on_no_branch` |
| squash merges read as direct pushes | 9 of 25 | newcomer rule excludes PR-associated commits |
| repo founders on day 0 | 11 of 25 | author must arrive in an established (180-day) repo |
| xz "arrived on day 0" | -- | arrival from earliest commit, not `created_at`: 0 -> 5,164 days |

Actions: 40 -> 11 alerts.

### 5.9 Calibration round 2 (first holdout, Oct 26)
**Problem:** 17 alerts, all briefed benign by the model, none a real attack. Reading them
showed the noise was not the hard problem -- it was five deterministic defects:

| Defect | Alerts | Fix |
|---|---|---|
| "No patch from GitHub" treated as "binary" -- empty `.gitkeep`, a 13,690-line bundle, vendored JS all became binaries | 8 | classify from line counts and the empty-blob hash; rebuild withheld diffs from both file versions; sniff NUL bytes |
| dependency rule matched any `"key": "1.x"` -- `"version"`, `"node"` | 1 (+30 bullets) | read package.json sections; ignore bumps; one finding per manifest |
| `env=dict(os.environ)` read as secret theft | 1 | passing env to a subprocess is not collection; sending it is |
| tag rules blind to repo conventions -- dual version schemes, off-branch release builds, a 2020 README tag | 8 | alias-scheme collapse; off-branch convention (>=2 releases); docs-only commits on a branch parent |
| queue listed every hit (~70 bullets on one alert) | -- | one bullet per rule, strongest first |

Counts overlap: mheap's five alerts each had both a binary and a tag cause.

**The fix that is also a detection gain:** a *modified* file whose diff GitHub withholds was
never scanned at all. A rebuilt `dist/index.js` -- exactly where tj-actions hid its payload
-- is the file GitHub withholds. Withheld diffs are now rebuilt, and in a rebuilt bundle
only patterns *new to the file* count, so a regenerated bundle's ordinary `child_process`
is not news but an injected payload is. Files that still cannot be read are reported as
unscanned instead of passing silently.

**Fixing one layer exposed the next (good slide: "every fix is a new instrument").**
Once Tier 0 could read rebuilt bundles, the first re-hunt escalated four ordinary
dependency upgrades in one repository and scored an initial release at 98. Every hit was
the bundled dependencies' own code:

| Hit | What it really was | Correction |
|---|---|---|
| base64 blob `AGFzbQ...` | `\0asm` -- undici's HTTP parser, inlined WebAssembly | decode the first bytes; images, fonts and (in bundles) wasm are assets |
| `eval("require")`, `child_process`, `fetch`, `Object.keys(process.env)` | ncc and library internals | in a *rebuilt* bundle only payload-shaped content counts; a hand-edited bundle (small diff) keeps every rule |
| `if (startIndex < Infinity && ...)` | a range check | the loop rule needs a loop header |
| "encoded payload in CI configuration" | blob in `dist/`, unrelated workflow edit elsewhere | file-scoped combos need both halves in one file |
| `for (...; i < Infinity; ...)` in `index.cjs.map` | a library's source embedded in a source map | source maps are derived like lockfiles: not scanned |

Each correction kept the ground truth at 5/5 with identical evidence scores.

**A wider window found more.** The first holdout hunt looked 10 commits deep. Re-hunting
the same (now calibration) targets 50 deep surfaced four more classes in older commits:
`eval("require")` (a bundler idiom that evaluates a fixed name), Office documents as test
inputs, an inline base64 source map in a committed `dist/`, and `normalizeEnv(process.env)`
-- the environment handed to a function, not sent anywhere. Environment collection now
requires a sink (stringify, post, send, write) in the same statement. Lesson for the slide:
**calibrate on more data than you measure on**, so the measurement does not become the
place defects are discovered.

**A final 50-deep sweep with every correction in place: 26 escalations -> 14.** The 12
removed were rules matching the wrong thing:

| Hit | What it really was | Correction |
|---|---|---|
| `.npmrc`, `~/.ssh/id_rsa` in a README | install instructions | prose is not executed -- except instruction files for coding agents (AGENTS.md, CLAUDE.md), which an agent acts on |
| `config/deploy_id_rsa`, `id_ed25519.pub` | a key the action decrypts into its own tree; a public key | key files match as names, not substrings |
| `https://203.0.113.10` + `secrets.GITHUB_TOKEN` = "credential exfiltration" (critical) | an RFC 5737 documentation address in a test, and a ghcr login | documentation address ranges route nowhere |
| `# .npmrc -- supply chain hardening` | the repo's `.npmrc` naming itself | a credential file naming itself is not access |
| `execSync`, `child_process`, `atob` in committed bundles | lines the same diff removed -- the bundler moved them | in a bundle, the patch's removed lines stand in for the previous version |
| `atoBm`, `atoB`, `aTOB` in a transliterated Bible (test data) | words | `atob` is a whole, case-sensitive word |

The 14 that remain split into correct detections (prebuilt ELF binaries, a `.gz` blob, a
benchmark fetching code from a gist, an action writing an SSH key into `~/.ssh`) and three
open **policy** questions left to the designer: whether `scripts/` is a build directory
(4 alerts: dev scripts using `child_process`), whether many low/medium findings in one
large feature commit should reach the threshold through the category bonus (2), and
library code in a newly added bundle (1: `@actions/core`'s own `powershell` call). All three were
settled before holdout-2 ran: each kept as it was.

**Review tooling.** The queue was rebuilt for the human reviewer: an at-a-glance table, one
card per alert with a plain-words headline and a fact table, evidence and circumstance
separated, a deterministic checklist with links straight to the flagged line, the
tagged-vs-parent comparison and each new package's npm page -- and the untrusted text
(commit message, model brief) last. `kitsunox tally --summary` writes a Markdown review
summary next to the queue. Untrusted file names and authors are escaped so they cannot
forge links or table cells; tested and mutation-checked.

**Method:** fixing defects found by reading the holdout made it in-sample. It was demoted to
calibration and a fresh holdout-2 was drawn (same queries and filters, seeded random
sample, disjoint by repository and owner) and hunted untouched.

### 5.10 Process failures caught and fixed
- A patch script's unasserted `str.replace` silently did nothing, and a commit message
  claimed it had worked. Now every scripted edit asserts its match.
- A commit went in with 3 failing tests because pytest was piped through `tail`, which
  hid the exit code. Commits now gate on `set -o pipefail`.
- New protections are **mutation-checked**: remove the protection, confirm its test fails.

---

## 6. Limitations (state them as findings)

1. The long con (xz: 756 days, 431 commits) is out of reach of any tenure rule.
2. Diff-level analysis cannot see a malicious dependency; event-stream is caught by *who*.
3. Five incidents: a demonstration, not a confidence interval.
4. LLM verdicts are contaminated by recognition; the ablation is mandatory.
5. A single change is the wrong unit for a staged attack (xz's trigger was tarball-only).
6. Precision in the wild is bounded by base rate: with no attack in the sample it can only
   show alert burden and minutes per alert, not recall.
7. Known evasions: parking a malicious commit on a branch defeats `tag.on_no_branch`;
   payloads under vendored paths, and Markdown other than agent instruction files, are
   not scanned; `tag.moved` needs a prior snapshot; inside a bundle, a hostile line that
   replaces an existing line using the same primitive (`execSync`) is not new.

---

## 7. Future work (deterministic, ranked by value per hour)

1. **Dependency provenance** from the npm registry -- package and version age, maintainer
   count, the dependency's own install scripts, name similarity to popular packages.
   Turns limitation 2 from "flags the author" into "flags the dependency".
2. **Commit-signing baseline** -- an author who always signs suddenly doesn't (AV-602,
   account takeover); the data is already in the fetched commits.
3. **Decode encoded blobs and re-scan them** deterministically, rather than relying on the
   LLM to do it (where recognition contaminates it).
4. **Rebuild `dist/` and compare** -- the strongest Actions check, the most expensive.
5. **Seeded-injection recall** -- splice attack-shaped changes into real holdout commits and
   measure detection rank, giving a recall number beyond five famous incidents with no
   recognition contamination.
