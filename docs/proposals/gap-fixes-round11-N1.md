# Round 11, agent N1: four Stage 2 rules for residual misses

Base: main `d08077a`. Source of the designs: agent M's gap analysis (round 11; the 91 residual
misses after main, `~/kitsunox-scratch/r11/GAP-ANALYSIS.md`), targets P2, P5, P4 and P6, which
the owner approved on 2026-11-13. M measured each shape with a throwaway scanner; this round
re-measured with the real rules. Scripts and outputs: `~/kitsunox-scratch/r11/N/N1/`
(`scripts/`, `out/`). Package text was read as data; nothing was executed and no host named in
a package was contacted.

All four are Stage 2 rules (three artifact rules, which read every file of every version
Stage 2 reads, and one file rule) at MEDIUM, weight 3, so each reports a version on its own.
They only add findings, so no decision can be lost; the replays confirm it. No Stage 4 change,
so no stage version bump; each rule is version 1. Adding a file rule changes Stage 2's
content-cache fingerprint (a fresh `cache/static/` directory after deploy, as with every
file-rule change).

| # | Rule | Recovers | Benign added, live | `vm-day1` |
|---|---|---|---|---|
| P2 | `static.host-ip-identity` (`rules/host_ip.py`) | `@atedone/workspace-context` 0.0.23, 0.0.24, 0.0.25 (malicious) | 0 | 3 malicious samples touched (`@depro-tech/cortana-md` 1.2.22, 1.2.49, 1.2.63: a proxy list's bare IP and a URL builder), not routed: no change |
| P5 | `static.html-redirector` (`ecosystems/npm/rules/hosted_page.py`) | `bfvkjmeikpwhqxc@1.0.1` (malicious; 1.0.0's tarball is gone); live and never reported: `@isla5mic/aasics` 1.0.0-1.0.2 (malicious) and 7 more versions of the template (below) | 0 | fires on none |
| P4 | `static.decoded-function` (`rules/static.py`) | `mock-data-sdk@1.0.1` (OSV) | 0 | 1 malicious sample touched (`@uallianceorg/config@1.0.2`), not routed: no change |
| P6 | `static.silent-native-load` (`ecosystems/npm/rules/native_load.py`) | `strutil-helpers-core@1.0.1` (OSV); fires on 1.0.2-1.0.5 too, which Stage 2 doesn't read | 0 | fires on none |

## How it was measured

- **Targets**: agent M's replay (`M/scripts/replay_m.py`: Stages 1-4 on main's code, routing as
  live, M's recovered tarballs first) of the 186 target versions, main (M's `out/main.jsonl`)
  vs this branch (`out/m-targets-v2.jsonl`): 6 versions newly reported, all positives, 0 lost,
  0 errors.
- **Replay set** (3,716 verdicted versions, `r5/K/replay.py` keyed on every version where a
  rule fires; re-baselined on main `d08077a`): only the atedone and bfvk versions are in it.
  +4 malicious (`@atedone/workspace-context` 0.0.23-0.0.25, `bfvkjmeikpwhqxc@1.0.1`), nothing
  else changes. Against round 10's final full replay (1,425 reported, 694 positive, 12
  unverified: 49.12%), precision becomes 698 / 1,417 = **49.26%**.
- **Live**: every distinct held tarball of the 14 days of decision ledgers (232,433, about
  what Stage 2 read; `out/full-v1.jsonl`), each rule run on the whole tarball (the file rule
  on every file, so an over-count for it: Stage 2 reads only new contents). The first
  versions fired on 17 versions; the 5 benign-looking ones (3 packages) led to the two
  narrowings below.
  Final rules: 12 versions, all positives or the redirector template, **0 benign**.
- **Populations** (agent M's `scan/population.json`): all 1,976 held tarballs with a benign
  verdict: 0; all 1,243 malicious/unwanted: 1 (`bfvkjmeikpwhqxc@1.0.1`); a random 25,000 live
  tarballs (seed 20261113): 1 (`@isla5mic/aasics@1.0.0`).
- **`vm-day1`** (all 4,944 samples): the four rules run as Stage 2 would (artifact rules on
  each sample's whole tree, the file rule on contents new against the base; DataDog zips
  decrypted in memory, tarballs read from the evaluation store offline; `scripts/vm_scan.py`,
  first versions of the rules, a superset of the final ones). They touch 4 samples, all
  malicious, none benign. `pipeline+4` (`scripts/vm_eval.py`) on those 4, main vs the final
  tree: unchanged, not reported either way, because none is routed (no Stage 1 signal, so
  Stage 2 never reads it). Nothing gained or lost there.

## P2. A bare IP built into an identity URL

The JSON half alone (a bare public IP under `host`, `server`, `ip`, ... with no scheme) is in
16 of the random 25,000, all `@mentra/cloud-protocol` URL test vectors; the code half (a URL
built from a scheme variable and the user's name or hostname read in the same file) is what
carries the rule. Not covered: atedone 0.0.13-0.0.22 (no bare IP; their start-up-file match
is P3, agent N2's).

## P5. A package that is a redirecting web page

The 11 live hits are one template (fetch from a key-value dead drop, AES-CTR
`crypto.subtle.decrypt`, `window.location.replace`), from three accounts:

| Account | Versions | Verdict | On npm 2026-11-13 |
|---|---|---|---|
| `dfghbvbfjh` | `bfvkjmeikpwhqxc@1.0.1` | malicious | removed (`0.0.1-security`) |
| `xfrkbihc` | `@isla5mic/aasics` 1.0.0, 1.0.1, 1.0.2 | malicious | yes |
| `xfrkbihc` | `@isla5mic/test` 1.0.0, 1.0.1, 1.0.3, 1.0.4, 1.0.5 | none yet | yes |
| `pdlzbbrb` | `hewuzdfhcxmrsu@1.0.0`, `mkdgwgbvpwqsf@1.0.0` | none yet | yes |

## P4. Code handed `require` after decoding

The first version counted a `"require"` parameter name in any position; live it also fired
on `@wix/agent-skills` 1.41.3/1.41.4 (`new Function('module', 'exports', 'require',
bundle)` evaluating esbuild output, in a file that decodes base64 data URIs) and
`axiom-math@1.1.0` (an Emscripten wrapper with `'require', 'module', 'exports'`). Module
wrappers (`"module"` or `"exports"` among the parameter names) now count only in a file that
also fetches: neither benign file fetches anything, while `vm-day1`'s
`@uallianceorg/config@1.0.2` (malicious) runs `new Function("module", "exports", "require",
code)` on a download from an `atob`-hidden URL. A wrapper that decodes its own body is a known
gap. An earlier slip (checking `static.function-require`'s pattern at `new`
instead of `Function`) fired on two benign `new Function(\n "require", ...)` files; fixed
before measuring.

## P6. A bundled addon loaded silently

The first version (any `require` of a shipped `.node` in a `try` with an empty `catch`)
fired live on `dsh-needs-you-mac` 0.2.0/0.2.1, a macOS notifier whose optional addon is
loaded in `try { const addon = require(...) ... } catch { // No binary ... }` and then used.
The rule now needs the `require` to be a statement of its own (the addon's exports unused,
as in `strutil-helpers-core`), which is the shape's point: loaded for what loading does.

## Owner questions

1. **Follow-ons of `static.silent-native-load`**: `strutil-helpers-core` 1.0.2-1.0.5 have no
   Stage 1 signal and are never read by Stage 2. Adding the rule to Stage 4's
   `FOLLOW_ON_ALONE` would carry 1.0.1's report to them (Stage 4, not this round's files).
2. **The 7 unverdicted redirector versions** (`@isla5mic/test` ×5, `hewuzdfhcxmrsu`,
   `mkdgwgbvpwqsf`) are the verdicted-malicious template, still on npm: verdicts and reports.
3. **Severity of `static.html-redirector`**: MEDIUM, as designed. It harms visitors, not
   installers; whether such packages count as malicious for the evaluation is the verdict
   policy's (all verdicted so far: malicious).

**Owner's answers (2026-11-13):** merge all four rules. (1) Yes: build and measure the
`FOLLOW_ON_ALONE` carry for `static.silent-native-load` as a follow-up change. (2) Done by
the integrator: all 7 recorded malicious (same template, read as data; `@isla5mic/test`
shares aasics's dead-drop and AES keys) and reported. (3) MEDIUM kept.
