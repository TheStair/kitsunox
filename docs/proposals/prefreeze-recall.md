# Proposal: pre-freeze recall fixes (shell start-up files, WhatsApp channel follows, small updates)

> **Status:** measured and implemented 2026-11-08, before the 2026-11-12 rule freeze. The owner
> approved building all three on 2026-11-08, each only if it doesn't flood benign reports.
> **Builds on:** [stage2-routing-recall](stage2-routing-recall.md) (the live misses and option
> B), decision [0008](../decisions/0008-stage2-routing-and-tarball-capture.md) (routing),
> decision [0015](../decisions/0015-reviewer-verdicts.md) addenda of 2026-11-08 (Baileys forks
> that follow channels are *unwanted*, hidden or disclosed; opt-in is benign; the headline
> matrix counts malicious + unwanted as positives, a strict matrix malicious only).
> Measurements are read-only on the VM's `data/`; scripts in [Reproducing](#reproducing).

## Summary

| Change | Implemented | (a) live misses reported | (b) reviewed malicious reports lost | (c) DataDog `vm-day1`, `pipeline+3` | (d) benign cost |
|---|---|---|---|---|---|
| 1. `static.shell-startup` (Stage 2) | yes: MEDIUM for install hooks and injected `source`/prompt lines, LOW for the rest | `@atedone/workspace-context` 0.0.12 and 0.0.18 (2 of 14 versions; both also need change 3) | 0 | 0 (no sample changes) | 1 newly reported version in 4.6 days (~0.2/day), a completion installer |
| 2. `static.channel-follow` (Stage 2) | yes: MEDIUM, "unwanted"; never demoted as "not new" | `@sakataa/baileys@2.0.0` (only through `ALWAYS_NEW`), `@axo_cuy/baileyss@3.0.1`; `kevinx-baileys@1.2.1` would be, but is over the 16 MB cap | 0 | +1 B follow-on (`violetics@7.0.3-alpha`) | 11 in 4.6 days (~2.4/day), all forks that follow by default: unwanted, so 0 false positives in the headline matrix, 11 in the strict one |
| 3. Route updates ≤ 64 KiB to Stage 2 (Stage 1) | yes (reason 6, `small update`) | none alone (it newly routes 18 of the 30 positive versions) | 0 | +62 B follow-ons (existing rules on newly routed versions) | +16.2k versions/day read, +0.14 GB/day (≤ 0.5 with bases), ~5 benign reports/day (2 of 6,436 sampled) |

All three are implemented: the numbers support them. Together they report **4 of the 30
positive live-miss versions (3 of 12 packages)** that nothing reported before, under the
headline reading (malicious + unwanted); under the strict reading (malicious only) they
recover **none** of the 10 (`@atedone` 0.0.23 changes no matching file and 0.0.24-0.0.25
repeat their base's match; the other malicious misses are gone from the registry or match
nothing). On DataDog `vm-day1`,
`pipeline+3` B follow-on recall goes from 606 to 669 of 1,093 (55.4% → 61.2%), nothing else
moves and no benign sample is added (13 of 1,500 before and after). Live, the cost is about
2.6 new reports a day from the rules (2.4 of them unwanted Baileys forks) and about 5 benign
ones a day from the routing, against ~250 reports a day today.

What was not done: no cap exception for the Baileys forks Stage 2 can't read
(`kevinx-baileys@1.2.1` 19.4 MB, `@ubedsockets/baileys` 24.9 MB, no install hook); no rule for
`@atedone`'s later releases (0.0.23 adds a hard-coded `"host": "150.136.8.159"` in JSON, not a
URL, so `static.hardcoded-ip` doesn't fire); the signatures KX-0008/0009/0011 are unchanged
(section 4). `pipeline+4` couldn't be run under the 4 GB memory cap (three tries: the CLI's 8
workers and then 2 were OOM-killed); `pipeline+3` was used, which for these changes decides
the same (a MEDIUM Stage 2 finding reports in Stage 4 unless it is in `WEAK_ALONE`, and
clearing is off).

## 1. Shell start-up persistence (`static.shell-startup`)

The live miss `@atedone/workspace-context` (14 versions, 0.0.12-0.0.25) persists through the
user's shell: 0.0.12's `lib/worker.js` writes a managed block with
`source "$HOME/.workspace-context/..."` into `~/.zshrc` or `~/.bashrc`; from 0.0.13 the write is
in `lib/sync.js` and the file name in `lib/state.js` (`'.bashrc' : '.zshrc'`, joined to `HOME`),
later versions write an `init.zsh` that sets `setopt prompt_subst` and
`PROMPT="$(node .../presentation.js ...)"`, and from 0.0.23 the prompt is rendered from a
profile fetched from `150.136.8.159:8080` with the user's `$USER`. It spawns through
`process.binding('spawn_sync')` built from string pieces, so no `child_process` rule fires.
No rule looked for any of this, and the version that added it (0.0.12: 6.5 KiB, +2.3 KiB) was
not routed.

**The rule** (`static.shell-startup`, `rules/static.py`) knows the start-up files
(`.bashrc`, `.bash_profile`, `.bash_login`, `.zshrc`, `.zprofile`, `.zshenv`, `.zlogin`,
`.profile`, `.cshrc`, `.tcshrc`, `.kshrc`, fish's `config.fish`, the PowerShell profile) and
reports at most one match per file and form:

| Form | Matches | Severity |
|---|---|---|
| `hook` | an install hook's value in `package.json` (`preinstall`/`install`/`postinstall`) appends to a start-up file (`>> ~/.bashrc`, `tee -a "$HOME/.zshrc"`, `Add-Content $PROFILE`) | MEDIUM, 3 |
| `inject` | a file that writes files (`writeFile*`, `appendFile*`, `createWriteStream`, `outputFile*`) and refers to the home directory holds a line sourcing a file under it (`source "$HOME/...`, `. ~/...`) or a prompt that runs a command (`setopt prompt_subst`, `PROMPT="$(`, `PS1="$(`) | MEDIUM, 3 |
| `shell` | the same shell redirect anywhere else (a script, a CLI's string) | LOW, 1 |
| `code` | a start-up file's name as a string literal, a file write within 1,000 characters of it, and a home-directory reference | LOW, 1 |

Each form needs a literal word (a file name, `$PROFILE`, a `source`/prompt form) before its
regular expressions run: on a 9.5 MB CLI bundle that has them, the rule takes 0.48 s (all
Stage 2 rules together: 2.7 s); on 7 MB without them, 0.05 s. Like every Stage 2 match except the signatures and
`channel-follow`, a form already in the base version's file is LOW ("not new").

### 1.1 Measurements

**(a) Live misses.** The 97 window-A misses (review11's 94 plus the routing agent's 48),
replayed: 30 positive versions (10 malicious, 20 unwanted) of 12 packages, 27 readable.
Reported after the change: `@atedone/workspace-context` **0.0.12** (`inject`: `lib/worker.js`
writes `source "$HOME/..."` next to `'.zshrc'`) and **0.0.18** (`inject`: the first
`prompt_subst` prompt). 0.0.13-0.0.17 and 0.0.19-0.0.25 repeat the previous version's match
(LOW); 0.0.22 and 0.0.23 change no matching file. Both reported versions are routed only by
change 3 (6.4 and 17.0 KiB declared, grew by less than 64 KiB).

**(b) Reviewed reports.** Findings only add, and Stage 4's `decide` only reports more with more
findings (clearing is off), so no reported version can be lost. Over every reviewed version
with a captured tarball (1,364 benign, 31 malicious, 22 unwanted, 15 unverified), the MEDIUM
forms match none.

**(c) DataDog `vm-day1`** (`pipeline+3`, before at `30b728d`, after with all three changes):
the rule flags no sample at MEDIUM that changes a decision.

**(d) Benign.** Every version Stage 2 read in the runs `20261107T163310Z-npm`,
`20261107T222723Z-npm` and `20261108T073127Z-npm` (Nov 3 17:15 to Nov 8 07:31, 4.6 days):
their 201,475 captured tarballs were scanned in memory (190,203 still on disk; a literal
prefilter, then the rule), and the 1,421 versions with a match were replayed exactly (their
recorded Stage 1-4 findings, the rule on their new contents against their base, `decide`).

| Form | MEDIUM matches not in the base | Newly reported |
|---|---|---|
| `hook` | 0 | 0 |
| `inject` (final) | 1 | 1: `@heyvamz/carry@0.4.3` (writes `[ -f ~/.carry/completion.zsh ] && source ...` into `.zshrc`) |
| `inject` (first form: any `source ~/...`, any `PROMPT=$(`) | ≥ 12 | ≥ 11: `paperclipai` canaries (`. "$HOME/.profile"`), `triflux`, `autopilot-ai` (an AI prompt variable), `replicas-cli`, `heibaicc` (advice text), ... |
| `shell` (as MEDIUM, measured on the last 14.7 h) | 5 | 5 (~8/day): `backupd`, `@backupd/cli`, `westkite`, `@ohos-ports/composio-mcp`, `@ohos-ports/smg-automotive-components` |
| `code` (as MEDIUM, same 14.7 h) | 2 | 1 (~1.6/day): `agentstalk` |

So `hook` and `inject` are MEDIUM, `shell` and `code` LOW (weight 1, evidence for a reviewer
and the LOW cap). Distinguishing a static PATH line from remote content written into a
start-up file wasn't possible from the data: no benign or malicious version wrote fetched
content into one directly (`@atedone` writes a static `source` line; what it fetches is read
later by the prompt). Install-time vs runtime is the `hook` form for shell commands; a
JavaScript file that an install hook runs isn't known to a file rule (Stage 3's
`npm.install-script-code` sees it).



## 2. WhatsApp channel follows (`static.channel-follow`)

Baileys forks that make the user's WhatsApp account follow (and often mute) channels the
author chose. The signature KX-0008 (`rules/signatures.py`) required `newsletterWMexQuery`
next to a plain `...@newsletter` id, so it missed the forms the live misses use:
`kevinx-baileys` 1.2.1/1.2.2 and `@sakataa/baileys` 2.0.0/3.0.0 hide four ids in base64 and
call `mexQuery({ newsletter_id: Buffer.from(jid, "base64")... }, Types.QueryIds.FOLLOW, ...)`
10-25 s after the socket opens; `@axo_cuy/baileyss@3.0.1` the same with one id;
`@ubedsockets/baileys` 1.7.9-1.7.12 follow a plain id on `connection: 'open'`.

**The rule** (`static.channel-follow`, `rules/static.py`) fires on a file that

1. uses a FOLLOW query (`<x>.FOLLOW`, `<x>["FOLLOW"]`, not an assignment) or calls
   `newsletterFollow(...)`, *outside* the library's own follow/mute methods (a definition such
   as `newsletterFollow: async (jid) => ...` within 220 characters before it), and not
   within 600 characters after an explicit opt-in `if (<...follow...> === true)`;
   or holds char-code arrays that spell `newsletterFollow` (`felicia-baileys`);
2. and either names channels (`\d{15,22}@newsletter`, `0029V` + 18-22 invite characters),
   hides them (in base64 literals, via the signatures' `decoded_strings`, or char codes),
   fetches over the network (`fetch(`, `axios.get(`, `https.get(`,
   `raw.githubusercontent.com`), or calls the code an auto-follow / auto-join / follow list.

The file must contain the word `newsletter` at all (a cheap gate; every Baileys fork does,
other code using a `FOLLOW` constant doesn't). The owner's ruling (decision 0015 addenda,
2026-11-08) is that channel follows are **unwanted**, hidden or disclosed, unless there is
evidence of malware; only opt-in is benign. A file rule can't tell hidden from disclosed (it
can't read the README reliably), so the finding is MEDIUM, weight 3 (reported), titled
"Auto-follows WhatsApp channels (unwanted)", and its explanation says it is account abuse, not
by itself a sign of malware. It is in `static.ALWAYS_NEW`, like the signatures: a release
whose base already followed is still unwanted, and `@sakataa/baileys@2.0.0` (a live miss)
changed the file but its base already followed.

### 2.1 The Baileys corpus

Every package with a verdict whose name or note says Baileys/WhatsApp/newsletter, plus the
live misses, with a tarball (captured blob or the registry; `luna-baileys`, `testbail`,
`@ikyzanx`/`@ikyzyn` are gone), whole package (no base), MEDIUM after the docs demotion.
Verdicts are those recorded when the corpus was built (before the 2026-11-08
reclassification): "malicious" Baileys forks are hidden auto-follows (now *unwanted*),
"inconclusive" ones disclosed or default-on (now *unwanted* too).

| Verdict | Versions (packages) | `channel-follow` | KX-0008/0009/0011 | Either |
|---|---|---|---|---|
| malicious (hidden auto-follow) | 26 (20) | **26** | 14 | 26 |
| inconclusive (disclosed / default-on) | 6 (6) | 4 | 1 | 4 |
| benign | 23 (19) | 1 | 0 | 1 |

- Malicious, all matched: `@gopyr/baileys@1.0.0` (invite codes), `@ikyerza/baileys@1.0.0`,
  `vp-baileys@9.0.34` and `lyxe-baileys`, `@nerxa/socketon` (fetched NOXLEYS list),
  `felicia-baileys@1.0.3` (char codes), `charape@1.0.20` (`autoFollow` default),
  `@leonoremods/baileys` 1.2.9 and 1.10.1, `@dancihuy/baileys@0.0.1`, `@finzzcloud/baileys`
  (follows through a helper given `QueryIds`), `kevinx-baileys` 1.2.1/1.2.2, `@sakataa` x2,
  `@axo_cuy`, `@ubedsockets` x4, `@chatbridgeworld@1.0.0`, `@bil-rgb`, `@lekzsync`,
  `@zaiilx`/`@zaidevx`, `sauruspro-bail`.
- Inconclusive: the 4 that follow (`@pasqua-dev/baileys@1.0.0`, `@alexiddev`,
  `@prasstzymhtrr`, `koezoet-baileys`) match; `hyrox@0.1.6` (no follow code) and
  `baileys-linius@1.0.0` (a wrapper; the fork it pulls in isn't on npm) don't.
- Benign: only `@yshtxxproject/baileys@0.0.1`, whose `lib/Socket/newsletter.js` follows the
  three `DEFAULT_AUTO_FOLLOW_CHANNELS` of `lib/Defaults/index.js` on the first `open`, the
  same code as `@dancihuy/baileys@0.0.1` (ruled malicious, then unwanted); its benign verdict
  ("a guard that blocks newsletterFollow by default") predates the policy and the guard doesn't
  cover the default list. `shadowx-baileys` (opt-in `=== true`) and the forks with only the API
  don't match.

Under the owner's reading the first two rows are positives in the headline matrix (30 of 30
followers caught, 0 of 22 benign but `@yshtxxproject`), and none is a positive in the strict
malicious-only matrix: there, all 31 matches are "false" positives by definition, which is
why the finding says "unwanted".

### 2.2 Measurements

- **(a) Live misses:** `@sakataa/baileys@2.0.0` and `@axo_cuy/baileyss@3.0.1` are reported
  (2.0.0 only because of `ALWAYS_NEW`: its base already followed). `@sakataa/baileys@3.0.0`
  and `@bil-rgb/baileys@1.0.1` change no matching file. Not reachable: `kevinx-baileys@1.2.1`
  (19.4 MB, no hook: over the cap; it would be reported) and `@ubedsockets/baileys`
  1.7.9-1.7.12 (24.9 MB, no hook, not routed); `luna-baileys` 9.0.x are gone.
- **(b) Reviewed reports:** none can be lost (findings only add). Of the reviewed versions with
  a captured tarball, it matches 10 of 22 unwanted (all channel-follow forks) and 4 benign: the
  `lexzymods-baileys` family (opt-in in another file, section 4); no malicious one (none of
  the 31 captured is a Baileys fork).
- **(c) DataDog `vm-day1`:** +1 B follow-on, `violetics@7.0.3-alpha` (a WhatsApp library,
  already routed for its install hook; its only MEDIUM finding). Benign unchanged.
- **(d) Live benign:** over 4.6 days of Stage 2 reads, 11 newly reported versions, all forks
  that follow by default (static.md, "WhatsApp channel follows"): ~2.4 a day, unwanted, none
  malware. 9 more matches were in versions already reported (`lexzymod*` x4, `@axelkalcer`,
  `@yannajah`, `@dancihuy`, `@leonoremods` x2).


## 3. Small updates to Stage 2

Option B of [stage2-routing-recall §4](stage2-routing-recall.md#4-questions-for-the-owner):
Stage 1 forwards every update that declares at most 64 KiB (`SMALL_UPDATE_BYTES`, reason
`small update`, checked after the growth route; `stages/triage.py`, ledger route `small`). The
evaluation's routing calls the same `triage`, so `pipeline*` predictors follow.

**Volume** (the 4-day run `20261107T163310Z-npm`: 405,710 changes, 3.97 days, Nov 3 17:15 to
Nov 7 16:33): 264,451 updates were not routed, 64,415 of them ≤ 64 KiB, **~16,200 versions a
day** (the 2026-11-02 estimate was 18,700); 3,250 ≤ 4 KiB, 16,331 ≤ 16 KiB, 18,742 ≤ 32 KiB,
26,092 ≤ 64 KiB. Declared unpacked bytes: 0.47 GB a day.

**A deterministic 1/10 sample** (6,436 versions, SHA-256 of `name@version` mod 10), fetched
from the registry as data (6,435 still there) and replayed (`harness.replay`: Stage 1 findings
as recorded, Stages 2-3 with today's rules plus the two new ones, Stage 4's `decide`; Stage 4's
repository and dependency rules are not run, as in the earlier proposal):

| | Sample | Per day (×10 / 3.97) |
|---|---|---|
| Tarballs fetched (new version) | 55.0 MB | **0.14 GB** |
| Base tarballs (upper bound: often already captured) | 146.4 MB | ≤ 0.37 GB |
| Flagged by Stage 2 | 2 | ~5 |
| Reported | **2** (0.031%; Wilson 95% 0.009–0.11%) | **~5** (1.4–18) |
| A new-rule match at MEDIUM | 0 | 0 |

The two reported are `@quecue/notify-core@0.1.0` (`static.exfil-endpoint`: a notifier that
posts to `api.telegram.org/bot${config.telegram.token}`, the user's own bot) and
`parallel-executor@2.0.0` (`static.function-require`: its worker compiles the task it is sent
with `new Function("require", ...)`); both look benign on inspection (unreviewed). Stage 2 and
3 read ~41% more versions (39.4k a day on 2026-11-02), and registry requests grow by about
16k a day (32k with bases); disk barely moves (+0.5 GB a day at most).

**(a) Live misses.** Alone it recovers none: of the 30 positive versions it newly routes 18,
and today's rules flag none of them. With `static.shell-startup` it is what reports
`@atedone/workspace-context` 0.0.12 and 0.0.18.

**(c) DataDog `vm-day1`** (`pipeline+3`): +62 B follow-ons (606 → 668 with the routing alone,
669 with `violetics`), all updates ≤ 64 KiB that Stage 1 didn't route before; their only
MEDIUM+ reasons are existing rules (`exfil-endpoint` 26, `encoded-url` 12, `obfuscated` 10,
`hardcoded-ip` 7, `function-require` 5). A, A follow-on and B first releases: unchanged (0 of
the 34 unrouted A first releases is flagged when read, as before). Benign: 13 of 1,500 before
and after.


## 4. Questions for the owner

1. **KX-0008, KX-0009, KX-0011** (`rules/signatures.py`) are HIGH "Matches a known malware
   family" for Baileys channel follows, which the owner now rules unwanted, not malware. On the
   corpus every version they match is also matched by `static.channel-follow` (14 of 14 and
   1 of 1). Retire them, relabel them, or keep them as family evidence? Not changed here.
2. **`@yshtxxproject/baileys@0.0.1`** is reviewed benign but follows three hard-coded channels
   by default, the same code as `@dancihuy/baileys@0.0.1`: re-record as unwanted?
3. **Opt-in in another file**: the `lexzymods-baileys` family (4 name variants, reviewed benign,
   opt-in through `repanAutoJoinChannels.enabled` read in `lib/Socket/index.js`) is reported:
   the follow and its bundled list are in `lib/Utils/repan-channels.js`. Acceptable, or
   should the rule look for an opt-in option anywhere in the package (an artifact rule)?
4. **Over-cap forks**: `kevinx-baileys@1.2.1` (19.4 MB) and `@ubedsockets/baileys` 1.7.9-1.7.12
   (24.9 MB) have no install hook, so Stage 2 never reads them. A larger cap for them would
   need a signal before the download (a package name is not one); left for after the freeze.
5. **`shell` and `code` at LOW**: kept as evidence. Raise `shell` to MEDIUM for files an
   install hook runs? That needs Stage 3's install sources, a cross-stage change; not done.


## Reproducing

Scripts in `~/kitsunox-scratch/agent-prefreeze/scripts/` (read-only on `data/`; tarballs read
as data, in memory; registry fetches go to the scratch blob store `fetch/`):

- `pf.py`: tarball lookup (a run's captured blob, else the registry).
- `harness.py`: a version replayed before/after: its recorded Stage 1-4 findings plus the new
  rules on its new contents against its base (all of Stages 2-3 recomputed for a version
  Stage 2 never read), Stage 4's `decide`, and the new routing and cap.
- `misses.py` (a), `verdicts.py` (b), `baileys_set.py` + `bcorpus.py` (the Baileys corpus),
  `scan.py` + `benign.py` (d: every captured tarball of the runs `20261107T163310Z`,
  `20261107T222723Z` and `20261108T073127Z`, literal prefilter, exact replay of each version
  with a match), `small.py` + `smallrep.py` (small updates: counts and a 1/10 sample).
- DataDog: `kitsunox eval run vm-day1 --predictor pipeline+4` against a scratch data dir
  (hard links to `data/eval`, `data/labels`, `data/watchlists`, the report store copied), the
  baseline from `30b728d`.
