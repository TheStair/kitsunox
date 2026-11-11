# 0015: Reviewer verdicts, recorded in the viewer

**Status:** accepted 2026-10-30 (the owner asked for it). **Supersedes:** the viewer's
"never writes" property ([viewer.md](../viewer.md)).

## Context

The review queue lists every reported version for a week, whether or not someone has looked
at it. The owner wants to review a version and mark it **malicious**, **inconclusive** or
**benign**; have it leave the queue and appear on that verdict's page; and keep a running
tally of verified malicious releases. Until now the viewer was strictly read-only.

## Decision

1. **Per version, append-only.** `data/verdicts/<ecosystem>.jsonl`, one `VerdictRecord` a
   line: the last record is the verdict; `reopened` puts the version back. History is kept.
   Each record copies the entry as reviewed (score, severity, rules, publisher, publish time,
   run and rank), so it outlives the run. A new release of the same package is a new item.
2. **The queue leaves reviewed versions out** (`reporting.queue.build_queue`), and the viewer
   filters again at render time, so a verdict takes effect at once. The tally rides along in
   `queue.json`, the queue page and the daily Discord summary.
3. **The viewer gets exactly one write, `POST /verdict`,** guarded by a per-start token in
   its own forms, `Origin` / `Sec-Fetch-Site` checks, a 16 KiB urlencoded body, and run id and
   rank looked up on disk (the form never supplies package text). CSP `form-action` becomes
   `'self'`. No token, so no writes, on a non-loopback address or with `--read-only`.
4. **`kitsunox verdict` records the same from a shell**, with `--by` naming the reviewer, so an
   analyst's verdicts are told apart from the owner's (`owner`, the viewer's).

## Alternatives

- **A separate review tool or file the owner edits by hand:** no buttons in the place where
  the evidence is; easy to get a key wrong.
- **Per package verdicts:** a package cleared today can be taken over tomorrow; the next
  release must be looked at again.
- **Accounts and TLS for remote review:** not needed for one reviewer; the SSH tunnel keeps
  the loopback guard.

## Consequences

- The viewer can change what the queue shows. Anyone who can reach the loopback port and load
  a page can record a verdict; that is the machine's own user.
- Verdicts are the first labels from live data: a later step can turn them into evaluation
  samples (verified malicious against what the rules caught).

## Addendum 2026-11-01: the `probe` tag and what counts as malicious

The owner was unsure whether bug-bounty probes, "likely mass produced legitimate bounties",
should count as malicious, "However, I could see real malware disguising itself as a bounty
placeholder or PoC". Decided (the owner: "Yes for both"):

- **Judge by behaviour.** Malicious if anything identifying leaves the machine or code is
  fetched and run, whatever the package claims; benign if it only acts locally with no network
  ([viewer.md](../viewer.md), "What counts as malicious"). An "authorized test" notice is a
  free string, and npm and OSV classify these probes as malware too.
- **A `probe` tag on the record** (`VerdictRecord.tags`, empty on older lines), set in the
  viewer or with `kitsunox verdict --probe`, any verdict but `reopened`. Tallies count tagged
  versions apart. The tag never feeds a score: like a verdict, it is a label on what the rules
  found.
- **Alternative rejected:** a fourth verdict, "probe". It would hide whether a probe exfiltrates,
  and a disguised attack would get the mild label.

## Addendum 2026-11-08: the Baileys policy, false disclosures, beacon-only probes

Recorded here because the live confusion matrix (decision 0019) uses reviewer verdicts as its
primary truth, so the rules reviewers apply must be written down.

- **WhatsApp forks that follow channels (the owner, 2026-10-31; devlog of that day).** A Baileys
  fork that makes the user's account follow WhatsApp channels is **malicious** when the follow
  is hidden (not mentioned in the README, not an option), **inconclusive** when it is disclosed
  or on by default with a documented way to turn it off, and **benign** when it is opt-in.
- **A disclosure that doesn't exist is no disclosure (the owner, 2026-11-08).** Code comments
  that claim a README or docs mention which isn't there count as hidden: malicious
  (`@leonoremods/baileys@1.10.1`, `@dancihuy/baileys@0.0.1`, 4-day run of 2026-11-07).
- **Beacon-only probes (the owner, 2026-11-08).** An install-time request to the researcher's or
  attacker's host that carries only a marker (no hostname, username, working directory,
  environment or credentials; DNS lookups of a marker host included) is **inconclusive** with
  the `probe` tag. Reviewers had first recorded these as malicious; 11 verdicts were changed the
  same day (`teick`, `lupedsagaces`, `lane-m-snackager-*`, `lane-m2-snackager-probe`,
  `my-unique-pinger@1.0.0`, `dependencykfeg@2.1.3`, `@mobile-platform/magnetic-components`).
  Anything identifying, or code fetched and run, stays malicious (`laneh-prepare-probe`'s other
  commits steal GCP and AWS credentials). A probe that only acts locally stays benign.
- **Vendor telemetry (the owner, 2026-11-08).** Install-time telemetry sent to the package
  vendor's own service is **benign** unless it collects secrets or credentials; the verdict
  note says what is sent (`@ohos-ports/itwcw-package-analytics`, `@wonderwhy-er/desktop-commander`,
  `signetai`).

## Addendum 2026-11-08 (later): four categories replace "inconclusive"

The owner: "inconclusive" made packages we caught but couldn't call malicious look like
packages we couldn't judge at all. Two different things were behind the one word: behaviour
we saw in full but that is not harmful enough to call malware, and behaviour we never saw.
They now have their own names. A verdict is one of:

| Verdict | Meaning | Examples |
|---|---|---|
| **malicious** | Harmful behaviour shown. | Credential or environment exfiltration, code fetched and run, a worm publishing with stolen tokens. |
| **unwanted** (new) | Behaviour seen in full; covert or intrusive, but not harmful enough to call malicious. Like an antivirus "PUA". | An install-time beacon that carries only a marker (no hostname, user, path, environment or credentials). A WhatsApp Baileys fork that auto-follows, joins or mutes channels (see below). |
| **benign** | Behaviour seen, and legitimate. | Vendor telemetry without secrets; a probe that only acts locally; an opt-in channel follow. |
| **unverified** (new) | We couldn't confirm what it does. Needs a reason tag. | See the tags. |

`reopened` keeps its meaning: the version goes back to the review queue.

**Reason tags** (`VerdictRecord.reason`; required for `unverified`, refused for every other
verdict, in the CLI with `--reason` and in the viewer as one button per tag):

| Tag | When |
|---|---|
| `gone` | The code was unpublished, or never captured (no tarball, run pruned). |
| `remote` | The payload is fetched from a git repository or URL we couldn't see. |
| `obfuscated` | We couldn't decode it. |
| `binary` | An unexplained native or binary payload. |

The `probe` tag still qualifies any verdict but `reopened` (a beacon-only probe is
`unwanted` with `probe`).

**Changes to the rulings above.** The earlier 2026-11-08 addendum is kept as written, with these
changes:

- "Beacon-only probes are **inconclusive** with the `probe` tag" now reads **unwanted** with
  the `probe` tag.
- "Disclosed or on by default with a documented way to turn it off is **inconclusive**" now
  reads **unwanted**, and is itself superseded by the next point.
- **Baileys forks (the owner, 2026-11-08, superseding the 2026-10-31 policy and the same day's
  "a disclosure that doesn't exist is no disclosure" ruling).** A Baileys/WhatsApp fork that
  auto-joins, follows or mutes WhatsApp channels is **unwanted**, hidden or disclosed alike,
  unless there is evidence that the channel follow is a way to spread malware. An opt-in
  follow stays **benign**. Anything else the package does is judged separately: if it
  downloads or runs code, exfiltrates, sends data besides the follow, or tampers with other
  packages, that decides the verdict. The older text above stays in place for the record, and
  verdicts recorded under it are reclassified by new records (the log is append-only).

**Legacy records.** The log is never rewritten. A record written as `inconclusive` still loads,
as `unverified` with no reason tag (the viewer shows "no reason (was inconclusive)", tallies
count it under `none`), until a newer record for the version reclassifies it. The commands
refuse to write `inconclusive`, and refuse `unverified` without a reason, so a reasonless
`unverified` is always a legacy one. The proposed reclassification of the current
`inconclusive` verdicts, and of `malicious` verdicts whose only harm is a channel follow, is
reviewed by the owner before it is applied; each new record's note starts "Reclassified
(owner, 2026-11-08):" followed by the old note.

**Evaluation.** The live matrices count `malicious` and `unwanted` as positives in the headline
("flag-worthy") matrix, show a strict malicious-only matrix beside it, and leave `unverified`
out of both, with best- and worst-case bounds ([0019](0019-live-evaluation.md), addendum).

## Addendum 2026-11-08 (later): AI-agent skills, hooks and settings

- **The owner, 2026-11-08:** a package built for AI-assisted development that installs its own
  skills, hooks or agent settings (`~/.claude/skills`, `~/.claude/settings.json` hooks such as
  `UserPromptSubmit`, `.agents/`, `AGENTS.md`) is **benign**: "developers are aware when
  installing ai specific packages". This matches the explained-install shape "agent-skill
  copier" approved for after the freeze (`docs/proposals/precision-round2.md`).
- Behaviour still decides: a hook or skill that sends data off the machine, fetches and runs
  code, or plants instructions that work against the user (e.g. telling the agent to hide
  activity, exfiltrate, or disable safeguards) is judged on that, as anywhere else.

## Addendum 2026-11-10: re-reviews under the 2026-11-09 rulings, and two new calls

- **Credential upload from a CLI command is malicious (the owner, 2026-11-10).** A command the
  user runs that covertly sends secret configuration (keys, salts, logins) or files, with
  `username@hostname`, to a chat or bot the vendor hard-coded is credential exfiltration, even
  though nothing happens at install: `esoftplay@0.0.269-beta96052d3` (`esp bcl`/`bcd` upload
  `config.live.json` to a hard-coded Telegram bot; `esp p`/`esp b` send host, user, Expo
  account). The other two live betas carry no hard-coded token (the bot is the user's own) and
  stay benign. This also squares the live labels with the DataDog labels of older esoftplay
  versions.
- **A lone persistent user variable is benign (the owner, 2026-11-10).** `@hsusulist/luc@0.3.1`
  runs its PowerShell installer with `-NoPath` and only sets `LUC_PATH`; no PATH or shell rc
  change. The owner added that scripts an install hook triggers must be analysed (obfuscation in
  a `.ps1` should be flagged): built the same day (`npm.install-script-loader`,
  `npm.install-script-exfil`, scripts started by scripts; see the round-4 G proposal).
- **Re-reviews.** The new `npm.install-persistence` rule fired on benign verdicts recorded before
  the 2026-11-09 rulings; reviewers re-read the code. 13 of 20 moved benign → unwanted
  (`pantheon-opencode` ×3, `triflux` ×2, `@muggleai/works`, `novahiz`, `warp-agent-mcp`,
  `@kopplin-co/claude-web-design-skill`, `@civitas-cerebrum/achilles` (global only),
  `@ohos-ports/gifsicle` (`brew install`), `@shanks-dev/baileys` and `shanks-dev` (media
  tagging)); 7 stayed (writes only behind a command the user runs: `0xray wear`, `install-skill`,
  `init`, `zn hooks install`). `stock-analyzer-skill@1.30.0` (runs `claude plugins marketplace
  add` on install) moved to unwanted. `@lunabotv6/luna-baileys@8.1.0` stays unverified: media
  tagging confirmed, but it depends on the obfuscated `@itsliaaa/starforge`, like `hyrox@0.1.6`.
- **Patching another program is unwanted (the owner, 2026-11-10).** An install hook that
  silently patches another installed program's or package's files outside the project is
  **unwanted**; harmful patches stay malicious. This makes the reviewers' precedent a ruling
  (`blue-crab`, `dsh-theme-mls-desktop@0.6.13` rewriting DeepSeek Harness Desktop's `app.asar`,
  `dsh-harmonyos@0.16.1` rewriting a DSH plugin under `~/.dsh/profiles` to use DeepSeek's vision
  model).
- **Silent system setting changes are unwanted (the owner, 2026-11-10):**
  `@frontendxlab/opencode-computer-use@0.1.5` enables GNOME toolkit accessibility with
  `gsettings` on every install.
- **Refreshing a setup the user agreed to is benign (the owner, 2026-11-10):** `memtrace`,
  `wyrm-mcp`, `gkg-cli` re-apply hooks or skills a setup command installed earlier, and write
  nothing if it never ran.
- **Second re-review** (65 benign versions where `npm.install-persistence` fires, 57 read): 10 more
  benign → unwanted (`openyida` ×5, `@follenfang/fupload`, `smithue-cli` (global only),
  `@geekbeer/minion` (Windows user PATH), `dsh-harmonyos`, `@frontendxlab/opencode-computer-use`);
  47 stay benign (printed advice, read-only checks, installers that ask first, code that never
  runs at install: the rule's false-fire shapes, handed to round 5).
- **Global git configuration counts as a user setting (integrator's reading of the ruling above,
  2026-11-10; pending the owner).** An install hook that runs `git config --global
  core.hooksPath` makes every repository on the machine run the package's hooks: a silent,
  user-wide setting change. `signoff-cli@4.2.0` was recorded unwanted, and a re-review moved six
  benign verdicts of 2026-11-08 to unwanted for the same code (`signoff-cli` 4.0.0, 4.1.2,
  4.1.9; `dsh-signoff` 3.10.0, 3.12.0, 3.13.0: postinstall `ensure --from-install` →
  `lib/bootstrap.js` `ensureGlobal`, on every install, the README's opt-out not checked on that
  path). Local `git config core.hooksPath` in the installing project stays benign
  (`@acertijosapps/android-viewer`, `@brighterly/lib-assessment`, `@xingwangzhe/stalux`,
  `clavarium`, `@arifbiswas/git-pre-push`). Main reports five of the six only through the
  install rules and no longer reports `signoff-cli@4.1.9` (round 4's `install-script-changed`
  v5); a rescue signal for global git configuration is being built before the freeze.
  **Confirmed by the owner (2026-11-10, later):** global git configuration at install is
  unwanted. Settings a development tool commonly makes for itself (editor, pager, diff and
  merge tools, signing program, proxies, aliases, `safe.directory`) are benign; what counts is
  hooks (`core.hooksPath`, `init.templateDir`), `core.sshCommand`, credential helpers, URL
  rewrites and `include` (`npm.install-persistence` v4 `git-config` form).
- **Install-time downloads of code are unwanted (the owner, 2026-11-10; strict, final).** Install
  code (a hook or a file it runs, not a command the user starts) that fetches files, scripts or
  binaries that are not in the registry tarball is **unwanted**, whoever hosts them: a vendor's
  `curl ... | bash` installer (`boldcreate-acp@0.1.0`), third-party runtimes, browsers, models,
  and also **the package's own binary from its own GitHub release or CDN** (cargo-dist,
  goreleaser and similar postinstall downloaders), checksum or not. Reason: the payload is
  outside the tarball, so neither the static rules nor the tarball-vs-repo comparison see it; a
  checksum shipped in the same tarball only proves it matches what the publisher intended, and a
  hijacked account or release can change both. Benign alternatives stay benign: the binary in
  the tarball, or in the package's own platform packages on the npm registry
  (`optionalDependencies`, esbuild-style, including a fallback that fetches that platform
  package's tarball from the registry), where it is immutable and scannable. A declared
  dependency's own install script that npm runs by itself is that dependency's business. The
  owner first chose "third-party only" (own-binary downloads benign, agent H's S6 explanation),
  then, the same day, the strict reading after weighing the risk; the confusion matrix is also
  shown under the narrower reading as a sensitivity row. Note prefixes: "Owner ruling
  2026-11-10 (third-party download at install = unwanted):" (with "; wrapper" for packages
  whose purpose is installing another project's tool) and "Owner ruling 2026-11-10 (own-binary
  download at install = unwanted, strict):".
- **An install hook that runs a Windows executable is unwanted at best (the owner, 2026-11-10:
  "malicious at worst, and unwanted at best").** A bundled or downloaded installer run at
  `npm install` (`@pro-gram/flux` 1.5.0/1.6.1 and `@pro-gram/drumbuddy` 1.1.1/1.4.1 run
  `DrumBuddy-Setup.exe`, a silent per-user desktop-app install with shortcuts and an HKCU
  Uninstall entry; `rvm-windows` 1.1.1/1.1.2-develop.1 run `rvm-windows-setup.exe`;
  `filipt@0.4.0` launches a bundled `hello.exe`) is **unwanted**, and malicious when analysis
  shows harm. Flux's installer was analysed statically (never run): a .NET installer running as
  the user, every string literal in the shipped C# source, an app with no network classes, and
  an `ffmpeg.exe` byte-identical to the official gyan.dev 9.0.2 build, so unwanted, not
  malicious. Checking the package's own CLI with `--version` is not covered.
- **Rulings of 2026-11-11 (the owner):**
  - **Transparent wrapper packages are benign** ("probably benign"): a package that openly
    exists to install a named tool and, at install, downloads only that tool from its official
    release host, doing nothing else. Rebranded resellers (`usingopen` selling oh-my-pi) and
    silent fallbacks to another project's binaries are not transparent and stay unwanted. Note
    prefix "Owner ruling 2026-11-11 (transparent wrapper = benign):". This is the one exception
    to the strict download rule above; the download rule still reports them (false positives
    the reviewer clears).
  - **A background process an install hook starts and leaves running is unwanted**
    (`great-cto` 3.75.6/3.76.1: a detached local board server on 127.0.0.1:3141 that outlives
    the install), whether or not it persists across reboots.
  - **Shell completion files are benign** when they edit no rc file and no PATH and need the
    user to source them, or are loaded by the shell only on demand
    (`@ohos-ports/jackwener-opencli`).
  - **An MCP server's tool output that steers the user's own agent through the package's own
    flow is benign** (`@rel-time/mcp-server`'s payment-invoice instructions): it acts on the
    user's side, at the user's request; harmful or covert instructions stay covered by the
    2026-11-08 agent rulings.
  - **A data-only download at install is benign** (later the same day): an install hook that
    fetches data which is validated and never executed (`free-email-domains@1.16.1` refreshes
    its disposable-domain list from six hosts, each entry checked against a strict hostname
    pattern) is not "code" under the strict download rule. Note prefix "Owner ruling 2026-11-11
    (data-only download at install = benign):". `npm.install-download` still reports it; a
    data-only exception is post-freeze work.
  - **The registry used as hidden hosting is unwanted**, even when nothing runs for the
    installer: `lumen-lib@2.1.8` (a fake utility library whose disguised SVG and asset folder
    carry a content-filter-evasion web proxy served through jsDelivr/unpkg, with four sibling
    fakes) is deceptive but harms no installer.
- **Command expansion in `binding.gyp` that enumerates the user's environment stays reported
  (the owner, 2026-11-10).** `<!(echo $HOME)` matches enumeration (`@ohos-ports/distringuish`;
  agent I's `npm.install-build-tool` v4 keeps it).

## Addendum 2026-11-09: user-wide agent installs are unwanted

- **The owner, 2026-11-09**, narrowing the addendum above: install code that silently writes a
  package's skills (and, by the same reasoning, hooks, agent settings or MCP registrations)
  into **user-wide** agent locations (`~/.claude/`, `~/.agents/`, `~/.codex/`, `~/.cursor/`,
  `~/.gemini/`, ...), so that every agent session in every project loads them, is
  **unwanted**: intrusive and persistent beyond the project the user installed into. Code
  obfuscation that hides it makes it covert as well ("the obfuscation is a big part too",
  `sino-bc-cli`, 20 versions decoded offline: same program, no network at install, recorded
  unwanted).
- Still **benign**: writes into the project (`INIT_CWD`, the project's `.claude/`, `AGENTS.md`),
  and user-wide writes the user starts themselves (an `init`/`install-skills` command run by
  hand, not by an install hook).
- Still **malicious**, on behaviour: a skill or hook that sends data off the machine, fetches and
  runs code, or plants instructions against the user, wherever it is written.
- Consequence for the rules: `npm.install-explained`'s S3 shape (agent-skill copier) must not
  explain user-wide copies, since those are now positives.

## Addendum 2026-11-09 (later): prompt telemetry, and the user-wide rule stays a note

- **Prompt telemetry is unwanted (the owner, 2026-11-09).** An install hook that silently sets
  user-wide coding-agent telemetry, so that every later session sends the user's prompts (and
  responses, tool details) to the vendor's own service, is **unwanted**, not malicious: vendor
  telemetry plus a user-wide settings write, with no credential harvesting
  (`@ciandt-flow/flow-ai-obs`, 7 versions, `~/.claude/settings.json` `env` pointing OTEL at
  `flow.ciandt.com`; `toga-ai` 1.0.1318/1319, `otel.togaiq.com` with a hardcoded bearer token).
  Sending them anywhere but the vendor's own service stays malicious.
- **`npm.install-agent-user-wide` stays INFO, weight 0 (the owner, 2026-11-09).** Measured on
  today's 9 runs: it fired on 67 versions (~58 distinct); all 58 now have a verdict: 30
  unwanted, 25 benign, 3 unverified (55% of the decided ones), and as a scoring rule it would
  add dozens of reports a day, far over the owner's bar of ~5 benign a day. The user-wide
  installers it does not report are counted as false negatives in the live matrices, and the
  write-up says so. Narrowing ideas for after the freeze (home reference and agent directory in
  one path expression; no comments or help text; skip writes only reachable behind an
  interactive prompt) are in the devlog.
- **Interactive opt-in is benign (the owner, 2026-11-09).** A global install that asks which
  agents to configure, and writes only what the user picks, is a write the user starts
  (`common-context-mcp`, `@gleapai/kai-bridge`; notes start "Interactive opt-in:").
- **Global-install-only user-wide writes are unwanted (the owner, 2026-11-09):** "user-wide agent
  file interactions should be unwanted", whether on every install or only on `npm -g` (notes
  start "Owner ruling 2026-11-09 (global install only):").
- **Shell rc edits are unwanted (the owner, 2026-11-09).** An install hook that silently edits the
  user's shell startup files (`~/.zshrc`, `~/.bashrc`, the shell profile: completion blocks,
  PATH lines, env lines) is **unwanted** (`@xfe-repo/cli@2.2.5`; six earlier benign verdicts
  re-recorded: `@phnx-labs/agents-cli@1.23.46`, `coding-friend-cli` 1.43.0/1.43.1,
  `rl-workspaces@0.7.0` (global only), `termux-dsh@0.2.2-rc.1-tdsh.1`, `tfv@6.2.0`). An edit
  the user switches on (`repilot`: only with `REPOPILOT_ACCEPT_EULA=1`) stays benign.
- **Persistent PATH changes are unwanted too (the owner, 2026-11-09),** on any platform,
  including hooks that add npm's own global bin directory to the Windows user PATH:
  `@visual-z/xeno@0.13.2`, `coolcanvas@1.0.0-beta.8` (global only), `@ziniao-open/cli`
  0.1.0-beta.170/175 and 1.3.0 (its setup script registers the CLI directory in the user's
  shell or user PATH on every install).
- **System package installs are unwanted (the owner, 2026-11-09).** An install hook that installs
  system packages (`sudo apt-get install -y`, `dnf`, `brew`, `winget`, `choco`) is **unwanted**,
  even when what it installs is harmless (git, cmake): the mechanism, root-level changes during
  `npm install`, which often runs unattended and, in CI and containers, with passwordless sudo,
  is what could be abused. The usual practice is to fail with a message naming what to install,
  which stays benign, as does an install the user is asked about first (`@cocreate/cli`).
  Recorded: `streamgrab@1.3.4`, `@ohos-ports/zerox@1.1.20-beta.0` (`sudo -n` where passwordless),
  `gebangautoupload@1.1.4`.
- **Baileys media tagging is unwanted (the owner, 2026-11-09).** A fork that attaches the author's
  channel (newsletter) annotation to messages the user sends, without following anything, is
  covert channel promotion under the Baileys policy (`@codexverified/baileys` 2.19.18/2.19.19).

## Addendum 2026-11-08 (later): the Baileys signatures are retired

The Stage 2 signatures KX-0008, KX-0009 and KX-0011 ("known malware family") were taken from
Baileys forks that follow WhatsApp channels, which this decision's addenda now rule *unwanted*.
`static.channel-follow` says exactly that (MEDIUM, "unwanted, not by itself a sign of malware")
and matched every version they matched (16 of 16 corpus and verdict tarballs, 2 of 2 of 35,544
live tarballs, 1 of 1 in `vm-day1`), so they were retired rather than relabelled (signatures v3,
`rules/signatures.py` `RETIRED`; [static.md](../stages/static.md)). No fork reported before
stops being reported; its severity drops from HIGH to MEDIUM.
