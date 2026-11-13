# Threat model

> **Status:** draft (2026-10-27). Stage and rule coverage below is *planned*; nothing is
> implemented yet. Update this table as rules land and as evaluation shows what actually works.

## What we defend

A reviewer (or a team that consumes npm packages) wants to know, soon after a release is
published, whether that release is likely to be malicious. Kitsunox doesn't block installs. It
triages recent registry changes and puts the suspicious ones in front of a human with evidence.

## Two attack shapes

Nearly every npm supply chain attack falls into one of two shapes, and they need different
detection strategies.

| | **A. Compromised existing package** | **B. New malicious package** |
|---|---|---|
| Example pattern | Maintainer account or CI pipeline taken over, a malicious version published under a trusted name | Typosquat, dependency-confusion name, "slopsquat" (name an LLM hallucinates), or a fake utility |
| Baseline available | Yes: previous versions, maintainers, publish method, repo | No: little or no history |
| Main signal | **Delta** between the new version and the previous one | **Absolute** properties plus name similarity to popular packages |
| Blast radius | High (existing dependents pull it in automatically) | Usually low until someone installs it |
| Volume | Rare | Most of the malicious packages in public datasets |

The pipeline handles both, but they flow differently. Shape A is diffed against the prior version.
Shape B is a "diff against nothing", plus name and account checks. Evaluation reports recall
separately for each shape, because a dataset dominated by shape B can hide poor shape-A recall
(see [evaluation.md](evaluation.md)).

## Attacker capabilities assumed

- Can publish any package name that's free, and any version of a package whose maintainer
  account, token, or CI publish workflow they control.
- Can publish code that never appears in the git repository (direct registry publish, or a
  compromised build step).
- Can produce **valid provenance**. A hijacked CI workflow that uses trusted publishing yields a
  legitimate Sigstore attestation; provenance proves *which pipeline* built the package, not that
  the code is benign. Provenance is therefore a *baseline* signal (did it change?), never an
  all-clear.
- Knows common static detections and may obfuscate, split payloads, fetch a second stage at
  runtime, or delay execution.

Out of scope for now: attacks on npm infrastructure itself, malicious code in the *build
toolchain* that leaves no trace in the published artifact, and compromised packages that are
benign at install time and only activate months later from a remote trigger. We may still catch
the last one through capability deltas.

## Attack patterns and planned coverage

Stages: **S1** metadata triage, **S2** static diff heuristics, **S3** AST/capability analysis,
**S4** correlation & enrichment, **S5** sandbox (later). See [architecture.md](architecture.md).

| # | Pattern | Indicators | Shape | Planned coverage |
|---|---|---|---|---|
| 1 | **Install-time hooks** | New or changed `preinstall` / `install` / `postinstall` / `prepare` script; `hasInstallScript` flips to true; hook runs a file that's new in this version; `binding.gyp` added (implicit install) | A, B | S1 (manifest diff), S3 (what the hook's file does) |
| 2 | **Obfuscation** | High-entropy strings; large base64/hex blobs; minified or packed code in a file that was previously readable; `eval`, `new Function` (also reached as `x.constructor.constructor`), `vm.runIn*`, dynamic `require(expr)`; string-array/rotate patterns typical of javascript-obfuscator | A, B | S2 (entropy, blobs, line-length), S3 (dynamic-code calls; the Function constructor reached through `constructor`, `globalThis.constructor.constructor`: `code.function-constructor`); S2 `static.decoded-function` (2026-11-13, MEDIUM): a small file that decodes text and hands a `Function(...)` it compiles `require` (`mock-data-sdk@1.0.1`) |
| 3 | **New capabilities** | Imports of `http`, `https`, `net`, `dgram`, `dns`, `tls`, global `fetch`, `child_process`, `worker_threads`; filesystem reads of `~/.npmrc`, `~/.ssh`, `~/.aws`, `.env`, browser profiles, crypto wallets; bulk `process.env` access | A, B | S3 (capability delta vs. prior version); S2 regex as the cheap pre-filter |
| 4 | **Exfiltration endpoints** | Hardcoded IPs and URLs (esp. new in this version); Discord/Slack/Telegram webhooks; pastebins; request-capture services; `*.oast.*`/interactsh domains; DNS-tunnelling shapes (long hex/base32 labels); a probe's private callback canary (`<random id>.ssrf-check.<company>`) called from a tiny package's loaded or installed code | A, B | S2 (extraction; `npm.canary-callback`, 2026-11-13, MEDIUM: a host whose first label is a 20-64 character letter-and-digit id, in a package of at most 6 files, from code that loading or installing runs and that uses the network; see [stages/static.md](stages/static.md#callback-canaries-npmcanary-callback-2026-11-13)), S4 (domain reputation / allow-list); S2 `static.host-ip-identity` (2026-11-13, MEDIUM): a bare IP with no scheme in a JSON setting, joined by code into a URL that carries the user's name (`@atedone/workspace-context` 0.0.23-0.0.25) |
| 5 | **Dependency changes** | New dependency added in a patch release; new dependency that is itself days old, unpopular, or has an install hook; new dependency that doesn't exist on the registry yet (the payload is published after its wrapper, or a private name anyone may register); name close to a popular package (typosquat); unscoped name that matches a known internal/scoped name (dependency confusion); `git+`/URL/tarball dependency specifiers | A, B | S1 (manifest diff, specifier type), S4 (lookup of the new dep: `npm.dependency.fresh-foreign` days old from unrelated accounts, `npm.dependency.missing` 404 under an unrelated name, `name-embeds-popular`, `known-malware`; see [stages/correlate.md](stages/correlate.md#missing-dependencies-npmdependencymissing-stage-version-12)); since 2026-11-13 a missing dependency is carried to follow-ons that still declare it (S4 `correlate.follow-on`). A payload the code `require`s without declaring it: S3 `npm.undeclared-package` (v2, INFO) names what loading the package loads at module load, and S4 `npm.undeclared.missing` (MEDIUM) reports it when the registry lacks the name (~0.8 benign a day; see [stages/correlate.md](stages/correlate.md#undeclared-and-missing-npmundeclaredmissing-stage-version-15)) |
| 5b | **Git dependency install code** | A dependency from a git repository (`github:o/r`, `o/r#ref`, `git+https://...`, an archive URL) whose `preinstall` / `install` / `postinstall`, or `prepare` (npm runs it, and the root lifecycle of `npm install` in the clone, for git dependencies) downloads, decrypts or runs code: the release's own tarball is clean (`web3-mev-error-decoder@0.1.0` → `github:outgoingyang/multicall-error-decoder`, 2026-11-09); a commit pushed to any fork is served through the parent repository's URLs (`github:antvis/G2#1916faa…`) | A, B | S1 `npm.dependency.non-registry` (the specifier); S4 `npm.git-dependency` (2026-11-12, decision 0020): the GitHub dependency's install code is read with the S1-S3 install rules at the commit its reference resolves to, findings scored as the release's own under `dep:<name>@<commit12>/` ([stages/correlate.md](stages/correlate.md#git-dependencies-npmgit-dependency-stage-version-22)). Since 2026-11-12 (owner) unchanged GitHub specs are read too: a branch reference installs new code without the spec changing. Not covered: other git hosts, GitHub release assets, tarballs on other hosts (noted, not fetched), the dependency's own dependencies |
| 6 | **Maintainer and account signals** | Publisher (`_npmUser`) not seen on earlier versions; maintainer added just before publish; publish from a dormant package (long gap); unusual version jump (e.g. 1.2.3 → 9.9.9 or a version above every existing one in a confusion attack); many packages published by one account in a short burst | A (B for bursts) | S1 |
| 7 | **Publish-method change** | Earlier versions were published by trusted publishing (OIDC, `_npmUser.trustedPublisher`) with provenance attestations, but this one was published manually with a token and has no attestation; staged-publish approver missing where it was present before; `gitHead` missing where it was present before | A | S1. Cheap and likely strong. Needs evaluation. |
| 8 | **Registry vs. repo mismatch** | Files in the tarball absent from the repo at the tagged commit / `gitHead`; files present in both with different content; `package.json` scripts in the tarball that differ from the repo's | A | S4 (tarball-vs-repo diff). First-class signal; see [open questions](roadmap.md#open-decisions). |
| 9 | **Self-propagation (worm)** | Reads npm tokens (`.npmrc`, `NPM_TOKEN`), calls the registry publish API or runs `npm publish`, enumerates the account's packages, bumps versions and re-publishes; writes CI workflow files into repos | A (B for self-publishing spam) | S3 `npm.publish-at-load` (2026-11-09, MEDIUM): a command that runs at load in the loaded files, or in the install code, publishes to npm (extractor v9; the `*_z3n` spam's `main`, the `@emilgroup/*` worm's `postinstall`; [stages/ast.md](stages/ast.md#self-publishing-at-load-or-install-npmpublish-at-load-extractor-v9)); S2 `static.npm-publish` (strings, LOW). Not covered: a publish from functions the parse doesn't see run (Shai-Hulud's minified `bundle.js`, reported by the install rules), `libnpmpublish` or a registry `PUT` (none seen at load or install in any set), CI workflow writes |
| 9b | **Archive-level evasion** | Entries hidden after an end-of-archive marker or invalid tar header (parser differential); trailing data; symlinks or hardlinks in the tarball; duplicate paths | A, B | Extraction (`util/archive.py`) reads leniently and records `anomalies`/`skipped`/`duplicates`; S2 rule to score them (planned) |
| 10 | **Known-malicious match** | Package/version listed in OSV `MAL-` records or GitHub malware advisories; file hash matches a known sample | A, B | S4 (lookup); also used as evaluation labels |
| 11 | **Runtime behavior** | Network connections, process spawns, sensitive file reads during install | A, B | S5 sandbox (later) |
| 12 | **AI-agent configuration** | Install code that copies skills, instruction files (`SKILL.md`, `AGENTS.md`, `.cursor/rules`), settings hooks (`UserPromptSubmit`, `PreToolUse`) or MCP servers into an agent's directory (`~/.claude`, `.agents`, `.codex`): a hook runs a command on every prompt (persistent code execution), an allow-list or bypass mode lets the agent act without asking, a remote MCP server or planted instructions steer it (hide activity, ignore earlier instructions, send `~/.ssh` / `.env` away; the 2025 nx compromise drove users' AI CLIs with permission-bypass flags). Packages built for AI-assisted development do this benignly (owner ruling, decision 0015 addendum 2026-11-08) | A, B | S3: the copier itself is install code (`npm.install-script-*`); `npm.install-explained` S3 stays quiet only when hook commands are a constant `echo` or a plain shipped script, nothing widens permissions and no instruction works against the user; `agent.hostile-instructions` (MEDIUM) reports planted instructions ([stages/ast.md](stages/ast.md#explained-install-s1-s3-and-agent-configuration)). Not covered: agent configuration written outside install code, or by obfuscated or downloaded code (other rules) |
| 13 | **Account abuse by a library (WhatsApp channel hijack)** | A Baileys fork that makes the user's WhatsApp account follow or mute channels the author chose: FOLLOW queries on hard-coded, base64- or char-code-hidden `...@newsletter` ids or `0029V...` invite codes, or a fetched list, at connect and not opt-in | B (forks) | S2 `static.channel-follow` (2026-11-08, MEDIUM, "unwanted" per decision 0015's addenda) and the family signatures KX-0008/0009/0011; S2 `static.channel-tagging` (2026-11-09, MEDIUM, unwanted): a fork that writes its channel into the forwarded-newsletter context of the user's messages (`@codexverified/baileys`) |
| 14 | **Persistence in shell start-up files** | Code or an install hook that writes `~/.bashrc`, `~/.zshrc`, `~/.profile`, fish's `config.fish` or the PowerShell profile; a written line that sources a file under `$HOME`, or a prompt that runs a command (`setopt prompt_subst`, `PROMPT="$(...)"`) | A, B | S2 `static.shell-startup` (2026-11-08): MEDIUM for an install hook that appends to one and for injected `source`/prompt lines; LOW evidence for other writes (CLIs add PATH and completion lines the same way). Live: `@atedone/workspace-context`; v2 (2026-11-13) keeps the injected lines MEDIUM on every release that changes the file and carries them to unchanged follow-ons (S4). S3 `npm.install-persistence` (2026-11-09, MEDIUM): install code that writes one, on every version since v7 (row 16) |
| 15 | **Load-time payload (no install hook)** | The entry point (`main`, `exports`), or a file it loads, does the harm when the package is `require`d or imported: host fingerprint (`os.hostname()`, `os.userInfo()`, `os.networkInterfaces()`, `os.homedir()`) sent away at module load (the dependency-confusion probe moved out of `preinstall`), an import-time implant that writes and spawns a helper (`archetype-index-sdk@1.0.0`), shell start-up edits (`@atedone/workspace-context`) | B (A when injected) | S2 content rules on the loaded files (`static.obfuscated`, `exfil-endpoint`, `encoded-url`, `shell-startup`, ...); S3 `npm.load-fingerprint` (2026-11-09, MEDIUM: two identity reads that run at load and network in the loaded files; extractor v8, [stages/ast.md](stages/ast.md#load-time-payloads-npmload-fingerprint-extractor-v8)). Not covered: a command, a file write or a detached spawn at load alone (measured, too noisy), reads across files or through computed names, payloads with no JavaScript entry |
| 16 | **Intrusive install beyond the project** | Install code (or a hook's command line) that writes an AI agent's configuration user-wide (`~/.claude`, `~/.codex`, `~/.cursor`, `~/.agents`, Claude Desktop's config), edits shell start-up files, changes PATH persistently (`SetEnvironmentVariable("Path", ..., "User")`, `setx PATH`) or installs system packages (`sudo apt-get install -y`, `brew`, `winget`, `choco`). The owner rules these unwanted (decision 0015, addenda of 2026-11-09): `npm install` runs unattended, in CI often with passwordless sudo | A, B | S3 `npm.install-persistence` (2026-11-09, MEDIUM; new or changed install code, comments and messages aside); `npm.install-agent-user-wide` (INFO) is the broad note. Not seen: persistence done by a script or binary the install code spawns (`tmailcli`, `@ornexus/neocortex`) |
| 17 | **Opaque native code loaded silently** | A bundled `.node` addon (a shared library: loading it runs its initialiser) required by the entry or install code inside a `try` with an empty `catch`, in a package that neither builds addons (`binding.gyp`) nor ships them in a prebuilt layout (`prebuilds/`, `node-pre-gyp`'s `binary`) | B | S2 `static.silent-native-load` (2026-11-13, MEDIUM; `strutil-helpers-core@1.0.1`). What the addon does is only visible to S5 |
| 18 | **Registry as web hosting** | The package is a web page (`main` is an HTML file, a handful of files) served by npm's CDNs (jsDelivr, unpkg): a fake browser check that fetches an encrypted value, decrypts it (`crypto.subtle`, CryptoJS) and redirects the visitor; the harm is to whoever opens the page, not the installer | B | S2 `static.html-redirector` (2026-11-13, MEDIUM; `bfvkjmeikpwhqxc`, `@isla5mic/aasics`) |

### Signals that are *not* evidence on their own

These fire often on benign releases and must only contribute weight in combination (S4 scoring):
minified code in `dist/` that was already minified in the previous version; `child_process` in
build tools and CLIs; `fetch` in HTTP client libraries; `postinstall` in packages with native
bindings (`node-gyp`, `prebuild-install`). The score rules must say what they discount and why.

## Assumptions to validate early

1. Publish-method changes (#7) are rare among benign releases. If true, this may be the
   highest-precision cheap signal for shape A.
2. Capability *deltas* (#3) are far less noisy than absolute capabilities.
3. Most build output that legitimately differs between tarball and repo lives in a small set of
   predictable places (`dist/`, `lib/`, `build/`, `*.d.ts`, `*.min.js`), so #8 can be made
   precise with a short allow-list.

Each assumption gets a measurement in [evaluation.md](evaluation.md) before it's relied on.
