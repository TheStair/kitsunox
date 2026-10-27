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
| 2 | **Obfuscation** | High-entropy strings; large base64/hex blobs; minified or packed code in a file that was previously readable; `eval`, `new Function`, `vm.runIn*`, dynamic `require(expr)`; string-array/rotate patterns typical of javascript-obfuscator | A, B | S2 (entropy, blobs, line-length), S3 (dynamic-code calls) |
| 3 | **New capabilities** | Imports of `http`, `https`, `net`, `dgram`, `dns`, `tls`, global `fetch`, `child_process`, `worker_threads`; filesystem reads of `~/.npmrc`, `~/.ssh`, `~/.aws`, `.env`, browser profiles, crypto wallets; bulk `process.env` access | A, B | S3 (capability delta vs. prior version); S2 regex as the cheap pre-filter |
| 4 | **Exfiltration endpoints** | Hardcoded IPs and URLs (esp. new in this version); Discord/Slack/Telegram webhooks; pastebins; request-capture services; `*.oast.*`/interactsh domains; DNS-tunnelling shapes (long hex/base32 labels) | A, B | S2 (extraction), S4 (domain reputation / allow-list) |
| 5 | **Dependency changes** | New dependency added in a patch release; new dependency that is itself days old, unpopular, or has an install hook; name close to a popular package (typosquat); unscoped name that matches a known internal/scoped name (dependency confusion); `git+`/URL/tarball dependency specifiers | A, B | S1 (manifest diff, specifier type), S4 (recursive lookup of the new dep) |
| 6 | **Maintainer and account signals** | Publisher (`_npmUser`) not seen on earlier versions; maintainer added just before publish; publish from a dormant package (long gap); unusual version jump (e.g. 1.2.3 → 9.9.9 or a version above every existing one in a confusion attack); many packages published by one account in a short burst | A (B for bursts) | S1 |
| 7 | **Publish-method change** | Earlier versions were published by trusted publishing (OIDC, `_npmUser.trustedPublisher`) with provenance attestations, but this one was published manually with a token and has no attestation; staged-publish approver missing where it was present before; `gitHead` missing where it was present before | A | S1. Cheap and likely strong. Needs evaluation. |
| 8 | **Registry vs. repo mismatch** | Files in the tarball absent from the repo at the tagged commit / `gitHead`; files present in both with different content; `package.json` scripts in the tarball that differ from the repo's | A | S4 (tarball-vs-repo diff). First-class signal; see [open questions](roadmap.md#open-decisions). |
| 9 | **Self-propagation (worm)** | Reads npm tokens (`.npmrc`, `NPM_TOKEN`), calls the registry publish API or runs `npm publish`, enumerates the account's packages, bumps versions and re-publishes; writes CI workflow files into repos | A | S3 (capability combo: token read + registry publish), S2 (strings) |
| 10 | **Known-malicious match** | Package/version listed in OSV `MAL-` records or GitHub malware advisories; file hash matches a known sample | A, B | S4 (lookup); also used as evaluation labels |
| 11 | **Runtime behavior** | Network connections, process spawns, sensitive file reads during install | A, B | S5 sandbox (later) |

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
