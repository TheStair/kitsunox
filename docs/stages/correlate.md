# Stage 4: Correlation, repository comparison and score

> **Status:** implemented 2026-10-28 (`stages/correlate.py`, `stages/repo.py`,
> `githost/github.py`; npm wiring in `stages/review.py`). It runs in `collect` after Stage 3.
> Design: [decision 0010](../decisions/0010-stage4-correlation-and-repo-comparison.md).

## Purpose

Stages 1-3 each judge a version on their own evidence. Stage 4 puts the evidence together and
decides what a person should review:

- **Combines** weak signals that mean little alone (a dormant package revived; a dependency
  added) into named combination findings.
- **Looks up** outside knowledge: does the release depend on a package OSV calls malware?
- **Compares** the release with its source repository at the commit it was built from. Code on
  npm that isn't in git is the mark of a publish with a stolen token, whatever the code does.
- **Scores** each version and orders the review queue by score.

## Usage

```sh
uv run kitsunox correlate <run_id>                          # after `ast`; writes correlate.jsonl
uv run kitsunox eval run <dataset> --predictor pipeline+4   # end to end: what would be reported
```

## Input and output

- **Input:** every version Stage 1 triaged (`triage.jsonl`), with Stages 2-3's findings for
  those routed to them (`ast.jsonl`). Unrouted versions carry only Stage 1 findings, but those
  can still combine.
- **Fetches:** for the versions `wants_repo` picks (any stage flagged it, or it updates a
  watched package): the repository's refs and one source archive per commit. Recorded in
  `correlate-snapshot.json` and kept by retention like Stage 2's tarballs. The release's own
  files come from the blob store (Stage 2 fetched them).
- **Output:** `correlate.jsonl` (one `Candidate` per line, in triage order, with Stage 4's
  findings and a `StageDecision`) and `correlate.json` (the label set, rule fingerprint and
  report score used).

## Decision and score

- **Report** a version when any finding is MEDIUM or above, or its score reaches
  `REPORT_SCORE` (6). The first keeps recall at least that of Stages 1-3 together; the second
  lets LOW findings add up.
- **Score:** the sum over the rules that fired, each counted once at its largest weight
  (Stage 2 reports a finding per matching file), INFO excluded. The CLI lists reported
  versions by score.

## Repository comparison (`stages/repo.py`)

1. **Repository and directory:** the normalised `repository` URL (GitHub only) and
   `repository.directory` for monorepos (`ecosystems/npm/repo.py`). When a release doesn't
   set `repository.directory`, the package is the repository's `package.json` with the
   release's `name`: the root's if it matches, else the shallowest (outside `node_modules/`).
   If none matches, the root manifest still counts unless it is a workspace (`workspaces`, or
   `private: true`): forks and renamed packages keep the old name. Otherwise there is no
   comparison. (Until `repo.compared` v2, such releases were
   compared with the monorepo's root manifest, which made Playwright's, `workerd`'s and taro's
   install hooks look absent from git; see the devlog, 2026-10-29.)
2. **Commit:** `gitHead` if recorded; otherwise a release tag: `v1.2.3`, `1.2.3`,
   `name@1.2.3`, `short@1.2.3`, `name@v1.2.3`, `short-v1.2.3`, `short@v1.2.3`. Tags come from the
   smart-HTTP ref advertisement (`<repo>.git/info/refs?service=git-upload-pack`), the same data
   `git ls-remote` reads, with annotated tags peeled. No GitHub API, no token.
3. **Contents:** `codeload.github.com/<repo>/tar.gz/<commit>`, through the immutable index
   (once per commit, across runs and across a monorepo's packages), extracted in memory with
   only the package's directory kept. Archives over 128 MB compressed are not compared.
4. **Manifest:** the release's `package.json` against the repository's: install hooks it has
   that the repository's doesn't (or has differently), and runtime dependencies the
   repository's manifest doesn't name in any section (names only: tools rewrite specs).
   Comparable `day1` updates: hooks 51 of 55 malicious, 0 of 116 benign; dependencies 7 of 55
   malicious, 2 of 116 benign (before `repo.compared` v2: hooks 53/57 and 0/121, dependencies
   30/57 and 14/121, inflated by root-manifest comparisons).
5. **Compare** the release's JavaScript/TypeScript files (line endings normalised):
   - *differing:* in the repository at the same path, different content;
   - *unexplained:* not in the repository, in a directory the repository has (the root
     always counts), with no file there of the same stem (`lib/x.js` next to `lib/x.ts` is
     compiled output). Build directories git ignores (`dist/`) are not in the repository, so
     their files never count.

## Rules

| Rule | Fires when | Severity | Weight |
|---|---|---|---|
| `npm.provenance.githead-dropped` | the previous release recorded `gitHead`, this one doesn't | LOW | 2 |
| `npm.dependency.known-malware` | an added (or re-pointed) runtime dependency, or its `npm:` alias target, is malware in every version per an OSV record published by `as_of` | HIGH | 5 |
| `npm.combination.revived-with-new-dependency` | `npm.dormant-revived` and `npm.dependency.added` both fired, on a release (not a prerelease) | MEDIUM | 2 |
| `repo.compared` | a comparison was attempted: what it found, or why there was none | INFO | 0 |
| `repo.code-differs` | a shipped code file differs from the repository's file at the same path | LOW | 2 |
| `repo.code-not-in-repo` | shipped code files are *unexplained* (above) | LOW | 2 |
| `npm.repo.install-script-not-in-repo` | the release's install hook isn't in the repository's `package.json` (or has another command) | HIGH | 5 |
| `npm.repo.dependency-not-in-repo` | a runtime dependency the repository's `package.json` doesn't name in any section | LOW | 1 |

## Evaluation

`day1` (sha256 `d99626981ae6`), 2026-10-28. Updates are shape A, new packages shape B; DataDog
is the malicious set; follow-on releases in parentheses.

| Predictor | Updates | New packages | Benign (weighted) |
|---|---|---|---|
| `pipeline+3` (Stages 1-3) | 89.7% (38.7%) | 66.0% (22.8%) | 0.8% |
| **`pipeline+4`** (what is reported) | **91.1%** (38.7%) | **66.5%** (22.9%) | **0.9%** |
| `pipeline+4` + manifest-vs-repo rules | **91.2%** (39.7%) | 66.5% (22.9%) | 0.9% |

What Stage 4 added: 13 malicious updates (12 `@mastra/*` and `xrpl@2.14.2`, through
`revived-with-new-dependency`) and 5 malicious new packages plus 1 follow-on release (through
`known-malware`, e.g. `tailwindcss-setfavicon` depending on the malware package `fs`). One benign update
(`@settlemint/dalp-cli@3.1.29-main.*`, a prerelease that dropped its `gitHead`) reached the score.
It lost nothing.

**Choosing the report score.** From a dump of every stage's findings for every sample: LOW
findings of Stages 1-3 summing to 3, 4 or 5 added 0.6, 0.2 and 0 points of recall on
malicious updates for 2.0, 0.8 and 0.4 points of benign updates; at 6 they add neither. A
score bar *instead of* the per-stage MEDIUM bars ("score ≥ 6" alone) is much more precise
(0.1% / 0.6% benign) but loses 2.2 points on updates and 9.5 on new packages. Missing an
attack costs more than a false positive, so the MEDIUM bars stay and the score orders the
queue.

The manifest-vs-repo rules add 1 malicious update and 5 follow-on releases end to end: live,
the comparison runs only for flagged or watched versions, which are mostly reported already.
Their value today is evidence a reviewer can check in seconds.

**Repository comparison** (965 malicious, 300 sampled benign updates):

| | Malicious | Benign |
|---|---|---|
| no GitHub repository | 237 | 46 |
| repository gone | 114 | 22 |
| no `gitHead` and no tag for the version | 543 | 75 |
| archive unavailable (404, too large) or directory empty | 15 | 30 |
| no manifest for the package (monorepo root only, v2) | 1 | 5 |
| **compared** (by `gitHead` / by tag) | **55** (32 / 23) | **116** (59 / 57) |
| differing or unexplained code | 48 | 3 |

Table as of `repo.compared` v2 (2026-10-29). Under v1, which compared monorepo packages with
the root manifest: 57 and 121 compared, 49 and 9 hits. The text below is from v1: 43 of the 49 malicious hits were already flagged by Stages 1-3; the other 6 (`@voiceflow/*`,
Shai-Hulud 2.0's `setup_bun.js`) are neither watched nor flagged, so live Stage 4 wouldn't
compare them. Benign hits were generated files at the package root (`@girs/*` bindings,
`index.cjs` bundles). Hence LOW: 3% of benign updates at MEDIUM would triple the pipeline's
false positives for no measured recall. The comparison's value today is evidence in the report
("this code is not in git"), and its reach grows with the git path.

**Known-malware dependencies.** Matching by package name alone hit 11 benign new packages
(`axios`, `chalk`, `debug`: OSV has records for compromised *versions*); counting only records
that cover every version: 11 malicious new packages, 0 benign.

## Known limits

- **Reach.** The comparison needs a GitHub repository and a commit. Most malicious updates
  record no `gitHead` and have no tag for the malicious version, so they get "no commit or tag
  for this version" (which `githead-dropped` already scores). It works best for the case it was
  designed for: a release whose `gitHead` or tag points at the clean commit while the tarball
  carries extra code.
- **Tags can move**, and anyone with push access can tag a malicious commit. The comparison
  records whether it used `gitHead` or a tag.
- **Monorepos over 128 MB** (compressed) and commits never pushed (HTTP 404, 15% of benign
  `gitHead`s sampled) can't be compared.
- **Non-JS payloads** (shell scripts, binaries) aren't compared; `package.json` is compared for
  install hooks and dependency names only.
- **Network failures** leave a version uncompared; Stage 4 doesn't retry.
