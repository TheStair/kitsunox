# 0020: Read the install code of git dependencies

**Date:** 2026-11-12
**Status:** Accepted and built (round 10, agent G; the owner approved the full version on
2026-11-12). Measured in [the proposal](../proposals/git-dependencies-round10-G.md).
**Builds on:** [0010](0010-stage4-correlation-and-repo-comparison.md) (Stage 4's repository
comparison: refs, archives, `RepoMemory`), [0009](0009-network-failure-handling.md) (network
failures are retried, never taken for "missing"), [0006](0006-scheduled-collection-and-retention.md)
(archives follow `--keep-repo-days`).
**Stage:** 4 ([stages/correlate.md](../stages/correlate.md), "Git dependencies")

## Context

`web3-mev-error-decoder@0.1.0` (run `20261109T133823Z-npm`, malicious) shipped a clean tarball
and one dependency, `"multicall-error-decoder": "github:outgoingyang/multicall-error-decoder"`.
npm installs that repository from GitHub and runs its lifecycle scripts. Its `package.json`
has `"install": "node dist/error-decoder/handlers.js"`, a file that AES-decrypts its strings,
downloads an archive and starts the executable in it (Windows), or pipes a remote script into
the shell (macOS). Kitsunox raised only `npm.dependency.non-registry` (Stage 1, MEDIUM, weight
3). Stages 2-4 never saw the dependency's code: they read the release's tarball, and the
payload was not in it.

npm runs more for a git dependency than for a registry one. It clones the repository, runs
`npm install` in the clone (with the dependency's devDependencies) when there is something to
prepare, runs `prepare`, packs the result and installs the pack. So besides `preinstall`,
`install` and `postinstall`, the root lifecycle of `npm install` runs: `prepublish`,
`preprepare`, `prepare`, `postprepare`. pacote's `DirFetcher` runs only `prepare` around the
pack, never `prepack` or `postpack`. A GitHub *archive URL*
(`codeload.github.com/o/r/tar.gz/<ref>`, `github.com/o/r/archive/<ref>.tar.gz`) is a remote
tarball to npm, and only the three install hooks run.

## Options

1. **Keep `npm.dependency.non-registry` alone.** It already reports every new or changed git
   dependency at MEDIUM unless the previous release vouches for it (v5-v10). But that is a
   flag on the specifier, not on the code, and it is the only thing keeping such a release in
   the queue. A precision round that narrows it would lose `web3-mev-error-decoder` silently.
2. **Read the dependency's install code with the rules that already read install code**
   (chosen). Resolve the reference, fetch the archive at the commit through the run's fetcher,
   extract it with the safe extractor, and run Stage 1's hook rule, Stage 2's file rules and
   Stage 3's code rules on what npm runs, as if the dependency were a package of its own.
3. **A separate set of rules for dependencies.** More work, and two sets of rules to keep in
   step. The install rules already encode the owner's rulings (decision 0015) and their
   explanations.
4. **Install it in the sandbox (Stage 5).** The airgapped sandbox can't fetch from GitHub;
   bundling the repository would work only for reported versions, after the fact.

## Decision

- **What is read.** Each runtime dependency (`dependencies`, `optionalDependencies`) a version
  adds or changes (`stages/gitdeps.wanted`, the same set `npm.dependency.non-registry` reads)
  whose spec names a GitHub repository (`ecosystems/npm/gitdep.github_spec`: `github:o/r`,
  `o/r`, `git+https://`, `git+ssh://`, `git://`, `git@github.com:`, `https://github.com/o/r`,
  and archive URLs; `#<committish>`, `#semver:<range>`, `::path:<dir>`). Credentials in a URL
  are never used: requests are built from the owner and name alone, and the spec is shown with
  `***@`.
- **Resolving.** The reference is resolved in the repository's refs (`parse_ref_advertisement`
  now keeps `HEAD`), as of the run: a full commit id as is, a tag then a branch, `semver:`
  the highest satisfying tag, an abbreviated id only when one ref's commit matches. Through
  `RepoMemory` (one request per pass) and the run's fetcher (`correlate-snapshot.json`).
- **Fetching and extracting.** The archive at the commit (`codeload.github.com`, immutable
  index, retention by `--keep-repo-days` like every repository archive), extracted with
  `extract_archive` under `DEPENDENCY_LIMITS` (64 MB compressed, 512 MB, 100,000 files) in the
  comparison pool. Only what npm runs is kept: `package.json`, the install code
  (`install_sources`), gyp files, agent configuration the install code may copy.
- **What npm runs**, as the rules read it (`npm_runs`): the three install hooks keep their
  slots; each git-only hook takes a free slot (`postinstall`, `install`, `preinstall`) and with
  none free joins the last slot with `&&`; `npm run <script>` is replaced with the script (and
  its `pre`/`post` scripts), three levels deep. Findings show the dependency's own hook names.
- **Analysis.** `npm.install-hook` (Stage 1), Stage 2's file rules on those files, and every
  Stage 3 code rule, the dependency taken as a new package; for a commit bump in the same
  repository (the previous release pinned a full commit id), as an update of that commit. The
  explanations (`EXPLAINED`) are applied within the dependency.
- **Showing and scoring.** `npm.git-dependency` (Stage 4, v1) adds each finding with its own
  rule id, severity and weight, so it scores like the release's own install findings, with the
  dependency named and its evidence under `dep:<name>@<commit12>/`. An INFO summary lists the
  commit, the scripts npm runs and what the install code uses (network, processes, files) and
  where it decrypts, downloads, writes files and starts processes (never scored). An explanation now applies only within its subject (the package, or one
  dependency: `dependency_subject`), and a dependency's severe finding is never cleared by the
  package's repository match.
- **Unreadable.** A deleted repository, a missing ref, an archive over the limits, an archive
  that is 404, a dependency over the cap: `npm.dependency.non-registry` alone, as before, plus
  an INFO `Not evaluated:` note. A network failure is retried in Stage 4's passes and counted
  (`git_dependencies` in `correlate.json`).
- **Not followed.** The dependency's own non-registry dependencies are listed (INFO), not read.
  Unchanged specs on an update are not read (as `non-registry`, which doesn't fire on them).
- **Other sources.** GitLab, Bitbucket and other git hosts: noted, not read. Tarball URLs on
  other hosts (`http(s)://<host>/x.tgz`): noted, **not fetched**. The host is often the
  attacker's (`packages.storeartifact.com`, bare IPs in `vm-day1`): a request tells them the
  package is being analysed, from where, and lets them answer the analyser with something
  else than what `npm install` gets. Requests to arbitrary hosts from the collection VM are
  also what an SSRF needs. GitHub release assets and raw files: noted, not read (they need a
  redirect to GitHub's object storage, and their bytes can be replaced under the same URL).
  `file:` and `link:` stay as before.
- **Caps.** `MAX_GIT_DEPENDENCIES` (200 distinct specs a run) and `MAX_PER_PACKAGE` (10 for all
  versions of one package in a run), planned in run order before any request.
- `STAGE_VERSION` 22.

## Consequences

- **Detection.** `web3-mev-error-decoder@0.1.0` is reported by the dependency's
  `npm.install-hook` and `npm.install-script-code` (MEDIUM), with the `install` hook, the
  process and network use and the decryption, download, write and start lines in the evidence.
  No positive is lost and none is gained on the live runs on disk, the replay set or
  `vm-day1`: every positive that adds a GitHub dependency was already reported. What changes
  for them is the evidence, and that the report no longer rests on the specifier alone.
- **Benign cost.** 4 benign versions newly reported, the same 4 on the live runs on disk and
  the replay set (replay precision 49.15% -> 49.01%): a dependency whose git-only hook builds
  it (`prepare: tsc ...` x3, `prepublish: webpack`), where today's `non-registry` is LOW (a tag
  in the package's own account). `npm.install-build-tool` lists no compiler; whether to
  explain `tsc` for git dependencies is an owner question in the proposal. 10 more benign
  versions, reported already, gained a MEDIUM dependency finding.
- **Replay.** Every request goes through the run's fetcher and is in `correlate-snapshot.json`,
  so a replay reads the same refs and archives. The replay harness for precision rounds reads
  them from a snapshot recorded once (see the proposal).
- **Disk.** 115 distinct commits on the live runs on disk took 191 MB of archives; they are
  pruned with the other repository archives.
- **Rate limits.** Refs and archives are not REST API calls: no token, no quota. One refs
  request per repository and one archive per commit, once per pass.
- **Deleted repositories.** A repository deleted (or a commit garbage-collected) before Stage 4
  runs can't be read: the INFO note says so, and `non-registry` still reports the release.
  On `vm-day1`, 69 of the 71 malicious samples that add a GitHub dependency can't be read
  today (the waves' fork commits on `tanstack/router`, `antvis/G2` and
  `opensearch-project/opensearch-js` are no longer served; `opensearch-project/openearch` is
  deleted), so `vm-day1` can't measure this rule's recall; no sample changed decision.
- **Unchanged specs** on an update, branch or default-branch references included, are not
  read: a push to a dependency's branch between two releases goes unseen (owner question in
  the proposal).
