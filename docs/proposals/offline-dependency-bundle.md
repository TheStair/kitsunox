# Proposal: offline dependency bundles for Stage 5

> **Status:** proposal, 2026-10-29; **implemented in Stage 5 on 2026-10-30**, with the
> differences listed in [Implementation status](#implementation-status). Not yet confirmed in
> package-analysis (evaluation step 1 is the owner's). The owner's direction: ship every
> dependency tarball the package needs *inside* the one package file, so offline analysis can
> run the install hooks.
> Stage design: [stages/sandbox.md](../stages/sandbox.md). Why package-analysis:
> [decision 0014](../decisions/0014-stage5-uses-ossf-package-analysis.md).

## Implementation status

Built (2026-10-30): `ecosystems/npm/ranges.py` (node-semver 7.7.4 and npm-pick-manifest
11.0.3), `sandbox/bundle.py` (read, resolve, fetch, build, `BundleRecord`), and the stage
integration in `stages/sandbox.py`, `sandbox/spool.py`, `sandbox/models.py` and
`sandbox/select.py`. The stage doc's
[Offline dependency bundles](../stages/sandbox.md#offline-dependency-bundles-sandboxbundlepy)
describes what runs. Where the build differs from this note:

| This note | As built | Why |
|---|---|---|
| An `incomplete` bundle is exported (and its install fails offline) | An incomplete bundle is **not** exported: the registry tarball is, under its usual key, with `unbundled_reason` (`incomplete: <codes>`) and `sandbox.bundle-incomplete` (INFO) | The integration brief: a half-built closure would install silently wrong; the original is what the registry published. So `sandbox.quiet` never sees an incomplete bundle |
| Key `sha256(tar_sha256, analyser, package, format)` | The same plus `dependencies_sha256` (the added packages' location, name, version and tarball sha256, sorted) | The brief: the key names the dependency set explicitly |
| Resolver in `ecosystems/npm/resolve.py` | In `sandbox/bundle.py` | It was built as one Stage 5 module; moving it is mechanical |
| `Packument.dist_tags` in `packument.py` | `bundle.RegistryPackument` reads `dist-tags` from the same document | `packument.py` belongs to another stage; switch when it exposes them |
| `ArtifactTree.modes` and `write_tar_gz` in `util/archive.py` | `ArtifactTree.modes` exists (2026-10-30, with `ArchiveLimitError` naming the limit hit); `write_tar_gz` is in `bundle.py`. Bundle format 2 writes `0755` for a file with any execute bit, else `0644`, and the self-check compares them (format 1 wrote every file `0644`) | Additive to the extractor; a script a hook runs by path (`./run.sh`) would fail with `EACCES` without it |
| Resolver queue: breadth-first from the package | arborist's DepsQueue order (shallower first, then by path in an approximation of ICU collation), peer sets placed with the package that needs them, the parent's range preferred for a peer, and REPLACE of a copy not yet processed (2026-10-30) | The FIFO queue picked different versions than npm (see [Resolver](#resolver), Placement) |
| (not in this note) | Kitsunox's own caps on lookups: 30,000 edges per pass, 3,000 packument names and 512 MiB of packument bodies per bundle; a range string over 1,024 characters is invalid (`ranges.MAX_RANGE_LENGTH`) | Edges that place nothing cost work and requests, and node-semver's range parser is quadratic in some inputs. Deliberate divergences from npm, which has none |
| `sandbox-snapshot.json` in `STAGE_SNAPSHOTS` | The stage writes it (`stages.sandbox.SANDBOX_SNAPSHOT`); adding it to `core/run.py` `STAGE_SNAPSHOTS` is left to the integrator | Not Stage 5's module. Until then retention may collect its blobs, and a replay of an older run then reads `BUNDLE_UNREPRODUCIBLE` |
| `<key>.bundle.json` copied into `data/sandbox/<key>/` on import | Stays in the export; a refresh reads it from there, a replay rebuilds the bundle from the snapshot and requires the recorded key | Replay checks the snapshot reproduces the export, and the cache holds only package-analysis's answers |
| `TransientFetchError` leaves the job pending | As designed, and the rest of that call stops bundling (one outage, not a retry storm per package); a run with a pending bundle counts as stale, so later live calls retry it. A definite `FetchError` (403, a size limit, a refused redirect) exports unbundled (`fetch-error`) | A permanent error would otherwise be retried every hour until retention |
| Network per live call 2 GiB | `run_sandbox_stage(bundle_budget=2 GiB)`, counting bytes the fetcher actually downloads; versions past it read pending, in score order | As designed |

Static coverage (evaluation step 2) was measured once on run `20261029T221803Z-npm`; see
[Evaluation](#evaluation).

## The problem

Stage 5 exports jobs with `-offline`, so package-analysis gives the sandbox `--network=none`.
`npm install /<key>.tgz` builds the whole dependency tree *before* it runs any lifecycle script.
A required dependency that isn't present makes the tree build fail, and npm exits before any
`preinstall` runs, including the package's own. Offline, every version with a registry
dependency comes back `failed` with no hook activity. That is the shape most packages have.

**Measured** on run `20261029T221803Z-npm` (registry manifests from `triage.jsonl`, not the
tarballs' own `package.json`): of the 135 versions where `npm.install-hook` fired (all of them
reported), **25 (19%) have no dependencies** and would install offline today. The other 110
(81%) need at least one: 16 have a required peer, 21 have optional dependencies, 2 use a
non-registry spec, and 2 already bundle something. Direct dependency names per version:
median 2, p90 14, max 77.

Online mode works around this, but it gives the package real internet from the analysis VM
(0014). This proposal keeps `--network=none` and gives npm everything it would otherwise
download.

## What npm 11.12.1 does with a bundle

The facts below were read from the sandbox image's layers without running anything:
`gcr.io/ossf-malware-analysis/dynamic-analysis:rel-38`, digest `sha256:d90cdfac…`, built
2026-05-20, ships nodejs **24.15.0**-1nodesource1 and npm **11.12.1**. The image's arborist
`lib/` is byte-identical to npm/cli tag `v11.12.1` (commit 63b9a7c). npm/cli commits its
`node_modules`, so pacote, semver and npm-pick-manifest can be linked at that tag too.
Abbreviations: `NPM` = `https://github.com/npm/cli/blob/v11.12.1/`,
`ARB` = `NPM/workspaces/arborist/lib/`,
`PA` = `https://github.com/ossf/package-analysis/blob/98cd1130815a3b5fb1cac44661ef93fa16da6962/`
(rel-38).

**Only one file reaches the sandbox.** `run_analysis.sh` rewrites `-local` to `/<basename>` and
mounts only that path (`PA/scripts/run_analysis.sh#L85-L99`, `#L177`). It refuses anything that
isn't a regular file (`#L215`). `analyze-node.js` runs `npm init --force`, then
`npm install /<key>.tgz`, then `require(<name>)` (`PA/sandboxes/dynamicanalysis/analyze-node.js#L13-L31`).
So whatever the install needs has to be inside `<key>.tgz`.

**Bundled dependencies are honoured, and nothing is fetched for them:**

- pacote's FileFetcher reads the tarball's `package.json` without calling the registry
  (`NPM/node_modules/pacote/lib/file.js#L19-L33`).
- While building the tree, arborist skips every edge of the package whose name is in its
  `bundleDependencies`, whatever the spec type (`ARB/arborist/build-ideal-tree.js#L1135-L1158`).
  The package has no children at this point, so the bundled packages' own dependencies are
  never examined.
- Reify unpacks the package, runs `loadActual` on its `node_modules/`, and moves in every
  folder whose `package.json` gives a `name@version` `_id`. A bundled name with no folder is
  recorded as missing, and nothing is fetched for it (`ARB/arborist/reify.js#L914-L1010`).
- A package counts as bundled if its parent lists it in `bundleDependencies`, or if a bundled
  package depends on it and it was deduped into the bundle (`ARB/node.js#L517-L557`). So only
  the package's *direct* names need listing. Transitive dependencies only have to sit in its
  `node_modules/` where Node's lookup finds them.
- `bundleDependencies: true` expands to the keys of `dependencies` only
  (`NPM/node_modules/@npmcli/package-json/lib/normalize.js#L211-L236`), so we always write an
  explicit array.
- The comment at `build-ideal-tree.js#L1136-L1142` warns that npm "WILL fetch bundled meta-deps
  which are also dependencies but not listed as bundled deps". So every name in `dependencies`
  and `optionalDependencies` goes in the list.

**Lifecycle scripts of bundled packages run.** `rebuild-bundle` defaults to true
(`NPM/workspaces/config/lib/definitions/definitions.js#L1733-L1740`). Rebuild queues every
`inBundle` child of a node that has bundleDependencies, and the node itself
(`ARB/arborist/rebuild.js#L177-L186`). It runs every queued `preinstall`, then links bins, then
runs every `install`, then every `postinstall` (`#L141-L167`). `prepare` runs only for links
(`#L151`), the same as in a registry install. A package with `binding.gyp` and no install
script gets an implicit `node-gyp rebuild` (`#L261-L274`).

**Failures are fast and come before any hook.** A required dependency that isn't bundled is
fetched. Under `--network=none` the lookup fails with ENOTFOUND or EAI_AGAIN, which
make-fetch-happen doesn't retry (`NPM/node_modules/make-fetch-happen/lib/remote.js#L14-L27`).
`#pruneFailedOptional` then throws (`build-ideal-tree.js#L1556-L1567`), before reify, so no
script runs. A missing *optional* dependency is marked inert and the install goes on.

**No integrity or lockfile is checked for bundled files.** pacote computes the package's own
integrity from the file. npm doesn't platform-check, engine-check or validate edges for
bundled packages either. Kitsunox has to do those checks itself (see [Resolver](#resolver)).

**npm still makes two calls of its own:** the quick-audit POST (`ARB/arborist/reify.js#L1100`,
failure caught at `ARB/audit-report.js#L284-L286`) and the update notifier
(`NPM/lib/cli/update-notifier.js#L18-L31`). Both fail harmlessly offline. They appear as DNS
and socket attempts that `sandbox.network` already attributes to npm in `install`.

## Options

| Option | Works with the fixed `npm install /<key>.tgz`? | Fidelity |
|---|---|---|
| **A. Bundle the closure inside the package**: `package/node_modules/…` plus an explicit `bundleDependencies` | **Yes** | Runs the package's hooks and every dependency's `preinstall`/`install`/`postinstall`; `require(<name>)` still works. The differences are listed below |
| B. A wrapper package W that bundles an unmodified package and its dependencies as siblings | Partly | The package's `package.json` and its position relative to its dependencies match a real install. But it lands at `node_modules/W/node_modules/x`, so `require('x')` from `/app` fails (`NODE_PATH=/app/node_modules`). That loses the import phase and changes `-package` |
| C. `file:` specs, or tarballs packed next to it | No | A tarball's `file:` dependencies resolve against the tarball's own directory, `/`, and only one file is mounted (`ARB/from-path.js#L21-L26`, `build-ideal-tree.js#L1254-L1286`) |
| D. `npm-shrinkwrap.json` inside the package | No | `hasShrinkwrap` comes only from `package._hasShrinkwrap` (`ARB/node.js#L173`), which only registry packuments set. normalize removes `_` keys (`normalize.js#L194-L201`), so the shrinkwrap is ignored and npm goes to the registry |
| E. A directory as `-local` | No | `run_analysis.sh#L215` rejects it. It would also be a symlinked install (`install-links=false`), which runs `prepare` |

**Choice: A.** It is the only option where npm itself runs the package's hooks and its
dependencies' hooks, in npm's own order, and the import phase still works. B is the fallback
if changing the package's `package.json` turns out to matter (open question 2).

**How A differs from a real install.** Every difference is recorded in the job (see
[The job manifest](#the-job-manifest)) and shown in the report:

- Dependencies sit at `node_modules/x/node_modules/*` instead of being hoisted to
  `/app/node_modules/*`.
- `package.json` is rewritten: `bundleDependencies` is set, and required peers are copied
  into `dependencies`.
- `npm_package_resolved` and `npm_package_integrity` are empty for dependencies.
- Script order goes by depth, then path. So the package's `preinstall` runs before its
  dependencies' `preinstall`. In a hoisted install, it would be sorted by path among its
  siblings.
- Malware that reads its own `package.json`, walks `../..` from `__dirname`, or looks for
  siblings in `/app/node_modules` may behave differently.

## Layout

One self-contained tarball per job, written as `<key>.tgz` in the export directory. The command
in `jobs.json` does not change.

```
package/                       pacote strips the first path component, whatever its name
  package.json                 the package's own, with only these changes (all recorded):
                                 "bundleDependencies": sorted union of the package's existing
                                   bundle list, every name in dependencies and
                                   optionalDependencies, and every required peer
                                 each required peer copied into "dependencies" with its
                                   original spec
                               everything else unchanged: scripts, os/cpu/libc, engines,
                               peerDependencies, key order
  ...                          every other file of the original tarball, byte for byte
  node_modules/
    <dep>/                     each resolved dependency, from its registry tarball (checked
    @scope/<dep>/              against dist.integrity, read with extract_tar_gz), re-rooted
                               here; must hold a package.json with name and version
    <dep>/node_modules/<dep2>/ only where a version conflicts (see Placement)
                               no .bin/, no symlinks: bin-links rebuilds .bin during rebuild
```

**The package's own `node_modules/`.** Some tarballs already ship a `node_modules/`, either for
their own `bundleDependencies` (2 of the 135 above) or unlisted. Whatever the original ships is
kept byte for byte and never overwritten. A name the resolver would add but that the original
already ships is not added. It is recorded as `supplied-by-package`. Its own dependencies are
**not** resolved (as built, 2026-10-30): npm never looks at a bundled package's dependencies
(`#problemEdges` skips bundled names), so nothing would install them. A file where a package
folder goes (`node_modules/<name>` as a regular file), or a file that is also another entry's
directory, makes the bundle incomplete (`path-collision`).

**Original tarballs that can't be repacked faithfully.** Repacking means reading the
original with `extract_tar_gz`, so the bundle holds what Kitsunox's lenient reader saw. If that
reading reports `skipped` entries (symlinks, hard links, unsafe paths), `duplicates` or
`anomalies` (a parser differential), the repacked file could differ from what npm's node-tar
reads. Those versions are **exported unbundled**, with the reason recorded, never repacked. A
`package.json` that isn't a JSON object is handled the same way. So is a top-level directory
other than one shared `package/`-style prefix.

Three readings follow npm instead of refusing (as built, 2026-10-30), each recorded in the
`BundleRecord`'s `normalized` so the reviewer sees the bundle is not byte for byte: **link
entries** (symlinks, hard links) are dropped, as pacote's extract filter drops them
(`link-entries-dropped`); a leading **BOM** is stripped, as json-parse-even-better-errors does
(`package-json-bom`); a **repeated key** keeps its last value at its first position, as
JSON.parse does (`package-json-duplicate-keys`). The rewritten `package.json` has neither. A
number past a double's range (`1e400`, which JSON.parse reads as `Infinity`) is written back
as its original text. Any other skipped entry (a device, an unsafe path) still refuses the
original.

## Resolver

The resolver is pure Python and runs offline from fetched packuments. It never runs anything.
It lives in `ecosystems/npm/` (`resolve.py`), because everything in it is about npm.

**Inputs:** the package's own `package.json` from its tarball (what npm reads, not the
registry's metadata), the run's `as_of`, a packument source (the run's fetcher), and the target
`Platform(os="linux", cpu="x64", libc="glibc", node="24.15.0", npm="11.12.1")`. The sandbox is
amd64 Ubuntu 24.04, and npm detects glibc through `process.report`
(`NPM/node_modules/npm-install-checks/lib/current-env.js#L38`).

**Edges.** For the package and for every package added to the closure:

- `dependencies` and `optionalDependencies`. Where a name is in both, the optional spec wins,
  as in npm.
- Required `peerDependencies`, meaning peers not marked optional in `peerDependenciesMeta`.
  npm 7+ installs required peers automatically.
- Never `devDependencies`. `overrides` are ignored, because they apply only to the root
  project and the package is a dependency of `/app`.
- Edges a dependency bundles itself (names in its own `bundleDependencies`) are not resolved.
  Its tarball's `node_modules/` is kept as it is. A listed name the tarball doesn't ship is
  recorded on the dependency (`bundled-dependency-missing`), and the bundle stays complete:
  npm records it and carries on (`reify.js#L987-L1006`).
- A dependency with its own `npm-shrinkwrap.json` (`_hasShrinkwrap` in the packument, or the
  file in its tarball) makes the bundle incomplete (`dependency-shrinkwrap`): npm installs
  what that file pins, not what this resolver picks (`build-ideal-tree.js#L794-L797`,
  `reify.js#L615-L646`).

**Version pick** (a port of `NPM/node_modules/npm-pick-manifest/lib/index.js`, 11.0.3):

1. Only versions with a `time` entry at or before `as_of` are candidates. A version with no
   publish time can't be shown to predate `as_of`, so it is excluded and counted. Stub
   placeholders (`"stub": true`) are excluded too.
2. Read the spec with npa's rules (`#L88-L94`). A **dist-tag** (anything that isn't a valid
   range) returns `dist-tags[tag]`. An **exact version** returns that version. A **range**
   (empty means `*`) is matched with `satisfies(v, range, loose=True)`, with prereleases
   excluded.
3. **`latest` first** (`#L118-L132`). If `dist-tags.latest` is a candidate (published by
   `as_of`), satisfies the range (or the range is `*`, even when `latest` is a prerelease),
   isn't deprecated and passes the engines check, pick it. If `latest` was published after
   `as_of`, the registry's tag says nothing about the run's moment: skip the `latest` step and
   record `latest-after-as-of`. A named tag that points past `as_of` is unresolved.
4. **Otherwise sort** (`#L151-L184`): not deprecated and engines OK, then engines OK, then not
   deprecated, then the highest version. "Restricted or staged" (npm's first key) never appears
   in public packuments, so it is dropped.
5. **Engines** means `engines.node` satisfies 24.15.0 and `engines.npm` satisfies 11.12.1, both
   with prereleases included.

**Placement** follows npm v3 hoisting, simplified. Packages are processed in arborist's
DepsQueue order (`build-ideal-tree.js#L51-L77`): physically shallower first, then by path
under `localeCompare('en')`, which Kitsunox approximates with ICU's root order for the
characters npm paths hold (punctuation, then digits, then letters case-blind; exact for
lowercase ASCII names). Each package's edges are visited in sorted name order. For each edge of
a package P:

- If Node's lookup from P (P's own `node_modules`, then each ancestor's, up to the package's)
  already finds a copy that satisfies the spec, reuse it.
- Otherwise, if the top slot `package/node_modules/<name>` is free, place it there. A free top
  slot means no earlier package needed that name, so nothing is shadowed.
- Otherwise, nest it in `P/node_modules/<name>`. This only shadows P's own subtree, which
  hasn't been resolved yet.

This duplicates more than npm does, because npm tries intermediate levels as well. That is
mostly a difference in layout, but it can change versions too: npm can place a conflicting
copy at an intermediate level where a sibling later dedupes onto it, and it can REPLACE a copy
already processed (then re-resolving under it), which Kitsunox does only for a copy not yet
processed. An earlier version of this note said the difference was only in layout; with a FIFO
queue it wasn't (a review on 2026-10-30 found `P -> a, m; a -> c; c -> x@~1.2.0; m -> x@^1`
installing 1.5.0 at the top and a nested 1.2.9 where npm installs one 1.2.9). A folder the
original ships satisfies the package's own edges whatever its version ("If it's included in a
bundle, we take whatever is specified", `build-ideal-tree.js#L1146-L1155`), but another
package's edge only if it matches; otherwise that package gets its own nested copy. A dist-tag
edge accepts any registry copy of the name (`dep-valid.js#L65-L68`).

**Peers** are placed with the package that needs them, as its peer set (`#loadPeerSet`,
`build-ideal-tree.js#L1322-L1385`), before the requirer's next edge: where P can `require`
them and P's parent sees the same copy, a sibling of P or higher. If P's parent has its own
edge for the name, the peer takes the parent's pick when the peer's range accepts it, else its
own pick when the parent's range accepts that (`#nodeFromEdge`, `#L1052-L1100`). A visible
copy that satisfies the spec is reused. A visible copy that doesn't is replaced by the peer's
pick when that copy hasn't been processed yet and the pick satisfies every edge that reached
it (npm's REPLACE); otherwise it is kept and the conflict recorded as `peer-conflict`, as npm
keeps it and warns ("ERESOLVE overriding peer dependency", `#L1385-L1405`). No second copy is
nested, so a plugin's peer on the package itself never ships another copy of the package. The
package's *own* required peers are a special case.
`#loadPeerSet` (`build-ideal-tree.js#L1103`, `#L1322-L1345`) fetches them as soon as the
package node is created, with no bundle check. So every required peer is also copied into the
package's `dependencies`, with the same spec, and into `bundleDependencies`. `#loadDepType`
loads peers first, and a later edge with the same name replaces the earlier one
(`ARB/node.js#L887-L945`, `ARB/edge.js#L99`). The edge then becomes a normal dependency that
the bundle skip covers. **This comes from reading the source, not from a run**: it is the first
thing to test (see [Evaluation](#evaluation)). Optional peers are not shipped, because npm
doesn't install them by default. They may cost npm one failed lookup, and they stay inert.

**Platform-specific optional packages** (esbuild, swc, sharp and similar). Kitsunox applies
npm-install-checks' rule (`NPM/node_modules/npm-install-checks/lib/index.js#L25-L83`) to every
optional package:

- Each of `os`, `cpu` and `libc` is absent, the string `"any"`, or a list.
- A value fails if it matches a negated entry (`!x`), or if there are positive entries and it
  matches none of them.
- `libc` fails if it is set and the host has none.
- Engines are checked as above.

Only packages that pass for linux/x64/glibc are shipped, so `-linux-x64-gnu` is shipped and
`-linux-x64-musl` is not. Every optional name of the *package* stays in its
`bundleDependencies`, so the ones not shipped are skipped without a fetch. A *non-optional*
dependency that fails the platform check is not shipped, and the job is marked incomplete
(`platform-mismatch`): npm on linux-x64 would refuse it with EBADPLATFORM, and inside a bundle
it would install silently. Getting this wrong matters in both directions. Shipping the wrong
binary runs its scripts. Leaving out the right one lets the parent's own `postinstall` (such as
esbuild's `install.js`) try to download it, fail offline, and possibly stop the postinstall
phase, including the package's own.

**Aliases and non-registry specs.**

- `npm:<name>@<range>` is resolved against `<name>`'s packument and placed under the alias
  folder. The `package.json` inside keeps the real name. This is believed to work from
  `loadActual`'s naming, but it is untested.
- git, `github:user/repo`, http(s) tarball, `file:`, `link:` and `workspace:` specs can't be
  resolved from a packument. The job is marked incomplete with the spec recorded, and nothing
  is guessed. A git dependency with a `prepare` script would need `npm pack`, which Kitsunox
  never runs.

**Missing dependencies.** A name the registry doesn't have (HTTP 404, or a packument that
fails `Packument` validation), or a spec no candidate satisfies by `as_of`, is recorded as
`unresolved: <reason>`. If it is required, the job is incomplete. These are signals in their
own right (a dependency published after the package, dependency confusion). Stage 4's
dependency rules already score them; Stage 5 only records them.

**Post-check.** After placement, a Python check confirms that every non-optional edge and
required peer of every shipped package can be resolved by Node's lookup to a copy that
satisfies its spec. npm checks none of this inside a bundle, so a resolver bug would otherwise
ship silently and show up only as a failed install.

## Semver ranges

`ecosystems/npm/semver.py` only parses SemVer 2.0.0 and orders versions. `evaluation/labels.py`
handles OSV's introduced/fixed intervals, and `rules/metadata.py:is_registry_spec` only
classifies specs. Neither matches npm's range grammar, so this needs **new code**, in a new
module `ecosystems/npm/ranges.py` that reuses `SemVer` and its precedence. It ports node-semver
**7.7.4** (`NPM/node_modules/semver/classes/range.js`, the version in the image):

- Split on `||`. An empty set means `*`.
- Hyphen ranges: in `A - B`, a partial A is padded with zeros, and a partial B becomes
  `<next-0`. So `1.2 - 2.3` means `>=1.2.0 <2.4.0-0` (`#L491`).
- Spaces after an operator are trimmed.
- Tilde (`#L288`): `~1.2.3` means `>=1.2.3 <1.3.0-0`, `~1` means `<2.0.0-0`, and `~>` is
  accepted.
- Caret (`#L332`): `^1.2.3` means `<2.0.0-0`, `^0.2.3` means `<0.3.0-0`, `^0.0.3` means
  `<0.0.4-0`, `^0.0` means `<0.1.0-0`, and `^0.x` means `<1.0.0-0`.
- X-ranges (`#L393`): `1.x`, `1.2.*`, `1`, `*`, `x`, and the empty string. With operators,
  `>1` means `>=2.0.0` and `<=1.2` means `<1.3.0-0`.
- Loose mode accepts `v` and `=` prefixes and a prerelease without its hyphen. Build metadata
  is ignored.
- Prerelease rule (`testSet`, `#L523-L557`): a prerelease version matches only when some
  comparator in the same set has a prerelease on the same major.minor.patch. The rule is
  turned off by `include_prerelease`, which the engines check uses.
- Anything that doesn't parse as a range is a dist-tag.

**Tests:**

- The examples in npm's documentation, the package.json `dependencies` section and
  node-semver's README ("Advanced Range Syntax"), written as table tests.
- node-semver's own fixtures at tag `v7.7.4` (`test/fixtures/range-include.js`,
  `range-exclude.js`, `range-parse.js`), transcribed as inert data with their ISC licence
  noted.
- Hypothesis properties: a desugared range and its comparator set agree, and `max_satisfying`
  is the maximum of `satisfies`.

The alternative is a dependency, `semantic_version`'s `NpmSpec`. It was not chosen, because
agreement with 7.7.4 in prerelease and loose-mode edge cases is the whole point. It could serve
as a second oracle in tests.

## Fetching and recording

- **Everything goes through `HttpFetcher`**, in a new stage snapshot,
  `sandbox-snapshot.json`. It is added to `STAGE_SNAPSHOTS`, so retention keeps its blobs and
  the export's `TarballIndex` sees them.
- **Packuments:** the full document (`Accept: application/json`, as `NpmEcosystem.packument`
  does), because the abbreviated form has no per-version `time`, which the `as_of` filter
  needs. Each name is fetched once per run.
- **Tarballs** are fetched with `immutable=True`, so dependencies shared across runs are
  downloaded and stored once. They are verified with `verify_integrity` against the
  packument's `dist.integrity`/`shasum`, and refused without a digest, by reusing
  `NpmEcosystem.fetch_artifact`. Only `https://registry.npmjs.org/` tarball URLs are fetched.
  npm rewrites other hosts to the configured registry anyway (`replace-registry-host`), and a
  packument's URL must not make Kitsunox fetch from an arbitrary host. Any other URL is
  `unresolved`.
- **Reading** dependency tarballs uses only `extract_tar_gz` (`strip_components=1`). A
  dependency whose reading reports skipped entries or anomalies is still shipped as read, and
  the anomaly is recorded on that dependency.
- **Network failures follow decision 0009.** A `TransientFetchError` is never treated as a
  missing package. The job is not exported (neither bundled nor unbundled) and stays
  `pending`, and the next live call tries again. Only a definite answer (404, a validation
  failure, an integrity mismatch) produces `unresolved`.
- **Locking:** bundling runs inside `run_sandbox_stage`'s live export, under `DataDir.lock()`,
  like every other write. It never runs in `replay=True`.

## Building the tarball

The bundle is written with the stdlib `tarfile` (writing only; nothing is read back with
`tarfile` directly):

- **Format:** `PAX_FORMAT`, because nested `node_modules` paths can exceed ustar's 100/155
  bytes. File entries only, with no directory entries, as `npm pack` writes them. pacote
  creates the directories.
- **Order:** sorted by the UTF-8 bytes of the path.
- **Metadata:** `mtime` is npm pack's fixed 1985-10-26T08:15:00Z (499162500); uid and gid are
  0; uname and gname are empty.
- **Modes:** `0644`, or `0755` when the source entry had any execute bit. pacote ORs the tar
  entry's mode into `0666 & ~umask` (`NPM/node_modules/pacote/lib/fetcher.js#L410-L418`), so
  this gives the same on-disk modes as a registry install, up to group and other bits. The
  source modes come from `ArtifactTree.modes` (bundle format 2).
- **gzip:** `mtime=0`, no file name in the header, level 9. zlib's output can differ between
  zlib builds, so the job key covers the sha256 of the *uncompressed* tar stream, and the
  `.tgz` sha256 is recorded separately to check the file.
- **Self-check:** the written `.tgz` is read back with `extract_tar_gz`, using the export's own
  limits (below). The check passes only if the file list, bytes and execute bits match what
  was meant to be written, with no skipped entries and no anomalies, and the written
  `package.json` reads as strict JSON (no BOM, no repeated keys).
- A **dependency-free package** is exported unchanged, as today: original bytes, original key.

## The job manifest

`SandboxJob` (schema 4) and `ExportEntry` gain these fields:

| Field | Meaning |
|---|---|
| `tarball_sha256` | Unchanged meaning: the sha256 of the exported `<key>.tgz` |
| `original_sha256` | The sha256 of the registry tarball, verified against its SRI |
| `bundle` | `null` for an unbundled export; otherwise a summary: `format` (`kitsunox-npm-bundle/2`; 1 before 2026-10-30), `status` (`complete` / `incomplete`), `tar_sha256`, `assumes` (npm 11.12.1, node 24.15.0, linux/x64/glibc), counts, and the bundle file's name |
| `unbundled_reason` | Why a version with dependencies was exported unbundled, from a fixed set: over a cap, original not repackable, resolver disabled, and so on |

The details go in a separate `<key>.bundle.json` next to the tarball, so `jobs.json` stays small
(1,500 dependencies × 30 jobs would come near `MAX_MANIFEST_BYTES`):

- `package_json`: the sha256 of the original and the rewritten file, and every change as
  `{field, before, after}` (`bundleDependencies`, and each copied peer).
- `added`: one entry per shipped package: folder (`node_modules/a/node_modules/b`), name,
  version, the spec(s) and requirer(s) it satisfies, integrity, tarball sha256, file count,
  bytes, whether it has hooks or a `binding.gyp`, and any reading anomalies.
- `supplied_by_package`: names the original already shipped.
- `skipped`: optional packages left out (platform or engines), with the failed check, and
  optional peers.
- `unresolved`: spec, requirer and reason (non-registry, not on the registry, nothing by
  `as_of`, `latest-after-as-of` for a named tag, platform mismatch).
- `predicted_network`: closure packages expected to need the network at install time (see
  [Failure modes](#failure-modes)).
- `files`: the bundle's file list by origin, which the importer uses (below).

**Key.** For a bundled job, the key is
`sha256(tar_sha256, analyser, package, bundle format)`. Unbundled jobs keep today's key, so
cached results stay valid. The bundle's bytes cover the dependency set, so a different
resolution is a different analysis. Once bundling is on, a version's job is the bundled one. An
older unbundled result stays in the cache under its own key, but no longer answers the
version.

## Importing and rules: package files vs dependency files

Today's rules know one package directory, `/app/node_modules/<package>`, and treat its
`node_modules/` as npm's. With a bundle, every dependency is *inside* that directory, so the
importer has to say where a path or command came from. `<key>.bundle.json` is copied into
`data/sandbox/<key>/bundle.json` on import (it is Kitsunox's own data, but it is validated like
`jobs.json`), and the rules' `Activity` gains an origin map:

- **Paths.** The longest matching folder in `added` gives the dependency
  (`dependency foo@1.2.3`). Paths in the original's own `node_modules/` are
  `package (shipped)`. Other paths in the package directory belong to the package. A path in
  the package directory that is in neither the original's file list nor the bundle's is
  `written at run time`.
- **Commands.** package-analysis records each `execve`'s environment. npm sets `npm_package_name`,
  `npm_package_version` and `npm_lifecycle_event` for every lifecycle script, and its children
  inherit them. An exec observation's origin is the package those variables name, if it is in
  the bundle, plus the hook. This is a label, not proof: a script can change its children's
  environment, and the values are untrusted text, escaped as usual.
- **Sockets and DNS** have no process, so their origin is unknown. They count for the job, as
  today.
- **`unshipped` / `download-exec`.** These now use the bundle's file list too. A file appearing
  in a dependency's folder that the bundle didn't ship was written during the run, which used
  to be invisible under `node_modules/`. The exclusions for node-gyp's `build/` directory
  extend to every dependency that has a `binding.gyp`.
- **Evidence** names its origin ("in bundled dependency `foo@1.2.3`, postinstall"). **Weights do
  not change in the first version:** a finding whose evidence all comes from dependencies still
  counts for the version, because the package pulled that code in, and a two-package attack
  (a benign-looking package plus a malicious dependency) is exactly what this should catch.
  The benign false-positive rate by origin decides whether that holds (open question 1).
  esbuild's `install.js`, for example, writes and runs its binary to check it, which
  `download-exec` would see.

**Report.** Every bundled analysis gets a new INFO finding, `sandbox.bundled` (weight 0), and
`sandbox.ran` says the same in one line. Both state that the analysis saw a **Kitsunox-built
bundle, not the registry tarball**, and give both sha256s, the `package.json` changes, the
number of dependencies added (the top-level ones by name), what was skipped or unresolved,
`complete`/`incomplete`, and the npm and node versions assumed. An unbundled export of a
version with dependencies says why (`unbundled_reason`), so a `failed` install isn't misread.
`sandbox.quiet` can't fire on an `incomplete` bundle.

## Sizes and caps

Measured 2026-10-29: deps.dev for the graph, the registry's `unpackedSize`, linux-x64 glibc
platform packages only, peers not counted, compressed size the sum of the separate tarballs.

| Package | Packages | Unpacked | Compressed |
|---|---|---|---|
| express@5.3.0 | 68 | 2.3 MB | 0.7 MB |
| eslint@10.13.0 | 77 | 11 MB | 2.4 MB |
| webpack@5.112.2 | 63 | 27 MB | 6.1 MB |
| jest@30.5.2 | 278 | 40 MB | 9 MB |
| @angular/cli@22.2.5 | 95 | 58 MB | 12 MB |
| vite@8.3.5 | 15 | 34 MB | 13 MB |
| sharp@0.35.5 | 9 | 30 MB | 12 MB |
| aws-sdk@2 | 47 | 103 MB | 13 MB |
| react-scripts@5.0.1 | 1,210 | 143 MB, 34.6k files | 32 MB |
| next@16.4.3 | 21 | 327 MB, 10.3k files | 92 MB |

**Caps for one bundle** (`ExportLimits`, separate from Stage 2's 16 MB artifact cap, which still
applies to the package's own tarball):

| Cap | Value | Why |
|---|---|---|
| Compressed `.tgz` | 128 MiB | Fits everything above except Next.js-sized trees (150 MiB would fit those; open question 4) |
| Unpacked total | 512 MiB | `extract_tar_gz`'s default total |
| Files | 50,000 | `extract_tar_gz`'s default; react-scripts has 34.6k |
| Packages | 1,500 | react-scripts has 1,210 |
| Dependency-chain depth | 64 | Stops pathological chains; real trees are far below |
| Nesting depth (`node_modules` levels) | 8 | Nesting only happens on conflicts |
| Path length | 1,024 bytes per entry, 255 per component | Well under Linux's limits inside the sandbox |
| One file in a dependency | What is left of the unpacked cap | Was `extract_tar_gz`'s 64 MiB, which made native CLI binaries (bun, opencode) unreadable: 12 of 154 bundles on the first live day (devlog 2026-10-30) |
| Network per live call | 2 GiB of new (uncached) bytes | Bounds a tick; jobs over it stay `pending`, in score order. Checked between bundles; one bundle can pass it by at most its own caps below |
| Edges walked per resolution pass | 30,000 | An edge that places nothing still costs a lookup |
| Packument names per bundle | 3,000 | Twice the package cap; 404s count |
| Packument bodies per bundle | 512 MiB | Counted from the responses, snapshot hits included, so a replay reaches the same cap. Only the manifest fields the resolver reads are kept |
| Range string | 1,024 characters (`ranges.MAX_RANGE_LENGTH`) | node-semver's `comparatorTrim` is quadratic on a run of `v`, `=` or spaces; longer is an invalid range (an unresolved spec, or `engines` not OK). npm has no such limit |

**Over a cap, the version is exported unbundled**, as today, with `unbundled_reason` naming the
cap. Nothing is trimmed silently. A half-shipped closure would look complete to npm and lose
hooks without saying so.

**Disk.** Dependency tarballs are blobs. They are shared across runs through the immutable
index and pruned with the runs that reference them. Exports are per run and pruned with them.
At 150-350 selected versions a day (sandbox.md's estimate), with most closures in the
1-15 MB range of the table above, exports would be on the order of 1-3 GB a day. That is an
estimate to measure, and small next to Stage 4's archives. Building the bundle in memory peaks
at the unpacked cap (512 MiB) per job; jobs are built one at a time. Each dependency tarball
is read with what is left of the bundle's caps, so the over-cap answer comes as soon as the
running total passes it, before the next tarball is fetched (the unpacked budget counts each
tar stream, headers included). A packument's `dist.unpackedSize` that is negative is no size,
never a credit.

## Failure modes

| Failure | Detected before export? | What happens | Recorded as |
|---|---|---|---|
| Non-registry spec (git, http, `file:`, `github:`) | Yes | Required: bundle `incomplete`, exported, and the install fails offline before hooks. Optional: skipped | `unresolved` |
| Dependency not on the registry, or nothing satisfies the spec by `as_of` | Yes | Same as above | `unresolved` |
| Transient network failure | Yes | Not exported; stays `pending`, retried on the next live call | `pending` (0009) |
| Over a cap | Yes | Exported unbundled | `unbundled_reason` |
| Original not repackable (skipped entries, duplicates, anomalies, bad `package.json`) | Yes | Exported unbundled | `unbundled_reason` |
| Native addon needing node-gyp headers (`binding.gyp`, implicit `node-gyp rebuild`; the image's Node has `use_prefix_to_find_headers=false` and no `~/.cache/node-gyp`, so node-gyp downloads headers from nodejs.org) | Yes, from the bundle's files | Exported as is. If the package isn't optional, its `install` fails, and the postinstall phase (the package's own included) may not run | `predicted_network`; the `failed` result is attributed to it, never `quiet` |
| Install-time downloaders (`prebuild-install`, `node-pre-gyp`, `node-gyp`, `cmake-js` in a hook; or a known downloader package with a hook: puppeteer, cypress, electron, electron-chromedriver, chromedriver, geckodriver, node-sass, ngrok, phantomjs-prebuilt, @prisma/engines) | Partly, from known script shapes and names | Same as above | `predicted_network` (`install-tool`, `known-downloader`) |
| A dependency ships `npm-shrinkwrap.json` | Yes | Exported unbundled | `incomplete: dependency-shrinkwrap` |
| An unexpected error while bundling (a bug on hostile input) | Yes | Exported unbundled; the stage carries on | `internal-error` (a fixed string) |
| Wrong platform package shipped (resolver bug) | Post-check and tests | npm installs it and runs its scripts; that is wrong evidence | prevented by the platform check; any slip is a bug |
| Required peer still fetched (the source-reading claim is wrong) | No | Install fails before hooks | caught in the first evaluation step |
| Resolution drift: `latest`, deprecation or engines changed after `as_of`, or a version unpublished | No | A version npm would have picked at `as_of` may differ | known limit; the packument fetch time is in the snapshot |
| npm version drift: a rebuilt image with another npm | No | Bundle semantics may change | `assumes` per job; the image digest is pinned in sandbox.md |
| Bundle rejected by package-analysis (size, time) | No | `infra-error` | existing handling |

## Determinism

| | Reproducible? | How |
|---|---|---|
| Resolution | Yes | A pure function of the package's `package.json`, `as_of`, the platform constant and the packuments in `sandbox-snapshot.json` |
| Bundle bytes | Yes (tar), within one zlib build (gzip) | Sorted entries, fixed metadata; the key covers the tar's sha256 |
| Rebuild in REPLAY mode | Yes | A test rebuilds a bundle from the snapshot and must reproduce `tar_sha256`; a `kitsunox sandbox bundle --replay <run_id>` check can do the same on real runs |
| `sandbox.jsonl` replay | Unchanged | `replay=True` doesn't touch the export; origins come from the cached `bundle.json` |

## Changes outside Stage 5

These touch other modules, so per CLAUDE.md they are flagged here rather than slipped in:

1. `core/run.py`: add `sandbox-snapshot.json` to `STAGE_SNAPSHOTS` (retention and the
   tarball index).
2. `util/archive.py`: `ArtifactTree` gains `modes: Mapping[str, int]` (done 2026-10-30, for
   tar archives; zips report none) and `ArchiveLimitError` (an `ArchiveError` naming the limit
   hit). Both are additive; existing callers are unaffected. A deterministic `write_tar_gz`
   next to the extractor is still in `bundle.py`.
3. `ecosystems/npm/packument.py`: expose `dist_tags`. New `ecosystems/npm/ranges.py` and
   `ecosystems/npm/resolve.py`.
4. `rules/sandbox.py`: the origin map in `Activity`, and `unshipped` over the bundle's file
   list.

## Evaluation

1. **Confirm the mechanics** (owner-run, about 8 jobs). Kitsunox builds inert fixture
   packages whose scripts only `echo` their name and hook, and the owner runs them offline in
   package-analysis. They check:
   - a plain bundle runs every hook, in the stated order;
   - the peer-into-dependencies fix (and the failure without it);
   - an optional peer tolerated offline;
   - an `npm:` alias folder;
   - a missing optional platform package;
   - a bundle near the size cap.

   Exec observations with `npm_lifecycle_event` show what ran. Without this, nothing below is
   trusted.
2. **Static coverage** (no sandbox), on `vm-day1` and on the reported versions with hooks of
   recent collection runs (135 in `20261029T221803Z-npm`). For every version that would be
   selected, run the resolver and record:
   - the share with no dependencies, complete, incomplete by reason, and unbundled by
     reason;
   - packages and bytes per bundle (p50, p90, max);
   - new bytes fetched;
   - `predicted_network`.

   For DataDog samples, use their own `package.json` (read in memory, as Stage 2's evaluation
   does), with `as_of` set to their publish time. Taken-down dependencies will show up as
   `unresolved`. The headline number is **predicted offline-installable**: no dependencies, or
   complete with no `predicted_network`, out of the versions Stage 5 selects. The baseline is
   19% (25 of 135).
3. **Measured install** (owner-run, about 30 benign reported versions with hooks and
   dependencies). Run each offline unbundled (the baseline, expected `failed`) and bundled.
   Record:
   - install `completed`;
   - import `completed`;
   - whether the package's own hook ran (an exec with its `npm_package_name` and the hook's
     `npm_lifecycle_event`);
   - prediction against outcome;
   - non-INFO findings by origin (package / dependency / unknown).
4. **Malicious samples**, once D7 allows detonating DataDog samples: the share with a non-INFO
   finding, bundled against unbundled.

Results go in `docs/evaluation.md` and in a new section of `docs/validation.md`. **Proposed
bar for turning bundling on by default:** at least 80% of `complete` bundles install offline,
and the package's own hook runs in all of them. A lower share means the resolver or the
mechanics are wrong.

## Known limits

- The fidelity differences listed under [Options](#options): nested layout, rewritten
  `package.json`, empty `npm_package_resolved`/`integrity`, script order.
- Only linux/x64/glibc behaviour is seen; a dependency that is malicious only on another
  platform isn't shipped.
- Resolution uses today's packument, filtered by `as_of`. It can't recover a `latest` tag or a
  deprecation as they were at `as_of`, or a version unpublished since.
- Deliberate differences from npm's pick, kept: a version without a publish time is excluded
  (npm's `isBefore` lets it through), and a named tag pointing past `as_of` is unresolved (npm
  would fall back to `<=tag`).
- Placement is npm's only approximately (see [Resolver](#resolver), Placement): no intermediate
  levels, REPLACE only of an unprocessed copy, and ICU collation approximated.
- A dependency published after the run's packument fetch isn't there, so an attack that
  publishes the dependency later is reproduced only as `unresolved`.
- Native addons and install-time downloaders still fail offline (predicted and attributed,
  not fixed).
- Commands are attributed only through npm's environment variables; files, sockets and DNS
  only by path, or not at all.

## Open questions for the owner

1. **Dependency findings:** should findings whose evidence comes only from bundled
   dependencies count at full weight for the version (as proposed), at reduced weight, or be
   reported separately? Decide after evaluation step 3.
2. **Rewriting `package.json`:** is it acceptable, given that it is recorded and reported? Or
   should we prefer the wrapper layout (B), which keeps it unmodified but loses the import
   phase?
3. **Unlisted `node_modules/` in the original:** keep the package's own copy and skip ours (as
   proposed), or export unbundled? What npm does with unlisted folders after
   `#pruneBundledMetadeps` hasn't been tested.
4. **Compressed cap:** 128 MiB (as proposed) or 150 MiB, so Next.js-sized trees fit? It is
   also unknown whether package-analysis or the analysis VM's disk cares at that size.
5. **Native addons:** export as is and accept `failed` (as proposed), or allow a recorded
   patch such as `"gypfile": false`, or marking the dependency optional, so the other hooks
   still run? Either changes the package further and needs a decision note.
6. **Selection:** the entry rule stays "the package's own `package.json` has a hook". Should a
   reported version whose *new* dependency has a hook (two-package attacks; Stage 4's
   `fresh-foreign` cases) also qualify, now that the dependency's hook would run?
7. **Shared bundles:** dependencies are copied into every job's bundle. Is per-job size
   acceptable, or should the export deduplicate across jobs, which package-analysis's
   one-file rule makes hard?
