"""Stage 5 rules: findings from one OpenSSF package-analysis result.

Stage 5's dynamic analysis is OpenSSF package-analysis (rel-38), which the owner runs on an
isolated VM; Kitsunox imports its JSON results as observations (`kitsunox.sandbox.models`).
Each rule is a pure function of the `SandboxRun`, its observations and the candidate (never the
clock, the network or the environment), so re-running the rules over a stored result gives the
same findings. Every string they read is attacker-controlled: snippets are capped and made
visible (control and bidirectional characters escaped), and nothing is interpreted.
`sandbox.not-run` and `sandbox.result-rejected` live with the stage (`stages/sandbox.py`).
Weights are starting points, to be set from evaluation.

**What package-analysis records** (pinned source: `pkg/api/analysisrun/result.go`,
`internal/strace/strace.go`, `internal/dnsanalyzer`, `sandboxes/dynamicanalysis/`), per
*phase*. For npm two phases run, in order, in one gVisor container (so state carries over):
`install` (`npm init --force`, then `npm install /<key>.tgz`, which runs the package's and its
dependencies' `preinstall`/`install`/`postinstall` scripts and fetches dependencies from
registry.npmjs.org) and `import` (`require(<name>)` from the driver script). Import is skipped
when install fails. Per phase, the result has sets, not a trace:

- **Commands**: the argv and environment of every `execve` (deduplicated). There is no
  executable path, no pid, no parent and no order: `argv[0]` is whatever the caller chose.
  Mapped to `exec` (`argv`, `env`).
- **Files**: a path with Read / Write / Delete booleans (opens by their flags; any `stat` is a
  read; unlink a delete). Return values are not checked, so a failed open or a stat of a missing
  file counts. `symlink`, `link`, `rename` and reads through an already-open descriptor are not
  traced, so `ln -s ~/.ssh/id_rsa /tmp/x; cat /tmp/x` shows only `/tmp/x`. Mapped to `open`.
- **Sockets**: `bind`/`connect` to IPv4/IPv6 addresses (from strace), with the names DNS
  answered for that address in the phase. Mapped to `connect`, one per name (`host`; none
  when no name resolved to the address), `port` None where it was recorded as 0.
- **DNS**: the questions seen on the sandbox bridge (no answers' payloads, no HTTP, no TLS).
  Mapped to `dns` (`host`, and class and types in `detail`).

**What that means for attribution.** npm's own activity, the package's hooks, and its
dependencies' hooks are mixed in one phase with no process tree. The rules therefore separate
expected npm/driver behaviour by *phase* and by *exact shape* (below, per rule), never by trusting
a process: in `install`, npm reads its config (`~/.npmrc`), writes `/app/package.json` and the
whole of `/app/node_modules`, and talks to registry.npmjs.org; in `import`, npm does not run, so
the same things are the package's (or a dependency's) own code. A package that hides inside npm's
expected install activity (reading `~/.npmrc` during install, rewriting another package in
`node_modules` during install, publishing through registry.npmjs.org) is not distinguishable here.
That is a known limit, stated in each rule.

**`~/.npmrc` in `install`.** npm reads `/root/.npmrc` (and `/app/.npmrc`) every time it starts,
and package-analysis's Files set records a path with Read/Write/Delete booleans and no process
per file. A `postinstall` that reads `~/.npmrc` to steal a token therefore leaves exactly the
entry npm's own read leaves: the two are indistinguishable, so `sandbox.sensitive-read` counts
an `.npmrc` read only in `import`, where npm doesn't run. The install-phase token stealer is a
recall gap here (Stages 2 and 3 read the code that does it; `sandbox.network` sees where it
sends it).

**Origins.** Where a path shows whose files they are, evidence says so: a path under
`/app/node_modules/<package>/` is "in the package", one under
`.../node_modules/<package>/node_modules/<dep>/` (the innermost `node_modules/<name>` wins) or a
hoisted `/app/node_modules/<dep>/` is "in dependency <dep>". For a command the path is the
program or script it runs, else the `npm_package_json` npm puts in every lifecycle script's
environment (`@npmcli/run-script` `make-spawn-args.js`: the running package's own
`package.json`), with `npm_lifecycle_event`. The environment is the package's to change, so that
label is a hint, never proof. A Kitsunox offline bundle (`docs/proposals/offline-dependency-
bundle.md`) puts every dependency under the package's own `node_modules/`; the caller passes the
names it added (`bundled_deps`), and a folder there that isn't one of them is "the package's own
node_modules/<name>" (it came in the original tarball). Weights don't depend on the origin: a
package answers for the code it pulls in.

**Baits.** package-analysis plants an RSA key at `/root/.ssh/id_rsa` and AWS credentials in the
environment, random per run. The design's canary rule (Kitsunox's own canary values, derived
from the job, found in DNS, HTTP and payloads) cannot work with that: there are no Kitsunox
canaries and no HTTP or payloads, so it is gone. The importer recovers the AWS bait values from
the recorded environments and masks them everywhere (`SandboxRun.canaries`);
`sandbox.bait-exfil` reports the mask, or a bait's *shape*, where only exfiltration or staging
would put it.

**What the rules know of the job.** The exported tarball's path in the sandbox
(`expected_tarball`: `/<key>.tgz`, where `run_analysis.sh` mounts `-local` and `cmd/analyze`
copies it), so only the driver's exact `npm init --force` and `npm install /<key>.tgz` are
package-analysis's own; and, when the caller passes it, the tarball's own file list
(`shipped`, paths inside the tarball with its top `package/` directory stripped), so a file in
the package's directory that npm didn't unpack is visible. In an airgapped run (`NETWORK`,
every job's: `--network=none`) or a bundled one, npm installs nothing under the package's own
`node_modules/` (a missing dependency fails the install before any hook), so that directory
is checked against the file list too, except npm's `.bin` links and node-gyp's `build/`
directories.

**Order.** Phases are ordered (`install` before `import`); nothing is ordered within a phase.
`sandbox.download-exec` therefore counts a file written and executed in the same phase.
Observations are sorted by a total order only so that output never depends on input order.

**Incomplete or failed runs.** A truncated or timed-out record (`sandbox.truncated`; HIGH when
the importer's count caps were hit, which only flooding reaches) and a failed
run (a phase that didn't complete, a run status other than `completed`) never end in
`sandbox.quiet`; the rules still run over whatever was recorded.

**Cost.** Linear in the number of observations (plus a sort).
"""

from __future__ import annotations

import ipaddress
import math
import posixpath
import re
import shlex
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Final, get_args

from kitsunox.core.models import Candidate, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.sandbox.models import (
    NETWORK,
    PHASES,
    Cut,
    Observation,
    ObservationKind,
    SandboxJob,
    SandboxRule,
    SandboxRun,
)
from kitsunox.sandbox.ossf import (
    CANARY_MARK,
    CANARY_VARS,
    MAX_ARGV,
    MAX_ENV,
    MAX_FIELD_CHARS,
    MAX_HOSTNAMES,
    MAX_NAME_CHARS,
    MAX_OBSERVATIONS,
    MAX_TYPES,
    STDIO_BYTES,
)

K = ObservationKind

# package-analysis's dynamic-analysis sandbox (sandboxes/dynamicanalysis/Dockerfile at rel-38):
# root, WORKDIR /app, NODE_PATH=/app/node_modules, npm's cache in /root/.npm.
HOME: Final = "/root"
APP: Final = "/app"
NODE_MODULES: Final = f"{APP}/node_modules"
NPM_CACHE: Final = f"{HOME}/.npm"
DRIVER: Final = "/usr/local/bin/analyze-node.js"  # the npm phase driver
# The image's own directories. The sandbox runs as root, so a hook *can* write here: a write
# is `sandbox.persistence-write` evidence ("system program directory"), and a path here only
# ever narrows what counts as npm or node.
IMAGE_ROOTS: Final = ("/usr/", "/bin/", "/sbin/")
# npm's config files, which npm reads on every start (`install` phase only).
NPM_CONFIG_FILES: Final = frozenset({f"{HOME}/.npmrc", f"{APP}/.npmrc"})

INSTALL: Final = "install"
# The sandbox's PATH (the image's ENV lines), where a bare command name is looked up.
SANDBOX_PATH: Final = (
    "/app/.pyenv/bin",
    "/usr/local/cargo/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)
SANDBOX_TMP: Final = "/tmp"  # noqa: S108 (a path inside the sandbox, not a temp file here)

SNIPPET_LIMIT: Final = 300  # as Stage 1's evidence snippets
SNIPPET_RADIUS: Final = 60  # around a match, as Stage 2
MAX_EVIDENCE: Final = 20
MAX_NETWORK_EVIDENCE: Final = 50
MAX_ORIGINS: Final = 10  # origins named in one explanation

Item = tuple[str, str | None, str | None]  # evidence path, snippet, after


# --- small helpers ---------------------------------------------------------------------------


def visible(text: str) -> str:
    """Escape every character that isn't printable (controls, bidirectional overrides,
    zero-width and line-separator characters, lone surrogates), so evidence reads as what it
    is."""
    return "".join(
        c if c.isprintable() else (f"\\u{ord(c):04x}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08x}")
        for c in text
    )


def clip(text: str, limit: int = SNIPPET_LIMIT) -> str:
    """Capped and made visible. The cap is applied before and after escaping, so a string of
    escapes can't grow past it."""
    shown = visible(text[:limit])[:limit]
    return shown if len(text) <= limit else f"{shown}... [{len(text) - limit} more chars]"


def window(text: str, start: int, end: int) -> str:
    """The part of `text` around a match, as Stage 2 shows it."""
    lo, hi = max(0, start - SNIPPET_RADIUS), min(len(text), end + SNIPPET_RADIUS)
    return clip(("..." if lo else "") + text[lo:hi] + ("..." if hi < len(text) else ""))


_ASCII_LOWER: Final = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def ascii_lower(text: str) -> str:
    """Lowercase A-Z only: unlike `str.lower`, never changes the length (DNS names are
    case-insensitive only in ASCII)."""
    return text.translate(_ASCII_LOWER)


def basename(path: str | None) -> str:
    return posixpath.basename((path or "").rstrip("/"))


def command(argv: Sequence[str]) -> str:
    """A command line for evidence."""
    return clip(shlex.join(argv)) if argv else ""


def shannon_entropy(text: str) -> float:
    """Bits per character. (No shared entropy helper exists in `util/` yet; Stage 2 uses
    character-class tests instead.)"""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def under_image(path: str | None) -> bool:
    """Inside the image's system directories, after resolving `..` (so `/usr/../tmp/npm`
    isn't). `//usr` stays `//usr` under POSIX rules: not image."""
    if not path or not path.startswith("/"):
        return False
    return posixpath.normpath(path).startswith(IMAGE_ROOTS)


def normal(path: str) -> str:
    """Absolute and normalised (`..` resolved). package-analysis joins `openat` paths with the
    directory gVisor reports, so recorded paths are absolute except for plain `open`/`stat`
    of a relative name, whose directory is unknown; those are kept relative."""
    if not path.startswith("/"):
        return posixpath.normpath(path)
    return "/" + posixpath.normpath(path).lstrip("/")


def _inside(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory.rstrip("/") + "/")


# --- the observation model -------------------------------------------------------------------


ExecTest = Callable[[Sequence[str]], bool]  # a predicate over a command's argv


def _order(o: Observation) -> tuple[object, ...]:
    """A total order over observations, so input order never changes a finding."""
    return (
        PHASES.index(o.phase),
        o.kind.value,
        o.source,
        o.argv,
        o.env,
        o.path or "",
        o.flags,
        o.address or "",
        -1 if o.port is None else o.port,
        o.host or "",
        o.detail or "",
    )


def expected_tarball(job: SandboxJob) -> str:
    """Where package-analysis puts the exported tarball in the sandbox, and so the one argument
    its driver's `npm install` has: `scripts/run_analysis.sh` mounts `-local <path>` at
    `/<basename>` and `cmd/analyze` copies it to the same path inside the sandbox; Kitsunox
    exports every tarball as `<key>.tgz` (`spool._entry`)."""
    return f"/{job.key}.tgz"


def shipped_paths(names: Iterable[str]) -> frozenset[str]:
    """A tarball's file list as npm unpacks it into the package directory: the paths with the
    top directory stripped (`extract_tar_gz(strip_components=1)`), normalised, `./` dropped.
    Unsafe names (absolute, `..`) are dropped too: npm doesn't unpack them either."""
    found: set[str] = set()
    for name in names:
        path = posixpath.normpath(name)
        if path.startswith(("/", "../")) or path in (".", ".."):
            continue
        found.add(path)
    return frozenset(found)


PACKAGE_ORIGIN: Final = "in the package"


def module_chain(path: str) -> tuple[tuple[str, ...], str] | None:
    """For a normalised path under `/app/node_modules`: the package names along its
    `node_modules/<name>` chain, outermost first (a scope and its name are one), and the rest
    of the path inside the innermost package (`node_modules/.bin/x` when the walk stops at a
    dot entry such as npm's `.bin` links or `.cache`). None outside `/app/node_modules`."""
    if not path.startswith(NODE_MODULES + "/"):
        return None
    parts = path[len(NODE_MODULES) + 1 :].split("/")
    names: list[str] = []
    i = 0
    nested = False  # parts[i] follows a package's own `node_modules/`
    while i < len(parts):
        part = parts[i]
        if not part or part.startswith("."):
            break
        if part.startswith("@"):
            if i + 1 >= len(parts) or not parts[i + 1] or parts[i + 1].startswith("."):
                break  # a scope directory itself
            names.append(f"{part}/{parts[i + 1]}")
            i += 2
        else:
            names.append(part)
            i += 1
        nested = i + 1 < len(parts) and parts[i] == "node_modules"
        if not nested:
            break
        i += 1
    # Stopped at a dot entry (or a scope) inside a package's node_modules: keep that prefix.
    rest = parts[i - 1 :] if nested else parts[i:]
    return tuple(names), "/".join(rest)


def join_label(*parts: str | None) -> str | None:
    """Evidence `after` text from optional parts, `; `-separated."""
    shown = [p for p in parts if p]
    return "; ".join(shown) if shown else None


@dataclass(frozen=True)
class Activity:
    """One result's observations, ordered and grouped by kind, with what the rules know of the
    job: the tarball's path in the sandbox, the tarball's own file list when given, and the
    dependencies Kitsunox bundled into it when it is a bundle."""

    ordered: tuple[Observation, ...]
    package_dir: str
    name: str  # `job.package`: what npm installs it as and the driver is given (lowercased)
    local_tarball: str  # `expected_tarball(job)`, unless the caller gave another path
    shipped: frozenset[str] | None  # `shipped_paths` of the tarball; None when not given
    by_kind: dict[ObservationKind, tuple[Observation, ...]]
    # Names of the packages Kitsunox bundled under the package's `node_modules/`; None: the
    # export is not a bundle.
    bundled: frozenset[str] | None = None
    # npm installed nothing under the package's own `node_modules/` (an airgapped or bundled
    # run), so the file list covers it too.
    closed_modules: bool = False

    def origin(self, path: str | None) -> str | None:
        """Whose files `path` (absolute) is among, when the path shows it: "in the package",
        "in dependency <name>", or the package's own shipped `node_modules/<name>` in a bundle.
        None outside `/app/node_modules` and for npm's `.bin` links."""
        if not path or not path.startswith("/"):
            return None
        chain = module_chain(normal(path))
        if chain is None or not chain[0]:
            return None
        names, rest = chain
        if _inside(rest, "node_modules/.bin"):
            return None
        last = clip(names[-1], 120)
        if names[0] != self.name:
            return f"in dependency {last}"  # hoisted beside the package (an online run)
        if len(names) == 1:
            return PACKAGE_ORIGIN
        if self.bundled is not None and names[-1] not in self.bundled:
            return f"in the package's own node_modules/{last} (not one Kitsunox bundled)"
        return f"in dependency {last}"

    def exec_origin(self, o: Observation) -> str | None:
        """Whose a command is, when a path shows it: the program or script it runs (absolute
        paths only), else the running package's `package.json` that npm puts in a lifecycle
        script's environment (`npm_package_json`, with `npm_lifecycle_event`): a label the
        package can forge, never proof."""
        targets = [o.argv[0]] if o.argv else []
        script = script_of(o.argv)
        if script is not None:
            targets.append(script)
        for target in targets:
            found = self.origin(target)
            if found is not None:
                return found
        values: dict[str, str] = {}
        for entry in o.env:
            key, _, value = entry.partition("=")
            values.setdefault(key, value)
        manifest = values.get("npm_package_json", "")
        if not manifest.endswith("/package.json"):
            return None
        found = self.origin(posixpath.dirname(manifest))
        if found is None:
            return None
        event = values.get("npm_lifecycle_event")
        via = "npm_package_json" + (f", {clip(event, 40)}" if event else "")
        return f"{found} (per {via})"

    def of(self, *kinds: ObservationKind) -> Iterator[Observation]:
        """The observations of these kinds, in order."""
        if len(kinds) == 1:
            return iter(self.by_kind.get(kinds[0], ()))
        wanted = frozenset(kinds)
        return (o for o in self.ordered if o.kind in wanted)

    def phases_with(self, test: ExecTest) -> frozenset[str]:
        """The phases in which some command passes `test`."""
        return frozenset(o.phase for o in self.of(K.EXEC) if test(o.argv))

    def resolutions(self, raw: str, phase: str) -> tuple[str, ...]:
        """Where a relative path may point: hooks run in the package directory (`install`),
        the driver in `/app` (both phases)."""
        if raw.startswith("/"):
            return (normal(raw),)
        dirs = (self.package_dir, APP) if phase == INSTALL else (APP, self.package_dir)
        return tuple(normal(f"{d}/{raw}") for d in dirs)

    def unshipped(self, path: str, building: bool) -> bool:
        """`path` (absolute, normalised) is a file inside the package's own directory that
        the tarball doesn't have, so npm didn't unpack it: something wrote it there. Not
        counted: where node-gyp ran (`building`), the package's `build/` directory; unless
        npm installed nothing there (`closed_modules`), anything under the package's
        `node_modules/` (nested dependencies npm installs); and npm's `.bin` links, and the
        `build/` directory of a dependency where node-gyp ran, under it. False when no file
        list was given."""
        if self.shipped is None or not path.startswith(self.package_dir + "/"):
            return False
        rel = path[len(self.package_dir) + 1 :]
        if rel.startswith("node_modules/"):
            if not self.closed_modules:
                return False
            chain = module_chain(path)
            inner = chain[1] if chain is not None else rel
            if _inside(inner, "node_modules/.bin") or (building and _inside(inner, "build")):
                return False
        elif building and _inside(rel, "build"):
            return False
        return rel not in self.shipped


def _names(given: Iterable[str] | None, what: str) -> frozenset[str] | None:
    if isinstance(given, str):  # a str is an Iterable[str] of characters: a caller's slip
        raise TypeError(f"{what} must be a collection of strings, not a string")
    return None if given is None else frozenset(given)


def analyse(
    run: SandboxRun,
    observations: Sequence[Observation],
    *,
    shipped: Iterable[str] | None = None,
    local_tarball: str | None = None,
    bundled_deps: Iterable[str] | None = None,
) -> Activity:
    """The activity model. `shipped` is the tarball's file list (paths inside the tarball
    with the top `package/` directory stripped, as `shipped_paths` takes it), `local_tarball`
    overrides `expected_tarball(run.job)`, `bundled_deps` names the packages Kitsunox bundled
    into the tarball's `node_modules/` (None: not a bundle)."""
    ordered = tuple(sorted(observations, key=_order))
    by_kind: dict[ObservationKind, list[Observation]] = {}
    for o in ordered:
        by_kind.setdefault(o.kind, []).append(o)
    job = run.job
    files = _names(shipped, "shipped")
    bundled = _names(bundled_deps, "bundled_deps")
    return Activity(
        ordered=ordered,
        package_dir=f"{NODE_MODULES}/{job.package}",
        name=job.package,
        local_tarball=expected_tarball(run.job) if local_tarball is None else local_tarball,
        shipped=None if files is None else shipped_paths(files),
        by_kind={kind: tuple(found) for kind, found in by_kind.items()},
        bundled=bundled,
        closed_modules=bundled is not None or run.network == NETWORK,
    )


# --- rule base -------------------------------------------------------------------------------


class SandboxRuleBase(BaseRule):
    """`evaluate` builds the activity model and calls `check`; `apply_rules` builds it once and
    calls `check` on every rule."""

    # 2: package-analysis observations (decision 0012 revision). 3: the exact driver, the
    # tarball file list, gyp build steps, upstream evidence named in every explanation.
    # 4: origins (package or dependency) in evidence, offline bundles, flooding cuts HIGH,
    # npx/yarn/pnpm nested installs.
    version = 4

    def evaluate(
        self,
        candidate: Candidate,
        run: SandboxRun,
        observations: Sequence[Observation],
        *,
        shipped: Iterable[str] | None = None,
        local_tarball: str | None = None,
        bundled_deps: Iterable[str] | None = None,
    ) -> Sequence[Finding]:
        activity = analyse(
            run,
            observations,
            shipped=shipped,
            local_tarball=local_tarball,
            bundled_deps=bundled_deps,
        )
        return self.check(run, activity)

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        raise NotImplementedError

    def report(
        self,
        explanation: str,
        evidence: Iterable[Item],
        *,
        severity: Severity | None = None,
        weight: float | None = None,
        limit: int = MAX_EVIDENCE,
        uses: str,
        phases: Iterable[str] = (),
        origins: Iterable[str | None] = (),
    ) -> Finding:
        """A finding with evidence deduplicated, sorted and capped (only the items kept become
        `Evidence`). `uses` names the package-analysis result sets the finding reads (Files,
        Commands, Sockets, DNS) and `phases` the phases they came from: both are stated in
        the explanation, and so are the evidence's `origins` (`Activity.origin`), every one,
        not only those of the items shown."""
        unique = sorted(set(evidence), key=lambda e: (e[0], e[1] or "", e[2] or ""))
        ran = sorted(set(phases), key=_phase_rank)
        where = sorted({o for o in origins if o})
        text = explanation
        if where:
            shown = "; ".join(where[:MAX_ORIGINS])
            more = f"; and {len(where) - MAX_ORIGINS} more" if len(where) > MAX_ORIGINS else ""
            text += f" Where the paths show it: {shown}{more}."
        text += f" Upstream evidence: package-analysis {uses}"
        text += f" ({', '.join(ran)})." if ran else "."
        if len(unique) > limit:
            text += f" Showing {limit} of {len(unique)} items."
        return Finding(
            rule_id=self.id,
            rule_version=self.version,
            severity=severity or self.severity,
            weight=self.weight if weight is None else weight,
            title=self.title,
            explanation=text,
            evidence=tuple(
                Evidence(kind=EvidenceKind.METADATA, path=p, snippet=s, after=a)
                for p, s, a in unique[:limit]
            ),
        )


def _phase_rank(phase: str) -> tuple[int, str]:
    return (PHASES.index(phase) if phase in PHASES else len(PHASES), phase)


# --- run status --------------------------------------------------------------------------------


# The importer's caps (`SandboxRun.cuts`), what each count means, in `Cut` order. The count
# caps (`FLOOD_CUTS`) sit far above anything a benign install records (thousands of arguments
# or environment entries in one command, 64 names for one address, 100,000 observations), so
# reaching one is a signal: a sample flooding the record to push evidence past the cut.
CUT_TEXT: Final[dict[str, str]] = {
    "field_chars": f"strings cut at {MAX_FIELD_CHARS} characters",
    "name_chars": f"addresses, names or DNS types cut at {MAX_NAME_CHARS} characters",
    "argv_items": f"commands with over {MAX_ARGV} arguments",
    "env_items": f"commands with over {MAX_ENV} environment entries",
    "hostnames": f"sockets with over {MAX_HOSTNAMES} names",
    "dns_types": f"DNS questions with over {MAX_TYPES} types",
    "output_bytes": f"output tails over {STDIO_BYTES} bytes",
    "forged_drivers": "driver-shaped commands with other bait values (forged, ignored)",
    "bait_mismatch": "phases whose drivers carry different baits",
    "observations": f"observations dropped over the {MAX_OBSERVATIONS} cap",
}
FLOOD_CUTS: Final[tuple[str, ...]] = ("argv_items", "env_items", "hostnames", "observations")
_CUT_ORDER: Final[tuple[str, ...]] = get_args(Cut)


def _cut_rank(cut: str) -> tuple[int, str]:
    return (_CUT_ORDER.index(cut) if cut in _CUT_ORDER else len(_CUT_ORDER), cut)


def cut_summary(run: SandboxRun, which: Iterable[str] | None = None) -> str:
    """The caps hit (all, or those in `which`), in `Cut` order, with their counts:
    `commands with over 4096 arguments: 2, ...`."""
    wanted = None if which is None else frozenset(which)
    hit = sorted((k for k, n in run.cuts.items() if n > 0), key=_cut_rank)
    return ", ".join(
        f"{CUT_TEXT.get(k, k)}: {run.cuts[k]}" for k in hit if wanted is None or k in wanted
    )


def flooded(run: SandboxRun) -> tuple[str, ...]:
    """The count caps the importer hit (`FLOOD_CUTS`, in order)."""
    return tuple(k for k in FLOOD_CUTS if any(c == k and n > 0 for c, n in run.cuts.items()))


def cut_groups(run: SandboxRun) -> str:
    """The (phase, kind) groups the observation cap cut, with recorded and kept counts
    (`SandboxRun.groups`)."""
    return ", ".join(
        f"{g.phase} {g.kind.value}: {g.recorded} recorded, {g.kept} kept"
        for g in run.groups
        if g.kept < g.recorded
    )


def truncation(run: SandboxRun) -> str | None:
    """Why the record is incomplete, or None: the importer hit its caps (the sample chooses
    how much it records; each cap is named with its count), or a phase timed out
    (`error_timeout`, never assigned at rel-38, which enforces no npm timeout; kept for later
    pins)."""
    reasons: list[str] = []
    if run.truncated:
        cuts = cut_summary(run)
        reasons.append(
            f"the importer hit its caps ({cuts}; {run.observation_count} observations kept)"
            if cuts
            else f"the importer dropped observations over its cap ({run.observation_count} kept)"
        )
    timed_out = [p.phase for p in run.phases if p.status == "error_timeout"]
    if run.status == "timeout" or timed_out:
        reasons.append("timed out" + (f" during {', '.join(timed_out)}" if timed_out else ""))
    return "; ".join(reasons) or None


def failure(run: SandboxRun) -> str | None:
    """Why the analysis did not complete normally, or None: the run's status, else the phases
    that didn't complete (a failed `install` means `import` never ran)."""
    if run.status != "completed":
        return f"run status {run.status}"
    failed = [f"{p.phase} {p.status}" for p in run.phases if p.status != "completed"]
    return ("phase " + ", ".join(failed)) if failed else None


def tail(text: str, limit: int = SNIPPET_LIMIT) -> str:
    """The end of a stream (where npm's verdict is), capped and made visible."""
    if len(text) <= limit:
        return clip(text)
    return f"[{len(text) - limit} chars before] ..." + visible(text[-limit:])[-limit:]


class Ran(SandboxRuleBase):
    """What ran and how each phase ended, with the end of each phase's output (package-analysis
    keeps the last 4 KiB). Context for the reviewer; not scored. An `install` that failed (npm
    exited non-zero) means `import` never ran: the package's main code is unseen."""

    id = "sandbox.ran"
    severity = Severity.INFO
    weight = 0.0
    title = "Package run in the package-analysis sandbox"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        job = run.job
        phases = ", ".join(f"{p.phase} ({p.status})" for p in run.phases)
        kinds = Counter(f"{o.phase}/{o.kind.value}" for o in activity.ordered)
        counted = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) or "none"
        cut = truncation(run)
        failed = failure(run)
        text = (
            f"Run {run.status} ({job.analyser}): {phases or 'no phases recorded'}. "
            f"Declared install hooks: {', '.join(job.hooks) or 'none'}. "
            f"{len(activity.ordered)} observations ({counted})"
            + (f"; incomplete: {cut}" if cut else "")
            + (f"; not completed: {failed}" if failed else "")
            + (f"; bait values masked: {clip(', '.join(run.canaries))}" if run.canaries else "")
            + ". "
            + (
                f"Tarball file list: {len(activity.shipped)} paths."
                if activity.shipped is not None
                else "Tarball file list not given: a file a hook drops into its own package "
                "directory during install is not counted by sandbox.download-exec."
            )
            + (
                f" Kitsunox bundle: {len(activity.bundled)} dependencies added under the "
                "package's node_modules (the analysis saw the bundle, not the registry tarball)."
                if activity.bundled is not None
                else ""
            )
        )
        evidence: list[Item] = [("sandbox", clip(f"{job.key} result {run.result_sha256}"), None)]
        for p in run.phases:
            for stream, text_ in (("stdout", p.stdout), ("stderr", p.stderr)):
                if text_:
                    evidence.append((f"output ({p.phase} {stream})", tail(text_), None))
        return (
            self.report(
                text,
                evidence,
                uses="phase Status, Stdout and Stderr, and the counts of Commands, Files, "
                "Sockets and DNS",
                phases=(p.phase for p in run.phases),
            ),
        )


class Truncated(SandboxRuleBase):
    """The record is incomplete: the importer hit one of its caps (`SandboxRun.cuts`), or a
    phase timed out. What happened after the cut is unseen; scored, so a cut record never reads
    as quiet.

    - **Flooding** (HIGH, weight 5): a count cap was hit (`FLOOD_CUTS`: a command with over
      4096 arguments or 1024 environment entries, a socket with over 64 names, over 100,000
      observations). Benign installs never come near these; a sample that reaches them is
      most likely padding the record so its evidence falls past the cut.
    - **Otherwise** (MEDIUM, weight 3): a long string cut at its length cap, an output tail
      over 4 KiB, too many DNS types or bait values, a timeout.

    The explanation names every cap that fired and its count."""

    id = "sandbox.truncated"
    # 2: flooding (count caps) HIGH, every cap named with its count.
    version = 2
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Sandbox record was cut"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        cut = truncation(run)
        if cut is None:
            return ()
        text = (
            f"The record is incomplete; what happened after the cut is unseen. Why: {cut}. "
            f"{len(activity.ordered)} observations recorded."
        )
        flood = flooded(run)
        if flood:
            groups = cut_groups(run)
            text += (
                f" Flooding: count caps hit ({cut_summary(run, flood)})"
                + (f"; groups cut: {groups}" if groups else "")
                + ". Benign installs never record that much, so the sample likely padded the "
                "record to push evidence past the cut."
            )
        return (
            self.report(
                text,
                (),
                severity=Severity.HIGH if flood else None,
                weight=5.0 if flood else None,
                uses="phase Status and the importer's caps",
                phases=(p.phase for p in run.phases),
            ),
        )


class Quiet(SandboxRuleBase):
    """The run completed, every phase recorded completed, the record is whole, and nothing
    above INFO fired. Never an all-clear: malware detects sandboxes, waits, or needs what the
    sandbox doesn't have (a token, CI variables, a call of one exported function)."""

    id = "sandbox.quiet"
    severity = Severity.INFO
    weight = 0.0
    title = "No behavior observed in the sandbox"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        found = [f for rule in DETECTION_RULES for f in rule.check(run, activity)]
        return self.after(run, found)

    def after(self, run: SandboxRun, findings: Sequence[Finding]) -> tuple[Finding, ...]:
        ran = [p.phase for p in run.phases]
        if (
            not ran
            or failure(run) is not None
            or truncation(run) is not None
            or any(f.severity is not Severity.INFO for f in findings)
        ):
            return ()
        text = f"No behavior observed; not evidence of safety. Phases run: {', '.join(ran)}."
        return (self.report(text, (), uses="Commands, Files, Sockets and DNS", phases=ran),)


# --- programs ----------------------------------------------------------------------------------


def _image_or_bare(word: str, names: Iterable[str]) -> bool:
    """`word` is one of `names` given bare (found on PATH, the image's) or as an image path."""
    return basename(word) in names and ("/" not in word or under_image(word))


def is_node(word: str) -> bool:
    return _image_or_bare(word, ("node", "nodejs"))


def npm_args(argv: Sequence[str]) -> tuple[str, ...] | None:
    """npm's arguments when `argv` runs the image's npm, as typed (`npm init`) or as the
    interpreter line its `#!/usr/bin/env node` shebang turns into (`node /usr/bin/npm init`)."""
    if not argv:
        return None
    if _image_or_bare(argv[0], ("npm",)):
        return tuple(argv[1:])
    if (
        is_node(argv[0])
        and len(argv) >= 2
        and under_image(argv[1])
        and basename(argv[1]) in ("npm", "npm-cli.js")
    ):
        return tuple(argv[2:])
    return None


# npm options that take a separate value (`npm --registry x publish`).
NPM_VALUE_OPTIONS: Final = frozenset(
    {"--registry", "--userconfig", "--globalconfig", "--prefix", "-C", "--cache", "--tag"}
    | {"--access", "--otp", "--workspace", "-w", "--loglevel", "--scope", "--auth-type"}
)


def operands(args: Sequence[str], value_options: frozenset[str]) -> list[str]:
    """The words that aren't options or the value of an option in `value_options`."""
    skip = False
    words: list[str] = []
    for word in args:
        if skip:
            skip = False
        elif word.startswith("-"):
            skip = "=" not in word and word in value_options
        else:
            words.append(word)
    return words


def npm_command(args: Sequence[str]) -> tuple[str | None, list[str]]:
    """npm's command (the first word that isn't an option or an option's value) and the words
    after it, also without options."""
    words = operands(args, NPM_VALUE_OPTIONS)
    return (words[0], words[1:]) if words else (None, [])


def npm_split(args: Sequence[str]) -> tuple[str | None, tuple[str, ...], tuple[str, ...]]:
    """npm's command, the options given before it, and every word after it (options
    included), as typed."""
    skip = False
    for i, word in enumerate(args):
        if skip:
            skip = False
        elif word.startswith("-"):
            skip = "=" not in word and word in NPM_VALUE_OPTIONS
        else:
            return word, tuple(args[:i]), tuple(args[i + 1 :])
    return None, tuple(args), ()


def npx_args(argv: Sequence[str]) -> tuple[str, ...] | None:
    """npx's arguments when `argv` runs the image's npx (`npx x`, or `node /usr/bin/npx x`,
    `node <image>/npx-cli.js x`, the line its shebang turns into). npx is `npm exec`."""
    if not argv:
        return None
    if _image_or_bare(argv[0], ("npx",)):
        return tuple(argv[1:])
    if (
        is_node(argv[0])
        and len(argv) >= 2
        and under_image(argv[1])
        and basename(argv[1]) in ("npx", "npx-cli.js")
    ):
        return tuple(argv[2:])
    return None


# `npm exec` and npx options that take a value (npx-cli.js's `opts`, and npm's): `--package`
# (npx's `-p`) names a package to install; the others are skipped.
EXEC_VALUE_OPTIONS: Final = NPM_VALUE_OPTIONS | frozenset(
    {"--package", "--call", "-c", "--userconfig", "--script-shell", "--shell", "--node-arg"}
)


def exec_specs(args: Sequence[str], *, npx: bool) -> list[str]:
    """The package specs `npm exec` (or npx) installs: every `--package` value (npx's `-p`
    too), or, when there is none, the first positional word (`npm exec <pkg> [args]`, also
    after `--`). The words after it are the command's arguments, not packages."""
    packages: list[str] = []
    positional: str | None = None
    i = 0
    while i < len(args):
        word = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if word == "--":
            positional = nxt
            break
        if not word.startswith("-"):
            positional = word
            break
        key, eq, value = word.partition("=")
        if key == "--package" or (npx and key == "-p"):
            if eq:
                packages.append(value)
            elif nxt is not None:
                packages.append(nxt)
                i += 1
        elif not eq and word in EXEC_VALUE_OPTIONS:
            i += 1
        i += 1
    if packages:
        return packages
    return [positional] if positional else []


# npm options that install somewhere other than the project: into a prefix or globally.
NPM_ELSEWHERE: Final = frozenset({"-g", "--global", "--prefix", "-C", "--location"})
NPM_INSTALL: Final = frozenset({"install", "i", "in", "isntall", "add"})


def install_elsewhere(options: Sequence[str]) -> str | None:
    """The option (as typed) with which an npm install goes into another prefix or the global
    directory (`-g`, `--global`, `--prefix <dir>`, `-C <dir>`, `--location=global`), or
    None. `--global=false` and `--location=project` stay in the project."""
    for i, word in enumerate(options):
        key, eq, value = word.partition("=")
        if key not in NPM_ELSEWHERE:
            continue
        if key == "--location":
            where = value if eq else (options[i + 1] if i + 1 < len(options) else "")
            if where in ("global", "user"):
                return f"{key} {where}"
            continue
        if key in ("-g", "--global") and eq and value in ("false", "0", ""):
            continue
        return key
    return None


# yarn and pnpm (not in package-analysis's image: a package that runs them brought them or
# runs them through corepack). Their commands that add packages, and their options with a
# separate value.
YARN_PNPM: Final = frozenset({"yarn", "yarnpkg", "pnpm", "pnpx"})
YARN_ADD: Final = frozenset({"add", "dlx"})
PNPM_ADD: Final = frozenset({"add", "install", "i", "dlx"})
YARN_PNPM_VALUE_OPTIONS: Final = frozenset(
    {"--cwd", "--dir", "-C", "--registry", "--filter", "-F", "--modules-folder", "--prefix"}
    | {"--global-folder", "--store-dir", "--cache-folder", "--global-dir", "--package"}
)


def yarn_pnpm_specs(argv: Sequence[str]) -> tuple[str, list[str]] | None:
    """`(tool command, specs)` when `argv` runs yarn or pnpm (any path, `node <x>/yarn.js`,
    or `corepack yarn`) with a command that adds packages: `yarn add`, `yarn global add`,
    `yarn dlx`, `pnpm add`, `pnpm install <spec>`, `pnpm dlx`, `pnpx <spec>`. None
    otherwise."""
    words = list(argv)
    if words and basename(words[0]) == "corepack":
        words = words[1:]
    if len(words) >= 2 and program(words) in ("node", "nodejs"):
        words = words[1:]  # node running the tool's script
    if not words:
        return None
    tool = basename(words[0])
    for suffix in (".js", ".cjs", ".mjs"):
        tool = tool.removesuffix(suffix)
    if tool not in YARN_PNPM:
        return None
    found = operands(words[1:], YARN_PNPM_VALUE_OPTIONS)
    if tool == "pnpx":
        return ("pnpx", found[:1])
    if tool.startswith("yarn") and found[:1] == ["global"]:
        found = found[1:]
    if not found:
        return None
    name = found[0]
    adds = PNPM_ADD if tool == "pnpm" else YARN_ADD
    if name not in adds:
        return None
    specs = found[1:2] if name == "dlx" else found[1:]
    return (f"{'yarn' if tool.startswith('yarn') else 'pnpm'} {name}", specs)


# npm commands that act on the account or the registry's packages: what a worm runs with a
# stolen token. `publish` is `sandbox.npm-publish`'s.
NPM_ACCOUNT: Final = frozenset(
    {"whoami", "token", "owner", "author", "access", "adduser", "add-user", "login", "logout"}
    | {"profile", "team", "org", "dist-tag", "dist-tags", "deprecate", "unpublish", "star"}
)
# npm commands that download and run, or install, more packages at run time (a dropper's).
NPM_FETCH: Final = frozenset({"exec", "x", "install", "i", "in", "isntall", "add", "ci"})
# The phases analyze-node.js accepts (`all` runs every phase in one call).
DRIVER_PHASES: Final = frozenset({*PHASES, "all"})


def is_driver(argv: Sequence[str], local_tarball: str, name: str) -> bool:
    """package-analysis's own commands for this job, exactly as its driver issues them
    (sandboxes/dynamicanalysis/analyze-node.js and internal/dynamicanalysis/sandbox_args.go at
    rel-38): the driver with `--local <the exported tarball> <phase> <name>` (run directly, or
    as the node line its shebang becomes); `npm init --force`; `npm install <the exported
    tarball>`, that one path and nothing else; the sandbox's `sleep 30m` entrypoint (with
    podman's init in front of it). `local_tarball` is `expected_tarball(job)`; `name` is the
    package name, which package-analysis lowercases."""
    if not argv:
        return False
    rest: Sequence[str] | None = None
    if argv[0] == DRIVER:
        rest = argv[1:]
    elif is_node(argv[0]) and len(argv) >= 2 and argv[1] == DRIVER:
        rest = argv[2:]
    if rest is not None:
        return (
            len(rest) == 4
            and rest[0] == "--local"
            and rest[1] == local_tarball
            and rest[2] in DRIVER_PHASES
            and rest[3] in (name, ascii_lower(name))
        )
    if tuple(argv) in (("sleep", "30m"), ("/run/podman-init", "--", "sleep", "30m")):
        return True
    args = npm_args(argv)
    if args is None:
        return False
    return list(args) in (["init", "--force"], ["install", local_tarball])


def is_node_gyp(argv: Sequence[str]) -> bool:
    """node-gyp as npm ships it: `node-gyp ...`, npm's `node-gyp-bin` shim run by `sh`, or node
    running an image `node-gyp.js`."""
    if not argv:
        return False
    if _image_or_bare(argv[0], ("node-gyp",)):
        return True
    if len(argv) >= 2 and (is_node(argv[0]) or _image_or_bare(argv[0], ("sh", "dash"))):
        return under_image(argv[1]) and basename(argv[1]) in ("node-gyp", "node-gyp.js")
    return False


# Exact command lines in package-analysis's own known-good list for npm (docs/queries.md at
# rel-38, "Exec'd Commands"), beyond those `is_driver`, `is_node`, `is_node_gyp` and the shell
# rule already allow.
KNOWN_GOOD: Final = frozenset(
    {
        ("node-gyp-build",),
        ("node-gyp-build-test",),
        (f"{NODE_MODULES}/esbuild/bin/esbuild", "--version"),
        ("python", "-c", "import sys; print(sys.executable);"),
        ("python2", "-c", "import sys; print(sys.executable);"),
        ("python3", "-c", "import sys; print(sys.executable);"),
    }
)
# esbuild's install check (`<esbuild>/bin/esbuild --version`, in KNOWN_GOOD for the hoisted
# path) wherever npm or a Kitsunox bundle put esbuild under `/app/node_modules`.
ESBUILD_BIN: Final = re.compile(
    rf"{re.escape(NODE_MODULES)}/(?:(?:@[^/]+/)?[^/.][^/]*/node_modules/)*esbuild/bin/esbuild"
)
# What node-gyp runs to build an addon: make, the compiler driver and the programs the driver
# runs, and the probes gyp makes (`uname`, `which`). Expected only in a phase where node-gyp
# itself ran, and only as bare names or image paths. Arguments aren't checked: a compiler
# reads headers from node-gyp's cache and writes objects anywhere in the build.
BUILD_TOOL: Final = re.compile(
    r"(?:(?:x86_64|aarch64)-linux-gnu-)?(?:gcc|g\+\+|cc|c\+\+|cpp|as|ld|ar|ranlib|strip)"
    r"(?:-\d+)?|cc1|cc1plus|collect2|lto-wrapper|ld\.bfd|ld\.gold|make|gmake"
    r"|uname|which|clang(?:\+\+)?(?:-\d+)?"
)
# The file tools the Makefiles gyp generates run (`mkdir -p` for every target; `touch`, `sed`,
# `grep` and `rm` in fixup_dep; `ln -f`, `rm -rf`, `cp -af` and `mv` in cmd_copy and the
# link steps). Expected only where node-gyp ran, and only with arguments that stay in the
# build (`build_arguments`).
BUILD_FILE_TOOLS: Final = frozenset({"mkdir", "touch", "sed", "grep", "rm", "ln", "cp", "mv"})
# Where those tools' path arguments may point: the project (`/app`, where the package and its
# build are), the sandbox's /tmp, /dev/null, and node-gyp's header caches.
BUILD_ROOTS: Final = (APP, SANDBOX_TMP, "/dev/null", f"{HOME}/.cache/node-gyp", f"{HOME}/.node-gyp")
# Options whose next word is a pattern or a script, not a path (`sed -e`, `grep -e`).
BUILD_PATTERN_OPTIONS: Final = frozenset({"-e", "--expression", "--regexp", "-f", "--file"})
PYTHON: Final = re.compile(r"python[23]?(?:\.\d+)?")
# node-gyp's find-python probes (lib/find-python.js: the executable, then its version), run
# with each candidate python, bare or by the path the first probe printed.
GYP_PYTHON_PROBES: Final = frozenset(
    {
        ("-c", "import sys; sys.stdout.buffer.write(sys.executable.encode('utf-8'));"),
        ("-c", 'import sys; print("%s.%s.%s" % sys.version_info[:3]);'),
        ("-c", "import sys; print(sys.executable);"),
    }
)
GYP_MAIN: Final = "/node_modules/node-gyp/gyp/gyp_main.py"
GYP_FLOCK_TOOL: Final = "gyp-flock-tool"  # written into build/ by gyp, run by link steps


def on_path(word: str) -> bool:
    """A bare name, an image path, or a path in one of the sandbox's PATH directories
    (`/app/.pyenv/bin/python3`, the python node-gyp finds through `sys.executable`)."""
    return "/" not in word or under_image(word) or posixpath.dirname(word) in SANDBOX_PATH


def build_arguments(argv: Sequence[str], package_dir: str) -> bool:
    """A build file tool's arguments stay in the build: no URL, and every path (absolute, or
    relative with `..`, resolved from the package's `build/` directory, where make runs)
    inside `BUILD_ROOTS`. A pattern (the first operand of `sed` and `grep`, or the word after
    `-e`) is not a path."""
    pattern = program(argv) in ("sed", "grep")
    skip = False
    for word in argv[1:]:
        if "://" in word:
            return False
        if skip:
            skip = False
            continue
        if word in BUILD_PATTERN_OPTIONS:
            skip, pattern = True, False
            continue
        if word.startswith("-"):
            continue
        if pattern:
            pattern = False
            continue
        if word.startswith("~"):
            return False
        if word.startswith("/") or ".." in word.split("/"):
            path = normal(word if word.startswith("/") else f"{package_dir}/build/{word}")
            if not any(_inside(path, root) for root in BUILD_ROOTS):
                return False
    return True


def is_build_step(argv: Sequence[str], package_dir: str) -> bool:
    """A command node-gyp's build runs (call only in a phase where node-gyp ran): make or the
    compiler toolchain; a gyp file tool with in-build arguments; gyp itself
    (`python3 <image>/node_modules/node-gyp/gyp/gyp_main.py`); gyp's `gyp-flock-tool`, run
    directly from the build directory or through python. Never a downloader, a shell other
    than `sh -c`, or python running anything else."""
    if not argv or (not on_path(argv[0]) and basename(argv[0]) != GYP_FLOCK_TOOL):
        return False
    name = program(argv)
    if BUILD_TOOL.fullmatch(name):
        return "/" not in argv[0] or under_image(argv[0])
    if name in BUILD_FILE_TOOLS:
        return ("/" not in argv[0] or under_image(argv[0])) and build_arguments(argv, package_dir)
    if name == GYP_FLOCK_TOOL:
        return _flock_tool(argv[0], package_dir) and build_arguments(argv, package_dir)
    if PYTHON.fullmatch(name) and len(argv) >= 2:
        if tuple(argv[1:]) in GYP_PYTHON_PROBES:
            return True
        script = argv[1]
        if under_image(script) and script.endswith(GYP_MAIN):
            return True
        return _flock_tool(script, package_dir) and build_arguments(argv[1:], package_dir)
    return False


def _flock_tool(path: str, package_dir: str) -> bool:
    """gyp's flock tool, as make's recipes name it (`./gyp-flock-tool`, from `build/`) or by
    its path in the package's build directory."""
    return path == f"./{GYP_FLOCK_TOOL}" or normal(path) == f"{package_dir}/build/{GYP_FLOCK_TOOL}"


SHELLS: Final = ("sh", "dash")


def is_shell_c(argv: Sequence[str]) -> bool:
    """`sh -c <command>`: how npm runs a lifecycle script and how `child_process.exec` runs a
    command. The shell itself is plumbing; the programs it starts are their own execs."""
    return len(argv) >= 3 and _image_or_bare(argv[0], SHELLS) and argv[1] == "-c"


def program(argv: Sequence[str]) -> str:
    return basename(argv[0]) if argv else ""


# --- the rules -------------------------------------------------------------------------------


# The result set each observation kind comes from, as package-analysis names it.
UPSTREAM_SET: Final = {K.EXEC: "Commands", K.OPEN: "Files", K.CONNECT: "Sockets", K.DNS: "DNS"}

# The importer's mask for a bait value (`ossf.CANARY_MARK`), for each bait variable.
BAIT_MARK: Final = re.compile(
    "|".join(re.escape(CANARY_MARK.format(name=name)) for name in CANARY_VARS)
)
AWS_KEY_ID: Final = re.compile(r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])")
AWS_KEY_ID_DNS: Final = re.compile(r"akia[a-z0-9]{16}")
PRIVATE_KEY: Final = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
BAIT: Final = "bait value"


class BaitExfil(SandboxRuleBase):
    """package-analysis's planted credentials where only exfiltration or staging puts them.

    - **The bait values** (CRITICAL). package-analysis plants random `AWS_ACCESS_KEY_ID` and
      `AWS_SECRET_ACCESS_KEY` values in the environment; the importer finds them there and
      masks every copy as `[canary:<NAME>]` (`SandboxRun.canaries`). A mask in a command line
      (`curl -d "$AWS_SECRET_ACCESS_KEY"`), a DNS name, a file path, or another environment
      variable (`DATA=<the value>`) means the value was read and passed on. Its own variable in
      every child's environment is where it was planted, and is not evidence.
    - **Their shape** (HIGH): an AWS access key ID (`AKIA` + 16) in a command line, a DNS name
      (case-insensitive) or a file path, or a PEM private key header (the planted
      `/root/.ssh/id_rsa`) in a command line. This catches a copy the importer didn't mask,
      and a key the package hard-codes, which is just as suspicious.

    Encoded copies (base64, hex) are not matched; hex in a DNS name is
    `sandbox.dns-tunnel-shape`'s. A value sent from JavaScript over HTTPS is not recorded at
    all (package-analysis keeps no payloads)."""

    id = "sandbox.bait-exfil"
    version = 2  # 2: command origins in evidence
    severity = Severity.CRITICAL
    weight = 10.0
    title = "Planted credential passed on by the package"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        evidence: list[Item] = []
        phases: set[str] = set()
        sets: set[str] = set()
        origins: list[str | None] = []
        planted = False
        for o in activity.of(K.EXEC, K.DNS, K.OPEN):
            origin = activity.exec_origin(o) if o.kind is K.EXEC else None
            for where, text, pattern, what in self._haystacks(o):
                match = pattern.search(text)
                if match is not None:
                    phases.add(o.phase)
                    sets.add(UPSTREAM_SET[o.kind])
                    origins.append(origin)
                    planted |= what == BAIT
                    evidence.append(
                        (
                            f"{where} ({o.phase})",
                            window(text, *match.span()),
                            join_label(what, origin),
                        )
                    )
        if not evidence:
            return ()
        uses = " and ".join(sorted(sets))
        if planted:
            return (
                self.report(
                    "A value package-analysis planted for this run (masked by the importer) "
                    "was passed to a command, a DNS name or a file path.",
                    evidence,
                    uses=uses,
                    phases=phases,
                    origins=origins,
                ),
            )
        return (
            self.report(
                "Text shaped like an AWS key or an SSH private key in a command line, a DNS "
                "name or a file path. The planted values were not found there: this may be an "
                "unmasked copy or a key the package carries.",
                evidence,
                severity=Severity.HIGH,
                weight=5.0,
                uses=uses,
                phases=phases,
                origins=origins,
            ),
        )

    @staticmethod
    def _haystacks(o: Observation) -> Iterator[tuple[str, str, re.Pattern[str], str]]:
        if o.kind is K.EXEC:
            for arg in o.argv:
                yield "command line", arg, BAIT_MARK, BAIT
                yield "command line", arg, AWS_KEY_ID, "AWS access key ID"
                yield "command line", arg, PRIVATE_KEY, "private key"
            for entry in o.env:
                name, _, value = entry.partition("=")
                own = CANARY_MARK.format(name=name)
                for mark in BAIT_MARK.finditer(value):
                    if mark.group() != own:  # a bait copied into another variable
                        yield f"environment variable {clip(name, 64)}", value, BAIT_MARK, BAIT
                        break
        elif o.kind is K.DNS and o.host:
            yield "dns name", o.host, BAIT_MARK, BAIT
            yield "dns name", ascii_lower(o.host), AWS_KEY_ID_DNS, "AWS access key ID"
        elif o.kind is K.OPEN and o.path:
            yield "file path", o.path, BAIT_MARK, BAIT
            yield "file path", o.path, AWS_KEY_ID, "AWS access key ID"


REGISTRY_HOSTS: Final = frozenset({"npmjs.org", "npm.pkg.github.com"})
URL_HOST: Final = re.compile(r"^[a-z][a-z0-9+.-]*://(?:[^/?#@]*@)?([^/?#:]*)", re.IGNORECASE)
SHELL_SEPARATORS: Final = re.compile(r"[;&|\n()`]")
HTTP_CLIENTS: Final = frozenset({"curl", "wget", "wget2", "http", "https", "xh"})
UPLOAD_FLAGS: Final = frozenset({"-T", "--upload-file", "--method=PUT", "--method=put"})


def registry_like(host: str) -> bool:
    """A host that serves the npm registry API: `registry.npmjs.org` and other `*.npmjs.org`,
    `npm.pkg.github.com`, or any `registry.*` (a worm can pass `--registry`)."""
    name = _host_name(host)
    return (
        name in REGISTRY_HOSTS
        or name.endswith(".npmjs.org")
        or (name.startswith("registry.") and len(name) > len("registry."))
    )


def _uploads_to_registry(words: Sequence[str]) -> bool:
    """An HTTP client command that PUTs to a registry-like URL (`curl -X PUT
    https://registry.npmjs.org/x`, `curl -T x.tgz ...`, `wget --method=PUT ...`)."""
    if not words or basename(words[0]) not in HTTP_CLIENTS:
        return False
    hosts = [m.group(1) for w in words if (m := URL_HOST.match(w))]
    if not any(registry_like(h) for h in hosts):
        return False
    return any(
        w in UPLOAD_FLAGS
        or w.upper() in ("-XPUT", "--REQUEST=PUT", "PUT")  # `PUT` alone: httpie's `http PUT url`
        or (w in ("-X", "--request") and i + 1 < len(words) and words[i + 1].upper() == "PUT")
        for i, w in enumerate(words)
    )


def _words_publish(words: Sequence[str]) -> bool:
    """Any npm (the image's or not: `node /usr/bin/npm publish`, `./npm publish`) whose
    command is `publish`, or an HTTP client uploading to a registry."""
    return any(
        basename(w) in ("npm", "npm-cli.js") and npm_command(words[i + 1 :])[0] == "publish"
        for i, w in enumerate(words)
    ) or _uploads_to_registry(words)


def publishes(argv: Sequence[str]) -> bool:
    """`npm publish` (or node running npm-cli.js with `publish`), or an HTTP client PUT to a
    registry, as the exec itself or inside a shell command string in its argv
    (`sh -c "cd x && npm publish"`)."""
    if _words_publish(argv):
        return True
    for arg in argv:
        if not ("publish" in arg or "PUT" in arg.upper() or "-T" in arg or "upload" in arg):
            continue
        for segment in SHELL_SEPARATORS.split(arg):
            try:
                words = shlex.split(segment)
            except ValueError:
                words = segment.split()
            if _words_publish(words):
                return True
    return False


class NpmPublish(SandboxRuleBase):
    """Worm behaviour: a command that publishes a package (`npm publish`, also through
    `node .../npm-cli.js` or a shell string) or uploads to a registry with an HTTP client.
    package-analysis records no HTTP, so a publish made from JavaScript (an HTTPS `PUT` from
    node) shows only as registry.npmjs.org traffic, which in `install` is npm's own
    (`sandbox.network` treats it as expected); in `import` it is `sandbox.network` evidence.
    The sandbox has no npm token, so a publish attempt fails, but the attempt is recorded."""

    id = "sandbox.npm-publish"
    severity = Severity.CRITICAL
    weight = 10.0
    title = "Package tries to publish to npm"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        found = [o for o in activity.of(K.EXEC) if publishes(o.argv)]
        if not found:
            return ()
        origins = [activity.exec_origin(o) for o in found]
        evidence: list[Item] = [
            (f"exec ({o.phase})", command(o.argv), where)
            for o, where in zip(found, origins, strict=True)
        ]
        return (
            self.report(
                "A command tried to publish a package.",
                evidence,
                uses="Commands",
                phases=(o.phase for o in found),
                origins=origins,
            ),
        )


# Package specs npm resolves outside the registry (npm-package-arg's types): a path, a
# tarball, a URL, a git remote or a GitHub `user/repo` shorthand.
FOREIGN_PREFIXES: Final = (
    "/", "./", "../", "~", "file:", "git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:",
    "http:", "https:", "link:", "portal:",
)  # fmt: skip
TARBALL_SUFFIXES: Final = (".tgz", ".tar.gz", ".tar")


def foreign_spec(spec: str) -> bool:
    """An npm package spec that doesn't come from the registry by name: a path, a tarball, a
    URL, a git remote or `user/repo`, also after `name@` (`x@file:../y`). `@scope/name` and
    `name@npm:other` are registry specs."""
    word = ascii_lower(spec.strip())
    at = word.find("@", 1)
    where = word[at + 1 :] if at > 0 and not word.startswith(FOREIGN_PREFIXES) else word
    return (
        where in (".", "..")
        or where.startswith(FOREIGN_PREFIXES)
        or "://" in where
        or where.endswith(TARBALL_SUFFIXES)
        or ("/" in where and not where.startswith("@") and not where.startswith("npm:"))
    )


class NestedInstall(SandboxRuleBase):
    """A second-stage install of a package from outside the registry (a local path or tarball,
    a URL, a git remote, yarn's `link:`/`portal:`; `foreign_spec`):

    - npm `install`/`add`/`ci`/... given such a spec other than this job's exported tarball,
      also with `--prefix`/`-g`/`--location=global`; and the analysed tarball itself installed
      into another prefix or globally (the driver installs it only into `/app`);
    - `npm exec`/`npm x` and npx (the image's `npx`, or node running its `npx-cli.js`) whose
      `--package` (npx's `-p`), or first positional word without one, is such a spec; the
      words after it are the command's arguments and aren't read;
    - yarn or pnpm (not in the image; any path, `node <x>/yarn.js`, `corepack yarn`):
      `yarn add`, `yarn global add`, `yarn dlx`, `pnpm add`, `pnpm install <spec>`,
      `pnpm dlx`, `pnpx` of such a spec;
    - package-analysis's driver run again with another `--local` tarball;
    - the exported tarball itself written or deleted (package-analysis copies it in before the
      container starts, so a recorded write is the package's).

    Uses Commands, and Files for the rewrite. A registry install by name (`npm install
    evil-dep`) is `sandbox.process-spawn`'s. Evidence names the command's origin where a path
    shows it (`Activity.exec_origin`). Limit: Commands is a set, so the package re-running the
    driver's exact `npm install` of the same tarball is not seen."""

    id = "sandbox.nested-install"
    severity = Severity.HIGH
    weight = 5.0
    title = "Package installs a second package from outside the registry"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        evidence: list[Item] = []
        phases: set[str] = set()
        origins: list[str | None] = []
        uses = {"Commands"}
        for o in activity.of(K.EXEC):
            why = self._nested(activity, o.argv)
            if why is not None:
                phases.add(o.phase)
                where = activity.exec_origin(o)
                origins.append(where)
                evidence.append((f"exec ({o.phase})", command(o.argv), join_label(why, where)))
        for o in activity.of(K.OPEN):
            if o.path and normal(o.path) == activity.local_tarball:
                changed = [f for f in o.flags if f in ("write", "delete")]
                if changed:
                    phases.add(o.phase)
                    uses.add("Files")
                    evidence.append(
                        (f"file ({o.phase})", clip(o.path), f"the analysed tarball: {changed[0]}")
                    )
        if not evidence:
            return ()
        text = "A package was installed from outside the registry, or the analysed tarball "
        text += "was replaced or installed elsewhere."
        return (
            self.report(
                text,
                evidence,
                uses=" and ".join(sorted(uses)),
                phases=phases,
                origins=origins,
            ),
        )

    @staticmethod
    def _nested(activity: Activity, argv: Sequence[str]) -> str | None:
        if is_driver(argv, activity.local_tarball, activity.name):
            return None
        rest: Sequence[str] = ()
        if argv and argv[0] == DRIVER:
            rest = argv[1:]
        elif argv and is_node(argv[0]) and len(argv) >= 2 and argv[1] == DRIVER:
            rest = argv[2:]
        if len(rest) >= 2 and rest[0] == "--local" and rest[1] != activity.local_tarball:
            return "driver given another tarball"
        tool = yarn_pnpm_specs(argv)
        if tool is not None:
            foreign = [w for w in tool[1] if foreign_spec(w)]
            return f"{tool[0]} of {clip(foreign[0], 120)}" if foreign else None
        npx = npx_args(argv)
        if npx is not None:
            foreign = [w for w in exec_specs(npx, npx=True) if foreign_spec(w)]
            return f"npx of {clip(foreign[0], 120)}" if foreign else None
        args = npm_args(argv)
        if args is None:
            return None
        name, before, after = npm_split(args)
        if name not in NPM_FETCH:
            return None
        if name in ("exec", "x"):
            specs = exec_specs(after, npx=False)
        else:
            specs = operands(after, NPM_VALUE_OPTIONS)
        elsewhere = install_elsewhere((*before, *after)) if name in NPM_INSTALL else None
        shown = f"npm {name}" + (f" {elsewhere}" if elsewhere else "")
        foreign = [w for w in specs if w != activity.local_tarball and foreign_spec(w)]
        if foreign:
            return f"{shown} of {clip(foreign[0], 120)}"
        if elsewhere and activity.local_tarball in specs:
            return f"{shown} of the analysed tarball"
        return None


# Credential, browser and wallet stores. Aligned with Stage 2's `static.sensitive-path`
# (`rules/static.py`), plus Linux browser profiles, more wallets, `.netrc`/`.pgpass`, GnuPG and
# other processes' environments (`/proc/<pid>/environ`, how stealers harvest). A directory
# itself (`~/.ssh`, opened to list it) counts.
SENSITIVE_PATH: Final = re.compile(
    r"/\.npmrc$|/\.ssh(?:/|$)|/\.aws(?:/|$)|/\.git-credentials$|/\.netrc$"
    r"|/\.pgpass$|/\.bash_history$|/\.zsh_history$|/\.docker/config\.json$|/\.kube/config$"
    r"|/\.config/gcloud(?:/|$)|/\.config/gh/hosts\.yml$|/\.gnupg(?:/|$)|/\.env(?:\.[\w.-]+)?$"
    r"|/\.config/(?:google-chrome|chromium|BraveSoftware|microsoft-edge|opera|vivaldi)/"
    r"|/\.mozilla/firefox/|/Login Data$|/Local State$|/Cookies$|/logins\.json$|/key4\.db$"
    r"|/Exodus/exodus\.wallet|/\.config/Exodus/|/\.electrum/wallets|/\.ethereum/keystore"
    r"|/\.bitcoin/wallet\.dat$|/\.config/solana/id\.json$|/Library/Keychains"
    r"|^/etc/(?:shadow|gshadow|sudoers)$|^/proc/(?:\d+|self|thread-self)/environ$",
)
SSH_BAIT: Final = f"{HOME}/.ssh/id_rsa"
NPMRC_NOTE: Final = (
    " Not counted: ~/.npmrc and /app/.npmrc read in install. npm reads them on every start and "
    "package-analysis records no process per file, so a hook's read is indistinguishable from "
    "npm's own; .npmrc reads count only in import."
)


class SensitiveRead(SandboxRuleBase):
    """A credential, browser or wallet store read or probed (package-analysis's Files with
    `Read`: an open for reading or any `stat`, successful or not, so probing for `~/.npmrc` or
    `~/.ssh/id_rsa` counts). Left out: anything under `/app/node_modules` (packages' shipped
    files, such as a `.env.example`), and in `install` npm's own config files (`/root/.npmrc`,
    `/app/.npmrc`), which npm reads on every start. In `import` npm doesn't run, so a read of
    `~/.npmrc` or of anything in `~/.ssh` there is the package's (or a dependency's) own code,
    and is reported HIGH like every other path here.

    Token stealers in `install` (a `postinstall` that reads `~/.npmrc` and sends it off, the
    commonest npm attack shape) are a known recall gap: Files records no process per file and
    no return value, so the hook's read of `/root/.npmrc` is the same entry as npm's own (npm
    reads it on every start) and can't be told apart. An `.npmrc` read therefore counts only
    in `import`; in `install` only the network finding remains. Every explanation says so.
    Stage 2 (`static.sensitive-path`) and Stage 3 cover the code that does it. Other limits:
    paths reached through a symlink or hard link, a rename, or an inherited descriptor show
    only under the other name (none of those syscalls is traced); a relative path from a
    plain `open` (directory unknown) is matched as if it started at a directory, and shown as
    recorded. The read path is the target, not the reader, so evidence names no origin."""

    id = "sandbox.sensitive-read"
    severity = Severity.HIGH
    weight = 5.0
    title = "Package reads credentials"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        evidence: list[Item] = []
        phases: set[str] = set()
        bait = False
        for o in activity.of(K.OPEN):
            if not o.path or "read" not in o.flags:
                continue
            phase = o.phase
            path = normal(o.path)
            # A relative path's directory is unknown: matched as if it began at a directory.
            anchored = path if path.startswith("/") else f"/{path}"
            if _inside(path, NODE_MODULES) or not SENSITIVE_PATH.search(anchored):
                continue
            if phase == INSTALL and path in NPM_CONFIG_FILES:
                continue
            bait |= path == SSH_BAIT
            phases.add(phase)
            evidence.append((clip(path), f"read ({phase})", None))
        if not evidence:
            return ()
        text = f"{len({e[0] for e in evidence})} credential paths read or probed"
        text += ", including the SSH key package-analysis plants for this run." if bait else "."
        if "import" in phases:
            text += " Reads in import are the package's own code: npm doesn't run there."
        text += NPMRC_NOTE
        return (self.report(text, evidence, uses="Files (Read)", phases=phases),)


PERSISTENCE: Final = (
    (
        "shell startup file",
        re.compile(
            r"^(?:/root|/home/[^/]+)/\.(?:bashrc|bash_profile|bash_login|bash_logout|profile"
            r"|zshrc|zshenv|zprofile|zlogin)$|^(?:/root|/home/[^/]+)/\.config/fish/"
            r"|^/etc/(?:profile|bash\.bashrc|zsh/|environment$)"
        ),
    ),
    ("desktop autostart", re.compile(r"^(?:/root|/home/[^/]+)/\.config/autostart/")),
    (
        "systemd unit",
        re.compile(r"^(?:/root|/home/[^/]+)/\.config/systemd/|^/etc/systemd/|^/lib/systemd/"),
    ),
    ("crontab", re.compile(r"^/var/spool/cron/|^/etc/cron|^/etc/crontab$")),
    ("sudoers", re.compile(r"^/etc/sudoers(?:\.d/|$)")),
    ("dynamic loader preload", re.compile(r"^/etc/ld\.so\.preload$")),
    ("CI workflow", re.compile(r"/\.github/workflows/")),
    ("git hook", re.compile(r"/\.git/hooks/")),
    ("SSH authorized key", re.compile(r"/\.ssh/authorized_keys2?$")),
    ("npm config", re.compile(r"/\.npmrc$")),
    (
        "system program directory",
        re.compile(r"^/(?:usr/(?:local/)?)?s?bin/|^/usr/(?:local/)?lib/node_modules/"),
    ),
    ("project manifest", re.compile(rf"^{APP}/package(?:-lock)?\.json$")),
    # Tools' caches (`node_modules/.cache`, find-cache-dir's convention) are not persistence.
    ("node_modules", re.compile(rf"^{NODE_MODULES}/(?!\.cache/)")),
)
# Written by npm during `install` (`npm init --force`, then npm unpacking every package):
# indistinguishable from a hook writing there.
INSTALL_WRITES: Final = ("project manifest", "node_modules")


class PersistenceWrite(SandboxRuleBase):
    """A write (package-analysis's Files with `Write`, from the open flags or `creat`) to a
    place that runs code or holds config later: shell startup files, autostart, systemd units,
    crontabs, sudoers, `/etc/ld.so.preload`, CI workflows, git hooks, `authorized_keys`, any
    `.npmrc`, the project's `package.json`, or `node_modules` outside the package. Writes inside
    the package's own directory, npm's cache and `/tmp` are not. Limit: in `install` npm itself
    writes `/app/package.json` and all of `/app/node_modules` (so a CI workflow a dependency
    ships, extracted there, is npm's too); those are counted only in `import`, where npm doesn't
    run. Writes through a symlink or a rename show only under the name used."""

    id = "sandbox.persistence-write"
    severity = Severity.HIGH
    weight = 5.0
    title = "Package writes a persistence location"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        evidence: list[Item] = []
        phases: set[str] = set()
        for o in activity.of(K.OPEN):
            if not o.path or "write" not in o.flags:
                continue
            phase = o.phase
            path = normal(o.path)
            if any(_inside(path, d) for d in (activity.package_dir, NPM_CACHE, SANDBOX_TMP)):
                continue
            if phase == INSTALL and _inside(path, NODE_MODULES):
                continue
            label = next((label for label, p in PERSISTENCE if p.search(path)), None)
            if label is None or (phase == INSTALL and label in INSTALL_WRITES):
                continue
            phases.add(phase)
            evidence.append((clip(path), f"write ({phase})", label))
        if not evidence:
            return ()
        kinds = sorted({e[2] or "" for e in evidence})
        return (
            self.report(
                f"Wrote: {', '.join(kinds)}.", evidence, uses="Files (Write)", phases=phases
            ),
        )


INTERPRETERS: Final = frozenset(
    {"node", "nodejs", "sh", "dash", "bash", "zsh", "python", "python3", "perl", "ruby", "bun"}
    | {"php", "pwsh", "deno"}
)
# shelljs's synchronous exec writes a script to /tmp/shelljs_* and runs it with node: in
# package-analysis's known-good list (docs/queries.md).
SHELLJS_TEMP: Final = re.compile(r"/tmp/shelljs_[^/]+")  # noqa: S108 (a sandbox path)


# Interpreter options after which the next word is code, not a script (`node -e`, `sh -c`).
# For a shell only `-c` is (`sh -e` is errexit).
CODE_OPTIONS: Final = frozenset({"-c", "-e", "-p", "--eval", "--print", "-E", "-m"})
SHELL_NAMES: Final = frozenset({"sh", "dash", "bash", "zsh", "ksh", "ash"})


def _code_options(argv: Sequence[str]) -> frozenset[str]:
    return frozenset({"-c"}) if program(argv) in SHELL_NAMES else CODE_OPTIONS


def script_of(argv: Sequence[str]) -> str | None:
    """The script an interpreter runs (`node x.js`, `sh ./a.sh`): its first operand, or None
    when it runs code from an option (`-c`, `-e`) or from its standard input."""
    if program(argv) not in INTERPRETERS:
        return None
    code = _code_options(argv)
    for word in argv[1:]:
        if word in code:
            return None
        if word == "-" or word == "--":
            return None
        if not word.startswith("-"):
            return word if word and "\n" not in word else None
    return None


class DownloadExec(SandboxRuleBase):
    """A file the run wrote, or one npm didn't unpack, is executed: as the command itself
    (`argv[0]`) or as the script an interpreter is given (`node /tmp/x.js`, `sh ./a.sh`).
    Uses Files (writes) and Commands.

    - **Written, then run**: written in a phase and executed in that phase (order within a
      phase is unknown) or a later one.
    - **Not in the tarball** (HIGH): given the tarball's file list (`shipped`: paths inside
      the tarball, `package/` stripped), a file in the package's own directory that the
      tarball doesn't have was put there during the run (a dropper's second stage): a write
      there in `install`, and any exec of an absolute path there (a rename into place isn't
      traced, so the exec alone counts). In an airgapped or bundled run npm installs nothing
      under the package's `node_modules/` (`Activity.closed_modules`), so a bundled
      dependency's folder is checked the same way.

    Evidence says whose directory the file is in ("in the package", "in dependency <dep>"). Not
    counted: other writes under `/app/node_modules` in `install` (npm unpacks every package
    there, then runs their hooks: the package's own `node install.js` would otherwise always
    fire), the package's nested `node_modules/` in an online, unbundled run (npm installs nested
    dependencies there; not a mode Kitsunox exports now), npm's `.bin` links, where node-gyp ran
    the `build/` directory of the package or a dependency, npm's cache, `/dev`, `/proc`, and
    shelljs's temporary scripts. Limits: without the file list, a hook that downloads into its
    own directory during `install` and runs it is missed; a hook overwriting a file the tarball
    ships looks like npm unpacking it; a `chmod +x` isn't seen, the exec is what counts;
    relative paths are tried against the package directory and `/app` for written files, and
    never count as "not in the tarball" (a dependency's hook runs in its own directory)."""

    id = "sandbox.download-exec"
    severity = Severity.HIGH
    weight = 5.0
    title = "Package runs a file it wrote"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        building = activity.phases_with(is_node_gyp)
        written: dict[str, int] = {}
        for o in activity.of(K.OPEN):
            if not o.path or "write" not in o.flags or not o.path.startswith("/"):
                continue
            phase = o.phase
            path = normal(o.path)
            if any(_inside(path, d) for d in ("/dev", "/proc", NPM_CACHE)):
                continue
            if SHELLJS_TEMP.fullmatch(path):
                continue
            if (
                phase == INSTALL
                and _inside(path, NODE_MODULES)
                and not activity.unshipped(path, phase in building)
            ):
                continue
            rank = PHASES.index(phase)
            written[path] = min(written.get(path, rank), rank)
        evidence: list[Item] = []
        phases: set[str] = set()
        origins: list[str | None] = []

        def add(path: str, o: Observation, why: str) -> None:
            where = activity.origin(path)
            phases.add(o.phase)
            origins.append(where)
            evidence.append((clip(path), command(o.argv) or None, join_label(why, where)))

        for o in activity.of(K.EXEC):
            phase = o.phase
            rank = PHASES.index(phase)
            built = any(PHASES.index(p) <= rank for p in building)
            for path in self._targets(activity, o, phase):
                if path in written and written[path] <= rank:
                    add(path, o, f"written, then exec ({phase})")
            for path in self._absolute(o.argv):
                if path not in written and activity.unshipped(path, built):
                    add(path, o, f"not in the tarball, exec ({phase})")
        if not evidence:
            return ()
        return (
            self.report(
                "Executed a file written during the run, or one in the package's directory "
                "(its own files or a bundled dependency's) that its tarball doesn't have.",
                evidence,
                uses="Files and Commands",
                phases=phases,
                origins=origins,
            ),
        )

    @staticmethod
    def _targets(activity: Activity, o: Observation, phase: str) -> list[str]:
        if not o.argv:
            return []
        first = o.argv[0]
        found = (
            {f"{d}/{first}" for d in SANDBOX_PATH}  # a bare name is looked up on PATH
            if first and "/" not in first
            else set(activity.resolutions(first, phase) if first else ())
        )
        if program(o.argv) in INTERPRETERS:
            for arg in o.argv[1:]:
                if arg and not arg.startswith("-") and "\n" not in arg:
                    found.update(activity.resolutions(arg, phase))
        return sorted(found)

    @staticmethod
    def _absolute(argv: Sequence[str]) -> list[str]:
        """The absolute paths an exec runs: `argv[0]`, and an interpreter's script."""
        found = {normal(w) for w in (argv[:1] if argv else ()) if w.startswith("/")}
        script = script_of(argv)
        if script is not None and script.startswith("/"):
            found.add(normal(script))
        return sorted(found)


DOWNLOADERS: Final = frozenset({"curl", "wget", "wget2"})
URL: Final = re.compile(r"(?:https?|ftps?)://[^\s'\"]+", re.IGNORECASE)
RUNNERS: Final = r"(?:sh|dash|bash|zsh|ksh|ash|node|nodejs|python[23]?|perl|ruby|php)"
_PATHED: Final = r"(?:[\w./-]*/)?"
# A shell string that pipes a download into an interpreter (`curl -fsSL u | sh`), or runs a
# download's output (`sh -c "$(curl u)"`, `bash <(wget -qO- u)`, `eval "$(curl u)"`).
# Both report where the shape starts as group `start` (the match itself starts earlier).
# Linear rewrites of `\b{_PATHED}(?:curl|wget2?)\b[^|;&\n]*\|...` and of
# `(?:\b(?:{RUNNERS}|eval|source)\b|(?:^|[\s;&|])\.)\s+(?:-\S+\s+)*...`, same spans: every
# start in one `|;&\n` segment (one run of `-x` options) shares the outcome, so each is tried
# once, from the segment's (run's) start, at its first start: retrying the rest made
# `x/curl/curl/...` cubic and `/a/a/...`, `sh -sh -sh ...` quadratic (16k chars: 93 s).
# A sudo option stops at `|` (v2): the shell ends sudo's command there, and `-\S+` let each
# `|sudo` re-scan the same option chain (`curl|sudo -curl|sudo ...`: 128k chars, 14 s).
PIPE_RUN: Final = re.compile(
    r"(?:^|(?<=[|;&\n]))(?>[^|;&\n]*?(?:(?<![\w./-])(?P<lead>[./-]*+))?"
    rf"(?P<start>\b(?(lead){_PATHED})(?:curl|wget2?)\b))"
    r"[^|;&\n]*+\|\s*(?:sudo\s+(?:-[^\s|]+\s+)*)?(?:env\s+)?"
    rf"{_PATHED}{RUNNERS}\b"
)
SUBST_RUN: Final = re.compile(
    r"(?:^|(?=\s(?!\s|-\S)))(?>(?:\s(?!\s|-\S))??(?:\S|\s++(?=-\S))*?"
    rf"(?P<start>\b(?:{RUNNERS}|eval|source)\b|(?:^|[\s;&|])\.)(?=\s))"
    r"\s+(?:-\S+\s+)*[\"']?"
    rf"(?:\$\(|`|<\()\s*{_PATHED}(?:curl|wget2?)\b"
)
CURL_FLAGS: Final = frozenset("sSLfkvqiI#Ogn")  # curl's short options that take no value


def _url_name(word: str) -> str | None:
    """The last path segment of a URL (what `curl -O` and `wget` save it as), or None."""
    match = URL.match(word)
    if match is None:
        return None
    rest = match.group().split("://", 1)[1].split("?", 1)[0].split("#", 1)[0]
    _, slash, path = rest.partition("/")
    name = posixpath.basename(path) if slash else ""
    return name if name not in ("", ".", "..") else None


def _outputs(argv: Sequence[str]) -> set[str]:
    """Where a downloader command saves: `curl -o X` / `--output X` / `-sSLoX`, `wget -O X` /
    `--output-document=X` (`-` is stdout, not a file); `curl -O` and plain `wget` save the
    URL's last path segment in the working directory."""
    curl = program(argv) == "curl"
    words = list(argv[1:])
    long_opt = "--output" if curl else "--output-document"
    short = "o" if curl else "O"
    remote = not curl  # wget saves under the URL's name unless told otherwise
    found: set[str] = set()
    for i, word in enumerate(words):
        nxt = words[i + 1] if i + 1 < len(words) else None
        value: str | None = None
        if word == long_opt:
            value = nxt
        elif word.startswith(f"{long_opt}="):
            value = word.split("=", 1)[1]
        elif curl and word in ("--remote-name", "--remote-name-all"):
            remote = True
        elif word.startswith("-") and not word.startswith("--"):
            flags = word[1:]
            head, sep, after = flags.partition(short)
            if sep and (not curl or set(head) <= CURL_FLAGS):
                value = after or nxt
            elif curl and "O" in flags and set(flags) <= CURL_FLAGS:
                remote = True
        if value is not None:
            remote = remote and curl
            if value != "-":
                found.add(value)
    if remote:
        found.update(name for word in words if (name := _url_name(word)) is not None)
    return {f for f in found if f}


INFO_OPTIONS: Final = frozenset({"--version", "-v", "-V", "--help", "-h"})


def _reads_stdin(argv: Sequence[str]) -> bool:
    """A shell or interpreter that runs what it reads on standard input: `sh`, `bash -s`,
    `sh -`, `node`, `python3 -` (no script operand and no `-c`/`-e` code)."""
    name = program(argv)
    if name not in SHELL_NAMES and name not in INTERPRETERS:
        return False
    args = argv[1:]
    code = _code_options(argv)
    if any(w in code or w in INFO_OPTIONS for w in args):
        return False
    if name in SHELL_NAMES and "-s" in args:
        return True
    operands = [w for w in args if not w.startswith("-") or w == "-"]
    return not operands or operands[0] == "-"


class DownloadRun(SandboxRuleBase):
    """The `curl | sh` shape: in one phase, a downloader (curl, wget) fetches a URL and a shell
    or interpreter runs what it reads on standard input, or runs the file the downloader saved
    (`curl -o /tmp/x u` and `sh /tmp/x`); or a shell command string pipes a download into an
    interpreter or runs its output (`curl u | sh`, `sh -c "$(curl u)"`). Uses Commands only.
    Limits: there is no process tree or order within a phase, so a download and an unrelated
    `sh` reading stdin in the same phase also fire; a download made from JavaScript and run
    with `eval` is not a command at all (Stage 2 and 3 read the code)."""

    # v2: a sudo option in a piped command stops at `|` (linear on `curl|sudo -curl|...`).
    id = "sandbox.download-run"
    version = 2
    severity = Severity.HIGH
    weight = 5.0
    title = "Package downloads and runs code"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        evidence: list[Item] = []
        phases: set[str] = set()
        origins: list[str | None] = []
        by_phase: dict[str, list[Observation]] = {}

        def add(o: Observation, snippet: str, why: str) -> None:
            where = activity.exec_origin(o)
            origins.append(where)
            evidence.append((f"exec ({o.phase})", snippet, join_label(why, where)))

        for o in activity.of(K.EXEC):
            by_phase.setdefault(o.phase, []).append(o)
            if len(o.argv) >= 3 and program(o.argv) in SHELL_NAMES and "-c" in o.argv[1:]:
                for word in o.argv[1:]:
                    match = PIPE_RUN.search(word) or SUBST_RUN.search(word)
                    if match is not None:
                        phases.add(o.phase)
                        add(o, window(word, match.start("start"), match.end()), "shell string")
                        break
        for phase, execs in by_phase.items():
            downloads = [
                o
                for o in execs
                if program(o.argv) in DOWNLOADERS and any(URL.match(w) for w in o.argv[1:])
            ]
            if not downloads:
                continue
            saved = {
                path
                for o in downloads
                for out in _outputs(o.argv)
                for path in activity.resolutions(out, phase)
            }
            fetching = {id(o) for o in downloads}
            runners: list[tuple[Observation, str]] = []
            for o in execs:
                if id(o) in fetching or not o.argv:
                    continue
                if _reads_stdin(o.argv):
                    runners.append((o, "runs standard input"))
                elif any(
                    saved.intersection(activity.resolutions(target, phase))
                    for target in (o.argv[0], script_of(o.argv))
                    if target
                ):
                    runners.append((o, "runs the downloaded file"))
            if runners:
                phases.add(phase)
                for o in downloads:
                    add(o, command(o.argv), "download")
                for o, why in runners:
                    add(o, command(o.argv), why)
        if not evidence:
            return ()
        return (
            self.report(
                "Code was downloaded and run: a downloader and a shell or interpreter running "
                "its output in the same phase.",
                evidence,
                uses="Commands",
                phases=phases,
                origins=origins,
            ),
        )


HEX_LABEL: Final = re.compile(r"[0-9a-f]{16,}")
BASE32_LABEL: Final = re.compile(r"[a-z2-7]{24,}")
DNS_TEXT: Final = re.compile(r"[a-z0-9_-]+")


def tunnel_shape(name: str) -> str | None:
    """Why a DNS name looks like data, or None. Each label but the TLD is tested, and so are
    the subdomain labels joined (data split across labels):

    - hex: 16+ hex characters with a digit (all-letter runs like `deadbeefcafebabe` are words);
    - base32: 24+ of `a-z2-7` with a digit and over 3.5 bits/char of entropy;
    - random: 30+ characters of over 4 bits/char (English-like names stay below)."""
    labels = [label for label in ascii_lower(name).rstrip(".").split(".") if label]
    parts = labels[:-1]
    if len(labels) > 3:
        parts.append("".join(labels[:-2]))
    for part in parts:
        if not DNS_TEXT.fullmatch(part):
            continue
        has_digit = any(c.isdigit() for c in part)
        if HEX_LABEL.fullmatch(part) and has_digit:
            return f"hex label of {len(part)} characters"
        if BASE32_LABEL.fullmatch(part) and has_digit and shannon_entropy(part) > 3.5:
            return f"base32-like label of {len(part)} characters"
        if len(part) >= 30 and shannon_entropy(part) > 4.0:
            return f"random-looking label of {len(part)} characters"
    return None


class DnsTunnelShape(SandboxRuleBase):
    """A DNS question (package-analysis's DNS queries, from the sandbox bridge's packets) whose
    labels look like encoded data: how secrets leave through DNS when nothing else gets out.
    Names a socket was answered for are DNS questions too, so only questions are read."""

    id = "sandbox.dns-tunnel-shape"
    severity = Severity.HIGH
    weight = 4.0
    title = "DNS lookup shaped like data exfiltration"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        evidence: list[Item] = []
        phases: set[str] = set()
        for o in activity.of(K.DNS):
            reason = tunnel_shape(o.host or "")
            if reason is not None:
                phases.add(o.phase)
                evidence.append((f"dns ({o.phase})", clip(o.host or ""), reason))
        if not evidence:
            return ()
        return (
            self.report(
                "Names that carry data in their labels.", evidence, uses="DNS", phases=phases
            ),
        )


# Hosts benign install hooks fetch from (prebuilt binaries, Node headers). Exact names: their
# subdomains and look-alikes are not on the list (raw.githubusercontent.com serves anyone's
# files). Still LOW, not silent: attackers host payloads on GitHub releases too.
# release-assets.githubusercontent.com: GitHub release downloads redirect there since 2025
# (rolled out from 2025-04-28; https://www.stepsecurity.io/blog/harden-runner-detects-new-
# traffic-to-release-assets-githubusercontent-com-across-multiple-customers and HashiCorp's
# https://support.hashicorp.com/hc/en-us/articles/42203329876883), next to the older
# objects.githubusercontent.com.
BENIGN_HOSTS: Final = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "codeload.github.com",
        "registry.npmjs.org",
        "nodejs.org",
    }
)
# What npm itself talks to during `install` (dependencies, `npm audit`, the update check):
# expected there, and not reported.
NPM_REGISTRY: Final = "registry.npmjs.org"
NETWORK_SETS: Final = "DNS and Sockets"
# package-analysis forces the sandbox's DNS to these (internal/sandbox/sandbox.go, rel-38).
RESOLVERS: Final = frozenset({"8.8.8.8", "8.8.4.4"})


def _host_name(host: str) -> str:
    """Lowercased, without a trailing dot or a `:port`."""
    name = ascii_lower(host).strip()
    if name.startswith("["):
        name = name[1:].split("]", 1)[0]
    elif name.count(":") == 1:
        name = name.split(":", 1)[0]
    return name.rstrip(".")


def _ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(address.strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _is_loopback(name: str) -> bool:
    ip = _ip(name)
    return name == "localhost" or name.endswith(".localhost") or (ip is not None and ip.is_loopback)


def socket_name(o: Observation) -> str | None:
    """The name an observation is for: a DNS question's name, or a name DNS answered for a
    socket's address (one of package-analysis's `Hostnames`). None for loopback names."""
    name = _host_name(o.host) if o.host else ""
    return name if name and not _is_loopback(name) else None


class Network(SandboxRuleBase):
    """DNS questions and sockets beyond loopback (package-analysis's DNS and Sockets; no
    payloads). Expected and not reported: npm's registry.npmjs.org traffic in `install` (names,
    and sockets whose only names are it) and connections to the sandbox's forced resolvers
    (8.8.8.8 and 8.8.4.4, port 53; the questions themselves are reported); a `bind` to port 0.
    LOW when every remaining name is a host benign hooks use and every address was answered by
    DNS for a name; MEDIUM otherwise (other names, an address no name resolved to, or a socket
    on an unspecified address with a port, a listener). registry.npmjs.org in `import` is the
    package's own traffic (npm doesn't run there), so it is reported, at LOW. Limit: a hook
    that talks to registry.npmjs.org during `install` (a worm publishing over HTTPS) is hidden
    in npm's traffic. Evidence lists every name and address, capped."""

    id = "sandbox.network"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Package uses the network"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        names: dict[str, set[str]] = {}  # name -> phases
        addresses: dict[str, tuple[set[str], set[int], bool]] = {}  # phases, ports, resolved
        for o in activity.of(K.DNS, K.CONNECT):
            phase = o.phase
            name = socket_name(o)
            if phase == INSTALL and name == NPM_REGISTRY:
                continue
            if o.kind is K.CONNECT and not self._address(o, name, phase, addresses):
                continue
            if name is not None:
                names.setdefault(name, set()).add(phase)
        if not names and not addresses:
            return ()
        seen = {p for found in names.values() for p in found}
        seen |= {p for found, _, _ in addresses.values() for p in found}
        other = sorted(n for n in names if n not in BENIGN_HOSTS)
        raw = sorted(a for a, (_, _, resolved) in addresses.items() if not resolved)
        evidence: list[Item] = [
            (
                f"dns/host ({', '.join(sorted(p))})",
                clip(n),
                "allow-listed" if n in BENIGN_HOSTS else "not allow-listed",
            )
            for n, p in names.items()
        ]
        evidence += [
            (
                f"address ({', '.join(sorted(p))})",
                clip(a + _ports(ports)),
                "answered by DNS" if resolved else "no name resolved to it",
            )
            for a, (p, ports, resolved) in addresses.items()
        ]
        if other or raw:
            text = (
                f"{len(other)} names not on the allow-list, {len(raw)} addresses no name "
                f"resolved to ({len(names)} names, {len(addresses)} addresses in all)."
            )
            return (
                self.report(
                    text, evidence, limit=MAX_NETWORK_EVIDENCE, uses=NETWORK_SETS, phases=seen
                ),
            )
        text = f"Only allow-listed hosts: {', '.join(sorted(names))}."
        return (
            self.report(
                text,
                evidence,
                severity=Severity.LOW,
                weight=1.0,
                limit=MAX_NETWORK_EVIDENCE,
                uses=NETWORK_SETS,
                phases=seen,
            ),
        )

    @staticmethod
    def _address(
        o: Observation,
        name: str | None,
        phase: str,
        addresses: dict[str, tuple[set[str], set[int], bool]],
    ) -> bool:
        """Record a socket's address; False when it isn't network evidence at all."""
        raw = (o.address or "").strip()
        port = o.port or 0
        ip = _ip(raw) if raw else None
        if ip is not None and ip.is_loopback:
            return False
        unspecified = not raw or (ip is not None and ip.is_unspecified)
        if unspecified and port == 0:
            return False  # bind to an ephemeral port: how a UDP client starts
        if str(ip) in RESOLVERS and port == 53:
            return False
        shown = "unspecified address" if unspecified else (str(ip) if ip is not None else raw)
        phases, ports, resolved = addresses.get(shown, (set(), set(), False))
        phases.add(phase)
        if port:
            ports.add(port)
        addresses[shown] = (phases, ports, resolved or (name is not None and not unspecified))
        return True


def _ports(ports: set[int]) -> str:
    shown = sorted(ports)
    return (" port " + ",".join(str(p) for p in shown[:10])) if shown else ""


class ProcessSpawn(SandboxRuleBase):
    """A command (package-analysis's Commands: the argv of every `execve`, failed attempts
    included) other than the expected ones. Expected, derived from package-analysis's own
    driver and its known-good list for npm (docs/queries.md at rel-38): the driver, `npm init
    --force` and `npm install` of this job's exported tarball, exactly as the driver issues them
    (`is_driver`), and `sleep 30m`; npm (as `npm` or `node <image>/npm`), except account
    commands (`whoami`, `token`, `owner`, `dist-tag`, ...: a worm's) and commands that fetch
    more packages (`install`, `exec`, ...: a second `npm install` of another tarball is also
    `sandbox.nested-install`); node (bare or an image path, never a `node` the package ships);
    `sh -c <command>` (npm's script shell and `child_process.exec`; what the shell runs is its
    own exec); node-gyp and node-gyp-build; esbuild's `--version` check; node-gyp's
    `python -c` probe; and, only in a phase where node-gyp ran, its build steps
    (`is_build_step`: make, the compiler and the programs it starts, `uname`, `which`, gyp's
    `python .../gyp_main.py` and node-gyp's find-python probes, the file tools its Makefiles
    run with arguments that stay in the build, and `gyp-flock-tool`). Everything else (curl,
    wget, bash, python, sudo, aws, kubectl, git, powershell, bun, `env`, a shipped script or
    binary, recon like `id`) is reported; esbuild's `--version` check is expected wherever
    esbuild sits under `/app/node_modules` (a bundle nests it). Evidence names the command's
    origin where a path shows it (`Activity.exec_origin`). Limits: there is no executable
    path or process tree, so `argv[0]` is the caller's word; a binary started as `node` hides
    as node, and in a node-gyp phase a `make`, compiler or in-build `cp` the package runs
    itself looks like the build's."""

    id = "sandbox.process-spawn"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Package starts unexpected programs"

    def check(self, run: SandboxRun, activity: Activity) -> Sequence[Finding]:
        building = activity.phases_with(is_node_gyp)
        evidence: list[Item] = []
        phases: set[str] = set()
        origins: list[str | None] = []
        for o in activity.of(K.EXEC):
            phase = o.phase
            why = self._unexpected(activity, o.argv, phase in building)
            if why is not None:
                phases.add(phase)
                where = activity.exec_origin(o)
                origins.append(where)
                evidence.append(
                    (
                        clip(program(o.argv) or "?"),
                        command(o.argv) or None,
                        join_label(f"{why} ({phase})", where),
                    )
                )
        if not evidence:
            return ()
        programs = sorted({e[0] for e in evidence})
        text = f"Started {', '.join(programs[:10])}" + ("..." if len(programs) > 10 else "") + "."
        return (self.report(text, evidence, uses="Commands", phases=phases, origins=origins),)

    @staticmethod
    def _unexpected(activity: Activity, argv: Sequence[str], building: bool) -> str | None:
        """Why a command is reported, or None when it is expected."""
        if not argv:
            return "empty argv"
        if is_driver(argv, activity.local_tarball, activity.name) or tuple(argv) in KNOWN_GOOD:
            return None
        if tuple(argv[1:]) == ("--version",) and ESBUILD_BIN.fullmatch(argv[0]):
            return None  # the known-good esbuild check, from a nested (bundled) esbuild
        if argv[0] == DRIVER or (is_node(argv[0]) and len(argv) >= 2 and argv[1] == DRIVER):
            return "package-analysis's driver with other arguments"
        args = npm_args(argv)
        if args is not None:
            name = npm_command(args)[0]
            if name in NPM_ACCOUNT:
                return f"npm account command `{name}`"
            if name in NPM_FETCH:
                return f"npm fetches more packages: `{name}`"
            return None  # `publish` is sandbox.npm-publish's
        if is_node(argv[0]) or is_shell_c(argv) or is_node_gyp(argv):
            return None
        if building and is_build_step(argv, activity.package_dir):
            return None
        return "not an expected program"


DETECTION_RULES: Final[tuple[SandboxRuleBase, ...]] = (
    Ran(),
    Truncated(),
    NpmPublish(),
    NestedInstall(),
    BaitExfil(),
    SensitiveRead(),
    PersistenceWrite(),
    DownloadExec(),
    DownloadRun(),
    DnsTunnelShape(),
    Network(),
    ProcessSpawn(),
)
QUIET: Final = Quiet()
# `QUIET.evaluate` runs the detection rules itself, so iterating RULES gives the same findings
# as `apply_rules` (which builds the activity model once).
RULES: Final[tuple[SandboxRule, ...]] = (*DETECTION_RULES, QUIET)


def apply_rules(
    candidate: Candidate,
    run: SandboxRun,
    observations: Sequence[Observation],
    *,
    shipped: frozenset[str] | Iterable[str] | None = None,
    local_tarball: str | None = None,
    bundled_deps: frozenset[str] | Iterable[str] | None = None,
) -> tuple[Finding, ...]:
    """Every Stage 5 finding for one result: the rules in `DETECTION_RULES` order, then
    `sandbox.quiet` if the run completed, the record is whole and nothing above INFO fired.

    - `shipped`: the analysed (exported) tarball's file list, paths inside it with the top
      `package/` directory stripped (as `extract_tar_gz(strip_components=1)` gives them; for
      a bundle, the bundle's list, its `node_modules/` included). Without it,
      `sandbox.download-exec` can't see a file dropped into the package's own directory.
    - `local_tarball` overrides `expected_tarball(run.job)`.
    - `bundled_deps`: the names of the packages Kitsunox bundled under the package's
      `node_modules/` (`docs/proposals/offline-dependency-bundle.md`); None when the export
      is not a bundle. Labels evidence ("in dependency <dep>" against "the package's own
      node_modules/<name>") and makes the file list cover the package's `node_modules/`.

    A plain `str` for either collection is refused (`TypeError`)."""
    activity = analyse(
        run,
        observations,
        shipped=shipped,
        local_tarball=local_tarball,
        bundled_deps=bundled_deps,
    )
    found = tuple(f for rule in DETECTION_RULES for f in rule.check(run, activity))
    return (*found, *QUIET.after(run, found))
