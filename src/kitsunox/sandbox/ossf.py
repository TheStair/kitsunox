"""Importing OpenSSF package-analysis dynamic results, as hostile data.

package-analysis (pinned at `models.ANALYSER`, rel-38, commit 98cd113) writes one JSON file per
analysed package: `$RESULTS_DIR/<version>.json` (`results.json` when run without `-version`),
the `DynamicAnalysisRecord` of `pkg/api/analysisrun/result.go`:

    {"Package": {"Ecosystem": "npm", "Name": <lowercased>, "Version": <version>},
     "CreatedTimestamp": <unix seconds>,
     "Analysis": {"install": <StraceSummary>, "import": <StraceSummary>}}

    StraceSummary = {"Status": "completed" | "error_timeout" | "error_analysis" | "error_other",
                     "Stdout": <base64> | null, "Stderr": <base64> | null,
                     "Files": [{"Path", "Read", "Write", "Delete"}] | null,
                     "Sockets": [{"Address", "Port", "Hostnames": [..]}] | null,
                     "Commands": [{"Command": [..] | null, "Environment": [..] | null}] | null,
                     "DNS": [{"Class", "Queries": [{"Hostname", "Types": [..]}] | null}] | null}

The Go structs have no `omitempty`, so every field is always written (nil as `null`); only
which phases appear varies (phases run in order and stop after the first that doesn't
complete; for npm only `install` and `import` run). This module is therefore strict: unknown
or missing fields, wrong types, `NaN`, repeated keys and the old "V1" object form of
`Environment` are all rejected (`MalformedResultError`, with a fixed message, never text from
the file). Field reference: `docs/data_schema.md` and
`function/loader/dynamic-analysis-schema.json` at the pinned commit; the test fixtures are
hand-written from those structs.

**Why hostile.** The file describes what a possibly malicious package did, and the package
chooses most of its content: paths, argv, environment strings, DNS names and the last 4 KiB of
npm's output. So:

- the file is read with `O_NOFOLLOW`, must be a regular file, at most `MAX_RESULT_BYTES`
  (bigger is rejected as `RESULT_TOO_LARGE`, which scores HIGH: inflating one's own record must
  not be a cheap way to erase it);
- it must be UTF-8 JSON, nested no deeper than the decoder's recursion limit (deeper is a
  rejection, never a crash), with no repeated keys;
- it must be for the job (ecosystem, the lowercased `-package` name, version): the file name
  alone proves nothing. package-analysis does not record the tarball's hash, so which tarball
  it analysed is known from the export (`spool.py`: one `<key>.tgz` per job, one results
  directory per key);
- every string is cleaned (`Cleaner`): lone surrogates become U+FFFD, the bait values below are
  masked, and it is cut to `MAX_FIELD_CHARS` (`MAX_NAME_CHARS` for addresses and DNS names),
  plus one `ELLIPSIS`; argv and environment lists are cut to `MAX_ARGV` / `MAX_ENV` items (plus
  one `ELLIPSIS` item);
- at most `MAX_OBSERVATIONS` observations are kept. package-analysis sorts `Commands` (by
  argv, then environment) and `Files` (by path), so the package chooses what sorts where, and
  a head-and-tail cut is steerable (round-4 review: 60k execs sorting before the real ones and
  60k after evicted `npm publish` and a bait exfiltration). So every entry is first ranked by
  a small, fixed high-value test (`priority`: tier 0 strong signals, tier 1 interesting
  programs, URLs or writes, tier 2 the rest), and the cap is spent tier by tier: each tier's
  entries get a max-min fair share per (phase, kind) group of what the tiers above left
  (`fair_quotas`), and a group cut within a tier keeps a sample keyed by the result file's
  sha256 (`keyed_sample`), which the package can't know while it chooses its entries. A flood
  of innocuous entries can't push out a high-value one; a flood that passes the same test
  competes with it by chance, not by sort order, and is itself what the rules see: per group,
  the recorded, kept and high-value counts are on the run (`SandboxRun.groups`) whether or not
  anything was cut.

**Every cap hit is counted** (`SandboxRun.cuts`, by cap) and sets `SandboxRun.truncated`, which
`sandbox.truncated` scores and which stops `sandbox.quiet`: a package that pads a command line
past a cap loses its evidence's detail, never its record's warning (round-3 review: padding hid
`npm publish` and a bait, and the run read as quiet). The caps are far above what a real
record holds, so only padding reaches them.

**Order and determinism.** Observations are deduplicated and kept in phase order, then by kind
(exec, open, connect, DNS), then in the order they first appear in the file. package-analysis
sorts files, sockets and commands; DNS queries and socket names come from Go map iteration, in
random order, but the same bytes always give the same tuple, and the cache keeps the bytes
(`results.py`), so a replay re-parses exactly what was imported. The rules sort for
themselves.

**Baits.** package-analysis plants fresh `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values and
an SSH key in every sandbox (`internal/worker/rundynamic.go`). The key pair never appears in the
results (reads of `/root/.ssh/id_rsa` do, as file observations). The AWS values are set in the
sandbox container's environment, so they appear in the environment of package-analysis's own
driver command (`driver_argv`) and of everything that inherits it. They are fake, but look like
credentials to secret scanners, so the values of the driver command (`_baits`) are replaced
everywhere (argv, environment, paths, names, output), ASCII case-insensitively, by
`CANARY_MARK` with its name: a bait value in a command line or a lowercased one in a DNS name
then reads `[canary:AWS_SECRET_ACCESS_KEY]`, which the rules look for. Per phase, only the
**first** driver-shaped command in upstream order whose environment holds each bait name
exactly once, in the generator's exact shape, is the driver; a later driver-shaped command
with other bait values is a forgery (upstream records argv, not the program, so a package can
fake the driver's command line) and is ignored and counted (`forged_drivers`), and phases
whose drivers disagree are counted too (`bait_mismatch`: package-analysis plants one pair per
sandbox, and both phases run in it). Values in other commands' environments are never baits,
so a package can't mask its own strings, and at most one pair per phase is ever masked.
Encoded copies (base64, hex) are not recognised.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from kitsunox.sandbox.models import (
    PHASES,
    Cut,
    FileFlag,
    GroupCount,
    Observation,
    ObservationKind,
    Phase,
    PhaseResult,
    PhaseStatus,
    RunStatus,
    SandboxJob,
    SandboxRun,
)
from kitsunox.util.hashing import sha256_hex

K = ObservationKind

MAX_RESULT_BYTES: Final = 32 * 1024 * 1024
RESULT_TOO_LARGE: Final = "result too large"  # the rejection reason (scored HIGH: select.py)
# Caps. Each hit is counted (`SandboxRun.cuts`) and sets `SandboxRun.truncated`, so a cut can
# hide some evidence but never silently: `sandbox.truncated` scores it and `sandbox.quiet`
# can't fire. They are set where a real record can't reach them, so only padding hits them.
MAX_FIELD_CHARS: Final = 128 * 1024  # Linux's MAX_ARG_STRLEN; paths are at most PATH_MAX
MAX_NAME_CHARS: Final = 1024  # addresses and DNS names (at most 253 chars) and types
ELLIPSIS: Final = "…"
MAX_ARGV: Final = 4096
MAX_ENV: Final = 1024
MAX_HOSTNAMES: Final = 64
MAX_TYPES: Final = 16
MAX_OBSERVATIONS: Final = 100_000  # memory: one socket's names multiply into observations
STDIO_BYTES: Final = 4096  # package-analysis keeps the last 4 KiB of each stream
MAX_STDIO_BASE64: Final = 64 * 1024  # far over 4 KiB of base64; longer is not package-analysis
DRIVER: Final = "/usr/local/bin/analyze-node.js"  # rel-38's npm driver in the sandbox image
CANARY_VARS: Final = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
# The shapes of rel-38's generated baits (`generateAWSKeys` in internal/worker/rundynamic.go).
BAIT_SHAPES: Final[Mapping[str, re.Pattern[str]]] = {
    "AWS_ACCESS_KEY_ID": re.compile(r"AKIAI[A-Z2-7]{14}Q"),
    "AWS_SECRET_ACCESS_KEY": re.compile(r"[A-Za-z0-9+/]{40}"),  # base64 of 30 bytes
}
CANARY_MARK: Final = "[canary:{name}]"
VERSION_FILE: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,255}")
UNVERSIONED_FILE: Final = "results.json"  # what package-analysis writes without -version
_SURROGATE: Final = re.compile("[\ud800-\udfff]")
_KIND_ORDER: Final = (K.EXEC, K.OPEN, K.CONNECT, K.DNS)
Bait = tuple[str, str]  # (variable name, planted value)

# The importer's high-value test (`priority`), kept ahead of the observation cap. Small and
# fixed on purpose: it decides only what survives a flood, never a finding (the rules do that).
# Tier 0 (strong): an argv word with a bait value, the exported tarball's path, "publish" or a
# credential path; a credential, persistence or exported-tarball file; a socket or DNS name off
# the benign list. Tier 1: an argv word with a URL, `/.config` or `/proc/`; a downloader,
# shell, interpreter or npm as the program; a write or delete outside npm's own directories.
# Tier 2: everything else.
TIERS: Final = 3
STRONG_WORDS: Final = ("publish", ".npmrc", "/.ssh", "/.aws")
WEAK_WORDS: Final = ("://", "/.config", "/proc/")
PRIORITY_PROGRAM: Final = re.compile(
    r"curl|wget2?|sh|dash|bash|zsh|ash|ksh|node|nodejs|npm|npx|python[0-9.]*|perl|ruby|php"
    r"|nc|ncat|netcat|socat|ssh|scp|git",
    re.ASCII,
)
PRIORITY_PATH: Final = re.compile(
    r"^(?:/root|/home/[^/]+)/\.(?:npmrc|ssh|aws|config|gnupg|netrc|git-credentials|docker"
    r"|kube|bashrc|bash_profile|bash_login|profile|zshrc|zshenv|zprofile)(?:/|$)"
    r"|^/app/\.npmrc$|/\.env(?:\.[\w.-]+)?$|/\.github/workflows/|/\.git/hooks/"
    r"|^/etc/(?:shadow|gshadow|sudoers|crontab|cron\.|ld\.so\.preload|profile|environment)"
    r"|^/proc/[^/]+/environ$|^/var/spool/cron/",
    re.ASCII,
)
NPM_OWN_DIRS: Final = ("/app/node_modules/", "/root/.npm/")  # npm unpacks and caches here
# The benign hosts of `rules.sandbox.BENIGN_HOSTS` (the rules import this module, so it can't
# import theirs; a test keeps the two equal).
PRIORITY_BENIGN_HOSTS: Final = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "codeload.github.com",
        "registry.npmjs.org",
        "nodejs.org",
    }
)


class MalformedResultError(ValueError):
    """A result failed validation. The message is ours, never text from the result."""


@dataclass(frozen=True)
class SandboxResult:
    """A validated analysis record and its observations."""

    run: SandboxRun
    observations: tuple[Observation, ...]


# --- the upstream schema (rel-38), strictly ---------------------------------------------------


class _Upstream(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class _Key(_Upstream):
    Ecosystem: str
    Name: str
    Version: str


class _File(_Upstream):
    Path: str
    Read: bool
    Write: bool
    Delete: bool


class _Socket(_Upstream):
    Address: str
    Port: int = Field(ge=0, le=65535)
    Hostnames: list[str] | None  # always a list at rel-38; null tolerated as empty


class _Command(_Upstream):
    Command: list[str] | None
    Environment: list[str] | None  # the "V1" object form fails here, as intended


class _Query(_Upstream):
    Hostname: str
    Types: list[str] | None


class _DNS(_Upstream):
    Class: str
    Queries: list[_Query] | None


class _Summary(_Upstream):
    Status: PhaseStatus
    Stdout: str | None
    Stderr: str | None
    Files: list[_File] | None
    Sockets: list[_Socket] | None
    Commands: list[_Command] | None
    DNS: list[_DNS] | None


class _Analysis(_Upstream):
    # The phases that ran; the only optional keys in the schema.
    install: _Summary | None = None
    import_: _Summary | None = Field(default=None, alias="import")
    execute: _Summary | None = None


class _Record(_Upstream):
    Package: _Key
    CreatedTimestamp: int = Field(ge=-(2**63), lt=2**63)
    Analysis: _Analysis | None


# --- parsing -----------------------------------------------------------------------------------


class _DuplicateKeyError(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    found = dict(pairs)
    if len(found) != len(pairs):
        raise _DuplicateKeyError
    return found


def _no_constants(name: str) -> object:
    raise ValueError(name)  # NaN, Infinity, -Infinity: not JSON, and not what Go writes


def load_json(data: bytes, max_bytes: int = MAX_RESULT_BYTES) -> object:
    """Untrusted JSON, with limits: size, UTF-8, nesting (the decoder's recursion limit),
    no repeated keys, no NaN/Infinity. Raises `MalformedResultError`."""
    if len(data) > max_bytes:
        raise MalformedResultError(RESULT_TOO_LARGE)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise MalformedResultError("the result is not UTF-8") from None
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except _DuplicateKeyError:
        raise MalformedResultError("the result repeats a key in an object") from None
    except RecursionError:
        raise MalformedResultError("the result is nested too deeply") from None
    except ValueError:  # JSONDecodeError, an integer over the digit limit
        raise MalformedResultError("the result is not valid JSON") from None


def _validate(data: bytes) -> _Record:
    raw = load_json(data)
    try:
        return _Record.model_validate(raw, strict=True)
    except ValidationError:
        raise MalformedResultError(
            "the result does not follow the package-analysis rel-38 schema"
        ) from None


def check_identity(package: _Key, job: SandboxJob) -> None:
    """The result names the job's package version: the name package-analysis was given
    (`SandboxJob.package`, which it lowercases) and the version."""
    ref = job.ref
    if (package.Ecosystem, package.Name, package.Version) != (
        ref.ecosystem,
        job.package.lower(),
        ref.version,
    ):
        raise MalformedResultError("the result is for another package or version")


def result_file_names(job: SandboxJob) -> tuple[str, ...]:
    """The file names package-analysis gives this job's result: `<version>.json`, or
    `results.json` without `-version` (refused later: it names no version)."""
    version = job.ref.version
    named = (f"{version}.json",) if VERSION_FILE.fullmatch(version) else ()
    return (*named, UNVERSIONED_FILE)


# --- cleaning ------------------------------------------------------------------------------------


class Cleaner:
    """Cleans every string of one result: lone surrogates replaced, baits masked (ASCII
    case-insensitively, so a lowercased copy in a DNS name is masked too), capped. Every cap
    hit is counted in `cuts`."""

    def __init__(self, baits: Iterable[tuple[str, str]]) -> None:
        # Longest first, so a value containing another is masked whole.
        pairs = sorted(set(baits), key=lambda b: (-len(b[1]), b))
        self.cuts: Counter[Cut] = Counter()
        self._names = {value.lower(): name for name, value in reversed(pairs)}
        self._pattern = (
            re.compile("|".join(re.escape(v) for _, v in pairs), re.IGNORECASE | re.ASCII)
            if pairs
            else None
        )

    def has_bait(self, value: str) -> bool:
        """`value` holds a bait value (ASCII case-insensitively)."""
        return self._pattern is not None and self._pattern.search(value) is not None

    def _mark(self, match: re.Match[str]) -> str:
        return CANARY_MARK.format(name=self._names[match.group().lower()])

    def text(self, value: str) -> str:
        """Cleaned, not capped."""
        value = _SURROGATE.sub("\ufffd", value)
        if self._pattern is not None:
            value = self._pattern.sub(self._mark, value)
        return value

    def capped(self, value: str, limit: int, cut: Cut) -> str:
        cleaned = self.text(value)
        if len(cleaned) <= limit:
            return cleaned
        self.cuts[cut] += 1
        return cleaned[:limit] + ELLIPSIS

    def __call__(self, value: str) -> str:
        """An argv item, environment entry or path."""
        return self.capped(value, MAX_FIELD_CHARS, "field_chars")

    def name(self, value: str) -> str:
        """An address, a host name, a DNS class or type."""
        return self.capped(value, MAX_NAME_CHARS, "name_chars")

    def items(self, values: Sequence[str] | None, limit: int, cut: Cut) -> tuple[str, ...]:
        values = values or ()
        kept = tuple(self(v) for v in values[:limit])
        if len(values) <= limit:
            return kept
        self.cuts[cut] += 1
        return (*kept, ELLIPSIS)


def sandbox_tarball(job: SandboxJob) -> str:
    """Where the exported `<key>.tgz` is in the sandbox: `run_analysis.sh` mounts `-local` at
    `/<basename>` and `cmd/analyze` copies it to the same path."""
    return f"/{job.key}.tgz"


def driver_argv(job: SandboxJob, phase: Phase) -> tuple[str, ...]:
    """package-analysis's own driver command for `job` in `phase`, as rel-38 starts it
    (`internal/dynamicanalysis/sandbox_args.go` `MakeAnalysisArgs`, run by `podman exec` in the
    sandbox): `analyze-node.js --local /<file> <phase> <name>`. The file is the export's
    `<key>.tgz`, mounted at `/<key>.tgz` by `run_analysis.sh`; the name is the lowercased
    `-package`."""
    return (DRIVER, "--local", sandbox_tarball(job), phase, job.package.lower())


def _is_driver(argv: Sequence[str], expected: tuple[str, ...]) -> bool:
    """The driver as `podman exec` starts it, or the `node` line its `#!/usr/bin/env node`
    shebang becomes."""
    if tuple(argv) == expected:
        return True
    return (
        len(argv) == len(expected) + 1
        and argv[0].rpartition("/")[2] == "node"
        and tuple(argv[1:]) == expected
    )


def _bait_env(environment: Sequence[str] | None) -> tuple[str, ...] | None:
    """The bait values of an environment, in `CANARY_VARS` order, when it holds each bait name
    exactly once, with a value in the generator's exact shape; else None."""
    values: dict[str, list[str]] = {name: [] for name in CANARY_VARS}
    for entry in environment or ():
        name, sep, value = entry.partition("=")
        if sep and name in values:
            values[name].append(value)
    found = []
    for name in CANARY_VARS:
        if len(values[name]) != 1 or not BAIT_SHAPES[name].fullmatch(values[name][0]):
            return None
        found.append(values[name][0])
    return tuple(found)


def _baits(
    present: Sequence[tuple[Phase, _Summary]], job: SandboxJob
) -> tuple[list[Bait], Counter[Cut]]:
    """The bait values package-analysis planted, and the forgeries found on the way.

    rel-38 plants them in the sandbox container's own environment (`podman create -e`, from
    `RunDynamicAnalysis` in `internal/worker/rundynamic.go`), so they are in the environment of
    package-analysis's driver command (`driver_argv`), which `podman exec` starts with the
    container's environment. Per phase, the driver is the **first** command in upstream order
    with the driver's argv (or the `node` line its shebang becomes, which has the same
    environment) whose environment holds both bait names once each, in the generator's shape
    (`generateAWSKeys`: `AKIAI` + 14 base32 letters + `Q`; 30 random bytes in standard base64).
    A package can't make one of its own values a bait by putting it in a child's environment
    (round-3 review: a child given `AWS_ACCESS_KEY_ID=<C2 address>` hid the address). It can
    forge the driver's command line (upstream records argv, not the executable): a later
    driver-shaped command with other bait values is ignored and counted as `forged_drivers`,
    so a flood of forgeries can't push the real values out (round-4 review: four forged drivers
    did), and phases whose drivers disagree are counted as `bait_mismatch` (both phases run in
    one sandbox, with one pair). A forgery that sorts before the real driver wins its phase:
    then the real values are not masked (the rules' shape tests still see an AWS key ID), and
    the forgery is counted, because the real driver then follows it."""
    cuts: Counter[Cut] = Counter()
    chosen: list[tuple[str, ...]] = []
    for phase, summary in present:
        expected = driver_argv(job, phase)
        first: tuple[str, ...] | None = None
        for command in summary.Commands or ():
            if not _is_driver(command.Command or (), expected):
                continue
            values = _bait_env(command.Environment)
            if values is None:
                continue
            if first is None:
                first = values
            elif values != first:
                cuts["forged_drivers"] += 1
        if first is not None:
            chosen.append(first)
    distinct = list(dict.fromkeys(chosen))
    if len(distinct) > 1:
        cuts["bait_mismatch"] += len(distinct) - 1
    baits = [
        (name, value)
        for values in distinct
        for name, value in zip(CANARY_VARS, values, strict=True)
    ]
    return baits, cuts


def _stdio(value: str | None, clean: Cleaner) -> str:
    """The base64 output tail as text (UTF-8, invalid bytes replaced), at most `STDIO_BYTES`
    of the end, cleaned."""
    if value is None:
        return ""
    if len(value) > MAX_STDIO_BASE64:
        raise MalformedResultError("an output field is far over package-analysis's 4 KiB")
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error, ValueError:
        raise MalformedResultError("an output field is not base64") from None
    if len(raw) > STDIO_BYTES:
        clean.cuts["output_bytes"] += 1
    return clean.text(raw[-STDIO_BYTES:].decode("utf-8", errors="replace"))


# --- observations ------------------------------------------------------------------------------
#
# Two passes, so that a flood costs little and can't choose what survives. First, every upstream
# entry becomes a light raw key (the parsed strings, uncleaned), deduplicated per (phase, kind)
# in first-appearance order, and ranked (`priority`). Then, if there are more than
# MAX_OBSERVATIONS, the cap is spent tier by tier (`_kept`). Only kept entries are cleaned and
# built.

_Raw = tuple[object, ...]


def _raw_entries(kind: ObservationKind, summary: _Summary, clean: Cleaner) -> Iterator[_Raw]:
    match kind:
        case K.EXEC:
            for command in summary.Commands or ():
                yield (tuple(command.Command or ()), tuple(command.Environment or ()))
        case K.OPEN:
            for file in summary.Files or ():
                yield (file.Path, file.Read, file.Write, file.Delete)
        case K.CONNECT:
            for socket in summary.Sockets or ():
                hosts: list[str | None] = list(dict.fromkeys(socket.Hostnames or ()))
                if len(hosts) > MAX_HOSTNAMES:
                    clean.cuts["hostnames"] += 1
                for host in hosts[:MAX_HOSTNAMES] or [None]:
                    yield (socket.Address, socket.Port, host)
        case K.DNS:
            for dns in summary.DNS or ():
                for query in dns.Queries or ():
                    yield (dns.Class, query.Hostname, tuple(query.Types or ()))


def _benign_host(host: str) -> bool:
    return host.lower().rstrip(".") in PRIORITY_BENIGN_HOSTS


def priority(kind: ObservationKind, raw: _Raw, clean: Cleaner, tarball: str) -> int:
    """The tier of a raw entry (0 first; see `TIERS`). A pure function of the entry, the bait
    values and the exported tarball's path in the sandbox (`sandbox_tarball`). An exec's
    environment is not looked at: every command inherits the baits."""
    match kind:
        case K.EXEC:
            argv = cast(tuple[str, ...], raw[0])
            joined = "\0".join(argv)  # no word holds a NUL, so no match spans two words
            lowered = joined.lower()
            if (
                tarball in joined
                or any(w in lowered for w in STRONG_WORDS)
                or clean.has_bait(joined)
            ):
                return 0
            program = argv[0].rpartition("/")[2] if argv else ""
            weak = any(w in lowered for w in WEAK_WORDS)
            return 1 if weak or PRIORITY_PROGRAM.fullmatch(program) else 2
        case K.OPEN:
            path, _, write, delete = cast(tuple[str, bool, bool, bool], raw)
            if path == tarball or PRIORITY_PATH.search(path):
                return 0
            return 1 if (write or delete) and not path.startswith(NPM_OWN_DIRS) else 2
        case K.CONNECT:
            host = cast(str | None, raw[2])
            return 2 if host is not None and _benign_host(host) else 0
        case K.DNS:
            return 2 if _benign_host(cast(str, raw[1])) else 0
    raise AssertionError(kind)  # pragma: no cover (the match is exhaustive)


def _build(phase: Phase, kind: ObservationKind, raw: _Raw, clean: Cleaner) -> Observation:
    match kind:
        case K.EXEC:
            argv, env = cast(tuple[tuple[str, ...], tuple[str, ...]], raw)
            return Observation(
                phase=phase,
                kind=kind,
                source="strace",
                argv=clean.items(argv, MAX_ARGV, "argv_items"),
                env=clean.items(env, MAX_ENV, "env_items"),
            )
        case K.OPEN:
            path, read, write, delete = cast(tuple[str, bool, bool, bool], raw)
            named: tuple[tuple[FileFlag, bool], ...] = (
                ("read", read),
                ("write", write),
                ("delete", delete),
            )
            return Observation(
                phase=phase,
                kind=kind,
                source="strace",
                path=clean(path),
                flags=tuple(flag for flag, on in named if on),
            )
        case K.CONNECT:
            address, port, host = cast(tuple[str, int, str | None], raw)
            return Observation(
                phase=phase,
                kind=kind,
                source="strace",
                address=clean.name(address),
                port=port or None,
                host=None if host is None else clean.name(host),
            )
        case K.DNS:
            klass, hostname, raw_types = cast(tuple[str, str, tuple[str, ...]], raw)
            types = sorted({clean.name(t) for t in raw_types})
            if len(types) > MAX_TYPES:
                clean.cuts["dns_types"] += 1
            return Observation(
                phase=phase,
                kind=kind,
                source="pcap",
                host=clean.name(hostname),
                detail=clean.name(" ".join([klass, *types[:MAX_TYPES]])),
            )
    raise AssertionError(kind)  # pragma: no cover (the match is exhaustive)


def fair_quotas(sizes: Sequence[int], total: int) -> list[int]:
    """Max-min fair shares of `total` for groups of these sizes: groups smaller than an equal
    share keep everything, and what they leave is shared among the others. Deterministic
    (ties by position)."""
    quotas = [0] * len(sizes)
    remaining = total
    order = sorted(range(len(sizes)), key=lambda i: (sizes[i], i))
    for position, i in enumerate(order):
        share = remaining // (len(sizes) - position)
        quotas[i] = min(sizes[i], share)
        remaining -= quotas[i]
    return quotas


def keyed_sample(entries: Sequence[_Raw], quota: int, salt: bytes) -> list[int]:
    """The positions of `quota` of `entries`, chosen by the sha256 of `salt` and each entry
    (lowest digests win; ties by position). With the result file's sha256 as the salt, the
    package can't steer the choice: the digest depends on the whole file, which holds the
    entries themselves (and package-analysis's timestamp and random DNS order), so it can't
    be known while they are chosen. A replay re-parses the same bytes and keeps the same."""
    if quota >= len(entries):
        return list(range(len(entries)))
    ranked = sorted(
        range(len(entries)),
        key=lambda i: (
            hashlib.sha256(salt + repr(entries[i]).encode("utf-8", "backslashreplace")).digest(),
            i,
        ),
    )
    return sorted(ranked[:quota])


@dataclass(frozen=True)
class _Group:
    phase: Phase
    kind: ObservationKind
    entries: list[_Raw]
    tiers: list[int]


def _kept(groups: Sequence[_Group], cap: int, salt: bytes) -> list[list[int]]:
    """The positions each group keeps under `cap`, in upstream order. The cap is spent tier by
    tier: each tier's entries get a max-min fair share per group of what the tiers above left
    (`fair_quotas`), so a flood in one group can't take another below its fair share, and a
    group cut within a tier keeps a keyed sample of that tier (`keyed_sample`), not its first and
    last entries: package-analysis sorts commands and files, so head and tail are the
    package's choice (round-4 review)."""
    kept: list[set[int]] = [set() for _ in groups]
    remaining = cap
    for tier in range(TIERS):
        members = [[i for i, t in enumerate(g.tiers) if t == tier] for g in groups]
        quotas = fair_quotas([len(m) for m in members], remaining)
        for group, keep, positions, quota in zip(groups, kept, members, quotas, strict=True):
            chosen = keyed_sample([group.entries[i] for i in positions], quota, salt)
            keep.update(positions[j] for j in chosen)
        remaining -= sum(quotas)
    return [sorted(keep) for keep in kept]


def _observations(
    present: Sequence[tuple[Phase, _Summary]], clean: Cleaner, job: SandboxJob, salt: bytes
) -> tuple[tuple[Observation, ...], tuple[GroupCount, ...]]:
    tarball = sandbox_tarball(job)
    groups: list[_Group] = []
    for phase, summary in present:
        for kind in _KIND_ORDER:
            unique = list(dict.fromkeys(_raw_entries(kind, summary, clean)))
            if unique:
                tiers = [priority(kind, raw, clean, tarball) for raw in unique]
                groups.append(_Group(phase, kind, unique, tiers))
    total = sum(len(g.entries) for g in groups)
    if total > MAX_OBSERVATIONS:
        kept = _kept(groups, MAX_OBSERVATIONS, salt)
        clean.cuts["observations"] += total - sum(len(k) for k in kept)
    else:
        kept = [list(range(len(g.entries))) for g in groups]
    counts = tuple(
        GroupCount(
            phase=g.phase,
            kind=g.kind,
            recorded=len(g.entries),
            kept=len(keep),
            priority=sum(t < TIERS - 1 for t in g.tiers),
            priority_kept=sum(g.tiers[i] < TIERS - 1 for i in keep),
        )
        for g, keep in zip(groups, kept, strict=True)
    )
    built = (
        _build(g.phase, g.kind, g.entries[i], clean)
        for g, keep in zip(groups, kept, strict=True)
        for i in keep
    )
    return tuple(dict.fromkeys(built)), counts  # cleaning can make two raw entries equal


def run_status(phases: Sequence[PhaseResult]) -> RunStatus:
    """What the analysis amounts to (see `models.RunStatus`)."""
    if not phases or phases[0].phase != "install":
        return "infra-error"
    statuses = {p.status for p in phases}
    if "error_other" in statuses:
        return "infra-error"
    if "error_timeout" in statuses:
        return "timeout"
    if "error_analysis" in statuses:
        return "failed"
    return "completed"


def parse_dynamic(data: bytes, job: SandboxJob) -> SandboxResult:
    """A package-analysis dynamic result for `job`, from the file's bytes. Raises
    `MalformedResultError`. A pure function of `data` and `job`."""
    record = _validate(data)
    check_identity(record.Package, job)
    analysis = record.Analysis
    present: list[tuple[Phase, _Summary]] = []
    if analysis is not None:
        by_phase = {
            "install": analysis.install,
            "import": analysis.import_,
            "execute": analysis.execute,
        }
        present = [(p, s) for p in PHASES if (s := by_phase[p]) is not None]
    baits, forged = _baits(present, job)
    clean = Cleaner(baits)
    clean.cuts.update(forged)
    phases = tuple(
        PhaseResult(
            phase=p, status=s.Status, stdout=_stdio(s.Stdout, clean), stderr=_stdio(s.Stderr, clean)
        )
        for p, s in present
    )
    digest = sha256_hex(data)
    observations, groups = _observations(present, clean, job, bytes.fromhex(digest))
    cuts = {cut: clean.cuts[cut] for cut in get_args(Cut) if clean.cuts[cut]}
    run = SandboxRun(
        job=job,
        status=run_status(phases),
        phases=phases,
        result_sha256=digest,
        created=record.CreatedTimestamp,
        observation_count=len(observations),
        truncated=bool(cuts),
        cuts=cuts,
        groups=groups,
        canaries=tuple(sorted({name for name, _ in baits})),
        network=job.network,
    )
    return SandboxResult(run=run, observations=observations)
