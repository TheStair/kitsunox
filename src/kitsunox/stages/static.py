"""Stage 2: static heuristics over the file contents a package batch adds.

See `docs/stages/static.md`. For a `PackageBatch`, every file content (by SHA-256) that is in
some version but not in the base is analysed once, through a content-addressed cache, and its
findings are attributed to the first version that contained it.

A changed file is matched whole, so its old matches would fire again on every release (a
Telegram bot's `api.telegram.org/bot` in every version of the bot). A match the base version's
file at the same path already had (same rule, same explanation up to numbers) is LOW, weight 1,
and says so; a bundler's content-hashed chunk (`registry-BX6j2lnF.mjs`) is compared with the
base's chunks of the same name (`BaseFiles`); a match only in a file that never runs
(documentation, type declarations, source maps, tests) is LOW too (`_demoted`; until
2026-10-30 only `exfil-endpoint`, then every rule: `@atairo/qixi` was MEDIUM for an IP in a
bundled dependency's README).
Nothing is dropped: the evidence stays for the reviewer and for scoring with other signals.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Container, Iterable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Final, Literal

import httpx

from kitsunox.core.interfaces import Ecosystem, PartialArtifacts
from kitsunox.core.models import (
    Candidate,
    Finding,
    PackageBatch,
    Record,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.core.rules import ArtifactRule, FileMatch, FileRule, rules_fingerprint
from kitsunox.core.run import STATIC_SNAPSHOT, DataDir, EcosystemFactory
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.ecosystems.npm.rules.metadata import has_install_hook
from kitsunox.rules.disguised import CLAIMS
from kitsunox.rules.partial import omitted_files, partial_summary
from kitsunox.rules.signatures import KnownSignature
from kitsunox.rules.static import (
    CONTEXT_NOTES,
    RULES,
    ChannelFollow,
    ChannelTagging,
    HardcodedIp,
    ShellStartup,
)
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.triage import at_least
from kitsunox.util.archive import KeepPolicy
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchError, FetchMode, HttpFetcher, Snapshot, TransientFetchError

STAGE_ID: Final = "static"
# 16 MB, not 2: the Shai-Hulud payload (`bun_environment.js`) is ~10 MB, and 698 of 965
# first-release compromised samples added a file over 2 MB (2026-10-27).
MAX_FILE_BYTES: Final = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES: Final = MAX_FILE_BYTES
# A version that declares an install hook is read up to 32 MB declared: the hook runs on every
# `npm install`, and the worm's follow-ons carry a ~10 MB payload in an otherwise large package
# (2026-11-08, `vm-day1`: 97 of 481 malicious shape-A follow-ons were over 16 MB, all hooked and
# all flagged by Stage 2 when read; 44 of them are at most 32 MB). Live, about 339 more versions
# and 2.5 to 4.8 GB of tarballs a day (docs/proposals/stage2-routing-recall.md).
MAX_HOOK_ARTIFACT_BYTES: Final = 2 * MAX_ARTIFACT_BYTES
# Over that, a version with an install hook is read partially, up to 1 GiB declared (decision
# 0021, `ArtifactFiles`): streamed once, its text and code kept, its binaries only listed. On
# 2026-11-11..13, 1,434 of the 1,437 hooked versions Stage 2 skipped for size were at most
# 512 MB, the other 3 were 659 MB.
MAX_PARTIAL_ARTIFACT_BYTES: Final = 1 << 30
# What a partial read keeps of each text file, and of all of them (decision 0021).
PARTIAL_FILE_BYTES: Final = MAX_FILE_BYTES
PARTIAL_KEPT_BYTES: Final = 64 * 1024 * 1024
INSTALL_HOOK_BY_ECOSYSTEM: Final[dict[str, Callable[[Mapping[str, Any]], bool]]] = {
    "npm": has_install_hook
}
# Decision reasons for missing files, e.g. "files unavailable: ..." or "; base unavailable, will
# retry: ...". The retry form marks a network failure, which `collect` retries.
UNAVAILABLE: Final = "unavailable: "
WILL_RETRY: Final = "unavailable, will retry: "
# A partial read's note on the decision reason (decision 0021): "; partial read: 12 files
# (310.2 MB) not read".
PARTIAL_NOTE: Final = "; partial read: "
DEFAULT_THRESHOLD: Final = Severity.MEDIUM
ARTIFACT_RULES_BY_ECOSYSTEM: Final[dict[str, Sequence[ArtifactRule]]] = {"npm": NPM_ARTIFACT_RULES}

Tree = Mapping[str, bytes]


class NewContent(Record):
    path: str
    sha256: str
    size: int
    first_version: str


class Unavailable(Record):
    """A version's files could not be read; `reason` says why (too large, fetch failed).
    `transient`: a network failure, so fetching again later may work."""

    reason: str
    transient: bool = False


def new_contents(
    base: Tree | None, versions: Iterable[tuple[str, Tree]]
) -> Iterator[tuple[NewContent, bytes]]:
    """Contents in any version that the base does not have, each once, in version order (then
    path order). The first path and version a content appears under is the one reported.
    `versions` is consumed lazily, so only one version's files need to be in memory."""
    seen = {sha256_hex(content) for content in (base or {}).values()}
    for version, tree in versions:
        for path in sorted(tree):
            content = tree[path]
            digest = sha256_hex(content)
            if digest in seen:
                continue
            seen.add(digest)
            yield (
                NewContent(path=path, sha256=digest, size=len(content), first_version=version),
                content,
            )


class ContentCache:
    """Rule results by content hash, on disk, per rule-set fingerprint. A pure-function cache:
    entries never need invalidating, because changing a rule changes the fingerprint."""

    def __init__(self, root: Path | None, rules: Sequence[FileRule]) -> None:
        self.rules = rules
        self.dir = root / rules_fingerprint(rules) if root else None

    def matches(self, digest: str, content: bytes) -> tuple[FileMatch, ...]:
        path = self.dir / digest[:2] / f"{digest}.json" if self.dir else None
        if path is not None and path.exists():
            try:
                return tuple(FileMatch.model_validate(m) for m in json.loads(path.read_bytes()))
            except ValueError:
                pass  # a damaged entry is a miss: recompute and overwrite it
        result = analyse(content, self.rules)
        if path is not None:
            atomic_write(path, json.dumps([m.model_dump(mode="json") for m in result]).encode())
        return result


# Files npm ships that never run: documentation, type declarations, source maps, tests.
NON_EXECUTING: Final = re.compile(
    r"(?:^|/)(?:readme|changelog|license|contributing|history|security)[^/]*$"
    r"|\.(?:md|markdown|mdx|txt|rst|d\.ts|d\.mts|d\.cts|map)$"
    r"|(?:^|/)(?:docs?|examples?|test|tests|__tests__|fixtures?)/",
    re.IGNORECASE,
)
# Round 5 (L): files named as tests, stories or mocks, which a test runner or Storybook loads,
# never `npm install` or `require`: `chatPorts.test.ts`, `MultiHostDesign.stories.tsx`,
# `alb_api_proxy.test.js`, `__mocks__/`, `test_x.py`, `x_test.go`. A test directory is in
# `NON_EXECUTING` already. Either way a file the package's install hooks or entry points load
# (`LoadedFiles`) is never taken for one: attackers put payloads in `test/` and run them.
TEST_FILES: Final = re.compile(
    r"(?:^|/)[^/]+[._-](?:test|spec)\.[cm]?[jt]sx?$"
    r"|(?:^|/)[^/]+\.(?:stories|story)\.[cm]?[jt]sx?$"
    r"|(?:^|/)(?:__mocks__|__fixtures__|__snapshots__)/"
    r"|(?:^|/)test_[^/]+\.py$|(?:^|/)[^/]+_test\.(?:py|go)$",
    re.IGNORECASE,
)
_NUMBER: Final = re.compile(r"[0-9]+")
PREVIOUS_NOTE: Final = " Also in the previous version's file: not new in this release."
ELSEWHERE_NOTE: Final = " Also in another of the previous version's files: not new in this release."
DOCS_NOTE: Final = " Only in a file that doesn't run (documentation, types, a source map or tests)."
TEST_NOTE: Final = (
    " Only in a test file (`*.test.js`, `*.spec.ts`, a story, a mock), which neither the"
    " install hooks nor the entry points load."
)
# `static.hardcoded-ip` v3 (F4b): files that hold data, not code that runs: markup and tables,
# lockfiles, notices, tests named `*.test.js` / `*.spec.ts` (NON_EXECUTING has `.txt` and test
# directories). `.json` and `.yml` are not here: an app loads its config from them
# (`dsh-model-pipeline@0.10.4`'s undisclosed LLM provider IP). See `_metadata_url` for
# `package.json`.
IP_DATA_FILES: Final = re.compile(
    r"\.(?:html?|xml|csv|tsv|svg|lock|txt)$"
    r"|(?:^|/)(?:NOTICE|NOTICES|THIRD_PARTY_NOTICES|AUTHORS)[^/]*$"
    r"|[._-](?:test|spec)\.[cm]?[jt]sx?$",
    re.IGNORECASE,
)
IP_DATA_NOTE: Final = " Only in a file that holds data or tests, not code that runs."
IP_METADATA_NOTE: Final = " The package's own repository, homepage or bugs URL."
_JSON_URL_LINE: Final = re.compile(
    r'\s*"(?:url|repository|homepage|bugs)"\s*:\s*"([^"\\]*)"\s*,?\s*'
)


def _metadata_url(manifest: bytes, line: int) -> bool:
    """Line `line` of `manifest` (a `package.json`) is one `"url"`, `"repository"`,
    `"homepage"` or `"bugs"` entry whose value is the package's `repository`, `homepage` or
    `bugs` URL, and no script uses it: metadata npm shows, not something that runs. A hook's
    command stays a finding."""
    lines = manifest.split(b"\n")
    if not 0 < line <= len(lines):
        return False
    entry = _JSON_URL_LINE.fullmatch(lines[line - 1].decode("utf-8", "replace"))
    try:
        parsed = json.loads(manifest)
    except ValueError:
        return False
    if entry is None or not isinstance(parsed, dict):
        return False
    urls = set()
    for field in ("repository", "homepage", "bugs"):
        value = parsed.get(field)
        urls.add(value.get("url") if isinstance(value, dict) else value)
    scripts = parsed.get("scripts")
    commands = scripts.values() if isinstance(scripts, dict) else ()
    url = entry.group(1)
    return url in urls and not any(isinstance(c, str) and url in c for c in commands)


def _key(match: FileMatch) -> tuple[str, str]:
    """A match's identity across versions: its rule and explanation, numbers aside (`3235
    obfuscator-style identifiers` and `3301 ...` are the same finding), and without a note
    that depends on the rest of the file (`CONTEXT_NOTES`, round 4): the previous version's
    quiet notifier file and this version's collecting one hold the same Telegram URL."""
    explanation = match.explanation
    for note in CONTEXT_NOTES:
        explanation = explanation.replace(note, "")
    return (match.rule_id, _NUMBER.sub("#", explanation))


# Never "not new": a known family's payload in the previous version too is still the payload,
# and a fork that auto-follows WhatsApp channels does so in every release, each one unwanted
# under the owner's policy (2026-11-08: the live miss `@sakataa/baileys@2.0.0` changed the file,
# but its base already followed, so it was reported only with this). A fork that tags the
# user's messages with its channel (`static.channel-tagging`, 2026-11-09) does so in every
# release too.
ALWAYS_NEW: Final = frozenset({KnownSignature.id, ChannelFollow.id, ChannelTagging.id})
# The same for one form of a rule: `static.shell-startup`'s `inject` (v2, round 11 P3,
# `docs/proposals/gap-fixes-round11-N2.md`). Code that plants a sourced file or a command prompt
# in the user's shell start-up files does so on every release that ships it (`@atedone/
# workspace-context` 0.0.19-0.0.25 changed `lib/sync.js` each time but kept the match, so only
# 0.0.12 and 0.0.18 were reported). The `hook` form is left out: `npm.install-persistence` v7
# (Stage 3) reads the hook command lines on every version, changed or not.
ALWAYS_NEW_FORMS: Final = frozenset({(ShellStartup.id, "inject")})


def always_new(match: FileMatch) -> bool:
    """Whether `match` is never demoted as "not new" (`ALWAYS_NEW`, `ALWAYS_NEW_FORMS`)."""
    if match.rule_id in ALWAYS_NEW:
        return True
    return match.rule_id == ShellStartup.id and (
        (match.rule_id, ShellStartup.form(match.explanation)) in ALWAYS_NEW_FORMS
    )


def _demoted(
    match: FileMatch,
    path: str,
    before: frozenset[tuple[str, str]],
    previous_note: str = PREVIOUS_NOTE,
    content: bytes = b"",
    loaded: Container[str] = frozenset(),
) -> FileMatch:
    """`match` made LOW with a note when it is not new or is in a file that doesn't run.
    `loaded`: the files the version's install hooks and entry points load (`LoadedFiles`),
    which never count as documentation or tests."""
    if match.severity in (Severity.INFO, Severity.LOW):
        return match
    if _key(match) in before and not always_new(match):
        note = previous_note
    elif NON_EXECUTING.search(path) and path not in loaded:
        note = DOCS_NOTE
    elif match.rule_id == HardcodedIp.id and IP_DATA_FILES.search(path):
        note = IP_DATA_NOTE
    elif (
        match.rule_id == HardcodedIp.id
        and path == "package.json"
        and _metadata_url(content, match.line)
    ):
        note = IP_METADATA_NOTE
    elif TEST_FILES.search(path) and path not in loaded:
        note = TEST_NOTE
    else:
        return match
    return match.model_copy(
        update={
            "severity": Severity.LOW,
            "weight": min(match.weight, 1.0),
            "explanation": match.explanation + note,
        }
    )


# A bundler's content hash before the extension: `-BX6j2lnF.mjs` (Vite, Rollup), `.3f2a9b1c.js`
# (webpack). It has a digit, so a word (`-registry.js`) is not taken for one.
_HASHED: Final = re.compile(r"[-.](?=[A-Za-z_]*[0-9])[A-Za-z0-9_]{8,20}(\.(?:m?js|cjs))$")
# Vite's 8-character base64url hash, which may have no digit and may contain `-` or `_`
# (`settings-panel-Bkki_GMk.js`, `-CnQC9-zc.js`): taken for one when it doesn't read as a word.
_VITE_HASH: Final = re.compile(r"-([A-Za-z0-9_-]{8})(\.(?:m?js|cjs))$")


def unhashed(path: str) -> str | None:
    """`path` without its content hash (`dist/a-BX6j2lnF.mjs` -> `dist/a.mjs`), or None."""
    if match := _HASHED.search(path):
        return path[: match.start()] + match.group(1)
    if (match := _VITE_HASH.search(path)) and _random_looking(match.group(1)):
        return path[: match.start()] + match.group(2)
    return None


def _random_looking(text: str) -> bool:
    """Not a word: it has a digit, `_` or `-`, or upper case past the first letter
    (`DPGhQMPB`, not `registry` or `Markdown`)."""
    return any(c.isdigit() or c in "_-" for c in text) or any(c.isupper() for c in text[1:])


class BaseFiles:
    """The base version's files a new file is compared with: the one at the same path, or for a
    content-hashed chunk, which gets a new name whenever its content changes, the base's chunks
    of the same name without the hash (`@camstack/addon-post-analysis` 1.2.654: a comment naming
    `*.trycloudflare.com` was HIGH again on every release). Every base chunk of that name counts,
    and what they matched is worked out once per name: esbuild calls all its chunks
    `chunk-<HASH>.js`, and the first four of them rarely held the match (`@wirecat/*` CLIs'
    bundled ngrok region table, HIGH in each release, 2026-10-31)."""

    def __init__(self, tree: Tree | None) -> None:
        self.tree: Tree = tree or {}
        self._by_name: dict[str, list[str]] | None = None
        self._keys: dict[tuple[str, str], frozenset[tuple[str, str]]] = {}
        self._anywhere: frozenset[tuple[str, str]] | None = None

    def counterparts(self, path: str) -> list[bytes]:
        if path in self.tree:
            return [self.tree[path]]
        name = unhashed(path)
        if name is None:
            return []
        if self._by_name is None:
            self._by_name = {}
            for other in sorted(self.tree):
                if (other_name := unhashed(other)) is not None:
                    self._by_name.setdefault(other_name, []).append(other)
        return [self.tree[p] for p in self._by_name.get(name, ())]

    def keys(self, path: str, cache: ContentCache) -> frozenset[tuple[str, str]]:
        """What `path`'s counterparts matched (nothing if it has none), once per chunk name."""
        name = None if path in self.tree else unhashed(path)
        if path not in self.tree and name is None:
            return frozenset()
        memo = ("path", path) if name is None else ("name", name)
        if memo not in self._keys:
            self._keys[memo] = frozenset(
                _key(m)
                for content in self.counterparts(path)
                for m in cache.matches(sha256_hex(content), content)
            )
        return self._keys[memo]

    def anywhere(self, cache: ContentCache) -> frozenset[tuple[str, str]]:
        """What any of the base's code files matched (not documentation, types, source maps or
        tests), worked out once. For a new file with no counterpart: a chunk renamed in a way
        `unhashed` can't see (`chunk-eevqxagd.js`, `main-Zlzlhfga.js`), code moved to a new
        path or a versioned directory (`framework/v0.7.7/`)."""
        if self._anywhere is None:
            self._anywhere = frozenset(
                _key(m)
                for path, content in sorted(self.tree.items())
                if not NON_EXECUTING.search(path)
                for m in cache.matches(sha256_hex(content), content)
            )
        return self._anywhere


def _base_keys(base: BaseFiles, path: str, cache: ContentCache) -> frozenset[tuple[str, str]]:
    """What the base version's counterparts of `path` matched (nothing if it had none)."""
    return base.keys(path, cache)


def content_matches(
    item: NewContent,
    content: bytes,
    base: BaseFiles,
    cache: ContentCache,
    loaded: Container[str] = frozenset(),
) -> list[FileMatch]:
    """A new content's matches as Stage 2 reports them (`_demoted` against the base).
    `loaded`: what the version's install hooks and entry points load (`LoadedFiles`)."""
    matches = cache.matches(item.sha256, content)
    before = _base_keys(base, item.path, cache) if matches else frozenset()
    note = PREVIOUS_NOTE
    if any(m.severity not in (Severity.INFO, Severity.LOW) for m in matches) and not (
        item.path in base.tree or base.counterparts(item.path)
    ):
        before, note = base.anywhere(cache), ELSEWHERE_NOTE
    manifest = content if item.path == "package.json" and _all_ips_shown(content, matches) else b""
    return [_demoted(m, item.path, before, note, manifest, loaded) for m in matches]


def _npm_loaded(tree: Tree) -> frozenset[str]:
    from kitsunox.ecosystems.npm.entry import load_sources
    from kitsunox.ecosystems.npm.install import install_sources

    return frozenset(install_sources(tree)) | frozenset(load_sources(tree))


LOADED_BY_ECOSYSTEM: Final[dict[str, Callable[[Tree], frozenset[str]]]] = {"npm": _npm_loaded}


class LoadedFiles(Container[str]):
    """The files a version's install hooks and entry points load, in its ecosystem's terms
    (npm: `install_sources` and `load_sources`), worked out on the first question: only a
    MEDIUM or higher match in a documentation or test path asks. An ecosystem with no such
    function loads nothing Stage 2 knows of."""

    def __init__(self, ecosystem: str, tree: Tree) -> None:
        self.ecosystem = ecosystem
        self.tree = tree
        self._paths: frozenset[str] | None = None

    def __contains__(self, path: object) -> bool:
        if self._paths is None:
            loaded = LOADED_BY_ECOSYSTEM.get(self.ecosystem)
            self._paths = loaded(self.tree) if loaded is not None else frozenset()
        return path in self._paths


def _all_ips_shown(content: bytes, matches: Sequence[FileMatch]) -> bool:
    """`static.hardcoded-ip` reported every IP URL in `content`: past its cap of matches, a
    hook's IP after three metadata URLs would go unseen, so then none is taken for metadata."""
    rule = HardcodedIp()
    text = content.decode("utf-8", errors="replace")
    every = sum(rule.accept(m) for m in rule.pattern.finditer(text))
    return every == sum(m.rule_id == HardcodedIp.id for m in matches)


def analyse(content: bytes, rules: Sequence[FileRule] = RULES) -> tuple[FileMatch, ...]:
    if len(content) > MAX_FILE_BYTES or b"\x00" in content[:8192]:
        return ()  # too large for regex triage, or binary
    text = content.decode("utf-8", errors="replace")
    return tuple(m for rule in rules for m in rule.evaluate_text(text))


def analyse_batch(
    batch: PackageBatch,
    trees: Callable[[VersionSnapshot], Tree | Unavailable],
    cache: ContentCache,
    *,
    artifact_rules: Sequence[ArtifactRule] = (),
    threshold: Severity = DEFAULT_THRESHOLD,
) -> PackageBatch:
    """Run Stage 2 on a batch. `trees` gives a version's extracted files (fetching as needed).
    File rules see each new content once; `artifact_rules` see each version's metadata and
    whole file tree. A version whose files are unavailable gets no findings and says why. An
    unavailable base counts as empty: every file of the first version is then new, which costs
    time but can only add findings.

    A new content is new to the batch (not in the base or an earlier version), but whether a
    match is "not new" (`content_matches`) is judged against the version's own previous release
    (`Change.previous`): the version before it in the batch, the base, or a release outside
    the batch (a package publishing two lines, `1.0.x-staging` and `5.0.x-runtime`, in one
    run). Until 2026-11-12 every version was compared with the batch's base, so a later
    version that rebuilt the same obfuscated files (javascript-obfuscator renames on every
    build) or kept any other match of the version before it got the match MEDIUM again, where
    the evaluation (one version against its own previous release) gets it LOW
    (`docs/proposals/precision-round9-S.md`, S2). When the previous release's files are
    unavailable, the base is used, as before, and the reason says so."""
    base = trees(batch.base) if batch.base else None
    base_note = ""
    if isinstance(base, Unavailable):
        base_note = f"; base {_unavailable(base)}"
    missing: dict[str, Unavailable] = {}
    by_artifact: dict[str, tuple[Finding, ...]] = {}
    loaded: dict[str, LoadedFiles] = {}
    previous_notes: dict[str, str] = {}
    partial_notes: dict[str, str] = {}
    base_tree = None if isinstance(base, Unavailable) else base
    base_files = BaseFiles(base_tree)
    # The files the version being read is compared with (its own previous release's), and the
    # last version read: usually the next one's previous release.
    compared = [base_files]
    last: list[tuple[str, Tree]] = []

    def own_previous(candidate: Candidate) -> BaseFiles:
        previous = candidate.change.previous
        if previous is None or (
            batch.base is not None and previous.ref.version == batch.base.ref.version
        ):
            return base_files
        if last and last[0][0] == previous.ref.version:
            return BaseFiles(last[0][1])
        tree = trees(previous)
        if isinstance(tree, Unavailable):
            note = f"; previous {previous.ref.version} {_unavailable(tree)}"
            previous_notes[candidate.change.new.ref.version] = note
            return base_files
        return BaseFiles(tree)

    def versions() -> Iterator[tuple[str, Tree]]:
        for candidate in batch.versions:
            snapshot = candidate.change.new
            version = snapshot.ref.version
            tree = trees(snapshot)
            if isinstance(tree, Unavailable):
                missing[version] = tree
                continue
            by_artifact[version] = tuple(
                f for rule in artifact_rules for f in rule.evaluate_artifact(snapshot, tree)
            )
            if omitted := omitted_files(tree):
                partial_notes[version] = f"{PARTIAL_NOTE}{partial_summary(omitted)}"
            loaded[version] = LoadedFiles(snapshot.ref.ecosystem, tree)
            compared[0] = own_previous(candidate)
            last[:] = [(version, tree)]
            yield version, tree

    found: dict[str, list[tuple[str, FileMatch]]] = {}
    for item, content in new_contents(base_tree, versions()):
        version = item.first_version
        for match in content_matches(item, content, compared[0], cache, loaded[version]):
            found.setdefault(version, []).append((item.path, match))
    updated = []
    for candidate in batch.versions:
        version = candidate.change.new.ref.version
        findings = by_artifact.get(version, ()) + tuple(
            match.finding(path) for path, match in found.get(version, [])
        )
        flagged = sorted({f.rule_id for f in findings if at_least(f.severity, threshold)})
        if version in missing:
            reason = f"files {_unavailable(missing[version])}"
        else:
            reason = f"rules: {', '.join(flagged)}" if flagged else "no signal"
        note = partial_notes.get(version, "") + base_note + previous_notes.get(version, "")
        decision = StageDecision(stage=STAGE_ID, forwarded=bool(flagged), reason=reason + note)
        updated.append(
            candidate.model_copy(
                update={
                    "findings": candidate.findings + findings,
                    "history": (*candidate.history, decision),
                }
            )
        )
    return batch.model_copy(update={"versions": tuple(updated)})


def _unavailable(missing: Unavailable) -> str:
    return f"{WILL_RETRY if missing.transient else UNAVAILABLE}{missing.reason}"


def has_hook(snapshot: VersionSnapshot) -> bool:
    """Whether the version declares an install hook, in its ecosystem's terms."""
    hooked = INSTALL_HOOK_BY_ECOSYSTEM.get(snapshot.ref.ecosystem)
    return hooked is not None and hooked(snapshot.manifest)


# Source and script extensions a partial read always keeps as text, a NUL byte or not: what the
# file rules, Stage 3 and the install-code rules read (`lang.javascript.language_for`,
# `rules.disguised.SCRIPT_MARKERS`, npm's `binding.gyp`).
SOURCE_EXTENSIONS: Final = frozenset(
    {
        *("js", "cjs", "mjs", "jsx", "ts", "cts", "mts", "tsx", "json", "json5"),
        *("sh", "bash", "zsh", "ps1", "psm1", "bat", "cmd", "vbs", "py"),
        *("gyp", "gypi"),
    }
)


def _extension(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name.lstrip(".") else ""


def _always_text(path: str) -> bool:
    return _extension(path) in SOURCE_EXTENSIONS


def _keep_rank(path: str, head: bytes) -> int:
    """Which text a partial read keeps first when its budget is full (lower first): (0) the
    manifest, `binding.gyp`, and text under a binary format's name (`static.disguised-file`'s
    candidates); (1) the package's own code; (2) code and JSON under `node_modules/`, and its
    own JSON; (3) the rest: documentation, type declarations, source maps, tests, data."""
    name = path.rsplit("/", 1)[-1]
    extension = _extension(path)
    if path == "package.json" or name == "binding.gyp" or extension in CLAIMS:
        return 0
    if NON_EXECUTING.search(path) or TEST_FILES.search(path):
        return 3
    if extension not in SOURCE_EXTENSIONS:
        return 3
    if "node_modules" in path.split("/") or extension in ("json", "json5"):
        return 2
    return 1


PARTIAL_POLICY: Final = KeepPolicy(
    version=1,
    max_file_bytes=PARTIAL_FILE_BYTES,
    max_kept_bytes=PARTIAL_KEPT_BYTES,
    text=_always_text,
    rank=_keep_rank,
)


def fetch_limit(
    snapshot: VersionSnapshot,
    max_bytes: int = MAX_ARTIFACT_BYTES,
    hook_max_bytes: int = MAX_HOOK_ARTIFACT_BYTES,
) -> int:
    """The largest declared unpacked size Stage 2 fetches for this version."""
    return max(max_bytes, hook_max_bytes) if has_hook(snapshot) else max_bytes


ReadMode = Literal["whole", "partial"]


def read_mode(
    snapshot: VersionSnapshot,
    max_bytes: int = MAX_ARTIFACT_BYTES,
    hook_max_bytes: int = MAX_HOOK_ARTIFACT_BYTES,
    partial_max_bytes: int = MAX_PARTIAL_ARTIFACT_BYTES,
) -> ReadMode | None:
    """How Stage 2 reads this version's files, from its metadata alone: whole up to
    `fetch_limit`; partially (decision 0021) when it declares an install hook and at most
    `partial_max_bytes`; else not at all (None)."""
    size = snapshot.artifact.unpacked_size if snapshot.artifact else None
    if size is None or size <= fetch_limit(snapshot, max_bytes, hook_max_bytes):
        return "whole"
    if has_hook(snapshot) and size <= partial_max_bytes:
        return "partial"
    return None


class ArtifactFiles:
    """Fetch a version's files through its ecosystem, skipping versions that declare an
    unpacked size over `max_bytes`, or `hook_max_bytes` for a version with an install hook
    (`fetch_limit`): almost all of that volume is platform binaries that the rules skip anyway
    (2026-10-27: versions over 16 MB were 9% of releases and 86% of bytes). A base is held to
    its own limit, so a hook added to a large package can leave its hookless base unread: all
    the files then count as new (Stage 1 flags an added hook HIGH anyway).

    A version with an install hook over its limit is read partially up to `partial_max_bytes`
    (`read_mode`, decision 0021), when the ecosystem can (`PartialArtifacts`): streamed once,
    its text and code kept under `PARTIAL_POLICY`, its binaries listed in the tree's
    `omitted`. Base, previous release or the version itself: the same rule for each."""

    def __init__(
        self,
        ecosystem: Ecosystem,
        max_bytes: int = MAX_ARTIFACT_BYTES,
        hook_max_bytes: int = MAX_HOOK_ARTIFACT_BYTES,
        partial_max_bytes: int = MAX_PARTIAL_ARTIFACT_BYTES,
    ) -> None:
        self.ecosystem = ecosystem
        self.max_bytes = max_bytes
        self.hook_max_bytes = hook_max_bytes
        self.partial_max_bytes = partial_max_bytes

    def __call__(self, snapshot: VersionSnapshot) -> Tree | Unavailable:
        artifact = snapshot.artifact
        if artifact is None:
            return Unavailable(reason="no artifact")
        mode = read_mode(snapshot, self.max_bytes, self.hook_max_bytes, self.partial_max_bytes)
        ecosystem = self.ecosystem
        if mode is None or (mode == "partial" and not isinstance(ecosystem, PartialArtifacts)):
            return Unavailable(reason=f"declared unpacked size {artifact.unpacked_size} bytes")
        try:
            if mode == "partial" and isinstance(ecosystem, PartialArtifacts):
                return ecosystem.fetch_artifact_partial(artifact, PARTIAL_POLICY)
            return ecosystem.fetch_artifact(artifact)
        except (FetchError, ValueError) as exc:  # ValueError: integrity or archive errors
            return Unavailable(
                reason=f"{type(exc).__name__}: {exc}"[:300],
                transient=isinstance(exc, TransientFetchError),
            )


def static_run(
    run_dir: Path,
    files: Callable[[VersionSnapshot], Tree | Unavailable],
    cache: ContentCache,
    *,
    workers: int = 8,
    artifact_rules: Sequence[ArtifactRule] = (),
) -> tuple[PackageBatch, ...]:
    """Stage 2 over a triaged run: reads `batches.jsonl`, writes `static.jsonl` (the same
    batches in the same order, each version with Stage 2 findings and decision). `files` must
    be thread-safe."""
    lines = (run_dir / "batches.jsonl").read_bytes().splitlines()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        batches = tuple(
            pool.map(
                lambda line: analyse_batch(
                    PackageBatch.load_json(line), files, cache, artifact_rules=artifact_rules
                ),
                [line for line in lines if line.strip()],
            )
        )
    write_jsonl(run_dir / "static.jsonl", batches)
    return batches


def record_static(
    data: DataDir,
    run_id: str,
    factory: EcosystemFactory,
    *,
    workers: int = 8,
    client: httpx.Client | None = None,
    seed: Snapshot | None = None,
) -> tuple[PackageBatch, ...]:
    """Stage 2 on a recorded, triaged run, fetching live. Tarballs go into the data directory's
    blob store (immutable, so a tarball already fetched is not fetched again), and the requests
    are recorded in `static-snapshot.json` next to the run. A `seed` (the run's own earlier
    snapshot, when re-scoring) serves what it holds as recorded and keeps it. The caller holds
    `DataDir.lock()`."""
    run_dir = data.run_dir(run_id)
    snapshot = seed if seed is not None else Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=client,
    )
    try:
        ecosystem = factory(fetcher)
        files = ArtifactFiles(ecosystem)
        cache = ContentCache(data.root / "cache" / "static", RULES)
        batches = static_run(
            run_dir,
            files,
            cache,
            workers=workers,
            artifact_rules=ARTIFACT_RULES_BY_ECOSYSTEM.get(ecosystem.name, ()),
        )
    finally:
        fetcher.close()
    snapshot.save(run_dir / STATIC_SNAPSHOT)
    return batches


def needs_retry(batches: Iterable[PackageBatch]) -> bool:
    """Whether any version or base of a Stage 2 result failed on the network."""
    return any(
        c.history[-1].stage == STAGE_ID and WILL_RETRY in c.history[-1].reason
        for b in batches
        for c in b.versions
    )
