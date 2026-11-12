"""npm dependencies installed from a GitHub repository instead of the registry, as data: which
repository and reference a dependency spec names, which commit that reference is in the
repository's refs, and which of the dependency's scripts `npm install` runs (decision 0020).

npm installs a git dependency by cloning it, running `npm install` in the clone (with the
dependency's devDependencies) when it has a script to prepare, running its `prepare`, packing
it and installing the pack: so besides `preinstall`, `install` and `postinstall`, the root
lifecycle of `npm install` runs, `prepublish`, `preprepare`, `prepare` and `postprepare`
(`GIT_ONLY_HOOKS`; pacote's `DirFetcher` runs only `prepare` around the pack, never
`prepack`/`postpack`). A GitHub *archive URL* (`codeload.github.com/o/r/tar.gz/<ref>`,
`github.com/o/r/archive/<ref>.tar.gz`) is a remote tarball to npm: only the three install hooks
run. `web3-mev-error-decoder@0.1.0` (2026-11-09, malicious) shipped no install code itself and
depended on `github:outgoingyang/multicall-error-decoder`, whose `install` hook ran its payload.

The rules that read install code know the three install hooks (`metadata.INSTALL_HOOKS`), so
the dependency is shown to them with what npm runs in those three slots (`npm_runs`): each
git-only hook takes a free slot, and `npm run <script>` is replaced with the script it runs
(npm also runs `pre<script>` and `post<script>` around it). Findings name the real hooks
(`SlotHooks`).

Only `github.com` repositories are read. Credentials in a spec's URL
(`git+https://<token>@github.com/...`) are never used: requests are built from the owner and
repository name alone, and `redacted` drops them from what is shown.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from kitsunox.ecosystems.npm.ranges import clean, max_satisfying
from kitsunox.ecosystems.npm.rules.metadata import (
    INSTALL_HOOKS,
    is_registry_spec,
    runtime_dependencies,
    scripts,
)
from kitsunox.githost.github import GitHubRepo

# The scripts npm runs for a git dependency besides the install hooks, in the order it runs
# them (the root lifecycle of `npm install` in the clone).
GIT_ONLY_HOOKS: Final = ("prepublish", "preprepare", "prepare", "postprepare")
GIT_HOOKS: Final = (*INSTALL_HOOKS, *GIT_ONLY_HOOKS)

_NAME: Final = r"[A-Za-z0-9_.-]+"
_SHA: Final = re.compile(r"^[0-9a-f]{40}$")
_SHORT_SHA: Final = re.compile(r"^[0-9a-f]{7,39}$")
# Git specs npm reads as a GitHub repository (npm-package-arg through hosted-git-info).
_SHORTCUT: Final = re.compile(rf"^github:(?P<owner>{_NAME})/(?P<repo>{_NAME})(?:#(?P<frag>.*))?$")
_BARE: Final = re.compile(
    rf"^(?P<owner>[A-Za-z0-9_-][A-Za-z0-9_.-]*)/(?P<repo>{_NAME})(?:#(?P<frag>.*))?$"
)
_GIT_URL: Final = re.compile(
    r"^(?:git\+)?(?:https?|ssh|git)://(?:[^@/\s]*@)?(?:www\.)?github\.com[:/]"
    rf"(?P<owner>{_NAME})/(?P<repo>{_NAME})/?(?:#(?P<frag>.*))?$",
    re.IGNORECASE,
)
_SCP: Final = re.compile(
    rf"^(?:git\+)?[^@/\s]+@github\.com:(?P<owner>{_NAME})/(?P<repo>{_NAME})(?:#(?P<frag>.*))?$",
    re.IGNORECASE,
)
# GitHub archive URLs, which npm fetches as remote tarballs.
_ARCHIVE_URL: Final = (
    re.compile(
        rf"^https?://codeload\.github\.com/(?P<owner>{_NAME})/(?P<repo>{_NAME})"
        r"/(?:legacy\.)?tar\.gz/(?P<ref>[^?#\s]+)$",
        re.IGNORECASE,
    ),
    re.compile(
        rf"^https?://(?:www\.)?github\.com/(?P<owner>{_NAME})/(?P<repo>{_NAME})"
        r"/archive/(?P<ref>[^?#\s]+)\.tar\.gz$",
        re.IGNORECASE,
    ),
    re.compile(
        rf"^https?://(?:www\.)?github\.com/(?P<owner>{_NAME})/(?P<repo>{_NAME})"
        r"/tarball/(?P<ref>[^?#\s]+)$",
        re.IGNORECASE,
    ),
)
_USERINFO: Final = re.compile(r"(?<=://)[^@/\s]+@")


@dataclass(frozen=True)
class GitHubSpec:
    """A dependency spec that installs a GitHub repository: the repository, the reference it
    names (`committish`: a commit, tag or branch; `semver`: a range over its tags; neither:
    the default branch), the subdirectory npm installs (`::path:`), and whether npm fetches it
    as a remote tarball (an archive URL: install hooks only) rather than as git."""

    owner: str
    name: str
    committish: str | None = None
    semver: str | None = None
    path: str = ""
    tarball: bool = False

    @property
    def repo(self) -> GitHubRepo:
        return GitHubRepo(owner=self.owner, name=self.name)

    @property
    def hooks(self) -> tuple[str, ...]:
        """The scripts npm runs when it installs the dependency this way."""
        return INSTALL_HOOKS if self.tarball else GIT_HOOKS

    @property
    def key(self) -> tuple[str, str, str, str, str, bool]:
        """What two specs share when they install the same thing (GitHub names are not case
        sensitive)."""
        return (
            self.owner.lower(),
            self.name.lower(),
            self.committish or "",
            self.semver or "",
            self.path,
            self.tarball,
        )

    @property
    def reference(self) -> str:
        """The reference as written, for explanations."""
        if self.semver is not None:
            return f"semver:{self.semver}"
        return self.committish or "the default branch"


def github_spec(spec: str) -> GitHubSpec | None:
    """The GitHub repository a dependency spec installs, or None for anything else (registry
    specs, local paths, other hosts, release assets and any URL npm doesn't read as a GitHub
    repository or archive)."""
    text = spec.strip()
    if is_registry_spec(text):
        return None
    for pattern in _ARCHIVE_URL:
        if (match := pattern.match(text)) is not None:
            ref = match["ref"]
            if not _plain_ref(ref):
                return None
            return GitHubSpec(
                owner=match["owner"],
                name=_repo_name(match["repo"]),
                committish=ref,
                tarball=True,
            )
    match = _SHORTCUT.match(text) or _GIT_URL.match(text) or _SCP.match(text)
    if match is None and "://" not in text and ":" not in text.split("#", 1)[0]:
        match = _BARE.match(text)
    if match is None:
        return None
    name = _repo_name(match["repo"])
    if name in ("", ".", "..") or match["owner"] in (".", ".."):
        return None
    committish, semver, path = _fragment(match["frag"] or "")
    if committish is not None and not _plain_ref(committish):
        return None
    return GitHubSpec(
        owner=match["owner"], name=name, committish=committish, semver=semver, path=path
    )


def _repo_name(text: str) -> str:
    return text[:-4] if text.lower().endswith(".git") else text


def _plain_ref(ref: str) -> bool:
    """A reference we can look up: no path traversal, whitespace or control characters."""
    return bool(ref) and ".." not in ref.split("/") and not re.search(r"[\s\x00-\x1f\\]", ref)


def _fragment(fragment: str) -> tuple[str | None, str | None, str]:
    """npm's git fragment: `::`-separated parts, each a committish, `semver:<range>` or
    `path:<directory>`. The last committish or range wins, as in npm-package-arg."""
    committish: str | None = None
    semver: str | None = None
    path = ""
    for part in fragment.split("::"):
        if not part:
            continue
        if part.startswith("semver:"):
            semver, committish = part.removeprefix("semver:"), None
        elif part.startswith("path:"):
            parts = [
                p for p in part.removeprefix("path:").strip("/").split("/") if p not in ("", ".")
            ]
            path = "" if any(p == ".." or "\\" in p for p in parts) else "/".join(parts)
        elif ":" not in part:
            committish, semver = part, None
    return committish, semver, path


def resolve(spec: GitHubSpec, refs: Mapping[str, str]) -> tuple[str, str] | None:
    """The commit `spec` names in the repository's refs (`parse_ref_advertisement`, with
    `HEAD`), and how it was found; None when the refs don't have it. A full commit id is taken
    as it is (GitHub serves commits that no ref names, a fork's included); a range takes the
    highest tag that satisfies it, as npm does; a name is a tag, then a branch; an abbreviated
    commit id must match exactly one ref's commit."""
    if spec.semver is not None:
        tags: dict[str, tuple[str, str]] = {}
        for name, commit in sorted(refs.items()):
            if name.startswith("refs/tags/"):
                version = clean(name.removeprefix("refs/tags/"), loose=True)
                if version is not None:
                    tags.setdefault(version, (commit, name.removeprefix("refs/tags/")))
        best = max_satisfying(tags, spec.semver, loose=True)
        if best is None:
            return None
        tagged, tag = tags[best]
        return tagged, f"tag {tag} (semver:{spec.semver})"
    ref = spec.committish
    if ref is None:
        head = refs.get("HEAD")
        return (head, "the default branch") if head is not None else None
    if _SHA.match(ref.lower()):
        return ref.lower(), "commit"
    for candidate, how in (
        (ref, "ref"),
        (f"refs/tags/{ref}", "tag"),
        (f"refs/heads/{ref}", "branch"),
        (f"refs/{ref}", "ref"),
    ):
        if candidate.startswith("refs/") and (found_at := refs.get(candidate)) is not None:
            return found_at, f"{how} {ref}"
    if _SHORT_SHA.match(ref.lower()):
        found = {c for c in refs.values() if c.startswith(ref.lower())}
        if len(found) == 1:
            return found.pop(), f"commit {ref}"
    return None


def redacted(spec: str) -> str:
    """The spec without credentials in its URL (`https://<token>@github.com/...`)."""
    return _USERINFO.sub("***@", spec)


# `npm run <script>` (and the same in pnpm, yarn and bun): replaced with what it runs.
_RUN: Final = re.compile(
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:run|run-script)\s+(?:--?[A-Za-z][\w-]*\s+)*"
    r"(?P<script>[\w:@./-]+)"
)
RUN_DEPTH: Final = 3
MAX_COMMAND_CHARS: Final = 4096


def expand_runs(command: str, declared: Mapping[str, str], depth: int = RUN_DEPTH) -> str:
    """`command` with each `npm run <script>` replaced by the commands npm runs for it
    (`pre<script>`, `<script>`, `post<script>`, joined with `&&`), `depth` levels deep. A script
    the manifest doesn't declare stays as written; so does anything past `MAX_COMMAND_CHARS`."""
    if depth <= 0:
        return command

    def replace(match: re.Match[str]) -> str:
        name = match["script"]
        if name not in declared:
            return match.group(0)
        parts = [declared.get(f"pre{name}", ""), declared[name], declared.get(f"post{name}", "")]
        inner = " && ".join(p.strip() for p in parts if p.strip())
        return expand_runs(inner, declared, depth - 1) if inner else match.group(0)

    expanded = _RUN.sub(replace, command)
    return expanded if len(expanded) <= MAX_COMMAND_CHARS else command


SlotHooks = Mapping[str, tuple[str, ...]]


def npm_runs(
    manifest: Mapping[str, Any], hooks: tuple[str, ...]
) -> tuple[dict[str, str], SlotHooks]:
    """What npm runs when it installs the dependency, in the three install-hook slots the rules
    read: `{slot: command}` and, for each slot, the dependency's own hooks it holds. An install
    hook keeps its slot; each git-only hook takes the first free one (`postinstall`, `install`,
    `preinstall`), and with none free joins the last slot taken with `&&`. Commands have their
    `npm run` steps expanded (`expand_runs`)."""
    declared = scripts(manifest)
    slots: dict[str, str] = {}
    held: dict[str, tuple[str, ...]] = {}
    for hook in INSTALL_HOOKS:
        if hook in hooks and declared.get(hook, "").strip():
            slots[hook] = declared[hook].strip()
            held[hook] = (hook,)
    last: str | None = None
    for hook in hooks:
        if hook in INSTALL_HOOKS or not declared.get(hook, "").strip():
            continue
        command = declared[hook].strip()
        free = next((s for s in ("postinstall", "install", "preinstall") if s not in slots), None)
        if free is not None:
            slots[free], held[free], last = command, (hook,), free
        else:
            target = last or "postinstall"
            slots[target] = f"{slots[target]} && {command}"
            held[target] = (*held[target], hook)
            last = target
    expanded = {slot: expand_runs(command, declared) for slot, command in slots.items()}
    return expanded, held


def presented_manifest(manifest: Mapping[str, Any], slots: Mapping[str, str]) -> dict[str, Any]:
    """`manifest` with its scripts replaced by what npm runs (`npm_runs`) and the scripts that
    don't run at install."""
    declared = scripts(manifest)
    kept = {k: v for k, v in declared.items() if k not in GIT_HOOKS}
    return {**manifest, "scripts": {**kept, **slots}}


def read_manifest(raw: bytes | None) -> dict[str, Any] | None:
    """A `package.json` as a JSON object, or None if missing or unreadable."""
    if raw is None:
        return None
    try:
        manifest = json.loads(raw)
    except ValueError, RecursionError:
        return None
    return manifest if isinstance(manifest, dict) else None


def non_registry(manifest: Mapping[str, Any]) -> dict[str, str]:
    """The runtime dependencies npm fetches from outside the registry (a dependency's own git
    dependencies: noted, not followed)."""
    return {
        name: spec
        for name, spec in sorted(runtime_dependencies(manifest).items())
        if not is_registry_spec(spec)
    }
