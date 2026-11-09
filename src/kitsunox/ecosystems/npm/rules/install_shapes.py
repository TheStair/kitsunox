"""Install code with a recognised benign shape: "explained install" (Stage 3).

Most benign versions reported through the install rules run install code of one of a few
shapes reviewers recognise at a glance (`docs/proposals/precision-round2.md`, S1-S3):

- **S1 platform-binary launcher.** The package ships its binary as per-platform packages in
  `optionalDependencies` (`<name>-linux-x64`, `@scope/<name>-darwin-arm64`), and the install
  code only picks or checks the right one: no network beyond the npm registry.
- **S2 own-release download.** The install code downloads a binary from the package's own
  GitHub repository's releases and checks its checksum, and fetches nothing else.
- **S3 agent-skill copier.** The install code copies the package's skills, hooks or agent
  settings into an AI coding agent's directory (`.claude`, `.agents`, ...) in the project, and
  reaches neither the network nor other processes. Install code (or an install hook's command
  line) that refers to the user's home directory (`os.homedir()`, `process.env.HOME`, `~/`,
  `$HOME`; `agent_config.home_references`) may write user-wide, which the owner rules
  unwanted (decision 0015, addendum 2026-11-09): it is not explained, and
  `npm.install-agent-user-wide` (INFO) says so. Neither is install code that loads a package
  by name (`Profile.packages`): where that package writes can't be seen. What gets copied is
  checked too
  (`kitsunox.lang.agent_config`): hook commands that are more than a constant `echo` or a
  shipped, plain script; permission widening (allow-lists beyond reading, bypass modes, remote
  MCP servers); instructions that work against the user (also flagged on their own,
  `agent.hostile-instructions`).

(S4, build-tool-only hooks, is `npm.install-build-tool`.) Every shape also needs: no install
hook that is shell beyond `node <file>` (`curl`, `| sh`, `$(...)`), no command from
`binding.gyp`, no whole-environment read, dynamic code or dynamic `require` in the install
code, and, for an update, no capability the install code didn't have before (a version whose
install code does something new keeps its findings). A package's name, description or
keywords never count.

The rule is INFO: an explanation for Stage 4 (`correlate.EXPLAINED`), which makes the install
MEDIUMs (`npm.install-hook`, `npm.install-script-changed`, `npm.install-script-code`) LOW,
never a content finding (`npm.install-script-obfuscated`, `static.exfil-endpoint`, ...).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts, snippet
from kitsunox.lang.agent_config import (
    MAX_AGENT_FILES,
    TEXT_SUFFIXES,
    home_references,
    hook_commands,
    hostile_instructions,
    names_agent_dir,
    plain_command,
    script_concerns,
    widening,
)
from kitsunox.lang.javascript import Capability, language_for
from kitsunox.stages.ast import CodeChange

C = Capability
# Never part of an explained shape (the install-code rule's RISKY, less network and process,
# which some shapes allow).
EXCLUDED: Final = frozenset({C.ENV_ALL, C.DYNAMIC_CODE, C.DYNAMIC_REQUIRE})
# What a hook script an agent runs on every prompt must not do (`npm.install-script-code`'s
# RISKY): it goes through the same test as install code.
HOOK_SCRIPT_RISKY: Final = frozenset(
    {C.NETWORK, C.PROCESS, C.ENV_ALL, C.DYNAMIC_CODE, C.DYNAMIC_REQUIRE}
)
# An install hook that runs more than a file: a download, a shell, a substitution.
SHELL_HOOK: Final = re.compile(
    r"^\s*(?:curl|wget|sh|bash|zsh|powershell|pwsh|cmd|python3?|\./)\b|\|\s*(?:sh|bash)\b"
    r"|\$\(|`",
    re.IGNORECASE,
)
PLATFORM: Final = re.compile(
    r"(?:^|[-_/.@])(?:darwin|macos|mac|osx|linux|linuxmusl|musl|win32|windows|win|freebsd|"
    r"openbsd|android|sunos|aix|ohos)(?:[-_.]|$)"
    r"|(?:^|[-_/])(?:x64|x86_64|arm64|aarch64|ia32|armv7l?|arm|ppc64le?|s390x|riscv64|loong64|"
    r"universal)(?:[-_.]|$)",
    re.IGNORECASE,
)
MIN_PLATFORM_BUILDS: Final = 2
MAX_SHOWN: Final = 3
URL: Final = re.compile(r"""https?://[^\s"'`)<>\\]+""")
CHECKSUM: Final = re.compile(
    r"""createHash\(\s*['"`]sha(?:256|384|512)|sha256sums|checksums?\.txt|\.sha256\b|"""
    r"""verifyChecksum""",
    re.IGNORECASE,
)
_CONST: Final = re.compile(
    r"""\b(?:const|let|var)\s+(\w+)\s*=\s*['"`]([\w.-]+(?:/[\w.-]+)?)['"`]"""
)
_SUBSTITUTION: Final = re.compile(r"\$\{\s*(\w+)\s*\}")
_TEMPLATED_HOST: Final = re.compile(
    r"^https?://\$\{|^https?://(?:www\.)?github\.com/(?:[^/\s\"'`]+/)?\$\{"
)
GITHUB_REPO: Final = re.compile(r"github\.com[:/]+([^/]+)/([^/#?]+?)(?:\.git)?(?:[/#?]|$)", re.I)
REGISTRY_HOSTS: Final = frozenset({"registry.npmjs.org"})
GITHUB_ASSET_HOSTS: Final = frozenset(
    {
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
_EXAMPLE_HOST: Final = re.compile(r"(?:^|\.)example\.(?:com|org|net)$|^localhost$|^127\.0\.0\.1$")
# A GitHub page a message links to (an issue tracker, a file view), not something downloaded.
_GITHUB_PAGE: Final = re.compile(
    r"^https?://github\.com/[^/]+/[^/]+/(?:issues|pull|blob|tree|wiki|discussions)(?:/|#|$)"
    r"|^https?://github\.com/[^/]+/[^/]+/?(?:#.*)?$"
)


class InstallExplained(BaseRule):
    """The version's install code has one of the explained shapes S1-S3 (module docstring).

    Added 2026-11-08 (`docs/proposals/precision-round2.md`, S1-S3, with the owner's three
    guards on S3), measured with Stage 4 on the live verdicts and on all 433 `vm-day1`
    malicious samples reported only through the install rules: see `docs/stages/ast.md`.
    v2 (2026-11-09): S3 only for copies into the project (no home-directory reference, no
    package loaded by name), decision 0015's addendum of that day."""

    id = "npm.install-explained"
    version = 2
    severity = Severity.INFO
    weight = 0.0
    title = "Install code has an explained shape"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        shaped = explain(change)
        if shaped is None:
            return ()
        explanation, evidence = shaped
        return (self.finding(explanation, *evidence),)


def explain(change: CodeChange) -> tuple[str, list[Evidence]] | None:
    """The shape the version's install code has, as (explanation, evidence), or None."""
    hooks = _hooks(change.snapshot.manifest)
    install = change.install
    if (
        install is None
        or not change.install_files
        or not hooks
        or change.build_commands
        or any(SHELL_HOOK.search(command) for command in hooks.values())
        or install.capabilities & EXCLUDED
    ):
        return None
    if change.before is not None and (
        install.capabilities
        - (change.install_before.capabilities if change.install_before else frozenset())
    ):
        return None  # an update whose install code does something new
    if names_agent_dir(change.install_files) and agent_concerns(change):
        return None
    caps = install.capabilities
    text = "\n".join(c.decode("utf-8", "replace") for c in change.install_files.values())
    urls = _urls(text)
    hook_evidence = [
        Evidence(
            kind=EvidenceKind.MANIFEST_FIELD, path=f"package.json:scripts.{h}", after=snippet(c)
        )
        for h, c in hooks.items()
    ]
    uses = ", ".join(sorted(c.value for c in caps)) or "nothing risky"
    manifest = change.snapshot.manifest
    builds = platform_builds(change.snapshot.ref.name, manifest)
    if (
        len(builds) >= MIN_PLATFORM_BUILDS
        and not _templated(urls)
        and (
            C.NETWORK not in caps
            or (
                all(_url_kind(u, None) in ("registry", "page") for u in urls)
                and any(_url_kind(u, None) == "registry" for u in urls)
            )
        )
    ):
        return (
            f"S1 platform-binary launcher: {len(builds)} platform builds of the package in "
            f"`optionalDependencies` ({', '.join(builds[:4])}); the install code uses {uses}, "
            "and reaches no host but the npm registry.",
            [
                *hook_evidence,
                Evidence(
                    kind=EvidenceKind.MANIFEST_FIELD,
                    path="package.json:optionalDependencies",
                    after=snippet(", ".join(builds)),
                ),
            ],
        )
    repo = own_repo(manifest)
    kinds = [_url_kind(u, repo) for u in urls]
    downloads = _own_download_urls(manifest, repo)
    checksum = CHECKSUM.search(text)
    if (
        C.NETWORK in caps
        and repo is not None
        and None not in kinds
        and ("own" in kinds or downloads)
        and checksum is not None
        and (downloads or not _templated(urls))
    ):
        own = [u for u, k in zip(urls, kinds, strict=True) if k == "own"] or downloads
        return (
            f"S2 own-release download: the install code downloads from the package's own "
            f"repository's GitHub releases ({repo[0]}/{repo[1]}) and checks a checksum "
            f"(`{checksum.group(0)}`); every URL it names is that, GitHub's asset hosts or the "
            f"npm registry; it uses {uses}.",
            [
                *hook_evidence,
                Evidence(kind=EvidenceKind.METADATA, snippet=snippet(", ".join(own[:3]))),
            ],
        )
    if (
        not caps & {C.NETWORK, C.PROCESS}
        and names_agent_dir(change.install_files)
        and not user_wide(change)
        and not install.packages
    ):
        copied = len(change.agent_files)
        return (
            "S3 agent-skill copier: the install code writes to an AI agent's configuration "
            "in the project (it names an agent directory, never the home directory, and loads "
            f"no package by name) and uses {uses}: no network, no process. The "
            f"{copied} agent file(s) it may copy hold no hook command beyond a constant echo "
            "or a plain shipped script, no permission widening and no instruction against "
            "the user.",
            hook_evidence,
        )
    return None


class InstallAgentUserWide(BaseRule):
    """The install code names an AI agent's configuration directory and refers to the user's
    home directory: it may install skills, hooks or settings user-wide, for every project,
    which the owner rules unwanted when an install hook does it (decision 0015, addendum
    2026-11-09). A note for the reviewer (INFO, weight 0): such install code is never S3, so
    it keeps its install findings, and this says why. Added 2026-11-09, measured in
    `docs/stages/ast.md`."""

    id = "npm.install-agent-user-wide"
    severity = Severity.INFO
    weight = 0.0
    title = "Install code may write agent configuration user-wide"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        if change.install is None or not names_agent_dir(change.install_files):
            return ()
        found = user_wide(change)
        if not found:
            return ()
        return (
            self.finding(
                "The install code names an AI agent's configuration directory and refers to "
                f"the user's home directory ({', '.join(p for p, _, _ in found[:MAX_SHOWN])}): "
                "it may install skills, hooks or agent settings user-wide, for every project "
                "(unwanted when an install hook does it unasked, decision 0015). Not an "
                "explained install: S3 is for copies into the project.",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=text,
                    )
                    for path, line, text in found[:MAX_SHOWN]
                ),
            ),
        )


def user_wide(change: CodeChange) -> list[tuple[str, int, str]]:
    """References to the user's home directory (`home_references`) in the install code and in
    the install hooks' command lines (`$HOME`, `~/`), as (path, line, text)."""
    hooks = {
        f"package.json:scripts.{hook}": command
        for hook, command in _hooks(change.snapshot.manifest).items()
    }
    return [*home_references(change.install_files), *home_references(hooks)]


def agent_concerns(change: CodeChange) -> list[str]:
    """Why the agent configuration the install code may copy is not the plain S3 shape (the
    owner's guards, 2026-11-08): too many files to check, a hook or MCP command beyond a
    constant echo or a plain shipped script, permission widening, or hostile instructions."""
    files = change.agent_files
    if len(files) > MAX_AGENT_FILES:
        return [f"more than {MAX_AGENT_FILES} agent files"]
    concerns: list[str] = []
    for command in hook_commands(files, change.install_files):
        plain, run = plain_command(command, files)
        if not plain:
            concerns.append(f"hook command: {command[:120]}")
            continue
        for path in run:
            concerns.extend(f"hook script {path}: {c}" for c in _script_concerns(change, path))
    for path, content in sorted({**files, **change.install_files}.items()):
        concerns.extend(f"{path}: {w}" for w in widening(path, content))
    # Agent text, and install code (which may write instruction files from its own strings).
    for path, content in sorted({**files, **change.install_files}.items()):
        code = path in change.install_files
        if code or path.lower().endswith(TEXT_SUFFIXES):
            concerns.extend(
                f"{path}: {what}" for _, what, _ in hostile_instructions(content, code=code)
            )
    return concerns


def _script_concerns(change: CodeChange, path: str) -> list[str]:
    """What a shipped hook script does that a plain one doesn't: for JavaScript, a risky
    capability in the package's own profile; otherwise `script_concerns` on its text."""
    if language_for(path) is not None:
        return sorted(
            {u.use.capability.value for u in change.after.uses if u.path == path}
            & {c.value for c in HOOK_SCRIPT_RISKY}
        )
    return script_concerns(change.agent_files.get(path, b""))


def _hooks(manifest: Mapping[str, Any]) -> dict[str, str]:
    declared = scripts(manifest)
    return {h: declared[h].strip() for h in INSTALL_HOOKS if declared.get(h, "").strip()}


def platform_builds(name: str, manifest: Mapping[str, Any]) -> list[str]:
    """`optionalDependencies` that are this package's own platform builds: in its scope (or,
    unscoped, containing its name) and naming an OS or CPU besides the name."""
    optional = manifest.get("optionalDependencies")
    if not isinstance(optional, dict):
        return []
    base = name.split("/")[-1].lower()
    scope = name.split("/")[0].lower() if name.startswith("@") else None
    builds = []
    for dep in sorted(optional):
        lower = dep.lower()
        tail = lower.split("/")[-1]
        mine = (scope is not None and lower.startswith(scope + "/")) or base in lower
        if mine and PLATFORM.search(tail.replace(base, "", 1)):
            builds.append(dep)
    return builds


def own_repo(manifest: Mapping[str, Any]) -> tuple[str, str] | None:
    """The (owner, name) of the GitHub repository `package.json` declares."""
    repository = manifest.get("repository")
    url = repository.get("url") if isinstance(repository, dict) else repository
    match = GITHUB_REPO.search(url) if isinstance(url, str) else None
    return (match.group(1).lower(), match.group(2).lower()) if match else None


def _urls(text: str) -> list[str]:
    """URL literals in the install code, with `${name}` replaced by the constant string the
    code assigns to `name` (when it does)."""
    constants = dict(_CONST.findall(text))
    return sorted(
        {
            _SUBSTITUTION.sub(lambda m: constants.get(m.group(1), m.group(0)), u)
            for u in URL.findall(text)
        }
    )


def _templated(urls: Sequence[str]) -> bool:
    """A URL whose host (or GitHub owner) is a variable the code doesn't assign a constant."""
    return any(_TEMPLATED_HOST.search(u) for u in urls)


def _url_kind(url: str, repo: tuple[str, str] | None) -> str | None:
    """'registry' (the npm registry), 'own' (the package's own GitHub releases), 'asset'
    (GitHub's release asset hosts), 'page' (an example host, a GitHub page), or None."""
    u = url.lower().rstrip(".,;")
    host = u.split("/")[2].split(":")[0] if u.count("/") >= 2 else ""
    if host in REGISTRY_HOSTS:
        return "registry"
    if _EXAMPLE_HOST.search(host) or ("${" not in u and _GITHUB_PAGE.match(u)):
        return "page"
    if host in GITHUB_ASSET_HOSTS:
        return "asset"
    if repo is not None:
        owner, name = repo
        for prefix in (
            f"https://github.com/{owner}/{name}/releases",
            f"https://api.github.com/repos/{owner}/{name}/releases",
        ):
            if u.startswith(prefix):
                return "own"
    return None


def _own_download_urls(manifest: Mapping[str, Any], repo: tuple[str, str] | None) -> list[str]:
    """cargo-dist's `artifactDownloadUrls`, when every one is the package's own releases."""
    urls = manifest.get("artifactDownloadUrls")
    if not isinstance(urls, list) or not urls:
        return []
    if all(isinstance(u, str) and _url_kind(u, repo) == "own" for u in urls):
        return [str(u) for u in urls]
    return []


RULES: Final = (InstallExplained(), InstallAgentUserWide())
