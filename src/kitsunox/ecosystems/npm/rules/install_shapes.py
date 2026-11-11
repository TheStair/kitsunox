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

- **S5 inert install code** (v3). The install code uses at most the filesystem and the
  machine's identity (`INERT`: no network, no process, no native code), loads no package by
  name, and names neither the user's home directory, an agent directory, a system path
  (`SYSTEM_PATH`) nor another installed package (`OTHER_PACKAGE`); it is readable (no line over
  `MAX_READABLE_LINE`, no code pushed off-screen by whitespace); it deletes nothing
  (`DELETES`), is shipped as a file (not inline `node -e` code), belongs to a package with code
  besides its install code (`placeholder`), and is not upstream Baileys's
  `engine-requirements.js`. It can print, or touch files of the project and the package,
  nothing else.
  The intrusive installs the owner rules unwanted (user-wide agent writes, shell rc edits,
  PATH changes, system package installs, beacons) all need one of those.

S2 needs no checksum when every download is named in `package.json` as the package's own
releases (cargo-dist's `artifactDownloadUrls`, v3): its npm installer checks none, and a
checksum shipped in the same release proves nothing about its author anyway.

- **S6 own-binary download, not run** (v4, round 5). The install code downloads from the
  package's own releases: its GitHub repository's or its owner's other repositories'
  (`github.com/<owner>/<any>/releases`, the release API), or the `homepage`'s own host when
  that is not a code host; every other URL it names is a GitHub asset host, the npm registry, a
  page link or a file of the owner's repositories (`raw.githubusercontent.com/<owner>/`), and a
  version in a download URL is the package's (or its release's, for a prerelease). It needs
  no checksum, because what it fetched never runs at install: every `child_process` call in
  every install file (reached or not, `lang.process_calls`) runs an archive or file-mode tool
  (`tar`, `unzip`, `chmod`, `xattr`, PowerShell's `Expand-Archive`, ...) or asks the platform
  what it is (`uname`, `sysctl`, `ldd --version`), with no shell chaining beyond `&&`/`cd`
  and no `tar` option that runs a command; and no worker, `vm`, WebAssembly or native load runs
  code another way. Every hook is plain `node <file>`, every install file JavaScript; the code
  loads no package by name (whose code could run anything) and no package file it doesn't ship
  (maybe the one it downloaded), has no inline `node -e` code, never names the home directory,
  an agent directory, another installed package, a system directory or the user's project
  (comments and messages aside), and sends nothing (`method: "POST"`, `.post(`). A downloader
  that runs what it fetched (`@byteplus/arkcli-probe-*`, unwanted: it then installs skills into
  every agent) or fetches from someone else's host stays reported.

(S4, build-tool-only hooks, is `npm.install-build-tool`.) Every shape also needs: no install
hook that is shell beyond `node <file>` (`curl`, `| sh`, `$(...)`), no command from
`binding.gyp`, no whole-environment read, dynamic code or dynamic `require` in the install
code, and, for an update, no capability the install code didn't have before (a version whose
install code does something new keeps its findings). Since v3 every shape also needs install
code a reader and the parser can see: plain UTF-8 (`plain_text`), no line over
`MAX_READABLE_LINE` characters and no code pushed off-screen by whitespace (`unreadable`). A
package's name, description or keywords never count.

The rule is INFO: an explanation for Stage 4 (`correlate.EXPLAINED`), which makes the install
MEDIUMs (`npm.install-hook`, `npm.install-script-changed`, `npm.install-script-code`) LOW,
never a content finding (`npm.install-script-obfuscated`, `static.exfil-endpoint`, ...).
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.install import INLINE_PREFIX
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
from kitsunox.lang.javascript import Capability, language_for, mask_comments_and_messages
from kitsunox.lang.process_calls import process_calls
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
# S5 (round 4): the only capabilities inert install code may have.
INERT: Final = frozenset({C.FILESYSTEM, C.OS_INFO})
# A path outside the project and the user's home that install code could write (system
# directories, the temporary directory, another drive's root): S5 refuses install code naming
# one. `/tmp` and `tmpdir`: `cesium-native@0.56.0` and `dep-graph-gen@1.0.0` (`vm-day1`
# malicious, RCE proofs) write their proof to `/tmp`.
SYSTEM_PATH: Final = re.compile(
    r"""["'`](?:/(?:etc|usr|bin|sbin|opt|var|tmp|Library|System|Applications|private)"""
    r"""(?:/|["'`])|[A-Za-z]:(?:\\\\|\\|/))|\btmpdir\b"""
)
# Install code that deletes files is not inert, whatever it deletes: `@uselagoon/ui-library@2.0.2`
# (`vm-day1` malicious) empties the directory it runs in under yarn. Protestware wipers delete.
DELETES: Final = re.compile(r"\b(?:unlink|unlinkSync|rmdir|rmdirSync|rm|rmSync)\s*\(")
# Install code that locates another installed package (`require.resolve(...)`) or builds a path
# into `node_modules` (`path.join(root, "node_modules", ...)`, `"node_modules/x/..."`): it may
# rewrite another package's code, which is how an install hook tampers with a dependency
# (decision 0015: tampering with other packages decides a verdict). S5 leaves it alone, even
# though most such hooks are benign patches (`chmod` of `node-pty`'s spawn helper, a
# `fastmcp` fix). A test that only asks whether the package sits in `node_modules`
# (`__dirname.includes("node_modules")`) is fine.
OTHER_PACKAGE: Final = re.compile(
    r"""node_modules["'`]\s*,|node_modules[/\\]+[@\w.]|require\.resolve\("""
)
# S5 rests on the capability analysis, which reads JavaScript only: every hook must be `node`
# running a file or inline code (optionally `|| true` / `|| exit 0`), and every install file
# JavaScript or TypeScript. `dotnet build`, `java -jar`, `npm run x && ...` run code the analysis
# never sees (`@eisland/windows-startup-helper@26.0.1`'s `dotnet build` had no capability).
_NODE_HOOK: Final = re.compile(r"\s*node\s+[^;&|`$]+?(?:\s*\|\|\s*(?:true|exit\s+0))?\s*")
_QUOTED: Final = re.compile(r""""(?:[^"\\]|\\.)*"|'[^']*'""")


def node_only(command: str) -> bool:
    """`command` is `node <file or -e code>`, nothing chained before or after it (quoted
    inline code may hold anything: it is install code the analysis reads)."""
    return bool(_NODE_HOOK.fullmatch(_QUOTED.sub('""', command)))


# S5 claims the install code does nothing, so it doesn't rest on the capability analysis
# alone: the text must not name what reaches the network or runs code either. Two reviewed
# versions showed why: `@openrouter/sdk@1.5.59` passes the global `fetch` as a default
# parameter (`fetchImpl = fetch`, no call the analysis sees) to read the model list, and
# `@onescience/onecode@1.19.3-202610291749`'s postinstall is UTF-16, which the parser reads as
# nothing, while it downloads a binary (both benign, both caught by this test).
RISKY_TEXT: Final = re.compile(
    r"""\bfetch\b|\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b|\bimport\s*\("""
    r"""|["'`](?:node:)?(?:https?|http2|net|tls|dns|dgram|child_process|worker_threads|vm"""
    r"""|cluster|inspector|module|undici|axios|got|node-fetch)["'`/]"""
    r"""|\beval\b|\bFunction\s*\(|\bprocess\s*\.\s*(?:binding|dlopen)\b"""
    r"""|\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\("""
)


def placeholder(change: CodeChange) -> bool:
    """The package's code is nothing but its install code: the shape of a dependency-confusion
    placeholder or proof of concept (`wc@1.5.0`, `coldbox@6.7.71`, `pmcrypto@0.1.0`,
    `grab-service-worker@1.0.1`, all `vm-day1` malicious, each a `postinstall` that prints).
    S5 explains install code of a package that has more to it."""
    shipped = [p for p in change.install_files if not p.startswith(INLINE_PREFIX)]
    return change.after.files_parsed <= len(shipped)


def plain_text(content: bytes) -> bool:
    """UTF-8 text without NUL bytes (what the parser reads as written)."""
    if b"\x00" in content:
        return False
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# S5 is "the code does nothing", which a reader must be able to check: install code with a
# line longer than this, or code pushed off-screen by a run of whitespace, is not S5.
# `hauntview@0.2.9` (malicious, 2026-11-09) hides an obfuscated C2 loader on line 14 of its
# postinstall after 266 tabs (12,699 characters); the capability extractor sees none of what
# the loader does. The longest line among the reviewed benign S5 versions is 406 characters,
# the longest padding 31.
MAX_READABLE_LINE: Final = 1_000
_PADDING: Final = re.compile(r"(?:^|\S)[ \t]{64,}(?=\S)", re.MULTILINE)


def unreadable(text: str) -> bool:
    """A line over `MAX_READABLE_LINE` characters, or 64+ spaces or tabs before code."""
    return any(len(line) > MAX_READABLE_LINE for line in text.splitlines()) or bool(
        _PADDING.search(text)
    )


# Upstream Baileys's `preinstall` (a Node-version check). Inert, but S5 leaves it alone: the
# WhatsApp forks the owner rules unwanted (channel auto-follow) keep it, and in a follow-on
# release whose follow code is in an unchanged file Stage 2 doesn't see the follow again, so
# the hook is what reports them (`kevinx-baileys@1.2.2`, unwanted; `hyrox@0.1.6` and
# `@lunabotv6/luna-baileys@8.1.0`, unverified).
BAILEYS_ENGINE_CHECK: Final = re.compile(r"(?:^|/)engine-requirements\.js$")
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
    """The version's install code has one of the explained shapes S1-S6 (module docstring).

    Added 2026-11-08 (`docs/proposals/precision-round2.md`, S1-S3, with the owner's three
    guards on S3), measured with Stage 4 on the live verdicts and on all 433 `vm-day1`
    malicious samples reported only through the install rules: see `docs/stages/ast.md`.
    v2 (2026-11-09): S3 only for copies into the project (no home-directory reference, no
    package loaded by name), decision 0015's addendum of that day.
    v3 (2026-11-10, `docs/proposals/precision-round4-E.md`): S2 also without a checksum when
    every download is named in `package.json` as the package's own releases (cargo-dist's
    `artifactDownloadUrls`); and S5, inert install code (`INERT` capabilities only, no package
    loaded by name, no home, agent or system directory named).
    v4 (2026-11-10, `docs/proposals/precision-round5-H.md`): S6, an own-binary download that
    runs nothing it fetched (module docstring).
    v5 (2026-11-11, `docs/proposals/precision-round6-Q.md`, Q2): an update whose install hook
    is new (`hook_added`: its previous version ran no install code) is judged like a new
    package instead of failing the new-capability test outright (every capability is new to
    it), for S1, S3 and S5 only (`ADDED_HOOK_SHAPES`), and never when the install code names
    the home directory or a URL besides the npm registry and page links. And S1 never holds
    when the install code names a download program or call (`DOWNLOAD_TOOL`: `curl`, `wget`,
    `Invoke-WebRequest`, ...) unless every URL it names is the npm registry (owner,
    2026-11-10: no download from outside the registry)."""

    id = "npm.install-explained"
    version = 5
    severity = Severity.INFO
    weight = 0.0
    title = "Install code has an explained shape"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        shaped = explain(change)
        if shaped is None:
            return ()
        explanation, evidence = shaped
        return (self.finding(explanation, *evidence),)


# v5 (round 6, Q2): the shapes an update whose install hook is new (no install code before)
# may have, judged like a new package's: S1, S3 and S5 only. A download (S2, S6) never: the
# owner rules install-time downloads of code unwanted (decision 0015, 2026-11-10).
ADDED_HOOK_SHAPES: Final = ("S1 ", "S3 ", "S5 ")


def hook_added(change: CodeChange) -> bool:
    """An update whose previous version ran no install code: its hook is new (or ran no file
    of the package), so every capability of the install code is "new" to it."""
    return change.before is not None and not change.install_files_before


def explain(change: CodeChange) -> tuple[str, list[Evidence]] | None:
    """The shape the version's install code has, as (explanation, evidence), or None. v5 only
    adds: what v4 explains is returned unchanged; an update whose install hook is new
    (`hook_added`) that v4 refuses (its new-capability test) is then judged like a new
    package, for the shapes `ADDED_HOOK_SHAPES` only, never for install code that names the
    home directory or a URL other than the npm registry or a page link."""
    shaped = _explain(change, added=False)
    if shaped is not None or not hook_added(change):
        return shaped
    shaped = _explain(change, added=True)
    if shaped is None:
        return None
    text = "\n".join(c.decode("utf-8", "replace") for c in change.install_files.values())
    if (
        not shaped[0].startswith(ADDED_HOOK_SHAPES)
        or user_wide(change)
        or any(_url_kind(u, None) not in ("registry", "page") for u in _urls(text))
    ):
        return None
    return (
        shaped[0] + " The hook is new in this update; it is judged like a new package's.",
        shaped[1],
    )


def _explain(change: CodeChange, *, added: bool) -> tuple[str, list[Evidence]] | None:
    """v4's shapes; with `added`, an update whose hook is new skips the new-capability test."""
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
    if (
        change.before is not None
        and not (added and hook_added(change))
        and (
            install.capabilities
            - (change.install_before.capabilities if change.install_before else frozenset())
        )
    ):
        return None  # an update whose install code does something new
    if names_agent_dir(change.install_files) and agent_concerns(change):
        return None
    caps = install.capabilities
    text = "\n".join(c.decode("utf-8", "replace") for c in change.install_files.values())
    if unreadable(text) or not all(plain_text(c) for c in change.install_files.values()):
        return None  # v3: code the parser or a reader can't see is never an explained shape
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
        and not (download_tool(change) and not _registry_only(urls))
        and (C.NETWORK not in caps or _registry_only(urls))
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
        and (checksum is not None or downloads)
        and (downloads or not _templated(urls))
    ):
        own = [u for u, k in zip(urls, kinds, strict=True) if k == "own"] or downloads
        checked = (
            f"checks a checksum (`{checksum.group(0)}`)"
            if checksum is not None
            else "names every download in `package.json` (cargo-dist's `artifactDownloadUrls`)"
        )
        return (
            f"S2 own-release download: the install code downloads from the package's own "
            f"repository's GitHub releases ({repo[0]}/{repo[1]}) and {checked}; every URL it "
            f"names is that, GitHub's asset hosts or the npm registry; it uses {uses}.",
            [
                *hook_evidence,
                Evidence(kind=EvidenceKind.METADATA, snippet=snippet(", ".join(own[:3]))),
            ],
        )
    if C.NETWORK in caps and not own_binary_concerns(change, urls):
        found = own_binary_urls(urls, manifest)
        return (
            "S6 own-binary download, not run: the install code downloads from the package's "
            f"own releases ({', '.join(sorted({h for _, h in found}))}); every URL it names is "
            "that, a file of the owner's repositories, GitHub's asset hosts, the npm registry or a "
            "page link; it runs no command "
            "but an archive or platform tool (never what it downloaded), loads no package by "
            f"name, never names the home directory and sends nothing; it uses {uses}.",
            [
                *hook_evidence,
                Evidence(
                    kind=EvidenceKind.METADATA,
                    snippet=snippet(", ".join(u for u, _ in found[:MAX_SHOWN])),
                ),
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
    if (
        caps <= INERT
        and all(node_only(command) for command in hooks.values())
        and all(language_for(path) is not None for path in change.install_files)
        and not install.packages
        and not names_agent_dir(change.install_files)
        and not user_wide(change)
        and not SYSTEM_PATH.search(text)
        and not OTHER_PACKAGE.search(text)
        and not RISKY_TEXT.search(text)
        and not DELETES.search(text)
        and not placeholder(change)
        and not any(path.startswith(INLINE_PREFIX) for path in change.install_files)
        and not any(BAILEYS_ENGINE_CHECK.search(path) for path in change.install_files)
    ):
        return (
            f"S5 inert install code: it uses {uses}: no network, no process, no native code, "
            "loads no package by name, and names neither the home directory, an agent "
            "directory, a system path nor another installed package; it is plain, readable "
            "JavaScript run by `node`, so it can only print or touch files in the project and "
            "the package.",
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


# v5: a program or call that downloads (outside `fetch`/`https`, which the capability analysis
# sees as the network): S1 is for platform builds from the npm registry only, and the owner rules
# install-time downloads of code from anywhere else unwanted, by any means (decision 0015,
# 2026-11-10). Comments and messages aside ("or install with curl ..."). A download tool whose
# every URL is the npm registry is still S1 (`@kprint/kprint@0.60.5` fetches its platform
# package's tarball from the registry with a pinned hash).
DOWNLOAD_TOOL: Final = re.compile(
    r"\b(?:curl|wget|aria2c|bitsadmin|certutil|Invoke-WebRequest|Invoke-RestMethod|iwr|irm"
    r"|Start-BitsTransfer|DownloadFile|DownloadString)\b",
    re.IGNORECASE,
)


def _registry_only(urls: Sequence[str]) -> bool:
    """Every URL is the npm registry or a page link, and at least one is the registry."""
    kinds = [_url_kind(u, None) for u in urls]
    return all(k in ("registry", "page") for k in kinds) and "registry" in kinds


def download_tool(change: CodeChange) -> str | None:
    """The first download program or call the install code names (`DOWNLOAD_TOOL`), comments
    and messages aside; None when it names none."""
    for path, content in sorted(change.install_files.items()):
        language = language_for(path)
        text = (
            mask_comments_and_messages(content, language) if language is not None else content
        ).decode("utf-8", "replace")
        if match := DOWNLOAD_TOOL.search(text):
            return match.group(0)
    return None


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


ARCHIVE_TOOLS: Final = frozenset(
    {"tar", "unzip", "7z", "7za", "gzip", "gunzip", "xz", "chmod", "xattr", "ditto"}
)
PLATFORM_PROBES: Final = frozenset({"uname", "sysctl", "getconf", "sw_vers", "which", "where"})
POWERSHELL: Final = frozenset({"powershell", "pwsh"})
_SHELL_SPLIT: Final = re.compile(r"&&|\|\||;")
_DEV_NULL: Final = re.compile(r"\d?>\s*/dev/null|2>&1|\d?>\s*nul\b", re.IGNORECASE)
_SHELL_META: Final = re.compile(r"[|<>`]|\$\(")
_PS_RISKY: Final = re.compile(
    r"invoke-|\biex\b|start-process|download|-enc|encodedcommand|[;&|`]|\$\(", re.IGNORECASE
)
# GNU tar can run commands itself (`--to-command`, `--checkpoint-action=exec=...`).
TAR_EXEC: Final = re.compile(
    r"to-command|checkpoint-action|use-compress-program|rsh-command|info-script|"
    r"new-volume-script",
    re.IGNORECASE,
)
# Code that runs code without `child_process`: workers, `vm`, WebAssembly, native addons.
RUNS_CODE: Final = re.compile(
    r"""["'`](?:node:)?(?:worker_threads|vm|cluster|inspector|module|wasi)["'`]"""
    r"""|\bnew\s+Worker\s*\(|\bWebAssembly\b|\bprocess\s*\.\s*(?:binding|dlopen)\b"""
)
# Install code that sends rather than downloads.
SENDS: Final = re.compile(
    r"""\bmethod\s*:\s*["'`](?:POST|PUT|PATCH)["'`]|\.(?:post|put|patch)\s*\(""",
    re.IGNORECASE,
)
# Where S6's install code may not write what it fetched: a system directory (the temporary
# directory is where downloads are staged, so it is allowed here, unlike S5), or the user's
# project (`INIT_CWD`, git hooks). Another installed package is `OTHER_PACKAGE`.
SYSTEM_DIR: Final = re.compile(
    r"""["'`](?:/(?:etc|usr|bin|sbin|opt|var|Library|System|Applications|private)"""
    r"""(?:/|["'`])|[A-Za-z]:(?:\\\\|\\|/))"""
)
# Decoding a string: how a URL or a command the checks above should see is hidden.
DECODES: Final = re.compile(
    r"""\batob\s*\(|\bBuffer\s*\.\s*from\s*\([^()]*["'`](?:base64|base64url|hex)["'`]\s*\)"""
)
# A runner told to use a shell (`spawn("tar", args, { shell: true })`): its arguments are a
# shell line too.
SHELL_OPTION: Final = re.compile(r"""\bshell\s*:\s*(?:true|["'`])""")
PROJECT: Final = re.compile(r"""\bINIT_CWD\b|\.git[/\\]+hooks|["'`]\.git["'`]""")
_VERSION_IN_URL: Final = re.compile(r"/v?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)(?=/|$)")


def _first_word(segment: str) -> str:
    word = segment.strip().split(" ", 1)[0].strip("\"'")
    word = re.split(r"[/\\]", word)[-1].lower()
    return word.removesuffix(".exe")


def allowed_command(command: str, shell: bool) -> bool:
    """`command` only unpacks an archive, sets file modes or attributes, or asks the platform
    what it is: never runs a downloaded file or anything else."""
    if not command or "…" in command.split(" ", 1)[0]:
        return False
    if TAR_EXEC.search(command):
        return False
    segments = [command]
    if shell:
        text = _DEV_NULL.sub("", command)
        segments = _SHELL_SPLIT.split(text)
        if _SHELL_META.search(_SHELL_SPLIT.sub(" ", text)):
            return False
    for segment in segments:
        word = _first_word(segment)
        if "${" in word or "…" in word:
            return False
        if word in POWERSHELL:
            rest = segment.strip().split(" ", 1)[-1]
            if "expand-archive" not in rest.lower() or "…" in rest or _PS_RISKY.search(rest):
                return False
        elif word == "ldd":
            if segment.split() != ["ldd", "--version"]:
                return False
        elif word not in ARCHIVE_TOOLS | PLATFORM_PROBES | ({"cd"} if shell else set()):
            return False
    return True


def _own_kind(url: str, repo: tuple[str, str] | None, home: str | None) -> str | None:
    """`_url_kind`, plus 'org' (a release or the release API of any of the repository
    owner's repositories), 'raw' (a file of one, `raw.githubusercontent.com/<owner>/`: never
    run, as the process test makes sure) and 'home' (the `homepage`'s own host, when it is
    not a code host)."""
    kind = _url_kind(url, repo)
    if kind is not None:
        return kind
    u = url.lower().rstrip(".,;")
    if re.fullmatch(r"https?://(?:www\.)?github\.com/?", u):
        return "page"
    host = u.split("/")[2].split(":")[0] if u.count("/") >= 2 else ""
    if repo is not None:
        owner = repo[0]
        for prefix in (
            f"https://github.com/{owner}/",
            f"https://api.github.com/repos/{owner}/",
        ):
            rest = u.removeprefix(prefix)
            if rest != u and "${" not in rest.split("/", 1)[0] and "/releases" in rest:
                return "org"
        rest = u.removeprefix(f"https://raw.githubusercontent.com/{owner}/")
        if rest != u and rest.split("/", 1)[0] and "${" not in rest.split("/", 1)[0]:
            return "raw"
    if home is not None and host == home and "${" not in host:
        return "home"
    return None


def _home_host(manifest: Mapping[str, Any]) -> str | None:
    homepage = manifest.get("homepage")
    if not isinstance(homepage, str) or "://" not in homepage:
        return None
    host = homepage.lower().split("/")[2].split(":")[0]
    if host in ("github.com", "www.github.com", "gitlab.com", "npmjs.com", "www.npmjs.com"):
        return None
    return host or None


def own_binary_urls(urls: Sequence[str], manifest: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The download URLs of S6, as (url, owner or host)."""
    repo = own_repo(manifest)
    home = _home_host(manifest)
    out = []
    for u in urls:
        kind = _own_kind(u, repo, home)
        if kind in ("own", "org") and repo is not None:
            out.append((u, repo[0]))
        elif kind == "home" and home is not None:
            out.append((u, home))
    return out + [(u, repo[0]) for u in _own_download_urls(manifest, repo) if repo is not None]


_LOCAL_LOAD: Final = re.compile(
    r"""\b(?:require|import)\s*\(\s*["'`](\.{1,2}/[^"'`]+)["'`]\s*\)"""
    r"""|\bfrom\s+["'](\.{1,2}/[^"']+)["']"""
)
_LOADABLE: Final = ("", ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", "/index.js", "/index.mjs")


def unshipped_loads(path: str, text: str, change: CodeChange) -> list[str]:
    """Package files `text` (the install file at `path`) loads by a constant relative path that
    are not among the install files Stage 3 read: maybe the file it just downloaded, which
    `require` would run. JSON is data."""
    out = []
    for match in _LOCAL_LOAD.finditer(text):
        spec = match.group(1) or match.group(2)
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
        if target.endswith(".json"):
            continue
        if not any(target + suffix in change.install_files for suffix in _LOADABLE):
            out.append(spec)
    return out


def own_binary_concerns(change: CodeChange, urls: Sequence[str]) -> list[str]:
    """Why the install code is not S6 (an own-binary download that runs nothing it fetched);
    empty when it is."""
    manifest = change.snapshot.manifest
    install = change.install
    repo = own_repo(manifest)
    home = _home_host(manifest)
    concerns = []
    if install is None:
        return ["no install profile"]
    hooks = _hooks(manifest)
    concerns += [f"hook: {c[:80]}" for c in hooks.values() if not node_only(c)]
    # A shipped installer, not inline `node -e` code (`dependencykfeg@1.5.6`, malicious: an
    # inline DNS exfiltration `preinstall` with no URL).
    concerns += [f"inline: {p}" for p in change.install_files if p.startswith(INLINE_PREFIX)]
    concerns += [f"url: {u[:100]}" for u in urls if _own_kind(u, repo, home) is None]
    found = own_binary_urls(urls, manifest)
    if not found:
        concerns.append("no own download")
    version = change.snapshot.ref.version
    release = re.split(r"[-+]", version, maxsplit=1)[0]
    for u, _ in found:
        literal = [v for v in _VERSION_IN_URL.findall(u.split("?", 1)[0]) if "${" not in v]
        if literal and not {version, release} & set(literal):
            concerns.append(f"version: {u[:100]}")
    if install.packages:
        concerns.append("packages: " + ",".join(sorted({p.load.name for p in install.packages})))
    if user_wide(change):
        concerns.append("home")
    if names_agent_dir(change.install_files):
        concerns.append("agent dir")
    # Comments and messages aside ("the binary lives in node_modules/<name>/", `herozion`).
    text = "\n".join(
        mask_comments_and_messages(c, language).decode("utf-8", "replace")
        if (language := language_for(p)) is not None
        else c.decode("utf-8", "replace")
        for p, c in change.install_files.items()
    )
    for name, pattern in (
        ("other package", OTHER_PACKAGE),
        ("system path", SYSTEM_DIR),
        ("project", PROJECT),
    ):
        if m := pattern.search(text):
            concerns.append(f"{name}: {m.group(0)}")
    for path, content in sorted(change.install_files.items()):
        language = language_for(path)
        if language is None:
            concerns.append(f"not javascript: {path}")
            continue
        text = content.decode("utf-8", "replace")
        if m := RUNS_CODE.search(text):
            concerns.append(f"runs code: {m.group(0)}")
        if m := SENDS.search(text):
            concerns.append(f"sends: {m.group(0)}")
        if m := TAR_EXEC.search(text):
            concerns.append(f"tar exec: {m.group(0)}")
        if m := DECODES.search(text):
            concerns.append(f"decodes: {m.group(0)[:40]}")
        concerns += [f"loads unshipped: {spec}" for spec in unshipped_loads(path, text, change)]
        calls = process_calls(content, language)
        if calls is None:
            concerns.append(f"process unreadable: {path}")
            continue
        shell = bool(SHELL_OPTION.search(text))
        concerns += [
            f"runs: {c.command[:80] or c.runner}"
            for c in calls
            if not allowed_command(c.command, c.shell or shell)
        ]
    return concerns


RULES: Final = (InstallExplained(), InstallAgentUserWide())
