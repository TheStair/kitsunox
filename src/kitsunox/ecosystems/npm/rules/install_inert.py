"""Install hooks whose code was read in full and can do nothing an attack needs (Stage 3).

`npm.install-hook` (Stage 1) sees only a hook's command line, so it reports every new package
with `"postinstall": "node scripts/postinstall.js"` whatever that file does. Most of them print
a thank-you, check the Node version, make a binary executable or copy a file inside the
package (precision round 4, B1). A supply-chain attack's install code has to reach something
outside the package to do harm: the network, another process, the environment, code it builds
at run time, a native module, another package's code, or files outside the package (the
user's home, the project's `node_modules`, the system). This rule says when Stage 3 read all
of it and found none of those.

It is INFO, weight 0: an explanation for Stage 4 (`correlate.EXPLAINED`), which then makes
`npm.install-hook` LOW, weight 1. It explains no other rule: the install code's content
findings (`npm.install-script-obfuscated`, `static.*`, `static.channel-follow`) and
`npm.install-script-changed` keep their severity.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.install import INLINE_PREFIX, resolve
from kitsunox.ecosystems.npm.rules.install_shapes import (
    BAILEYS_ENGINE_CHECK,
    DELETES,
    OTHER_PACKAGE,
    RISKY_TEXT,
    SYSTEM_PATH,
    placeholder,
    plain_text,
    unreadable,
    user_wide,
)
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts, snippet
from kitsunox.lang.agent_config import names_agent_dir
from kitsunox.lang.javascript import Capability, language_for, local_paths
from kitsunox.stages.ast import MAX_INSTALL_FILE_BYTES, CodeChange

C = Capability
# What install code needs to do harm beyond the package: none of these may be in its profile.
# `filesystem` and `os-info` stay allowed: without one of these, what it reads can't leave.
REACHING: Final = frozenset(
    {C.NETWORK, C.PROCESS, C.ENV_ALL, C.DYNAMIC_CODE, C.DYNAMIC_REQUIRE, C.NATIVE}
)
# Shell operators a hook may chain its commands with; any other (`|`, `>`, `&`, `(`) is not
# a plain command list.
CHAIN: Final = frozenset({"&&", "||", ";"})
# `node` options that change nothing about which code runs. Anything else (`-r`/`--require`,
# `--import`, `--loader`) preloads code from elsewhere.
NODE_OPTIONS: Final = re.compile(
    r"--no-warnings|--no-deprecation|--enable-source-maps|--trace-warnings"
    r"|--input-type=(?:module|commonjs)|--max-old-space-size=\d+"
)
NODE: Final = frozenset({"node", "node.exe"})
INLINE_FLAGS: Final = frozenset({"-e", "--eval", "-p", "--print"})
# Words that end a hook harmlessly: `|| exit 0`, `|| true`.
NO_OPS: Final = frozenset({"true", ":", "exit"})
# Where install code writes outside its package even without the home directory: the project's
# other packages (`blue-crab` patched `dsh-tui`'s files, `charape` replaced other Baileys
# packages with shims; both unwanted), the project root, the system's directories, and the
# credential and shell files of decision 0015's rulings.
OUTSIDE: Final = re.compile(
    r"node_modules|\bINIT_CWD\b|process\.cwd\("
    r"|['\"`](?:/etc|/usr|/opt|/var|/Library|/System|/Applications|/bin|/sbin)\b"
    r"|['\"`][A-Za-z]:\\\\|%[A-Za-z_]+%"
    r"|\.npmrc|\.yarnrc|\.ssh\b|\.aws\b|\.gitconfig|\.(?:bash|zsh)rc|\.(?:bash_)?profile\b"
)
# Climbing out of a directory: `../../x` or `path.join(__dirname, "..", "..")`. One level
# per directory the file is in stays inside the package (`scripts/x.js` reads
# `../package.json`); more leaves it.
_UP: Final = re.compile(r"(?:\.\.[/\\])+|(?:[\"'`]\.\.[\"'`]\s*,?\s*)+")
MAX_SHOWN: Final = 3
# What a probe prints to prove its hook ran (`vm-day1`, labelled malicious:
# `echo "code injection possible by golu"` in `node-pdfmake@7.7.7`, `surpaonchainagent@7.7.7`,
# `contentful-app-entry-localization-matrix@7.7.7`; `echo "takeover poc"` in
# `openwhisk-probot-builder@1.0.0`; `echo 'Dependency Confusion PoC'`, `PREINSTALL_WORKS`,
# `POSTINSTALL_FIRED`, `I CAN RUN Anyting`, `Vulnerable Application!`, `Test redteam`,
# `Security research`): an echo-only hook that says so keeps its finding. The same for install
# code that says it (`wc@1.5.0`: `console.log("PoC: wc@1.5 installed — possible dependency
# confusion vector")`; `grab-service-worker@1.0.1`, `coldbox@6.7.71`) or a file named so
# (`pmcrypto@0.1.0` runs `poc.js`): inert, but labelled malicious on `vm-day1`.
PROBE_TEXT: Final = re.compile(
    r"\bpoc\b|proof.of.concept|takeover|inject|pwn|hack|confusion|security|vulnerab|exploit"
    r"|red.?team|bounty|research|\b(?:pre|post)?install(?:ed)?[ _](?:works|fired|ran|executed)\b"
    r"|\b(?:works|fired)\b|\bcan run\b|\brce\b|\bflag\b",
    re.IGNORECASE,
)


# Another installed package's files, found by resolving its name
# (`require.resolve("@xterm/xterm")`, `createRequire(...).resolve(...)`): the code may patch
# that package (`@personai/agent-ui-terminal` rewrites `@xterm/xterm`'s bundle; `blue-crab`,
# unwanted, patched `dsh-tui`). The owner keeps these reported, even a `chmod` of `node-pty`'s
# `spawn-helper` (S5's rule, round 4).
RESOLVED: Final = re.compile(r"""(?:\brequire|\bimport\.meta|\))\.resolve\(\s*["'`](?![./])""")


# S5's guards (agent E, `install_shapes`, `npm.install-explained` v3, round 4), shared so that
# B1 never explains what S5 refuses: `RISKY_TEXT` (text naming the network or code execution,
# for what the capability analysis can miss), `DELETES`, `SYSTEM_PATH` (system directories,
# `/tmp`, `tmpdir`, another drive), `OTHER_PACKAGE` (`require.resolve`, a path into
# `node_modules`), `plain_text`/`unreadable` (UTF-16, overlong or padded lines), `placeholder`
# (no code but the install code) and `BAILEYS_ENGINE_CHECK` (upstream Baileys's
# `engine-requirements.js`: the hook is what reports a fork's follow-on whose channel follow
# sits in an unchanged file, `kevinx-baileys@1.2.2`).


def outside(path: str, text: str) -> str | None:
    """The first place `text` (the install file at `path`) names something outside the
    package (`OUTSIDE`, S5's `SYSTEM_PATH`, more `..` than `path` is deep, or another installed
    package: `OTHER_PACKAGE`, `RESOLVED`, whatever the code then does with it, as S5 decides),
    or does what S5 refuses (`RISKY_TEXT`, `DELETES`), or None."""
    for pattern in (OUTSIDE, SYSTEM_PATH, OTHER_PACKAGE, RESOLVED, RISKY_TEXT, DELETES):
        if match := pattern.search(text):
            return match.group(0)
    depth = 0 if path.startswith(INLINE_PREFIX) else path.count("/")
    for match in _UP.finditer(text):
        if match.group(0).count("..") > depth:
            return match.group(0)
    return None


def hook_runs(command: str) -> tuple[list[str], bool] | None:
    """The package files a hook's command line runs with `node` (as written, `./` removed),
    and whether it runs inline code (`node -e`), when the line is only `node <file>`,
    `node -e <code>`, a constant `echo`, `true`, `:` or `exit`, chained with `&&`, `||` or
    `;`. None for anything else: another program, a pipe or redirect, a substitution (`$(`,
    a backtick, even inside double quotes), an environment assignment, a `node` option that
    loads other code, or a line the shell couldn't split."""
    if "$(" in command or "`" in command:
        return None
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in CHAIN:
            segments.append([])
        elif token and set(token) <= set("();<>|&"):
            return None
        else:
            segments[-1].append(token)
    files: list[str] = []
    inline = False
    for words in segments:
        if not words:
            continue
        head, rest = words[0], words[1:]
        if head == "echo":
            if any("$" in w for w in rest):
                return None
        elif head in NO_OPS:
            if head == "exit" and not all(w.isdigit() for w in rest):
                return None
        elif head in NODE:
            options = rest
            while options and NODE_OPTIONS.fullmatch(options[0]):
                options = options[1:]
            if not options:
                return None
            if options[0] in INLINE_FLAGS:
                inline = True
            elif options[0].startswith("-"):
                return None
            else:
                files.append(options[0].removeprefix("./"))
        else:
            return None
    return files, inline


def inert(change: CodeChange) -> tuple[str, list[Evidence]] | None:
    """Why the version's install hooks are inert, as (explanation, evidence), or None."""
    declared = scripts(change.snapshot.manifest)
    hooks = {h: declared[h].strip() for h in INSTALL_HOOKS if declared.get(h, "").strip()}
    install = change.install
    if not hooks or change.build_commands or change.previous_version is not None:
        return None  # an update: see `InstallInert`
    run: list[str] = []
    for hook, command in hooks.items():
        parsed = hook_runs(command)
        if parsed is None:
            return None
        files, inline = parsed
        if inline:
            files = [*files, f"{INLINE_PREFIX}{hook}.js"]
        if any(f not in change.install_files for f in files):
            return None  # a file the hook runs that Stage 3 didn't read (missing or not JS)
        run.extend(files)
    evidence = [
        Evidence(
            kind=EvidenceKind.MANIFEST_FIELD,
            path=f"package.json:scripts.{hook}",
            after=snippet(command),
        )
        for hook, command in hooks.items()
    ]
    if any("echo" in command and PROBE_TEXT.search(command) for command in hooks.values()):
        return None  # a probe saying it ran: the hook rule decides
    if any(
        PROBE_TEXT.search(path) or PROBE_TEXT.search(data.decode("utf-8", "replace"))
        for path, data in change.install_files.items()
    ):
        return None  # install code that says it is a probe: the hook rule decides
    if not run:
        return (
            "Every install hook only prints a constant message (`echo`): no package code "
            "runs at install.",
            evidence,
        )
    code = change.install_files
    if install is None:
        return None
    if (
        any(BAILEYS_ENGINE_CHECK.search(path) for path in code)
        or not all(plain_text(data) for data in code.values())
        or any(unreadable(data.decode("utf-8")) for data in code.values())
        or placeholder(change)
        or install.capabilities & REACHING
        or install.packages
        or install.files_with_errors
        or install.files_parsed != len(code)
        or any(len(data) >= MAX_INSTALL_FILE_BYTES for data in code.values())
        or not _complete(code)
        or user_wide(change)
        or names_agent_dir(code)
    ):
        return None
    for path, data in sorted(code.items()):
        if outside(path, data.decode("utf-8", "replace")) is not None:
            return None
    uses = ", ".join(sorted(c.value for c in install.capabilities)) or "nothing"
    shown = sorted(code)[:MAX_SHOWN]
    return (
        f"Every install hook only runs package code Stage 3 read in full ({', '.join(shown)}"
        + (f", +{len(code) - MAX_SHOWN} more" if len(code) > MAX_SHOWN else "")
        + f"), which uses {uses}: no network, process, whole environment, dynamic code, "
        "native module or other package, and nothing outside the package (home directory, "
        "project, `node_modules`, system paths).",
        evidence,
    )


# A relative path the code loads (`require("./x")`, `import "./x"`, `import("./x")`,
# `from "./x"`), and a path naming a script by its suffix (`path.join(__dirname, "x.js")`).
_LOADED: Final = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|\bimport\s+)["'`](\.{1,2}/[^"'`]+)["'`]"""
)
_SCRIPT: Final = re.compile(r"\.(?:[cm]?js|[cm]?ts|jsx|tsx)$")


def _complete(code: Mapping[str, bytes]) -> bool:
    """Every package file the install code loads or names as a script is among what was read
    (Stage 3 follows two levels, at most 20 files of at most 256 KiB): what it didn't read can
    do anything. A `.json` file is data; other paths it names (`bin/tool`, `README.md`) are
    files it may chmod or copy, not code it runs."""
    for path, content in code.items():
        language = "javascript" if path.startswith(INLINE_PREFIX) else language_for(path)
        if language is None:
            return False
        text = content.decode("utf-8", "replace")
        loaded = {m.group(1) for m in _LOADED.finditer(text)}
        for specifier in {*local_paths(content, language), *loaded}:
            bare = specifier.split("?")[0]
            if bare.endswith(".json") or (specifier not in loaded and not _SCRIPT.search(bare)):
                continue
            if resolve(path, specifier, code) is None:
                return False
    return True


class InstallInert(BaseRule):
    """Every install hook only runs package code (`node <file>`, `node -e`), Stage 3 read all
    of it, and it can reach nothing outside the package (module docstring). An explanation for
    Stage 4, not a signal: `correlate.EXPLAINED` makes `npm.install-hook` LOW, weight 1.

    New packages only. Stage 2 reads every file of a new package, so a payload anywhere in it
    is in front of the content rules; of an update it reads only the changed files, and the
    hook's finding may be what still points at a package whose payload sits in an unchanged
    file: `kevinx-baileys@1.2.2` (unwanted) follows channels from an unchanged
    `lib/Socket/newsletter.js`, so `static.channel-follow` never sees it, and is reported by
    its changed Node-version `preinstall` (and `npm.install-script-changed`).

    Added 2026-11-10 (`docs/proposals/precision-round4-B.md`, B1)."""

    id = "npm.install-inert"
    severity = Severity.INFO
    weight = 0.0
    title = "Install hooks run only inert package code"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        found = inert(change)
        if found is None:
            return ()
        explanation, evidence = found
        return (self.finding(explanation, *evidence),)


RULES: Final = (InstallInert(),)
