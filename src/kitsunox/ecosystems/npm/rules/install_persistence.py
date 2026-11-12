"""Install code that changes the user's machine beyond the project (Stage 3).

`npm install` runs install hooks unattended, often in CI and containers, with the user's
privileges. The owner rules these install-time behaviours **unwanted** (decision 0015,
addenda of 2026-11-09), harmless as what they install may be:

- **`agent`**: writing an AI coding agent's configuration user-wide (`~/.claude/`,
  `~/.codex/`, `~/.cursor/`, a user `mcp.json`, Claude Desktop's config), so every agent
  session in every project loads the package's skills, hooks, settings or MCP servers;
- **`shell-rc`**: writing the user's shell start-up files (`~/.zshrc`, `~/.bashrc`, the
  PowerShell profile): completion blocks, PATH and environment lines;
- **`path`**: changing PATH persistently (the Windows user or machine PATH, `setx PATH`, the
  `HKCU\\Environment` key, `/etc/paths.d`, `/etc/profile.d`);
- **`system-package`**: installing system packages (`sudo apt-get install -y`, `dnf`,
  `brew`, `winget`, `choco`, ...): root-level changes during `npm install`;
- **`git-config`** (v3, the owner's 2026-11-10 ruling: a silent system or user setting change at
  install is unwanted): changing the user's **global or system git configuration** for a key
  that decides what git runs or where it sends data in every repository on the machine
  (`git config --global core.hooksPath ~/.x/hooks`, `credential.helper`, `url.*.insteadOf`,
  ...; `GIT_KEYS`), or writing `~/.gitconfig`. A project's own setting (`git config
  core.hooksPath .githooks`, no `--global`) and per-command overrides (`git -c k=v ...`) are
  not.

The test reads the install code as `npm.install-script-code` does (the files the hooks run
and those they load), plus the hook command lines, with comments and messages masked
(`lang.javascript.mask_comments_and_messages`; `#`/`REM` comments and `echo` lines in shell
files): a path in a help text, a comment or an error message is not a write. It is a static
test of what the code names, not of what it reaches: a write behind an interactive prompt or a
`npm_config_global` check counts too (the owner rules global-only writes unwanted as well).

MEDIUM, weight 3: install code that does one of these is reported for what it does. Only new
or changed install code counts (`ONLY_WHEN_CHANGED`), as for the other install rules, except
for the `agent` form (`ALWAYS_FORMS`, v6) and the `shell-rc` form (v7), which count on every
version. Measured
in `docs/stages/ast.md` and `docs/proposals/precision-round4-A.md`."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts
from kitsunox.lang.flow import Write, reaches_write, unfollowed_installer
from kitsunox.lang.javascript import (
    language_for,
    mask_comments_and_messages,
    opt_in_parameter,
    passes_argument,
    shown_not_run,
)
from kitsunox.lang.shell import mask_script_messages
from kitsunox.rules.static import ShellStartup
from kitsunox.stages.ast import CodeChange

MAX_SHOWN: Final = 3
SNIPPET_RADIUS: Final = 70

# The directories (under the home directory) and files AI coding agents keep their user-wide
# configuration in. `.claude.json` is Claude Code's own user file.
_AGENT: Final = (
    r"\.(?:claude|agents|codex|cursor|gemini|windsurf|opencode|qwen|kiro|qoder|openclaw|trae"
    r"|codeium|roo|cline|augment|copilot|factory|crush|goose|aider|kilocode|junie|hermes"
    r"|workbuddy|zcode|dsh)(?![\w-])"
    r"|\.config[/\\]+(?:opencode|crush|goose|github-copilot)(?![\w-])"
)
# A home-directory expression: `os.homedir()` (also minified, `l.homedir()`, `(0, os.homedir)()`),
# `process.env.HOME`/`USERPROFILE` (also `["HOME"]`).
_HOME_CALL: Final = (
    r"(?:[\w$]+\s*\.\s*)?homedir\s*\)?\s*\(\s*\)"
    r"|process\s*\.\s*env\s*(?:\.\s*(?:HOME|USERPROFILE)\b|\[\s*[\"'`](?:HOME|USERPROFILE)[\"'`]\s*\])"
)
_SEP: Final = r"\s*,\s*[\"'`]"
# A caller's override in front of the home expression: `join(options.home ?? homedir(), ...)`.
_OVERRIDE: Final = r"(?:[\w$.?]+\s*(?:\?\?|\|\|)\s*)?"
# The next argument of a `join`/`resolve` names an agent directory, also in a choice
# (`join(homedir(), target === "codex" ? ".codex" : ".agents", "skills")`).
_AGENT_ARG: Final = r"\s*,[^,()\n]{0,60}?[\"'`](?:" + _AGENT + ")"
# A path written out under the home directory, or joined to a home expression.
AGENT_PATH: Final = re.compile(
    r"[\"'`]~[/\\]+(?:" + _AGENT + ")"
    r"|\$\{?HOME\}?[/\\]+(?:" + _AGENT + ")"
    r"|%USERPROFILE%[/\\]+(?:" + _AGENT + ")"
    r"|\$env:USERPROFILE[/\\]+(?:" + _AGENT + ")"
    r"|\$\{\s*(?:" + _HOME_CALL + r")\s*\}[/\\]+(?:" + _AGENT + ")"
    r"|(?:join|resolve)\s*\(\s*"
    + _OVERRIDE
    + r"(?:"
    + _HOME_CALL
    + r")(?:\s*\|\|\s*[\"'`]{2})?"
    + _AGENT_ARG
    + r"|(?:join|resolve)\s*\(\s*(?:"
    + _HOME_CALL
    + r")"
    + _SEP
    + r"(?:Library|AppData|\.config)"
    r"[^\"'`]{0,40}[\"'`](?:\s*,\s*[\"'`][^\"'`]{0,40}[\"'`]){0,3}\s*,\s*[\"'`](?:Claude|Code)[\"'`]"
    r"|claude_desktop_config\.json"
)
# A variable given the home directory: `const home = os.homedir()`, `let e = l.homedir()`,
# `const HOME = process.env.HOME || os.homedir()`.
HOME_VARIABLE: Final = re.compile(
    r"(?:\b(?:const|let|var)\s+|[,{]\s*)([\w$]+)\s*[=:]\s*(?:"
    + _HOME_CALL
    + r"|(?:[\w$]+\.)?(?:get)?[Hh]ome(?:[Dd]ir(?:ectory)?)?\s*\(\s*\))"
)
# An agent's own user-wide configuration directory, from its environment variable.
AGENT_HOME_VARIABLE: Final = re.compile(
    r"(?:\benv\s*\.\s*|\benv\s*\[\s*[\"'`]|\$\{?|%)"
    r"(?:CLAUDE_CONFIG_DIR|CODEX_HOME|GEMINI_CLI_HOME|CURSOR_CONFIG_DIR|OPENCODE_CONFIG_DIR)\b"
)
# Changing PATH for good.
PERSISTENT_PATH: Final = re.compile(
    r"SetEnvironmentVariable\s*\(\s*[\"'](?:Path|PATH)[\"'][^\n]{0,300}?[\"'](?:User|Machine)[\"']"
    r"|\bsetx\s+(?:/M\s+)?[\"']?PATH\b"
    r"|\breg(?:\.exe)?\s+add\s+[\"']?HK(?:CU|EY_CURRENT_USER)\\+Environment"
    r"|/etc/paths\.d/|/etc/profile\.d/"
    r"|\blaunchctl\s+setenv\s+PATH\b",
    re.IGNORECASE,
)
# A system package manager's install command, where a command starts: at the start of a string
# or a shell line, or after `&&`, `||`, `;`, `|`, `$(`. A sentence naming one ("Install it with:
# brew install x") doesn't start a command.
SYSTEM_PACKAGE: Final = re.compile(
    r"(?:^|[\"'`]|&&|\|\||[;|]|\$\()\s*"
    r"(?:sudo\s+(?:-[A-Za-z]+\s+)*(?:env\s+\S+\s+)?)?(?:DEBIAN_FRONTEND=\S+\s+)?"
    r"(?:apt-get|apt|aptitude|dnf|yum|zypper|apk|pacman|brew|port|winget|choco|scoop|snap)"
    r"\s+(?:-\S+\s+)*(?:install|add|-S|-Sy|-Syu)\b",
    re.MULTILINE,
)
# v2: the same install command as an argument list: `spawnSync("sudo", ["apt-get", "install",
# "-y", ...])`, `run("brew", ["install", "ffmpeg"])` (`streamgrab@1.3.4`, `gebangautoupload@1.1.4`,
# unwanted: their only command strings are messages).
SYSTEM_PACKAGE_ARGV: Final = re.compile(
    r"""["'`](?:sudo["'`]\s*,\s*\[\s*(?:["'`]-\w+["'`]\s*,\s*)*["'`])?"""
    r"(?:apt-get|apt|aptitude|dnf|yum|zypper|apk|pacman|brew|port|winget|choco|scoop|snap)"
    r"""["'`]\s*,\s*\[?\s*(?:["'`]-[\w-]+["'`]\s*,\s*)*["'`](?:install|add|-S|-Sy|-Syu)["'`]"""
)
# Script lines that only talk: comments, `echo`/`printf`/`Write-Host`/`print` messages.
_SCRIPT_TALK: Final = re.compile(
    r"^\s*(?:#|REM\b|::|@?echo\b|printf\b|Write-(?:Host|Output|Warning)\b|print\().*$",
    re.MULTILINE | re.IGNORECASE,
)
_SHELL_STARTUP: Final = ShellStartup()
# Install files besides JavaScript and TypeScript that run as code (a README or a JSON file the
# hooks name is data).
SCRIPT_SUFFIXES: Final = (".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd")


# Fire only for install code that is new or changed since the previous version (a new
# package, a changed or newly run install file), where the install rules already look: the
# rule names what such code does, and adds no report for an installer that is the same as in
# the previous version. False fires on every version whose install code does it (measured in
# `docs/proposals/precision-round4-A.md`: more unwanted versions reported, and more benign).
ONLY_WHEN_CHANGED: Final = True
# v6 (2026-11-11, recall round 8 R, `docs/proposals/recall-round8-R.md`): the forms that count
# on every version whose install code does them, changed or not. A user-wide agent install runs
# on every `npm install` of every release that ships it, and the owner rules each such release
# unwanted (`@aswless_854771076/ai_short_studio_cli@0.1.236`: its postinstall, unchanged since
# 0.1.235, copies skills into `~/.codex/skills`, found by the label-blind daily sample).
# v7 (2026-11-12, round 9 Q4, `docs/proposals/precision-round9-Q.md`): `shell-rc` too. `botmux`
# 3.59.2-3.59.5 (unwanted) append a PATH line to the shell start-up files on every global
# install from an unchanged postinstall. `path` and `system-package` stay changed-only: on
# unchanged code they add 21 benign versions (round 8 R: `glimmervoid` x17, a PATH help text
# in a bundled chunk; `agentiqa` x4, an install hint) for no positive.
ALWAYS_FORMS: Final = frozenset({"agent", "shell-rc"})


class InstallPersistence(BaseRule):
    """The install code (or an install hook's command line) writes an AI agent's user-wide
    configuration, a shell start-up file, the persistent PATH, or installs system packages
    (module docstring). Added 2026-11-09 (round 4, `docs/proposals/precision-round4-A.md`).

    v2 (2026-11-10, round 5, `docs/proposals/precision-round5-J.md`): a system package manager's
    command string that JavaScript install code only shows or keeps as data (printed advice, a
    per-distribution table, a returned hint) is not an install (`_system_package`); the same
    command as an argument list (`spawnSync("sudo", ["apt-get", "install", ...])`) now counts,
    which keeps the two unwanted installers whose only command strings are messages.

    v3 (2026-11-10, round 5, `docs/proposals/precision-round5-M.md`): the `git-config` form
    (`_git_config`): install code that changes the global or system git configuration for a
    key that runs code or redirects data in every repository (`signoff-cli`, `dsh-signoff`:
    `spawnSync("git", ["config", "--global", "core.hooksPath", dir])`, unwanted by the owner's
    2026-11-10 ruling).

    v4 (2026-11-10, owner): `GIT_KEYS` narrowed to hooks, templates, ssh, credential helpers,
    URL rewrites and includes; settings a development tool commonly makes for itself (editor,
    pager, diff and merge tools, signing program, proxies, `!` aliases, `safe.directory=*`)
    are benign by the owner's ruling and no longer count. None fired on live data.

    v5 (2026-11-11, round 6, `docs/proposals/precision-round6-S.md`): in JavaScript install
    code, the `agent` form needs the value naming the agent's user-wide location to reach a
    write (`lang.flow.reaches_write`: a file write at its destination argument, a writing shell
    command, a library function named for writing), not just to be named: a usage meter that
    reads `~/.codex/sessions` (`aiimpactmeter`), a check whether a skill is installed
    (`nansen-cli`), an environment report (`dsh-undo-savepoint`) are reads (S1). When nothing
    in the install files writes it but they run a program with an installer subcommand that
    the analysis can't read (`lang.flow.unfollowed_installer`: `wkappbot-code` spawns its own
    CLI's `install`, `local-mcp` a downloaded binary's `--configure-clients`), it still
    counts. An agent CLI's install command that JavaScript only shows or keeps as data no
    longer counts (`_agent_cli`, S2: `memtrace@1.2.13`'s "(written by `claude mcp add-json
    --scope user` ...)" description). For `shell-rc` in JavaScript, `ShellStartup`'s `code`
    form (a start-up file's name within 1,000 characters of any write) is replaced by the same
    value analysis from the name (`RC_FILE`): `polydev-ai` lists `~/.zshrc` to read it;
    `coding-friend-cli` returns `join(home, ".zshrc")` from one function and writes it in
    another, out of `ShellStartup`'s reach (S3). Shell scripts and hook command lines are
    matched as before; the `git-config` form is unchanged.

    v6 (2026-11-11, recall round 8 R, `docs/proposals/recall-round8-R.md`): the `agent` form
    (`ALWAYS_FORMS`) counts on every version whose install code does it, changed or not; the
    other forms still need new or changed install code (`ONLY_WHEN_CHANGED`).

    v7 (2026-11-12, round 9 Q4, `docs/proposals/precision-round9-Q.md`): the `shell-rc` form
    joins `ALWAYS_FORMS`. `botmux` 3.59.2-3.59.5 (unwanted: a global install's postinstall
    appends a PATH line to `~/.zshrc`/`~/.bashrc`/the login file) had unchanged install code
    and were reported only by an accidental `npm.install-download` hit, which round 8 P2
    (`npm.install-download` v3) rightly removed."""

    id = "npm.install-persistence"
    version = 7
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Install code changes the user's machine beyond the project"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        before = change.install_files_before
        unchanged = ONLY_WHEN_CHANGED and before is not None and before == change.install_files
        if unchanged and not ALWAYS_FORMS:
            return ()
        found = persistence(change.install_files, scripts(change.snapshot.manifest))
        if unchanged:  # v6: unchanged install code counts for `ALWAYS_FORMS` only
            found = [item for item in found if item[0] in ALWAYS_FORMS]
        if not found:
            return ()
        forms = sorted({form for form, _, _, _ in found})
        return (
            self.finding(
                "`npm install` "
                + "; ".join(FORM_TEXT[form] for form in forms)
                + ". Unwanted when an install hook does it (decision 0015).",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=text,
                    )
                    for _, path, line, text in _first_per_form(found)[:MAX_SHOWN]
                ),
            ),
        )


FORM_TEXT: Final = {
    "agent": "works on an AI coding agent's user-wide configuration (a path under the home "
    "directory): it may install skills, hooks, settings or MCP servers for every project",
    "path": "changes the PATH persistently",
    "shell-rc": "writes the user's shell start-up files",
    "system-package": "installs system packages",
    "git-config": "changes the user's global git configuration (hooks, ssh, credentials or "
    "remotes): every repository on the machine is affected",
}


def persistence(
    install_files: Mapping[str, bytes], declared: Mapping[str, str]
) -> list[tuple[str, str, int, str]]:
    """What the install code and hook command lines do beyond the project, as
    (form, path, 1-based line, text around it)."""
    texts = {
        path: code_text(path, data)
        for path, data in sorted(install_files.items())
        if language_for(path) is not None or path.lower().endswith(SCRIPT_SUFFIXES)
    }
    for hook in INSTALL_HOOKS:
        if command := declared.get(hook, "").strip():
            texts[f"package.json:scripts.{hook}"] = command
    found: list[tuple[str, str, int, str]] = []
    code = _javascript(install_files, texts)
    agent_seeds: dict[str, list[tuple[int, int]]] = {}
    rc_seeds: dict[str, list[tuple[int, int]]] = {}
    for path, text in texts.items():
        if path in code:
            if match := _agent_cli(code[path], text):
                found.append(("agent", path, *_where(text, match.start(), match.end())))
            elif spans := agent_spans(text):  # v5: only a value that reaches a write counts
                agent_seeds[path] = [_bytes(text, span) for span in spans]
        elif match := _agent_path(text):
            found.append(("agent", path, *_where(text, match.start(), match.end())))
        startups = _SHELL_STARTUP.evaluate_text(text)
        if path in code:  # v5: a start-up file's name near a write is followed instead
            startups = [s for s in startups if "(form `code`)" not in s.explanation]
        for startup in startups:
            found.append(("shell-rc", path, startup.line, startup.snippet))
        rc_names = [m.span() for m in RC_FILE.finditer(text)] if path in code else []
        if rc_names and not startups and _HOME_WORD.search(text):
            rc_seeds[path] = [_bytes(text, span) for span in rc_names]
        if match := PERSISTENT_PATH.search(text):
            found.append(("path", path, *_where(text, match.start(), match.end())))
        if match := _system_package(path, install_files.get(path), text):
            found.append(("system-package", path, *_where(text, match.start(), match.end())))
        if match := _git_config(path, install_files, text):
            found.append(("git-config", path, *_where(text, match.start(), match.end())))
    if agent_seeds and not any(form == "agent" for form, *_ in found):
        write = reaches_write(code, agent_seeds) or unfollowed_installer(code)
        if write is not None:
            found.append(("agent", *_located(code, write)))
    shell_rc = any(form == "shell-rc" for form, *_ in found)
    if rc_seeds and not shell_rc and (write := reaches_write(code, rc_seeds)) is not None:
        found.append(("shell-rc", *_located(code, write)))
    order = {path: i for i, path in enumerate(texts)}
    return sorted(found, key=lambda item: (order.get(item[1], len(order)), item[2]))


# v5: a shell start-up file's name as a string, for the value analysis (`ShellStartup` finds
# the names it can see next to a write; `coding-friend-cli` builds `join(home, ".zshrc")` in
# one function and writes it in another).
RC_FILE: Final = re.compile(
    r"[\"'`](?:~/|\$HOME/)?\.(?:bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin"
    r"|profile|cshrc|tcshrc|kshrc)[\"'`]|[\"'`]config\.fish[\"'`]"
    r"|Microsoft\.PowerShell_profile\.ps1"
)
_HOME_WORD: Final = re.compile(r"homedir|\bHOME\b|USERPROFILE|ZDOTDIR")


def agent_spans(text: str) -> list[tuple[int, int]]:
    """Every expression in `text` that names an AI agent's user-wide configuration (the
    expressions `_agent_path` finds the first of, except an agent CLI's install command)."""
    spans = [m.span() for m in AGENT_PATH.finditer(text)]
    if XDG_HOME.search(text):
        spans += [m.span() for m in XDG_AGENT.finditer(text)]
    spans += [m.span() for m in AGENT_HOME_VARIABLE.finditer(text)]
    names = sorted({m.group(1) for m in HOME_VARIABLE.finditer(text)}, key=len, reverse=True)
    if names:
        home = "(?:this\\.)?(?:" + "|".join(re.escape(n) for n in names) + ")"
        agent = "(?:" + _AGENT + ")"
        joined = re.compile(
            rf"(?:join|resolve)\s*\(\s*{_OVERRIDE}{home}{_AGENT_ARG}"
            rf"|\$\{{\s*{home}\s*\}}[/\\]+{agent}"
            rf"|(?<![\w$.]){home}\s*\+\s*[\"'`][/\\]+{agent}"
        )
        spans += [m.span() for m in joined.finditer(text)]
    return sorted(set(spans))


def _javascript(
    install_files: Mapping[str, bytes], texts: Mapping[str, str]
) -> dict[str, tuple[bytes, str]]:
    """The JavaScript and TypeScript install files whose masked text maps back to their bytes
    (decoding replaced nothing), as (content, language) for `lang.flow`."""
    out = {}
    for path, data in sorted(install_files.items()):
        language = language_for(path)
        text = texts.get(path)
        if language is not None and text is not None and len(text.encode("utf-8")) == len(data):
            out[path] = (data, language)
    return out


def _bytes(text: str, span: tuple[int, int]) -> tuple[int, int]:
    return len(text[: span[0]].encode("utf-8")), len(text[: span[1]].encode("utf-8"))


def _located(code: Mapping[str, tuple[bytes, str]], write: Write) -> tuple[str, int, str]:
    """(path, 1-based line, text around it) of a write `lang.flow` found."""
    data = code[write.path][0] if write.path in code else b""
    start = write.offset
    end = min(start + len(write.text.encode("utf-8")), start + 160)
    line = data.count(b"\n", 0, start) + 1
    around = data[max(0, start - SNIPPET_RADIUS) : end + SNIPPET_RADIUS]
    return write.path, line, " ".join(around.decode("utf-8", "replace").split())


def _system_package(path: str, data: bytes | None, text: str) -> re.Match[str] | None:
    """The first system-package install command in `text` that the code may run (v2): an
    argument list (`SYSTEM_PACKAGE_ARGV`) always; a command string unless, in JavaScript, it is
    only shown or kept as data (`lang.javascript.shown_not_run`: printed advice, a table of
    commands per package manager, a returned hint). `argonauts-code@0.2.0`'s `xz-check.js` keeps
    one per distribution in an array, `wyrm-mcp@9.4.2` returns them, `uniwind-pro@1.9.2` pushes
    one into its keyring help text: all benign, none run."""
    if match := SYSTEM_PACKAGE_ARGV.search(text):
        return match
    language = language_for(path)
    # Offsets map back to the bytes only when decoding replaced nothing.
    mapped = language is not None and data is not None and len(text.encode("utf-8")) == len(data)
    for match in SYSTEM_PACKAGE.finditer(text):
        if not mapped or data is None or language is None:
            return match
        if not shown_not_run(data, language, len(text[: match.end() - 1].encode("utf-8"))):
            return match
    return None


# v3: git configuration keys that decide, for every repository, what git runs as hooks (the
# hooks directory, templates that carry hooks) or how and where it connects and sends
# credentials (ssh command, credential helpers, URL rewrites), or that pull in another
# configuration file (`include`). Owner 2026-11-10: keys a development tool commonly sets for
# itself (editor, pager, diff and merge tools, signing program, proxies, aliases,
# `safe.directory`) are benign and not listed.
GIT_KEYS: Final = (
    r"core\.(?:hooksPath|sshCommand)|init\.templateDir"
    r"|credential\.(?:[^\s\"'`=]+\.)?helper"
    r"|url\.[^\s\"'`=]+\.(?:push)?insteadOf"
    r"|include\.path|includeIf\.[^\s\"'`=]+\.path"
)
# Options that only read or remove (`--get`, `--list`, `--unset`, ...) end the match.
_READ_OPTION: Final = (
    r"--(?:get|list|unset|remove|rename|show|name-only|edit|null|default)|-[lez](?![\w-])"
)
# Options before the scope can't be the scope (one way to match: linear, not quadratic, on a
# line of thousands of `--global`).
_SCOPE_OPTION: Final = r"|--(?:global|system|file)(?![\w-])|-f(?![\w-])"
_OPTION: Final = r"(?:(?!" + _READ_OPTION + r")--?\w[\w-]*(?:=\S+)?\s+)*"
_PRE_OPTION: Final = r"(?:(?!" + _READ_OPTION + _SCOPE_OPTION + r")--?\w[\w-]*(?:=\S+)?\s+)*"
_HOME_FILE: Final = r"(?:~|\$\{?HOME\}?|%USERPROFILE%)[/\\]+\.gitconfig"
# As a command string: `git config --global core.hooksPath ~/.x`, `git config set --system ...`,
# a string starting at `config` (`runGit("config --global ...")`), `git config --file
# ~/.gitconfig ...`.
GIT_CONFIG: Final = re.compile(
    r"(?:\bgit(?:\.exe)?[\"']?\s+(?:-C\s+\S+\s+)*|(?<=[\"'`]))config\s+(?:set\s+)?"
    + _PRE_OPTION
    + r"(?:--(?:global|system)\s+|(?:--file|-f)[\s=]+[\"']?"
    + _HOME_FILE
    + r"[\"']?\s+)"
    + _OPTION
    + r"[\"']?(?:"
    + GIT_KEYS
    + r")(?![\w.-])",
    re.IGNORECASE,
)
_Q: Final = r"[\"'`]"
_ARG_OPTION: Final = (
    r"(?:" + _Q + r"(?!" + _READ_OPTION + r")--?\w[\w-]*(?:=[^\"'`]*)?" + _Q + r"\s*,\s*)*"
)
_PRE_ARG_OPTION: Final = (
    r"(?:"
    + _Q
    + r"(?!"
    + _READ_OPTION
    + _SCOPE_OPTION
    + r")--?\w[\w-]*(?:=[^\"'`]*)?"
    + _Q
    + r"\s*,\s*)*"
)
# As an argument list: `spawnSync("git", ["config", "--global", "core.hooksPath", dir])`,
# `git(["config", "set", "--global", ...])`.
GIT_CONFIG_ARGV: Final = re.compile(
    _Q
    + r"config"
    + _Q
    + r"\s*,\s*(?:"
    + _Q
    + r"set"
    + _Q
    + r"\s*,\s*)?"
    + _PRE_ARG_OPTION
    + _Q
    + r"--(?:global|system)"
    + _Q
    + r"\s*,\s*"
    + _ARG_OPTION
    + _Q
    + r"(?:"
    + GIT_KEYS
    + r")"
    + _Q,
    re.IGNORECASE,
)
# `~/.gitconfig` (or the XDG `~/.config/git/config`) written out under the home directory or
# joined to a home expression.
_GITCONFIG: Final = r"(?:\.gitconfig|\.config[/\\]+git[/\\]+config)\b"
HOME_GITCONFIG: Final = (
    r"[\"'`]~[/\\]+"
    + _GITCONFIG
    + r"|\$\{?HOME\}?[/\\]+"
    + _GITCONFIG
    + r"|%USERPROFILE%[/\\]+"
    + _GITCONFIG
    + r"|\$\{\s*(?:"
    + _HOME_CALL
    + r")\s*\}[/\\]+"
    + _GITCONFIG
    + r"|(?:join|resolve)\s*\(\s*"
    + _OVERRIDE
    + r"(?:"
    + _HOME_CALL
    + r")"
    + _SEP
    + r"(?:\.gitconfig|\.config[\"'`]\s*,\s*[\"'`]git[\"'`]\s*,\s*[\"'`]config)[\"'`]"
)
# Written: a file-writing call with the path in its arguments, or a shell redirection or `tee`.
_WRITES: Final = (
    r"\b(?:writeFile|appendFile|outputFile|createWriteStream|copyFile|cpSync|writeJson)\w*"
)
GITCONFIG_WRITE: Final = re.compile(
    _WRITES
    + r"\s*\([^;\n]{0,160}?(?:"
    + HOME_GITCONFIG
    + r")|(?:>>?|\btee\s+(?:-a\s+)?)\s*[\"']?(?:~|\$\{?HOME\}?|%USERPROFILE%)[/\\]+"
    + _GITCONFIG
)
# A variable given the path, then written: `const p = join(homedir(), ".gitconfig");
# fs.appendFileSync(p, ...)`.
GITCONFIG_VARIABLE: Final = re.compile(
    r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:" + HOME_GITCONFIG + r")"
)


def _git_config(path: str, install_files: Mapping[str, bytes], text: str) -> re.Match[str] | None:
    """The first change of the global or system git configuration in `text` that install code
    may make (v3): `GIT_CONFIG_ARGV` and `GIT_CONFIG` for a key in `GIT_KEYS`, or a write of
    `~/.gitconfig`. In JavaScript, a command string only shown or kept as data
    (`lang.javascript.shown_not_run`) doesn't count, nor a change made only inside `if (p)`
    where `p` is a parameter with an off default (`f(cwd, isGlobal = false)`) that no install
    file passes (`lang.javascript.opt_in_parameter`, `passes_argument`):
    `@arifbiswas/git-pre-push@1.0.0` sets `core.hooksPath` globally only when its CLI asks."""
    data = install_files.get(path)
    language = language_for(path)
    # Offsets map back to the bytes only when decoding replaced nothing.
    mapped = language is not None and data is not None and len(text.encode("utf-8")) == len(data)
    matches = [
        *((m, False) for m in GIT_CONFIG_ARGV.finditer(text)),
        *((m, True) for m in GIT_CONFIG.finditer(text)),
        *((m, False) for m in GITCONFIG_WRITE.finditer(text)),
    ]
    for name in sorted({m.group(1) for m in GITCONFIG_VARIABLE.finditer(text)}):
        written = _WRITES + r"\s*\(\s*" + re.escape(name) + r"(?![\w$])"
        matches += [(m, False) for m in re.finditer(written, text)]
    for match, command in sorted(matches, key=lambda item: item[0].start()):
        if not mapped or data is None or language is None:
            return match
        offset = len(text[: match.start()].encode("utf-8"))
        if command and shown_not_run(data, language, offset):
            continue
        if _opt_in_only(data, language, offset, install_files):
            continue
        return match
    return None


def _opt_in_only(
    data: bytes, language: str, offset: int, install_files: Mapping[str, bytes]
) -> bool:
    """Whether the code at `offset` runs only when a caller passes an option that no install
    file passes."""
    if (guard := opt_in_parameter(data, language, offset)) is None:
        return False
    name, index = guard
    return not any(
        passes_argument(code, other, name, index)
        for path, code in sorted(install_files.items())
        if (other := language_for(path)) is not None
    )


# The XDG config home (`$XDG_CONFIG_HOME`, else `~/.config`) and an agent that keeps its
# user configuration there (`join(configHome, "opencode", "skills")`).
XDG_AGENT: Final = re.compile(
    r"(?:join|resolve)\s*\([^()\n]{0,80},\s*[\"'`](?:opencode|crush|goose|github-copilot)[\"'`]"
)
XDG_HOME: Final = re.compile(
    r"XDG_CONFIG_HOME[\s\S]{0,400}?(?:join|resolve)\s*\(\s*(?:" + _HOME_CALL + r")[^()\n]{0,60}?"
    r"[\"'`]\.config[\"'`]"
)


# An agent's own CLI installing into its user configuration: `claude plugin install`,
# `claude plugin marketplace add` (user scope by default), `claude mcp add --scope user`,
# `codex mcp add` (`~/.codex/config.toml`); also through a variable holding the CLI
# (`"$CLAUDE_BIN" plugin install`, `anolisa-tokenless`) or an argument list.
AGENT_CLI: Final = re.compile(
    r"(?:\bclaude|\$\{?CLAUDE\w*\}?)[\"']?\s+plugins?\s+(?:install|marketplace\s+add)\b"
    r"|\bclaude\s+mcp\s+add\b[^\n]{0,200}?(?:--scope[ =]|-s\s+)user\b"
    r"|\bcodex\s+mcp\s+add\b"
    r"|[\"'`]claude[\"'`]\s*,\s*\[\s*[\"'`]plugins?[\"'`]\s*,\s*[\"'`](?:install|marketplace)[\"'`]"
)


def _agent_cli(source: tuple[bytes, str], text: str) -> re.Match[str] | None:
    """The first agent CLI install command in JavaScript that the code may run (v5): one only
    shown or kept as data (`lang.javascript.shown_not_run`: a description in an object,
    `memtrace@1.2.13`'s "written by `claude mcp add-json --scope user`") doesn't count."""
    data, language = source
    for match in AGENT_CLI.finditer(text):
        if not shown_not_run(data, language, len(text[: match.start()].encode("utf-8"))):
            return match
    return None


def _agent_path(text: str) -> re.Match[str] | None:
    if match := AGENT_PATH.search(text):
        return match
    if match := AGENT_CLI.search(text):
        return match
    if XDG_HOME.search(text) and (match := XDG_AGENT.search(text)):
        return match
    if match := AGENT_HOME_VARIABLE.search(text):
        return match
    names = sorted({m.group(1) for m in HOME_VARIABLE.finditer(text)}, key=len, reverse=True)
    if not names:
        return None
    home = "(?:this\\.)?(?:" + "|".join(re.escape(n) for n in names) + ")"
    agent = "(?:" + _AGENT + ")"
    return re.search(
        rf"(?:join|resolve)\s*\(\s*{_OVERRIDE}{home}{_AGENT_ARG}"
        rf"|\$\{{\s*{home}\s*\}}[/\\]+{agent}"
        rf"|(?<![\w$.]){home}\s*\+\s*[\"'`][/\\]+{agent}",
        text,
    )


def code_text(path: str, data: bytes) -> str:
    """An install file's text with comments and messages blanked, offsets and lines kept:
    JavaScript and TypeScript through `mask_comments_and_messages`; a shell, PowerShell or
    batch script through `lang.shell.mask_script_messages` (since 2026-11-10: a message printed
    through the script's own print-only function is blanked too, and an `echo` that pipes or
    writes a file is kept); any other file without its comment and `echo`/`print` lines
    (`_SCRIPT_TALK`)."""
    if (language := language_for(path)) is not None:
        return mask_comments_and_messages(data, language).decode("utf-8", "replace")
    text = data.decode("utf-8", "replace")
    if path.lower().endswith(SCRIPT_SUFFIXES):
        return mask_script_messages(text)
    return _SCRIPT_TALK.sub(lambda m: " " * len(m.group(0)), text)


def _where(text: str, start: int, end: int) -> tuple[int, str]:
    line = text.count("\n", 0, start) + 1
    snippet = " ".join(text[max(0, start - SNIPPET_RADIUS) : end + SNIPPET_RADIUS].split())
    return line, snippet


def _first_per_form(
    found: list[tuple[str, str, int, str]],
) -> list[tuple[str, str, int, str]]:
    seen: set[str] = set()
    out = []
    for item in found:
        if item[0] not in seen:
            seen.add(item[0])
            out.append(item)
    return out


RULES: Final = (InstallPersistence(),)
