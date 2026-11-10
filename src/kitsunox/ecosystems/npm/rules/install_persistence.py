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
  `brew`, `winget`, `choco`, ...): root-level changes during `npm install`.

The test reads the install code as `npm.install-script-code` does (the files the hooks run
and those they load), plus the hook command lines, with comments and messages masked
(`lang.javascript.mask_comments_and_messages`; `#`/`REM` comments and `echo` lines in shell
files): a path in a help text, a comment or an error message is not a write. It is a static
test of what the code names, not of what it reaches: a write behind an interactive prompt or a
`npm_config_global` check counts too (the owner rules global-only writes unwanted as well).

MEDIUM, weight 3: install code that does one of these is reported for what it does. Only new
or changed install code counts (`ONLY_WHEN_CHANGED`), as for the other install rules. Measured
in `docs/stages/ast.md` and `docs/proposals/precision-round4-A.md`."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts
from kitsunox.lang.javascript import language_for, mask_comments_and_messages, shown_not_run
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


class InstallPersistence(BaseRule):
    """The install code (or an install hook's command line) writes an AI agent's user-wide
    configuration, a shell start-up file, the persistent PATH, or installs system packages
    (module docstring). Added 2026-11-09 (round 4, `docs/proposals/precision-round4-A.md`).

    v2 (2026-11-10, round 5, `docs/proposals/precision-round5-J.md`): a system package manager's
    command string that JavaScript install code only shows or keeps as data (printed advice, a
    per-distribution table, a returned hint) is not an install (`_system_package`); the same
    command as an argument list (`spawnSync("sudo", ["apt-get", "install", ...])`) now counts,
    which keeps the two unwanted installers whose only command strings are messages."""

    id = "npm.install-persistence"
    version = 2
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Install code changes the user's machine beyond the project"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        before = change.install_files_before
        if ONLY_WHEN_CHANGED and before is not None and before == change.install_files:
            return ()
        found = persistence(change.install_files, scripts(change.snapshot.manifest))
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
    for path, text in texts.items():
        if match := _agent_path(text):
            found.append(("agent", path, *_where(text, match.start(), match.end())))
        for startup in _SHELL_STARTUP.evaluate_text(text):
            found.append(("shell-rc", path, startup.line, startup.snippet))
        if match := PERSISTENT_PATH.search(text):
            found.append(("path", path, *_where(text, match.start(), match.end())))
        if match := _system_package(path, install_files.get(path), text):
            found.append(("system-package", path, *_where(text, match.start(), match.end())))
    return found


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
