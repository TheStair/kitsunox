"""What an AI coding agent reads and runs from a package: skills, instruction files, settings
with hooks and permissions, MCP servers (Stage 3).

A package built for AI-assisted development often installs its own skills or agent settings
at install time (`~/.claude/skills/<x>/SKILL.md`, a `UserPromptSubmit` hook in
`~/.claude/settings.json`, `.agents/`, `AGENTS.md`). The owner rules that benign as a verdict
(decision 0015, addendum 2026-11-08), but the same copy is how a prompt-injection payload or a
persistent hook would be planted, so the rule that stays quiet about it
(`npm.install-explained`, shape S3) needs the plain shape proved from the files themselves:

1. **Hook commands** (`hook_commands`): a settings hook runs a shell command on every prompt
   or tool call, and an MCP server's command runs whenever the agent starts. Only a constant
   `echo`, or a script shipped in the package run by a plain interpreter, is plain
   (`plain_command`); such a script must itself be plain (`script_concerns`).
2. **Permission widening** (`widening`): tool allow-lists beyond reading, bypass modes, remote
   MCP servers.
3. **Instructions aimed at the agent** (`hostile_instructions`): telling it to hide what it
   does, to ignore earlier instructions, to switch off safeguards, or to send credentials away.

Everything here is text matching over package files, which are untrusted data: nothing is run,
nothing is followed off the package. Matching is deliberately strict (a miss only means a
version stays reported); the measurements are in `docs/stages/ast.md`.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from collections.abc import Iterator, Mapping
from typing import Final

# The directories AI coding agents read their configuration from. Install code that names one
# is treated as writing agent configuration. Names only (proposal round 2, S3), never the
# package's name, description or keywords.
AGENT_DIRS: Final = (
    ".claude",
    ".agents",
    ".cursor",
    ".codex",
    ".gemini",
    ".windsurf",
    ".opencode",
)
AGENT_NAMED: Final = re.compile(
    r"(?<![\w-])\.(?:claude|agents|cursor|codex|gemini|windsurf|opencode)(?![\w-])"
    r"|SKILL\.md|AGENTS\.md|\.mcp\.json"
)
# Files an agent reads by name wherever the copier puts them.
AGENT_FILE_NAMES: Final = frozenset(
    {
        "skill.md",
        "agents.md",
        "claude.md",
        "gemini.md",
        ".cursorrules",
        ".windsurfrules",
        ".mcp.json",
        "mcp.json",
        "hooks.json",
        "settings.json",
        "settings.local.json",
        "plugin.json",
    }
)
# Plugin layouts keep agents, commands, hooks and rules in plain directories; only their text
# and configuration files count there (`commands/` and `hooks/` also name ordinary code).
PLUGIN_DIRS: Final = frozenset({"skills", "agents", "commands", "hooks", "rules", "prompts"})
CONFIG_SUFFIXES: Final = (".json", ".toml", ".yaml", ".yml")
TEXT_SUFFIXES: Final = (".md", ".mdc", ".txt", ".markdown")
MAX_AGENT_FILES: Final = 300
MAX_AGENT_FILE_BYTES: Final = 256 * 1024


def names_agent_dir(code: Mapping[str, bytes]) -> bool:
    """The code names an agent configuration directory or file (`AGENT_NAMED`)."""
    return any(AGENT_NAMED.search(c.decode("utf-8", "replace")) for c in code.values())


def is_agent_file(path: str) -> bool:
    """A package file an agent would read once copied into its configuration."""
    parts = path.split("/")
    lower = [p.lower() for p in parts]
    if any(p in AGENT_DIRS or p.removesuffix("-plugin") in AGENT_DIRS for p in lower[:-1]):
        return True
    if lower[-1] in AGENT_FILE_NAMES:
        return True
    if "skills" in lower[:-1]:
        return True
    return any(p in PLUGIN_DIRS for p in lower[:-1]) and lower[-1].endswith(
        TEXT_SUFFIXES + CONFIG_SUFFIXES
    )


def agent_files(tree: Mapping[str, bytes], install_code: Mapping[str, bytes]) -> dict[str, bytes]:
    """The agent configuration a package's install code may copy, when that code names an
    agent directory: the agent files (`is_agent_file`) and the package scripts their hook
    commands name (`hook_commands`, by file name), each cut at `MAX_AGENT_FILE_BYTES`, at most
    `MAX_AGENT_FILES` + 1 of them (more is "too many to check"). Empty otherwise."""
    if not names_agent_dir(install_code):
        return {}
    chosen = sorted(p for p in tree if is_agent_file(p))[: MAX_AGENT_FILES + 1]
    found = {p: bytes(tree[p][:MAX_AGENT_FILE_BYTES]) for p in chosen}
    named = {
        name for command in hook_commands(found, install_code) for name in script_names(command)
    }
    for path in sorted(tree):
        if len(found) > MAX_AGENT_FILES:
            break
        if path not in found and posixpath.basename(path) in named:
            found[path] = bytes(tree[path][:MAX_AGENT_FILE_BYTES])
    return found


# --- 1. hook and MCP server commands -----------------------------------------------------

# A `command` value in JavaScript or JSON (`command: "node x.js"`, `"command": "..."`), and in
# TOML (`command = "..."`). Install code that builds settings writes them this way.
_COMMAND_IN_CODE: Final = re.compile(
    r"""["']?\bcommand["']?\s*[:=]\s*(?:"((?:[^"\\\n]|\\.){0,400})"|'((?:[^'\\\n]|\\.){0,400})'"""
    r"""|`([^`]{0,400})`)"""
)
# Install code that mentions hook events or MCP servers is writing commands an agent runs.
_RUNS_COMMANDS: Final = re.compile(
    r"\b(?:UserPromptSubmit|PreToolUse|PostToolUse|SessionStart|SessionEnd|SubagentStop|"
    r"PreCompact|Notification|Stop|mcpServers|mcp_servers|statusLine)\b"
)


def hook_commands(files: Mapping[str, bytes], install_code: Mapping[str, bytes]) -> list[str]:
    """The commands agent configuration makes an agent run: every `command` (with its `args`)
    in the configuration files, and every `command` value in install code that writes hooks or
    MCP servers (`_RUNS_COMMANDS`)."""
    commands: list[str] = []
    for path, content in sorted(files.items()):
        text = content.decode("utf-8", "replace")
        if path.lower().endswith(".json"):
            try:
                commands.extend(_json_commands(json.loads(text)))
            except ValueError, RecursionError:
                commands.extend(_code_commands(text))
        elif path.lower().endswith(CONFIG_SUFFIXES):
            commands.extend(_code_commands(text))
    for content in install_code.values():
        text = content.decode("utf-8", "replace")
        if _RUNS_COMMANDS.search(text):
            commands.extend(_code_commands(text))
    return commands


def _code_commands(text: str) -> Iterator[str]:
    for match in _COMMAND_IN_CODE.finditer(text):
        yield next(g for g in match.groups() if g is not None)


def _json_commands(value: object) -> Iterator[str]:
    """`command` strings anywhere in a JSON document, with an `args` list beside them."""
    if isinstance(value, dict):
        command = value.get("command")
        if isinstance(command, str):
            args = value.get("args")
            words = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
            yield " ".join([command, *(shlex.quote(w) for w in words)])
        for item in value.values():
            yield from _json_commands(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_commands(item)


# Interpreters a hook may run a shipped script with.
_RUNNERS: Final = frozenset({"node", "bun", "deno", "bash", "sh", "zsh", "python", "python3"})
# Where the agent puts a copied script: the plugin's root, the project, the home directory.
_PATH_VAR: Final = re.compile(
    r"^(?:\$\{?(?:CLAUDE_PLUGIN_ROOT|CLAUDE_PROJECT_DIR|HOME|PWD)\}?|~)(?=/|$)"
)
_DEV_NULL: Final = re.compile(r"\s*\d?>>?\s*/dev/null|\s*\d?>&\d")
_SEPARATORS: Final = re.compile(r"\s*(?:&&|\|\||;)\s*")
_SHELL_META: Final = re.compile(r"[$`|&;<>(){}\\*?]")
_CONSTANT_ECHO: Final = re.compile(r"""echo(?:\s+-[ne]+)?(?:\s+[^$`|&;<>(){}\\]*)?""")
_SCRIPT_SUFFIXES: Final = (".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".py")


def _parts(command: str) -> list[str] | None:
    """`command` split into its simple commands (on `&&`, `||`, `;`), with redirections to
    `/dev/null` dropped; None if it uses any other shell feature."""
    stripped = _DEV_NULL.sub("", command.replace('\\"', '"')).strip()
    if not stripped or "\n" in stripped:
        return None
    return [p for p in _SEPARATORS.split(stripped) if p]


def _words(part: str) -> list[str] | None:
    try:
        return shlex.split(part)
    except ValueError:
        return None


def script_path(word: str) -> str | None:
    """A script path a hook names, relative to where the agent keeps it, or None if the word
    is not a plain path (a variable other than `_PATH_VAR`, a glob, a substitution)."""
    path = _PATH_VAR.sub("", word).lstrip("/")
    if not path or _SHELL_META.search(path) or not path.lower().endswith(_SCRIPT_SUFFIXES):
        return None
    return path


def script_names(command: str) -> set[str]:
    """The file names of the scripts `command` runs (`plain_command`'s scripts)."""
    names = set()
    for part in _parts(command) or ():
        for word in _words(part) or ():
            if (path := script_path(word)) is not None:
                names.add(posixpath.basename(path))
    return names


def plain_command(command: str, shipped: Mapping[str, bytes]) -> tuple[bool, list[str]]:
    """Whether `command` only echoes a constant or runs scripts shipped in the package
    (`shipped`, matched by file name) with an interpreter and constant arguments; and the
    shipped paths it runs. `command -v <x>`, `true`, `exit 0` and `/dev/null` redirections
    may join them with `&&`, `||` or `;`."""
    parts = _parts(command)
    if parts is None:
        return False, []
    scripts: list[str] = []
    by_name: dict[str, list[str]] = {}
    for path in shipped:
        by_name.setdefault(posixpath.basename(path), []).append(path)
    for part in parts:
        if part in ("true", "exit 0", ":") or _CONSTANT_ECHO.fullmatch(part):
            continue
        words = _words(part)
        if not words:
            return False, []
        if words[0] == "command" and len(words) == 3 and words[1] == "-v":
            continue
        if words[0] in _RUNNERS:
            words = words[1:]
        script = script_path(words[0]) if words else None
        if script is None or any(_SHELL_META.search(w) for w in words[1:]):
            return False, []
        found = by_name.get(posixpath.basename(script))
        if not found:
            return False, []
        scripts.extend(found)
    return True, sorted(set(scripts))


# What a non-JavaScript hook script (shell, Python) must not do: reach the network, fetch and
# run code, dump the environment, decode or evaluate code. JavaScript scripts are judged by
# their parsed capabilities instead.
_SCRIPT_CONCERN: Final = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|tftp|telnet|"
    r"Invoke-WebRequest|Invoke-RestMethod|iwr|irm|printenv|eval|exec)\b"
    r"|/dev/(?:tcp|udp)/|https?://|\|\s*(?:ba|z)?sh\b|base64\s+-{1,2}d|"
    r"\bsource\s+<\(|^\s*env\s*$|\benv\s*[|>]|\bexport\s+-p\b|"
    r"\b(?:urllib|requests|httpx|socket|subprocess|http\.client)\b|os\.(?:system|popen)|"
    r"os\.environ(?!\s*(?:\[|\.get\b))",
    re.MULTILINE,
)


def script_concerns(content: bytes) -> list[str]:
    """What a non-JavaScript script does that a plain hook doesn't (`_SCRIPT_CONCERN`); the
    shebang line is skipped (`#!/usr/bin/env bash`)."""
    text = content.decode("utf-8", "replace")
    if text.startswith("#!"):
        text = text.partition("\n")[2]
    return sorted({m.group(0).strip() for m in _SCRIPT_CONCERN.finditer(text)})


# --- 2. permission widening --------------------------------------------------------------

# Modes and flags that let an agent act without asking (Claude Code, Codex, Gemini CLI, Cline,
# Cursor): any of them in agent configuration or install code is widening.
_BYPASS: Final = re.compile(
    r"bypassPermissions|dangerously[-_]?skip[-_]?permissions|dangerouslySkipPermissions|"
    r"skipDangerousModePermissionPrompt|--yolo\b|\byolo[\"']?\s*[:=]\s*true|"
    r"approval_policy\s*=\s*[\"']never|danger-full-access|dangerously-bypass-approvals|"
    r"--full-auto\b|--trust-all-tools\b|\bautoApprove\b|\balwaysAllow\b|\bauto_approve\b|"
    r"\bautoAccept\b|[\"']?trust[\"']?\s*:\s*true|"
    r"defaultMode[\"']?\s*[:=]\s*[\"'](?:bypassPermissions|acceptEdits|dontAsk|auto)[\"']",
    re.IGNORECASE,
)
# A tool allow-list: settings' `permissions.allow`, `allowedTools`, a skill's or command's
# `allowed-tools` front matter.
_ALLOW_LIST: Final = re.compile(
    r"""["']?\b(?:allow|allowedTools|allowed_tools)["']?\s*[:=]\s*\[([^\]]{0,4000})\]"""
    r"""|^allowed[-_]tools\s*:[ \t]*(\S[^\n]{0,2000})?((?:\n[ \t]*-[^\n]{0,200}){0,100})""",
    re.MULTILINE,
)
_TOOL: Final = re.compile(r"[A-Za-z_][\w.-]*(?:\([^)\n]{0,200}\))?")
# Tools that only read the project: auto-approving them widens nothing that matters here.
READ_ONLY_TOOLS: Final = frozenset(
    {"Read", "Grep", "Glob", "LS", "TodoRead", "TodoWrite", "NotebookRead", "AskUserQuestion"}
)
_REMOTE_MCP: Final = re.compile(
    r"mcp-remote|[\"']?(?:url|serverUrl|httpUrl)[\"']?\s*[:=]\s*[\"'`]https?://|"
    r"[\"']?(?:type|transport)[\"']?\s*[:=]\s*[\"'](?:https?|sse|streamable-?http)[\"']",
    re.IGNORECASE,
)
_MCP: Final = re.compile(r"mcpServers|mcp_servers|\.mcp\.json|mcp\.json", re.IGNORECASE)


def widening(path: str, content: bytes) -> list[str]:
    """How one file (agent configuration, or install code) widens the agent's permissions:
    a bypass mode or flag, an allow-list naming a tool beyond `READ_ONLY_TOOLS`, or a remote
    MCP server. Each item is the matched text."""
    text = content.decode("utf-8", "replace")
    found = [m.group(0) for m in _BYPASS.finditer(text)]
    for match in _ALLOW_LIST.finditer(text):
        listed = " ".join(g for g in match.groups() if g)
        tools = [t.group(0) for t in _TOOL.finditer(listed.replace('"', " ").replace("'", " "))]
        wide = [t for t in tools if t.split("(")[0] not in READ_ONLY_TOOLS]
        if wide:
            found.append(f"allow-list: {', '.join(wide[:5])}")
    if _MCP.search(text) or path.lower().endswith("mcp.json"):
        found.extend(m.group(0) for m in _REMOTE_MCP.finditer(text))
    return found


# --- 3. instructions aimed at the agent --------------------------------------------------

# (what, pattern, whether a negation in its sentence makes it advice against it: "never
# ignore earlier instructions" is a safeguard, "do not tell the user" is the attack itself).
_HOSTILE: Final = (
    (
        "hide its activity from the user",
        False,
        re.compile(
            r"\b(?:do\s+not|don['\u2019]t|never)\s+(?:tell|inform|notify|alert|warn)\s+the\s+user\b"
            r"(?!\s+to\b)"
            r"|\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+user\b"
            r"|\b(?:hide|conceal)\s+(?:this|these|it|that|the|your|all|any)\b[^.\n]{0,60}?"
            r"\bfrom\s+the\s+user\b"
            r"|\bthe\s+user\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|find\s+out|be\s+told)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ignore its earlier instructions",
        True,
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?"
            r"(?:previous|prior|above|earlier|preceding|system)\s+"
            r"(?:instructions|prompts?|rules|directions|guidelines)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "switch off its safeguards",
        True,
        re.compile(
            r"\b(?:disable|bypass|circumvent|turn\s+off)\s+(?:all\s+|any\s+|the\s+|your\s+)?"
            r"(?:safety|security)?\s*(?:safeguards?|guardrails?|safety\s+(?:checks?|filters?|"
            r"measures?)|permission\s+(?:checks?|prompts?))\b",
            re.IGNORECASE,
        ),
    ),
)
_CREDENTIAL: Final = re.compile(
    r"~/\.ssh|\.ssh/|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|\.npmrc|\.netrc|"
    r"\.git-credentials|(?<![\w.])\.env\b|wallet\.dat|\bseed\s+phrase|\bprivate\s+keys?\b",
    re.IGNORECASE,
)
_SEND: Final = re.compile(
    r"\b(?:send|upload|post|exfiltrate|transmit|forward|curl|wget|webhook)\b", re.IGNORECASE
)
_NEGATED: Final = re.compile(
    r"\b(?:never|not|don['\u2019]t|avoid|without|prevent|block|refuse)\b", re.IGNORECASE
)
# A sentence: up to a full stop that ends it (one inside `.env` or `~/.ssh` does not).
_SENTENCE: Final = re.compile(r"(?:[^.!?;\n\u3002\uff01\uff1f\uff1b]|[.!?;](?=\S)){1,400}")
# A credential and the verb sending it must be close: one long line of documentation names
# both far apart (`@finebi/finebi-cli`'s Chinese deployment notes, a `.env.local` and a `POST`
# endpoint 200 characters later).
CREDENTIAL_NEAR_SEND: Final = 80


# Text that discusses an attack rather than making one: a phrase quoted as an example, or a
# sentence about spotting, refusing or testing injections (security-review agents quote
# "Ignore previous instructions" as the pattern to catch: `great-cto@3.75.6`, benign).
_QUOTE_BEFORE: Final = re.compile(r"""["'`\u201c\u2018]\s*$""")
_DISCUSSES: Final = re.compile(
    r"\b(?:refuse|reject|detect|flag|block|attacks?|attackers?|injections?|adversarial|"
    r"malicious|examples?|e\.g\.|such\s+as|patterns?|suspicious|asks?\s+you\s+to|report)\b",
    re.IGNORECASE,
)


def hostile_instructions(content: bytes, *, code: bool = False) -> list[tuple[int, str, str]]:
    """Instructions in agent text that work against the user: (line, what, snippet). Telling
    the agent to hide what it does, to ignore earlier instructions, or to switch off its
    safeguards; or one sentence naming a credential file and sending it, not negated. A
    phrase in quotes (except in `code`, whose strings are all quoted), or in a sentence that
    discusses attacks (`_DISCUSSES`), is not one."""
    text = content.decode("utf-8", "replace")
    found: list[tuple[int, str, str]] = []
    for what, negatable, pattern in _HOSTILE:
        for match in pattern.finditer(text):
            if not code and _QUOTE_BEFORE.search(text, max(0, match.start() - 3), match.start()):
                continue
            sentence = _sentence_at(text, match.start(), match.end())
            if _DISCUSSES.search(sentence) or (negatable and _NEGATED.search(sentence)):
                continue
            found.append((_line(text, match.start()), what, _around(text, match)))
    for each in _SENTENCE.finditer(text):
        s = each.group(0)
        if _near(s) and not _NEGATED.search(s) and not _DISCUSSES.search(s):
            found.append((_line(text, each.start()), "send credentials away", s.strip()[:200]))
    return sorted(found)


_BREAK: Final = re.compile(r"[.!?;](?=\s)|[\n\u3002\uff01\uff1f\uff1b]")


def _sentence_at(text: str, start: int, end: int) -> str:
    """The sentence around `text[start:end]`: from the break before it to the one after it
    (at most 400 characters each way)."""
    floor = max(0, start - 400)
    left = max((m.end() for m in _BREAK.finditer(text, floor, start)), default=floor)
    after = _BREAK.search(text, end, min(len(text), end + 400))
    return text[left : after.start() if after else min(len(text), end + 400)]


def _near(sentence: str) -> bool:
    """A credential and a sending verb within `CREDENTIAL_NEAR_SEND` characters."""
    sends = [m.start() for m in _SEND.finditer(sentence)]
    return any(
        abs(c.start() - s) <= CREDENTIAL_NEAR_SEND
        for c in _CREDENTIAL.finditer(sentence)
        for s in sends
    )


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _around(text: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - 60)
    return text[start : match.end() + 60].replace("\n", " ").strip()
