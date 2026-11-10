"""Install code that fetches or decodes code and runs it, in shell, PowerShell or batch (Stage 3).

Most install rules read JavaScript through tree-sitter (`npm.install-script-code` counts
capabilities, `npm.install-script-obfuscated` looks for javascript-obfuscator). A shell,
PowerShell or batch script that an install hook runs (`"postinstall": "sh setup.sh"`,
`powershell -File x.ps1`) or that install code starts (`install.spawned_scripts`) has no
capability profile: whatever it does, those rules see nothing. The owner, 2026-11-10: "the
scripts triggered by the package should be analyzed. For example if that .ps1 file had
obfuscation it should be flagged."

`npm.install-script-loader` reads the install code (the files the hooks run, those they load
and the scripts they start) and the hook command lines, with comments and messages masked
(`loader_text`), for the precise shapes of a loader: code that is downloaded
or decoded and run in the same breath, and the obfuscation that hides it (`SHAPES`):

- **shell**: a download piped into a shell (`curl ... | sh`, `wget -qO- ... | bash`), a shell
  or `eval` running a download (`bash -c "$(curl ...)"`, `sh <(curl ...)`, `eval "$(wget ...)"`),
  decoded data run (`echo <base64> | base64 -d | sh`, `eval "$(... | base64 -d)"`, `xxd -r`,
  `printf '\\x..'`), a reverse shell (`/dev/tcp/host/port`, `nc -e /bin/sh`);
- **PowerShell**: `-EncodedCommand`/`-enc` with base64, `Invoke-Expression`/`iex` of a
  download (`irm ... | iex`, `iex (New-Object Net.WebClient).DownloadString(...)`) or of
  decoded text (`FromBase64String`, `[char]` codes, `-join`), `[char]` code chains, a string
  reversed into code (`-join ... [-1..-n]`), an assembly loaded from bytes;
- **Windows tools that download or decode** (shell, PowerShell or batch): `certutil -urlcache`
  / `-decode`, `bitsadmin /transfer`, `mshta http:`/`vbscript:`, `rundll32 javascript:`,
  `regsvr32 /i:http` (scrobj), and batch substring obfuscation (`%v:~3,1%` chains).

MEDIUM, weight 3. A download piped into a shell from the package's own site (the host of its
`homepage`, `repository` or `bugs` URL, or `raw.githubusercontent.com` / `github.com` under the
repository's owner) is how many tools install their binary: LOW, weight 1 (`OWN_NOTE`). From a
raw IP address, a paste site, a tunnel, a URL shortener or a file drop (`RISKY_HOSTS`) it says
so. On an update only a shape the previous version's install code didn't have counts (by
shape and host), as for the other install rules. Measured in `docs/stages/ast.md` and
`docs/proposals/precision-round4-G.md`.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final
from urllib.parse import urlsplit

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.install import SCRIPT_SUFFIXES
from kitsunox.ecosystems.npm.rules.install_code import HIDDEN_RUN, hidden_code
from kitsunox.ecosystems.npm.rules.install_persistence import code_text
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts
from kitsunox.lang.javascript import language_for
from kitsunox.lang.shell import mask_script_messages
from kitsunox.stages.ast import CodeChange

_I: Final = re.IGNORECASE
_SHELL: Final = r"(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(?:/\S*/)?(?:ba|z|da|k)?sh\b"
_FETCH: Final = r"\b(?:curl|wget)(?:\.exe)?\b"
# A decoder whose output is code here: base64, hex (`xxd -r`), openssl's base64, escapes.
_DECODE: Final = (
    r"(?:\bbase64\s+(?:-\w+\s+)*(?:-d|--decode|-D)\b|\bxxd\s+(?:-\w+\s+)*-r\b"
    r"|\bopenssl\s+(?:enc\s+)?(?:-\w+\s+)*-(?:d|base64\s+-d)\b"
    r"|\b(?:printf|echo\s+-e)\s+[\"']?(?:\\x[0-9a-fA-F]{2}){4,})"
)
_DOWNLOAD_PS: Final = (
    r"(?:DownloadString|DownloadData|DownloadFile|Invoke-WebRequest|Invoke-RestMethod"
    r"|\biwr\b|\birm\b|Net\.WebClient|Start-BitsTransfer)"
)
_IEX: Final = r"(?:\biex\b|Invoke-Expression|\[scriptblock\]::Create)"
_PS_DECODE: Final = r"(?:FromBase64String|\.GetString\s*\(|-join\b|\[char\]|-bxor\b)"

# (shape, what it does, pattern). Each pattern is read on one logical line (continuation
# backslashes joined) of the masked install text.
SHAPES: Final[tuple[tuple[str, str, re.Pattern[str]], ...]] = (
    (
        "pipe-to-shell",
        "pipes a download into a shell",
        re.compile(
            _FETCH + r"[^\n|]*?\|(?!\|)\s*" + _SHELL + r"(?!\s+-c\b)"
            r"|" + _FETCH + r"[^\n|]*?\|(?!\|)\s*(?:sudo\s+)?(?:python3?|perl|ruby|node)"
            r"(?=\s*(?:-\s|-$|$|[;&|)\"'`]))",
            _I | re.MULTILINE,
        ),
    ),
    (
        "shell-runs-download",
        "runs a download through a shell or eval",
        re.compile(
            r"(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*|\beval\s+|\bsource\s+|(?<![\w./])\.\s+)"
            r"[\"']?(?:\$\(|<\(|`)\s*" + _FETCH,
            _I,
        ),
    ),
    (
        "decoded-to-shell",
        "decodes data and runs it",
        re.compile(
            _DECODE + r"[^\n|]*?\|(?!\|)\s*(?:" + _SHELL + r"|eval\b)"
            r"|(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*-c\s+|\beval\s+)[\"']?(?:\$\(|`)[^\n]{0,400}?"
            + _DECODE,
            _I,
        ),
    ),
    (
        "reverse-shell",
        "opens a reverse shell",
        re.compile(
            r"/dev/(?:tcp|udp)/[\w.$-]+/\d+|\bn(?:c|cat|etcat)\b[^\n|;]{0,60}?\s-[ec]\s+"
            r"[\"']?(?:/bin/|/usr/bin/)?(?:ba|z)?sh\b",
            _I,
        ),
    ),
    (
        "ps-encoded-command",
        "runs PowerShell from base64 (-EncodedCommand)",
        re.compile(
            r"\b(?:powershell|pwsh)(?:\.exe)?[\"']?\s[^\n]{0,300}?[\s\"'][-/]e(?:c|n[a-z]*)?\s+"
            r"[\"']?[A-Za-z0-9+/]{20,}={0,2}",
            _I,
        ),
    ),
    (
        "ps-iex-download",
        "runs a download with Invoke-Expression",
        re.compile(
            _IEX + r"[^\n]{0,300}?" + _DOWNLOAD_PS + r"|" + _DOWNLOAD_PS + r"[^\n]{0,300}?\|\s*"
            r"(?:\biex\b|Invoke-Expression)",
            _I,
        ),
    ),
    (
        "ps-iex-decoded",
        "runs decoded text with Invoke-Expression",
        re.compile(
            _IEX + r"[^\n]{0,300}?" + _PS_DECODE + r"|" + _PS_DECODE + r"[^\n]{0,300}?\|\s*"
            r"(?:\biex\b|Invoke-Expression)\b",
            _I,
        ),
    ),
    (
        "ps-load-assembly",
        "loads a program from bytes in memory",
        re.compile(r"\[(?:System\.)?Reflection\.Assembly\]::Load\s*\(", _I),
    ),
    (
        "char-codes",
        "builds text from character codes",
        re.compile(
            r"(?:\[char\]\s*(?:0x[0-9a-f]+|\d+)\s*[+,]\s*){8,}"
            r"|\[char\[\]\]\s*\(?\s*(?:(?:0x[0-9a-f]+|\d+)\s*,\s*){8,}",
            _I,
        ),
    ),
    (
        "string-reversal",
        "reverses a string into code",
        re.compile(r"-join\b[^\n]{0,400}?\[\s*-1\s*\.\.|\|\s*rev\s*\|\s*" + _SHELL, _I),
    ),
    (
        "batch-substrings",
        "builds commands from substrings of variables (batch obfuscation)",
        re.compile(r"(?:%[\w$#@]+:~-?\d+(?:,-?\d+)?%){8,}"),
    ),
    (
        "windows-downloader",
        "downloads or decodes with a Windows system tool",
        re.compile(
            r"\bcertutil(?:\.exe)?\b[^\n]{0,200}?[-/](?:urlcache|decode(?:hex)?)\b"
            r"|\bbitsadmin(?:\.exe)?\b[^\n]{0,200}?/transfer\b"
            r"|\bmshta(?:\.exe)?[\"']?\s+[\"']?(?:https?:|vbscript:|javascript:|\\\\)"
            r"|\brundll32(?:\.exe)?[\"']?\s+[^\n]{0,80}?(?:javascript:|mshtml\s*,\s*RunHTML)"
            r"|\bregsvr32(?:\.exe)?\b[^\n]{0,120}?/i:\s*[\"']?(?:https?:|\\\\)",
            _I,
        ),
    ),
)
# Shapes that name where they download from: the host decides how sure the finding is.
DOWNLOADS: Final = frozenset({"pipe-to-shell", "shell-runs-download", "ps-iex-download"})
_URL: Final = re.compile(r"\bhttps?://[^\s\"'`)<>|;]+", _I)
# Hosts nobody installs a tool from: paste sites, tunnels, URL shorteners, anonymous file drops.
RISKY_HOSTS: Final = (
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "ghostbin.com",
    "rentry.co",
    "rentry.org",
    "dpaste.org",
    "dpaste.com",
    "controlc.com",
    "justpaste.it",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "serveo.net",
    "loca.lt",
    "localtunnel.me",
    "pinggy.link",
    "bit.ly",
    "tinyurl.com",
    "is.gd",
    "goo.gl",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "t.ly",
    "rebrand.ly",
    "transfer.sh",
    "temp.sh",
    "file.io",
    "0x0.st",
    "catbox.moe",
    "gofile.io",
    "cdn.discordapp.com",
    "webhook.site",
)
OWN_NOTE: Final = (
    " It downloads from the package's own site ({}), as tool installers do: LOW, weight 1."
)
_GITHUB_HOSTS: Final = ("github.com", "raw.githubusercontent.com", "objects.githubusercontent.com")
RISKY_NOTE: Final = " It downloads from {}: {}."
MAX_SHOWN: Final = 3
SNIPPET_RADIUS: Final = 80
_CONTINUATION: Final = re.compile(r"\\\r?\n")


class InstallScriptLoader(BaseRule):
    """Install code (a shell, PowerShell or batch script the hooks run, any other install file,
    or a hook command line) fetches or decodes code and runs it, or hides it in the ways such
    loaders do (module docstring, `SHAPES`). Added 2026-11-10 (round 4,
    `docs/proposals/precision-round4-G.md`)."""

    id = "npm.install-script-loader"
    version = 1
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Install code downloads or decodes code and runs it"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        found = loader_shapes(change.install_files, _hooks(change.snapshot.manifest))
        if change.install_files_before is not None:
            # What the previous version's install code already did ran before: only a shape
            # (with its host) new to the install code counts.
            seen = {
                (shape, host) for shape, host, *_ in loader_shapes(change.install_files_before, {})
            }
            found = [f for f in found if (f[0], f[1]) not in seen]
        if not found:
            return ()
        own = _own_hosts(change.snapshot.manifest)
        mine = [f for f in found if not (f[0] in DOWNLOADS and f[1] and _is_own(f[1], own))]
        what = "; ".join(sorted({_WHAT[shape] for shape, *_ in (mine or found)}))
        shown = (mine or found)[:MAX_SHOWN]
        risky = sorted({host for _, host, *_ in mine if host and _risky(host)})
        note = ""
        if risky:
            note = RISKY_NOTE.format(", ".join(risky), _risk_kind(risky[0]))
        elif not mine:
            note = OWN_NOTE.format(", ".join(sorted({f[1] for f in found if f[1]})))
        return (
            self.finding(
                f"`npm install` runs code that {what}." + note,
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=text,
                    )
                    for _, _, path, line, text in shown
                ),
                severity=None if mine else Severity.LOW,
                weight=None if mine else 1.0,
            ),
        )


_WHAT: Final = {shape: what for shape, what, _ in SHAPES} | {
    "hidden-padding": "hides code past the edge of the screen"
}


def _hooks(manifest: Mapping[str, Any]) -> dict[str, str]:
    declared = scripts(manifest)
    return {hook: declared[hook] for hook in INSTALL_HOOKS if declared.get(hook, "").strip()}


def loader_shapes(
    install_files: Mapping[str, bytes], hooks: Mapping[str, str]
) -> list[tuple[str, str, str, int, str]]:
    """Every loader shape in the install code and hook command lines, as (shape, host or "",
    path, 1-based line, text around it), comments and messages masked (`loader_text`)."""
    texts = {
        path: loader_text(path, data)
        for path, data in sorted(install_files.items())
        if is_script(path, data)
    }
    for hook, command in hooks.items():
        texts[f"package.json:scripts.{hook}"] = command
    found: list[tuple[str, str, str, int, str]] = []
    for path, raw in texts.items():
        # A continuation backslash joins two lines; blanks keep the offsets.
        text = _CONTINUATION.sub(lambda m: " " * len(m.group(0)), raw)
        for shape, _, pattern in SHAPES:
            for match in pattern.finditer(text):
                host = _host(text, match) if shape in DOWNLOADS else ""
                line = raw.count("\n", 0, match.start()) + 1
                start = max(0, match.start() - SNIPPET_RADIUS)
                snippet = " ".join(text[start : match.end() + SNIPPET_RADIUS].split())
                found.append((shape, host, path, line, snippet))
        if path in install_files and (hidden := hidden_in_script(path, install_files[path])):
            found.append((HIDDEN, "", path, *hidden))
    return _first_per_key(found)


def is_script(path: str, data: bytes) -> bool:
    """A shell, PowerShell or batch file (`install.SCRIPT_SUFFIXES`), or a text file with no
    suffix that starts with `#!` (`"install": "./build"`). JavaScript install files are not
    read: there the same text is mostly help messages (module docstring)."""
    if b"\x00" in data[:8192] or language_for(path) is not None:
        return False
    name = path.rsplit("/", 1)[-1]
    return name.lower().endswith(SCRIPT_SUFFIXES) or ("." not in name and data.startswith(b"#!"))


HIDDEN: Final = "hidden-padding"
# A run of `HIDDEN_RUN`+ spaces or tabs, then code that is not a comment.
_PADDED: Final = re.compile(rf"(?<![ \t])[ \t]{{{HIDDEN_RUN},}}(?=[^\s#])")


def hidden_in_script(path: str, data: bytes) -> tuple[int, str] | None:
    """In a shell, PowerShell or batch file, code after a run of `HIDDEN_RUN`+ spaces or tabs
    (outside quotes, not a comment) that `npm.install-script-code`'s `hidden_code` doesn't
    report: one that starts with a quote (`cd /tmp<150 tabs>"$P" | sh`; in JavaScript a quote
    there is a string's own padding). Before `code_text` read scripts with
    `lang.shell.mask_script_messages`, also one on an `echo` line (`echo ok<150 tabs>; curl
    ... | sh`), which it blanked whole. As (1-based line, the code that follows)."""
    if not is_script(path, data):
        return None
    text = _COMMENT_LINE.sub(_blank, data.decode("utf-8", "replace"))
    for match in _PADDED.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        if any(text[line_start : match.start()].count(q) % 2 for q in "\"'"):
            continue  # inside a quoted string: an aligned message, data
        if hidden_code(path, data) is not None:
            return None  # `npm.install-script-code` reports it
        end = text.find("\n", match.end())
        tail = text[match.end() : len(text) if end == -1 else end]
        return text.count("\n", 0, match.start()) + 1, " ".join(tail[:160].split())
    return None


# A comment line (shell and PowerShell `#`, batch `REM` and `::`).
_COMMENT_LINE: Final = re.compile(r"^[ \t]*(?:#|REM\b|::).*$", re.MULTILINE | re.IGNORECASE)


def loader_text(path: str, data: bytes) -> str:
    """An install file's text with comments and messages blanked, offsets and lines kept:
    JavaScript and TypeScript as `code_text` masks them; a script as
    `lang.shell.mask_script_messages` does (comment lines, and lines that only print, also
    through the script's own print-only functions; `code_text` blanks every `echo` line, which
    hides `echo <base64> | base64 -d | sh`)."""
    if language_for(path) is not None:
        return code_text(path, data)
    return mask_script_messages(data.decode("utf-8", "replace"))


def _blank(match: re.Match[str]) -> str:
    return " " * len(match.group(0))


def _first_per_key(
    found: list[tuple[str, str, str, int, str]],
) -> list[tuple[str, str, str, int, str]]:
    seen: set[tuple[str, str]] = set()
    out = []
    for item in found:
        if (item[0], item[1]) not in seen:
            seen.add((item[0], item[1]))
            out.append(item)
    return out


def _host(text: str, match: re.Match[str]) -> str:
    """The host of the first URL in the match, else on its line (lower case; "" if none); on
    GitHub's hosts, `host/owner`."""
    url = _URL.search(match.group(0))
    if url is None:
        start = text.rfind("\n", 0, match.start()) + 1
        end = text.find("\n", match.end())
        url = _URL.search(text[start : len(text) if end == -1 else end])
    if url is None:
        return ""
    try:
        parts = urlsplit(url.group(0))
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if host in _GITHUB_HOSTS:  # GitHub's hosts serve anyone's files: the owner says whose
        owner = parts.path.strip("/").split("/")[0].lower()
        return f"{host}/{owner}" if owner else host
    return host


def _own_hosts(manifest: Mapping[str, Any]) -> frozenset[str]:
    """The package's own sites: the hosts of its `homepage`, `repository` and `bugs` URLs, and
    for a GitHub repository its owner's raw and release hosts (as `host/owner`)."""
    urls: list[str] = []
    for field in ("homepage", "repository", "bugs"):
        value = manifest.get(field)
        if isinstance(value, Mapping):
            value = value.get("url")
        if isinstance(value, str):
            urls.append(value)
    own: set[str] = set()
    for url in urls:
        url = re.sub(r"^git\+|^github:", "", url.strip())
        if "://" not in url:
            url = "https://github.com/" + url  # the `owner/repo` shorthand
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        if not host:
            continue
        if host in ("github.com", "www.github.com"):
            owner = parts.path.strip("/").split("/")[0].lower()
            if owner:
                own.update(f"{h}/{owner}" for h in _GITHUB_HOSTS)
            continue
        own.add(_registrable(host))
    return frozenset(own)


def _is_own(host: str, own: frozenset[str]) -> bool:
    return host in own if "/" in host else _registrable(host) in own


def _registrable(host: str) -> str:
    """A host's last two labels (`get.example.dev` -> `example.dev`); three under a two-letter
    second-level label (`www.example.co.uk` -> `example.co.uk`)."""
    labels = host.lower().rstrip(".").split(".")
    keep = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else 2
    return ".".join(labels[-keep:])


def _risky(host: str) -> bool:
    host = host.split("/")[0]
    return _is_ip(host) or any(host == h or host.endswith("." + h) for h in RISKY_HOSTS)


def _risk_kind(host: str) -> str:
    return "a raw IP address" if _is_ip(host) else "a paste site, tunnel, shortener or file drop"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


RULES: Final = (InstallScriptLoader(),)
