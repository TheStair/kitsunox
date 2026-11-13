"""Stage 2 artifact rule: a file whose name claims a binary format but whose bytes are a script
or a program.

`pdf-html5-page-flip` 2.0.1 and 2.0.2 (live, 2026-11-10, malicious) shipped
`dist/lib/fonts/fa-solid-400.woff2`: not a font but 1.8 KB of JavaScript that reads cloud, npm,
git and SSH credentials, posts them to a bare IP and installs a crontab `curl | bash`. Nothing
loaded it yet: a dormant payload for a later loader. Stage 2's file rules only saw it as text
in an odd place (one `static.hardcoded-ip`, LOW credential paths), and the follow-on release,
which shipped the same file unchanged, had no Stage 2 finding at all: file rules see only the
contents an update adds.

So this rule reads every file of every version (an `ArtifactRule`, not a file rule): it fires
on a follow-on release that still ships the file. A file is checked when its extension claims
a binary format (fonts, images, audio, video, WebAssembly, native modules, archives, PDF,
generic `.bin`/`.dat`). Its first bytes are compared with that format's magic numbers; a file
that matches some binary format (a WebP named `.png`, a WOFF named `.ttf`) is a mislabel, not
a disguise, and is left alone. What is left is classified cheaply:

- a native executable (ELF, PE, Mach-O) under a name that isn't a native module: HIGH;
- script text (JavaScript, shell, PowerShell, Python, batch), directly or base64-encoded:
  HIGH when it uses process execution, the network, credentials or dynamic code; MEDIUM when
  another code file of the package names it (a loader); LOW otherwise. Under a program's name
  (`.exe`, `.dll`, `.so`, `.dylib`) a script is the launcher or placeholder that platform-binary
  packages ship (every benign hit on 230,290 live tarballs): INFO, unless it reads credentials
  or builds code at run time;
- an archive under a font, image or media name: LOW;
- markup (an SVG named `.png`, an HTML error page saved as a font), a Git LFS pointer, JSON,
  base64 of a binary format, empty files and other plain text: nothing.

The numbers behind the shapes are in `docs/stages/static.md` and
`docs/proposals/precision-round6-T.md`.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule
from kitsunox.rules.partial import omitted_files
from kitsunox.rules.static import (
    DynamicCode,
    EnvHarvest,
    Network,
    NpmPublish,
    ProcessExec,
    SensitivePath,
)

# Magic numbers: (offset, bytes). A format matches when any of its signatures does.
_SIG = tuple[tuple[int, bytes], ...]
_MP4: Final[_SIG] = ((4, b"ftyp"), (4, b"moov"), (4, b"mdat"), (4, b"wide"), (4, b"free"))
FORMATS: Final[Mapping[str, _SIG]] = {
    "woff": ((0, b"wOFF"),),
    "woff2": ((0, b"wOF2"),),
    "sfnt": ((0, b"\x00\x01\x00\x00"), (0, b"true"), (0, b"OTTO"), (0, b"ttcf"), (0, b"typ1")),
    "eot": ((34, b"LP"),),
    "png": ((0, b"\x89PNG"),),
    "jpeg": ((0, b"\xff\xd8\xff"),),
    "gif": ((0, b"GIF8"),),
    "ico": ((0, b"\x00\x00\x01\x00"), (0, b"\x00\x00\x02\x00")),
    "bmp": ((0, b"BM"),),
    "tiff": ((0, b"II*\x00"), (0, b"MM\x00*")),
    "icns": ((0, b"icns"),),
    "psd": ((0, b"8BPS"),),
    "riff": ((0, b"RIFF"),),  # WebP, WAV, AVI
    "iso-bmff": _MP4,  # MP4, MOV, M4A, AVIF, HEIC, 3GP
    "ogg": ((0, b"OggS"),),
    "flac": ((0, b"fLaC"),),
    "mp3": ((0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2"), (0, b"\xff\xfa")),
    "aac": ((0, b"\xff\xf1"), (0, b"\xff\xf9")),
    "matroska": ((0, b"\x1a\x45\xdf\xa3"),),  # WebM, MKV
    "midi": ((0, b"MThd"),),
    "wasm": ((0, b"\x00asm"),),
    "pdf": ((0, b"%PDF"),),
    "zip": ((0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"PK\x07\x08")),
    "gzip": ((0, b"\x1f\x8b"),),
    "bzip2": ((0, b"BZh"),),
    "xz": ((0, b"\xfd7zXZ\x00"),),
    "7z": ((0, b"7z\xbc\xaf\x27\x1c"),),
    "zstd": ((0, b"\x28\xb5\x2f\xfd"),),
    "rar": ((0, b"Rar!\x1a\x07"),),
    "tar": ((257, b"ustar"),),
    "elf": ((0, b"\x7fELF"),),
    "pe": ((0, b"MZ"),),
    "macho": (
        (0, b"\xfe\xed\xfa\xce"),
        (0, b"\xfe\xed\xfa\xcf"),
        (0, b"\xce\xfa\xed\xfe"),
        (0, b"\xcf\xfa\xed\xfe"),
        (0, b"\xca\xfe\xba\xbe"),
    ),
}
EXECUTABLES: Final = frozenset({"elf", "pe", "macho"})
# Magic numbers short enough for text to start with (`BM...`, `MZ...`): trusted only when the
# file doesn't read as text, which real bitmaps, programs and MP3 frames never do.
WEAK_MAGIC: Final = frozenset({"bmp", "pe", "mp3", "aac", "eot", "tar"})
ARCHIVES: Final = frozenset({"zip", "gzip", "bzip2", "xz", "7z", "zstd", "rar", "tar"})
# What each claimed extension's family is called in an explanation, and the formats where an
# archive or executable is expected there (and so is no disguise).
_FONT = "font"
_IMAGE = "image"
_MEDIA = "audio or video file"
CLAIMS: Final[Mapping[str, str]] = {
    **dict.fromkeys(("woff", "woff2", "ttf", "otf", "eot", "ttc"), _FONT),
    **dict.fromkeys(
        ("png", "jpg", "jpeg", "gif", "ico", "cur", "bmp", "webp", "tif", "tiff", "icns"), _IMAGE
    ),
    **dict.fromkeys(("avif", "heic", "psd"), _IMAGE),
    **dict.fromkeys(
        ("mp3", "wav", "ogg", "oga", "opus", "flac", "m4a", "aac", "mid", "midi"), _MEDIA
    ),
    **dict.fromkeys(("mp4", "m4v", "mov", "webm", "mkv", "avi", "ogv", "3gp"), _MEDIA),
    "wasm": "WebAssembly module",
    "pdf": "PDF document",
    **dict.fromkeys(("node", "so", "dylib", "dll", "exe"), "native module or program"),
    **dict.fromkeys(
        ("zip", "gz", "tgz", "bz2", "xz", "7z", "zst", "rar", "tar", "jar", "whl", "nupkg"),
        "archive",
    ),
    **dict.fromkeys(("bin", "dat"), "binary data file"),
}
NATIVE: Final = frozenset({"node", "so", "dylib", "dll", "exe"})
# Programs and libraries an npm package ships for one platform. A script under such a name is
# the launcher or placeholder shape of packages that put a platform binary there at install
# (`bin/dscode.exe`: `#!/bin/sh echo "Error: dscode native binary not installed."`, replaced by
# `postinstall`; `@vercel/vc-native`'s `bin/vercel.exe`, a Node fallback launcher): 131 of the
# 133 tarballs this rule fired on in 230,290 live ones (2026-11-10), all benign (the other two
# were `pdf-html5-page-flip`'s font). Such a script
# is INFO unless it reads credentials or builds code at run time, which no launcher there did.
# A `.node` file is loaded with `dlopen`, never as a script, so it has no such shape.
PROGRAMS: Final = frozenset({"exe", "dll", "so", "dylib"})
LAUNCHER_ESCALATES: Final = frozenset({"credentials", "dynamic code"})
ARCHIVE_NAMES: Final = frozenset(
    {"zip", "gz", "tgz", "bz2", "xz", "7z", "zst", "rar", "tar", "jar", "whl", "nupkg"}
)
# Where an archive or an executable is expected: a native module may be any executable format,
# an archive any archive format, and generic binary data anything.
_EXPECTS_EXECUTABLE: Final = NATIVE | frozenset({"bin", "dat"})
_EXPECTS_ARCHIVE: Final = ARCHIVE_NAMES | frozenset({"bin", "dat"})

HEAD_BYTES: Final = 8192
MAX_DECODE_BYTES: Final = 4 * 1024 * 1024
# Text: no NUL in the head, and at most this share of other control bytes (tab, CR, LF, FF
# aside).
MAX_CONTROL_RATIO: Final = 0.02

_LFS: Final = re.compile(rb"\s*version https://git-lfs\.github\.com/spec/")
_BASE64: Final = re.compile(rb"[A-Za-z0-9+/=_\-\s]+")
_DATA_URI: Final = re.compile(rb"\s*data:[\w.+/-]+(?:;[\w=.+-]+)*;base64,")

# Script markers: a language counts when at least two different markers of it occur (or a
# shebang names it).
_SHEBANG: Final = re.compile(
    r"\A\s*#!\s*(?:\S*/)?(?:env\s+(?:-\S+\s+)*)?"
    r"(node|nodejs|bash|sh|zsh|dash|ksh|python[\d.]*|pwsh|bun|deno)\b"
)
SCRIPT_MARKERS: Final[Mapping[str, tuple[re.Pattern[str], ...]]] = {
    "JavaScript": (
        re.compile(r"\brequire\s*\(\s*[\"'`]"),
        re.compile(r"\bmodule\.exports\b|\bexports\.\w+\s*="),
        re.compile(r"\b(?:const|let|var)\s+[\w$]+\s*="),
        re.compile(r"\bfunction\b\s*[\w$]*\s*\("),
        re.compile(r"=>"),
        re.compile(r"\bimport\s+[\w${},*\s]+\s+from\s+[\"'`]|\bimport\s*\(\s*[\"'`]"),
        re.compile(r"\bprocess\.(?:env|argv|platform|exit|cwd)\b"),
        re.compile(r"\}\s*\)\s*\(\s*\)|\bawait\s+[\w$]"),
    ),
    "shell": (
        re.compile(r"\b(?:curl|wget)\s+-"),
        re.compile(r"\|\s*(?:ba|z|da)?sh\b"),
        re.compile(r"\bchmod\s+[+0-7]"),
        re.compile(r"^\s*export\s+\w+=", re.MULTILINE),
        re.compile(r"^\s*(?:if\s+\[|fi$|then$|done$)", re.MULTILINE),
        re.compile(r"\$\{?HOME\}?/|\bnohup\b|/dev/null\s+2>&1"),
    ),
    "PowerShell": (
        re.compile(r"\bInvoke-(?:WebRequest|Expression|RestMethod)\b", re.IGNORECASE),
        re.compile(r"\bIEX\b|\bStart-Process\b|\bSet-ItemProperty\b"),
        re.compile(r"\$env:\w+", re.IGNORECASE),
        re.compile(r"New-Object\s+(?:System\.)?Net\.WebClient", re.IGNORECASE),
        re.compile(r"-(?:EncodedCommand|ExecutionPolicy|WindowStyle)\b", re.IGNORECASE),
    ),
    "Python": (
        re.compile(r"^\s*import\s+\w+", re.MULTILINE),
        re.compile(r"^\s*from\s+[\w.]+\s+import\s", re.MULTILINE),
        re.compile(r"^\s*def\s+\w+\s*\(.*\)\s*:", re.MULTILINE),
        re.compile(r"\bsubprocess\.|\bos\.(?:system|popen|environ)\b"),
        re.compile(r"__name__\s*==\s*[\"']__main__[\"']"),
    ),
    "batch": (
        re.compile(r"^\s*@echo\s+off\b", re.MULTILINE | re.IGNORECASE),
        re.compile(r"^\s*set\s+\w+=", re.MULTILINE | re.IGNORECASE),
        re.compile(r"%~dp0|%APPDATA%|%TEMP%", re.IGNORECASE),
        re.compile(r"^\s*(?:start|call)\s+", re.MULTILINE | re.IGNORECASE),
    ),
}
SCRIPT_NAMES: Final = {
    "JavaScript": "JavaScript code",
    "shell": "a shell script",
    "PowerShell": "a PowerShell script",
    "Python": "a Python script",
    "batch": "a Windows batch file",
}
_SHEBANG_LANGUAGE: Final = {
    "node": "JavaScript",
    "nodejs": "JavaScript",
    "bun": "JavaScript",
    "deno": "JavaScript",
    "pwsh": "PowerShell",
}

# What a script can do, for its severity. The JavaScript patterns are Stage 2's own file rules'.
CAPABILITIES: Final[Mapping[str, tuple[re.Pattern[str], ...]]] = {
    "process execution": (
        ProcessExec.pattern,
        re.compile(r"\b(?:execSync|execFileSync|spawnSync|execFile|spawn)\s*\("),
        re.compile(r"\|\s*(?:ba|z|da)?sh\b|\bcrontab\b|\bnohup\b"),
        re.compile(r"\bsubprocess\.|\bos\.(?:system|popen)\s*\("),
        re.compile(r"\bStart-Process\b|\bInvoke-Expression\b|\bIEX\b", re.IGNORECASE),
        re.compile(r"\bpowershell(?:\.exe)?\s+-|\bcmd(?:\.exe)?\s+/c\b", re.IGNORECASE),
    ),
    "network": (
        Network.pattern,
        re.compile(r"\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\(|\baxios\b"),
        re.compile(r"\b(?:https?|wss?|tcp|ftp)://[\w.-]"),
        re.compile(r"\b(?:curl|wget)\s"),
        re.compile(
            r"\bInvoke-(?:WebRequest|RestMethod)\b|Net\.WebClient|\burllib\b|\brequests\.(?:get|post)\b"
            r"|\bsocket\.(?:socket|create_connection)\b",
            re.IGNORECASE,
        ),
    ),
    "credentials": (
        SensitivePath.pattern,
        EnvHarvest.pattern,
        NpmPublish.pattern,
        re.compile(r"\.ssh/|\bid_(?:rsa|ed25519|ecdsa)\b|\.netrc\b|\.pypirc\b"),
        re.compile(r"process\.env\.[\w$]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)\b"),
        re.compile(r"\bos\.environ\b|\$env:\w*(?:TOKEN|SECRET|KEY)\b", re.IGNORECASE),
    ),
    "dynamic code": (DynamicCode.pattern,),
}

# Where a reference to the file means something loads it: code files and manifests, not
# stylesheets or markup (a font named in CSS is a font being used).
_CODE_FILE: Final = re.compile(
    r"(?:\.(?:[cm]?[jt]sx?|sh|bash|zsh|ps1|psm1|py|bat|cmd|vbs)|(?:^|/)package\.json)$",
    re.IGNORECASE,
)
MAX_FINDINGS: Final = 5
SNIPPET_CHARS: Final = 160


@dataclass(frozen=True)
class Disguise:
    """What a disguised file holds: `kind` is `executable`, `script` or `archive`; `what` names
    it (`JavaScript`, `ELF executable`); `capabilities` what a script uses (name, first match);
    `encoded` whether the script was base64 text; `snippet` the evidence."""

    kind: str
    what: str
    snippet: str
    capabilities: tuple[tuple[str, str], ...] = ()
    encoded: bool = False


def extension(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1]
    if "." not in name.lstrip("."):
        return None
    return name.rsplit(".", 1)[-1].lower()


def detect_format(content: bytes, *, binary: bool = False) -> str | None:
    """The binary format `content` starts like, or None. `binary`: the content is known not
    to read as text (a partial read's head of a binary file), so weak magic is trusted."""
    for name, signatures in FORMATS.items():
        for offset, magic in signatures:
            if content[offset : offset + len(magic)] == magic:
                if name in WEAK_MAGIC and not binary and _text(content) is not None:
                    continue
                return name
    if b"%PDF" in content[:1024]:
        return "pdf"
    return None


def _text(content: bytes) -> str | None:
    """`content` as text, or None when it reads as binary."""
    head = content[:HEAD_BYTES]
    if b"\x00" in head:
        return None
    controls = sum(1 for b in head if b < 32 and b not in (9, 10, 12, 13))
    if head and controls / len(head) > MAX_CONTROL_RATIO:
        return None
    text = content.decode("utf-8", errors="replace")
    if text.count("�") > max(8, len(text) // 100):
        return None
    return text


def script_language(text: str) -> str | None:
    """The script language `text` is written in, by its markers, or None."""
    if shebang := _SHEBANG.match(text):
        word = shebang.group(1)
        return _SHEBANG_LANGUAGE.get(word, "Python" if word.startswith("python") else "shell")
    best: tuple[int, str] | None = None
    for language, markers in SCRIPT_MARKERS.items():
        hits = sum(1 for marker in markers if marker.search(text))
        if hits >= 2 and (best is None or hits > best[0]):
            best = (hits, language)
    return best[1] if best else None


def capabilities(text: str) -> tuple[tuple[str, str], ...]:
    """What `text` uses, each with the first match as evidence."""
    out = []
    for name, patterns in CAPABILITIES.items():
        found = [m for p in patterns if (m := p.search(text))]
        if found:
            first = min(found, key=lambda m: m.start())
            out.append((name, first.group(0)[:80]))
    return tuple(out)


def _snippet(text: str) -> str:
    flat = " ".join(text[: SNIPPET_CHARS * 4].split())
    return flat[:SNIPPET_CHARS] + ("..." if len(flat) > SNIPPET_CHARS else "")


def _decoded(content: bytes) -> bytes | None:
    """`content` decoded, when it is base64 text (optionally a `data:` URI) and long enough to
    hold something."""
    if len(content) > MAX_DECODE_BYTES:
        return None
    body = content
    if uri := _DATA_URI.match(body):
        body = body[uri.end() :]
    if len(body.strip()) < 16 or not _BASE64.fullmatch(body):
        return None
    compact = re.sub(rb"\s+", b"", body).replace(b"-", b"+").replace(b"_", b"/")
    try:
        return base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
    except binascii.Error, ValueError:
        return None


def _script(text: str, *, encoded: bool = False) -> Disguise | None:
    language = script_language(text)
    if language is None:
        return None
    return Disguise(
        kind="script",
        what=language,
        snippet=_snippet(text),
        capabilities=capabilities(text),
        encoded=encoded,
    )


def disguise(ext: str, content: bytes) -> Disguise | None:
    """What `content` hides under the extension `ext`, or None when it is no disguise: it is
    the claimed format, another binary format, or text that isn't a script."""
    found = detect_format(content)
    if found in EXECUTABLES or found in ARCHIVES:
        return _binary_disguise(ext, found, content)
    if found is not None:
        return None  # another binary format: a mislabel, not a disguise
    text = _text(content)
    if text is None:
        return None  # binary in a format not known here
    stripped = text.lstrip("﻿ \t\r\n")
    if not stripped or stripped.startswith("<") or _LFS.match(content):
        return None  # empty, markup (SVG, HTML), a Git LFS pointer
    if (decoded := _decoded(content)) is not None:
        inner = _text(decoded)
        if detect_format(decoded) is not None or inner is None:
            return None  # base64 of a binary file
        return _script(inner, encoded=True)
    if stripped[0] in "{[":
        try:
            json.loads(stripped)
        except ValueError:
            pass
        else:
            return None
    return _script(text)


def _binary_disguise(ext: str, found: str, content: bytes) -> Disguise | None:
    """An executable or archive (`found`) under the extension `ext`: a disguise unless the
    extension expects one."""
    if found in EXECUTABLES:
        if ext in _EXPECTS_EXECUTABLE:
            return None
        what = {"elf": "ELF", "pe": "Windows PE", "macho": "Mach-O"}[found]
        return Disguise(kind="executable", what=f"{what} executable", snippet=content[:16].hex())
    if ext in _EXPECTS_ARCHIVE or CLAIMS[ext] not in (_FONT, _IMAGE, _MEDIA):
        return None
    return Disguise(kind="archive", what=f"{found} archive", snippet=content[:16].hex())


def head_disguise(ext: str, head: bytes) -> Disguise | None:
    """`disguise` for a binary file a partial read only kept the head of (decision 0021): an
    executable or an archive under another format's name. A binary file is never a script, so
    nothing else can be one."""
    found = detect_format(head, binary=True)
    if found in EXECUTABLES or found in ARCHIVES:
        return _binary_disguise(ext, found, head)
    return None


def _referenced_by(path: str, files: Mapping[str, bytes]) -> str | None:
    """The first code file of the package that names `path`'s file name."""
    name = path.rsplit("/", 1)[-1].encode()
    for other in sorted(files):
        if other != path and _CODE_FILE.search(other) and name in files[other]:
            return other
    return None


class DisguisedFile(BaseRule):
    """A file named as a binary format whose bytes are a script or a program."""

    id = "static.disguised-file"
    severity = Severity.HIGH
    weight = 5.0
    title = "File disguised as a binary format"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        found: list[Finding] = []
        for path in sorted(files):
            ext = extension(path)
            if ext is None or ext not in CLAIMS:
                continue
            what = disguise(ext, files[path])
            if what is not None:
                found.append(self._finding(path, ext, what, files))
        for omitted in omitted_files(files):
            ext = extension(omitted.path)
            if ext is None or ext not in CLAIMS or omitted.reason != "binary":
                continue
            what = head_disguise(ext, omitted.head)
            if what is not None:
                found.append(self._finding(omitted.path, ext, what, files))
        found.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
        return found[:MAX_FINDINGS]

    def _finding(self, path: str, ext: str, what: Disguise, files: Mapping[str, bytes]) -> Finding:
        claim = f"`{path}` is named as a {CLAIMS[ext]} (`.{ext}`), but it is"
        evidence = [
            Evidence(kind=EvidenceKind.FILE_SPAN, path=path, line_start=1, snippet=what.snippet)
        ]
        if what.kind != "script":
            severity = Severity.HIGH if what.kind == "executable" else Severity.LOW
            return self.finding(
                f"{claim} a {what.what}.", *evidence, severity=severity, weight=WEIGHTS[severity]
            )
        holds = f"{SCRIPT_NAMES[what.what]}{' (base64-encoded)' if what.encoded else ''}"
        uses = ", ".join(f"{name} (`{hit}`)" for name, hit in what.capabilities)
        uses = f" that uses {uses}" if uses else ""
        loader = _referenced_by(path, files)
        if loader is not None:
            evidence.append(Evidence(kind=EvidenceKind.FILE_SPAN, path=loader))
            loaded = f" `{loader}` names it."
        else:
            loaded = UNLOADED_NOTE
        severity = script_severity(ext, what, loaded=loader is not None)
        if severity is Severity.INFO:
            loaded += LAUNCHER_NOTE
        return self.finding(
            f"{claim} {holds}{uses}.{loaded}",
            *evidence,
            severity=severity,
            weight=WEIGHTS[severity],
        )


SEVERITY_ORDER: Final = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
WEIGHTS: Final = {Severity.HIGH: 5.0, Severity.MEDIUM: 3.0, Severity.LOW: 1.0, Severity.INFO: 0.0}
UNLOADED_NOTE: Final = (
    " No code file of the package names it: it may be a payload for a later loader."
)
LAUNCHER_NOTE: Final = (
    " A script in place of a platform program is the launcher or placeholder shape of packages"
    " that put the real binary there at install; it reads no credentials and builds no code."
)


def script_severity(ext: str, what: Disguise, *, loaded: bool) -> Severity:
    """HIGH for a script that uses process execution, the network, credentials or dynamic code;
    MEDIUM for one a code file names (a loader); LOW otherwise. Under a program's name
    (`PROGRAMS`), INFO unless it reads credentials or builds code (`LAUNCHER_ESCALATES`)."""
    names = {name for name, _ in what.capabilities}
    if ext in PROGRAMS:
        return Severity.HIGH if names & LAUNCHER_ESCALATES else Severity.INFO
    if names:
        return Severity.HIGH
    return Severity.MEDIUM if loaded else Severity.LOW
