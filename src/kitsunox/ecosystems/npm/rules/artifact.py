"""npm rules that compare a version's registry metadata with its tarball (Stage 2).

The registry stores the manifest a publisher sends next to the tarball and does not check that
the two agree ("manifest confusion"). Stage 1 only sees the metadata, so a publisher can show it
one thing and ship another:

- `npm install` runs the install scripts from the tarball's `package.json`, so a hook that only
  the tarball has is invisible to Stage 1's `npm.install-hook`.
- `dist.unpackedSize` is declared, not measured; Stage 1 routes updates to Stage 2 by its growth
  (decision 0008), so understating it is a way around that. Overstating gains nothing.

On 1,069 live versions (2026-10-28) the declared size matched the real one exactly in every case,
and no tarball had an install hook the metadata lacked. The differences that did occur are npm's
own normalisation: the registry drops a `node_modules/.bin/` prefix (undone before comparing)
and adds `install: node-gyp rebuild` when the package has a `binding.gyp` (a hook only the
metadata has, which is not the dangerous direction and is not flagged).
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.rules.hosted_page import HtmlRedirector
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts, snippet
from kitsunox.ecosystems.npm.rules.native_load import SilentNativeLoad
from kitsunox.rules.channels import ChannelFollowOnConnect
from kitsunox.rules.disguised import DisguisedFile
from kitsunox.rules.host_ip import HostIpIdentity

SIZE_TOLERANCE_BYTES: Final = 1024
SIZE_TOLERANCE_RATIO: Final = 0.01


def _normalised(command: str) -> str:
    return " ".join(command.replace("node_modules/.bin/", "").split())


class HiddenInstallScript(BaseRule):
    """The tarball's `package.json` has an install hook the registry metadata doesn't show."""

    id = "npm.artifact.hidden-install-script"
    severity = Severity.HIGH
    weight = 5.0
    title = "Install script in the tarball that the registry metadata hides"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        raw = files.get("package.json")
        if raw is None:
            return ()
        try:
            packed = json.loads(raw)
        except ValueError:
            return ()
        if not isinstance(packed, dict):
            return ()
        shown = scripts(snapshot.manifest)
        findings = []
        for hook, command in sorted(scripts(packed).items()):
            if hook not in INSTALL_HOOKS:
                continue
            if _normalised(command) == _normalised(shown.get(hook, "")):
                continue
            findings.append(
                self.finding(
                    f"`npm install` runs the tarball's `{hook}` script, but the registry "
                    "metadata shows "
                    + (f"`{snippet(shown[hook])}`." if hook in shown else "no such script."),
                    Evidence(
                        kind=EvidenceKind.MANIFEST_FIELD,
                        path=f"package.json:scripts.{hook}",
                        before=snippet(shown.get(hook)),
                        after=snippet(command),
                    ),
                )
            )
        return findings


class DeclaredSizeMismatch(BaseRule):
    """The files are bigger than `dist.unpackedSize` says: the routing signal was understated.

    Only understatement is flagged. Overstating gains an attacker nothing (a bigger growth
    routes the version to more analysis, and a version over the download cap is never fetched,
    so it can't be checked here). On DataDog samples, overstated mismatches were all files
    missing from the dataset's zips (e.g. 47 MB declared, 13 KB present), not attacks.
    """

    id = "npm.artifact.size-mismatch"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Declared unpacked size doesn't match the tarball"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        declared = snapshot.artifact.unpacked_size if snapshot.artifact else None
        if declared is None:
            return ()
        real = sum(len(content) for content in files.values())
        gap = real - declared
        if gap <= max(SIZE_TOLERANCE_BYTES, SIZE_TOLERANCE_RATIO * declared):
            return ()
        return (
            self.finding(
                f"The registry metadata declares {declared:,} bytes unpacked; the tarball's files "
                f"total {real:,} (understated by {gap:,}). Size growth decides whether an "
                "update's code is read at all, so an understated size can hide a payload.",
                Evidence(
                    kind=EvidenceKind.MANIFEST_FIELD,
                    path="dist.unpackedSize",
                    before=str(declared),
                    after=str(real),
                ),
            ),
        )


# Words that end a hook harmlessly after the failing `node <file>`: `|| true`, `|| exit 0`.
_NO_OP_TAILS: Final = frozenset({("true",), (":",), ("exit",), ("exit", "0")})
# A path as a hook line writes it: relative, plain characters, no shell expansion; every segment
# starts with a word character, `@` or `+`, so none is `.`, `..` or a `node` option (`-v`).
_PLAIN_PATH: Final = re.compile(r"(?:\./)?[\w@+][\w.@+-]*(?:/[\w@+][\w.@+-]*)*")


def hook_target(command: str) -> str | None:
    """The package path a hook runs when the whole line is `node <path>`, optionally followed
    by `|| true` or `|| exit 0`; None for anything else (another program, a `node` option,
    inline code, a chain, a redirect, a variable, a path with `..` or outside the package).
    A line with a backslash is none: Windows runs `node lib\\index.js` as the package's
    `lib/index.js`, while a POSIX shell reads `libindex.js` (`company-ts@1.0.3`, `vm-day1`
    malicious, runs its payload that way)."""
    if "\\" in command:
        return None
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None
    if tokens[2:3] == ["||"]:
        if tuple(tokens[3:]) not in _NO_OP_TAILS:
            return None
        tokens = tokens[:2]
    if len(tokens) != 2 or tokens[0] not in ("node", "node.exe"):
        return None
    path = tokens[1]
    if not _PLAIN_PATH.fullmatch(path):
        return None
    path = path.removeprefix("./")
    return None if path.startswith("node_modules/") else path


def shipped(path: str, files: Mapping[str, bytes]) -> bool:
    """Whether `node <path>` could find a file of the package: the path itself, the path with
    any suffix Node tries (`.js`, `.json`, `.node`, `.cjs`, `.mjs`, ...) or a directory of that
    name (its `index.js` or `package.json`'s `main`). Compared without case: macOS and Windows
    file systems ignore it."""
    lower = path.lower()
    return any(
        p == lower or p.startswith((lower + ".", lower + "/")) for p in (f.lower() for f in files)
    )


class InstallTargetMissing(BaseRule):
    """Every install hook is `node <file>` and no file of the tarball is that file (with any
    suffix, as a directory, or in another case): `npm install` runs the hook, Node fails to
    find the file, and nothing of the package runs. A packaging slip, not a signal: the
    `files` list of `package.json` leaves the script out (`@copio/sdk@0.1.0`,
    `site2paper@0.1.0`, `@whcecw/maotu@0.0.29`), or a monorepo's hook points at a workspace
    script. INFO, weight 0: an explanation for Stage 4 (`correlate.EXPLAINED`), which makes
    `npm.install-hook` LOW, weight 1.

    It needs the whole package to say a file is missing, so it holds only when the tarball's
    hooks are the ones the registry shows, it has no `binding.gyp` (npm then adds
    `node-gyp rebuild` itself), nothing in it was skipped (links, unsafe paths, unreadable
    entries), it has no tar anomaly or duplicate entry, and its files add up to the size the
    registry declares (a sample set's archive with files missing, like DataDog's, does not).

    A hook that runs nothing can still be a broken attack, and the next release fixes it; such a
    package keeps its `npm.install-hook` finding (`broken_attack`): one with no JavaScript at
    all (a probe placeholder, `@testcarrot/supply9@1.0.2`), one whose declared `main` is not
    shipped either (an emptied package, `modern-react@17.2.6`), and one that ships the
    install script the hook misnames (`instal.js` beside `node install.js`:
    `parashaxmgflhg@0.33.4`; `postinstall.js` beside `node install.js`:
    `@vampirchik147/libxmljs2@0.19.7`; all `vm-day1` malicious).

    Added 2026-11-11 (`docs/proposals/precision-round6-Q.md`, Q1)."""

    id = "npm.artifact.install-target-missing"
    severity = Severity.INFO
    weight = 0.0
    title = "Install hooks run a file the package doesn't ship"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        raw = files.get("package.json")
        if raw is None or "binding.gyp" in files or not _whole(snapshot, files):
            return ()
        try:
            packed = json.loads(raw)
        except ValueError:
            return ()
        if not isinstance(packed, dict):
            return ()
        hooks = {h: c for h, c in scripts(packed).items() if h in INSTALL_HOOKS}
        shown = {h: c for h, c in scripts(snapshot.manifest).items() if h in INSTALL_HOOKS}
        if not hooks or {h: _normalised(c) for h, c in hooks.items()} != {
            h: _normalised(c) for h, c in shown.items()
        }:
            return ()
        targets = {hook: hook_target(command) for hook, command in sorted(hooks.items())}
        if any(t is None or shipped(t, files) for t in targets.values()):
            return ()
        named = [t for t in targets.values() if t is not None]
        if broken_attack(packed, named, files):
            return ()
        return (
            self.finding(
                "Every install hook runs a file the package doesn't ship ("
                + ", ".join(f"`{hook}`: `{target}`" for hook, target in targets.items())
                + "): Node finds no such file (nor one with a suffix, a directory of that name "
                "or the name in another case), so nothing of the package runs at install.",
                *(
                    Evidence(
                        kind=EvidenceKind.MANIFEST_FIELD,
                        path=f"package.json:scripts.{hook}",
                        after=snippet(hooks[hook]),
                    )
                    for hook in targets
                ),
            ),
        )


# A JavaScript file Node could run: what a placeholder ships none of.
_JAVASCRIPT: Final = (".js", ".cjs", ".mjs")


def broken_attack(
    manifest: Mapping[str, object], targets: Sequence[str], files: Mapping[str, bytes]
) -> bool:
    """Whether a package whose hooks run missing files looks like a broken attack rather than a
    packaging slip: it ships no JavaScript, its declared `main` is missing too, or it ships a
    JavaScript file named like an install script (`instal` in the name, any case) at its root
    or beside a missing target, which the hook was meant to run."""
    if not any(p.lower().endswith(_JAVASCRIPT) for p in files):
        return True
    main = manifest.get("main")
    if (
        isinstance(main, str)
        and main.strip()
        and not shipped(main.strip().removeprefix("./"), files)
    ):
        return True
    dirs = {""} | {t.rsplit("/", 1)[0] if "/" in t else "" for t in targets}
    for path in files:
        folder, _, name = path.rpartition("/")
        if folder in dirs and "instal" in name.lower() and name.lower().endswith(_JAVASCRIPT):
            return True
    return False


# Whitespace and comments between the tokens of a stub (`_STUB`).
_GAP: Final = r"(?:\s|//[^\n]*|/\*(?:[^*]|\*(?!/))*\*/)*"
# A string literal with no code in it: quoted, or a template literal with no `${...}`.
_LITERAL: Final = (
    r"(?:\"(?:[^\"\\\n]|\\[\s\S])*\"|'(?:[^'\\\n]|\\[\s\S])*'"
    r"|`(?:[^`\\$]|\\[\s\S]|\$(?!\{))*`)"
)
_CONSTANT: Final = rf"{_LITERAL}(?:{_GAP}\+{_GAP}{_LITERAL})*"
# A whole file that only throws a constant message: an optional `#!` line and `"use strict"`,
# then `throw new Error("...")`, `throw Error("...")` or `throw "..."`, string literals joined
# with `+` allowed. No identifier but `Error`, no call but its constructor, no other statement.
_STUB: Final = re.compile(
    rf"(?:#![^\n]*\n)?{_GAP}(?:(?:\"use strict\"|'use strict'){_GAP};?{_GAP})?"
    rf"throw{_GAP}(?:(?:new{_GAP})?Error{_GAP}\({_GAP}{_CONSTANT}{_GAP}\)|{_CONSTANT})"
    rf"{_GAP};?{_GAP}"
)
# Files that never run: documentation and licence texts.
_TEXT_FILE: Final = re.compile(
    r"(?:^|/)(?:readme|license|licence|changelog|notice|authors)[^/]*$|\.(?:md|txt)$",
    re.IGNORECASE,
)
_STUB_FILE: Final = (".js", ".cjs", ".mjs")


def stub_file(path: str, files: Mapping[str, bytes]) -> str | None:
    """The package file `node <path>` runs when it is a JavaScript file that only throws a
    constant message (`_STUB`), else None. Node tries the path, then `<path>.js`."""
    for candidate in (path, path + ".js"):
        content = files.get(candidate)
        if content is None:
            continue
        if not candidate.lower().endswith(_STUB_FILE):
            return None
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return candidate if _STUB.fullmatch(text) else None
    return None


class InstallStub(BaseRule):
    """A dependency-confusion placeholder: every install hook in the tarball is `node <file>`,
    each file only throws a constant message (`throw new Error("...")`, string literals joined
    with `+`), and the package ships nothing else but its `package.json` and text
    (README, licence, `.md`, `.txt`). `npm install` stops at the first hook with that error, and
    there is no other code to load. Companies publish such stubs under their internal package
    names at a high version so that a misconfigured install fails loudly instead of fetching
    an attacker's package: JetBrains' `kotlinconf@999.9.9`, `jetbrains-icons@999.9.9` and
    eight more on 2026-11-12, each `preinstall: node fail.js` with "This is stub package to
    mitigate risks of Dependency Confusion attacks", a hook the registry's metadata doesn't
    show (`npm.artifact.hidden-install-script`) and a `999.9.9` version
    (`npm.version.suspicious`).

    INFO, weight 0: an explanation for Stage 4 (`correlate.EXPLAINED`), which makes
    `npm.artifact.hidden-install-script`, `npm.install-hook` and `npm.version.suspicious` LOW.
    It needs the whole package (`_whole`: nothing skipped, no tar anomaly, the files add up to
    the declared size), each hook exactly `node <file>` (no `|| true`, no option, no chain),
    and the file only the one `throw` statement: a call to anything but `Error`, a `${...}`
    in a template, a `require` or any other statement is not a stub. A dependency-confusion
    probe needs to run code that reports back (`vm-day1`'s 131 such samples all do), which this
    shape cannot.

    Added 2026-11-12 (`docs/proposals/precision-round9-S.md`, S1)."""

    id = "npm.artifact.install-stub"
    severity = Severity.INFO
    weight = 0.0
    title = "Install hooks only throw an error: a dependency-confusion placeholder"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        raw = files.get("package.json")
        if raw is None or not _whole(snapshot, files):
            return ()
        try:
            packed = json.loads(raw)
        except ValueError:
            return ()
        if not isinstance(packed, dict):
            return ()
        hooks = {h: c for h, c in sorted(scripts(packed).items()) if h in INSTALL_HOOKS}
        if not hooks:
            return ()
        stubs: dict[str, str] = {}
        for hook, command in hooks.items():
            target = hook_target(command)
            if target is None or "||" in command:
                return ()
            stub = stub_file(target, files)
            if stub is None:
                return ()
            stubs[hook] = stub
        if any(
            path != "package.json" and path not in stubs.values() and not _TEXT_FILE.search(path)
            for path in files
        ):
            return ()
        return (
            self.finding(
                "Every install hook runs a file that only throws an error ("
                + ", ".join(f"`{hook}`: `{stub}`" for hook, stub in stubs.items())
                + ") and the package ships no other code: `npm install` stops there, so it "
                "installs nothing that runs. A dependency-confusion placeholder.",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=stub,
                        line_start=1,
                        snippet=snippet(files[stub].decode("utf-8").strip()),
                    )
                    for stub in sorted(set(stubs.values()))
                ),
            ),
        )


def _whole(snapshot: VersionSnapshot, files: Mapping[str, bytes]) -> bool:
    """The tree is the whole package: nothing skipped, no tar anomaly or duplicate, and the
    files add up to the declared unpacked size (within `DeclaredSizeMismatch`'s tolerance)."""
    if any(getattr(files, attr, ()) for attr in ("skipped", "anomalies", "duplicates")):
        return False
    declared = snapshot.artifact.unpacked_size if snapshot.artifact else None
    if declared is None:
        return False
    real = sum(len(content) for content in files.values())
    return abs(real - declared) <= max(SIZE_TOLERANCE_BYTES, SIZE_TOLERANCE_RATIO * declared)


# `static.disguised-file`, `static.channel-follow-on-connect` and `static.host-ip-identity`
# (ecosystem-agnostic, `rules/disguised.py`, `rules/channels.py`, `rules/host_ip.py`) run here
# because they read every file of every version, not only the contents an update adds; so do
# the npm rules in their own modules (`static.html-redirector`,
# `hosted_page.py`; `static.silent-native-load`, `native_load.py`).
RULES: Final = (
    HiddenInstallScript(),
    DeclaredSizeMismatch(),
    InstallTargetMissing(),
    InstallStub(),
    DisguisedFile(),
    ChannelFollowOnConnect(),
    HostIpIdentity(),
    HtmlRedirector(),
    SilentNativeLoad(),
)
