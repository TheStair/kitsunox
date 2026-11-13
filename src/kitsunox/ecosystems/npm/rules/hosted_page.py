"""Stage 2 npm artifact rule: a package that is only a web page which decrypts where to send
its visitor and sends them there (the registry used as web hosting).

npm's tarballs are served again by public CDNs (jsDelivr, unpkg) as web pages, so a package can
be a phishing redirector that never runs on a developer's machine at all: its `main` is an
HTML file, and the page, opened from a CDN link, shows a fake browser check ("Checking your
browser", "Just a moment"), fetches an encrypted value from a dead-drop service, decrypts it
in the browser (`crypto.subtle.decrypt`, CryptoJS AES) and redirects with `location.replace`.
The decrypted target is never in the package, so no URL rule sees it. `bfvkjmeikpwhqxc` 1.0.0
and 1.0.1 (OSV-labelled, malicious verdict) and `@isla5mic/aasics` 1.0.0-1.0.2 (live, never
reported, malicious verdict 2026-11-13) are this template; nothing in Stages 1-4 fired MEDIUM
on them (round 11, `docs/proposals/gap-fixes-round11-N1.md`, P5).

The rule fires when

- the tarball's `package.json` names an HTML file the package ships as what loading it gives
  (`main`, or a string `exports` / `exports["."]`; `MAIN_FIELDS`);
- the package is tiny: at most `MAX_FILES` files (the page, `package.json`, a README); an
  application that ships its built web UI as `main` has more (`@accounter/client`'s alphas);
- and one of its HTML or JavaScript files does all three: fetches something (`fetch(`,
  `XMLHttpRequest`, jQuery's `$.ajax`/`$.get`/`$.post`), decrypts something
  (`crypto.subtle.decrypt(`, a CryptoJS cipher's `.decrypt(`) and navigates the visitor away
  (`location.replace(`, `location.assign(`, an assignment to `location.href` or `location`).

MEDIUM, weight 3. The harm is to whoever opens the page, not to whoever installs it; the
explanation says so.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule

MAX_FILES: Final = 5
MAX_PAGE_BYTES: Final = 2 * 1024 * 1024
MAIN_FIELDS: Final = ("main", "browser")
SNIPPET_RADIUS: Final = 60
_PAGE: Final = (".html", ".htm", ".xhtml")
_SCRIPT: Final = (*_PAGE, ".js", ".mjs", ".cjs")
FETCHES: Final = re.compile(
    r"(?<![\w$.])fetch\s*\(|\bXMLHttpRequest\b|\$\s*\.\s*(?:ajax|get|post|getJSON)\s*\("
)
DECRYPTS: Final = re.compile(
    r"\bsubtle\s*\.\s*decrypt\s*\(|\bCryptoJS\s*\.\s*\w+\s*\.\s*decrypt\s*\("
)
NAVIGATES: Final = re.compile(
    r"\blocation\s*\.\s*(?:replace|assign)\s*\("
    r"|\blocation\s*\.\s*href\s*=(?!=)"
    r"|\b(?:window|document|top|self)\s*\.\s*location\s*=(?!=)"
)


def html_entries(files: Mapping[str, bytes], fallback: Mapping[str, object]) -> list[str]:
    """The shipped HTML files the tarball's `package.json` (or, without one, the registry's
    manifest) names as the package's entry: `main`, `browser`, a string `exports` or
    `exports["."]`."""
    manifest: object = fallback
    raw = files.get("package.json")
    if raw is not None:
        try:
            manifest = json.loads(raw)
        except ValueError:
            return []
    if not isinstance(manifest, dict):
        return []
    targets = [manifest.get(field) for field in MAIN_FIELDS]
    exports = manifest.get("exports")
    targets.append(exports.get(".") if isinstance(exports, dict) else exports)
    found = []
    for target in targets:
        if not isinstance(target, str):
            continue
        path = target.strip().removeprefix("./")
        if path.lower().endswith(_PAGE) and path in files and path not in found:
            found.append(path)
    return found


def _evidence(path: str, text: str, match: re.Match[str]) -> Evidence:
    line = text.count("\n", 0, match.start()) + 1
    around = text[max(0, match.start() - SNIPPET_RADIUS) : match.end() + SNIPPET_RADIUS]
    return Evidence(
        kind=EvidenceKind.FILE_SPAN,
        path=path,
        line_start=line,
        line_end=line,
        snippet=" ".join(around.split()),
    )


class HtmlRedirector(BaseRule):
    """A tiny package whose entry is a web page that fetches, decrypts and redirects (module
    docstring)."""

    id = "static.html-redirector"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "The package is a web page that decrypts a target and redirects its visitors"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        if len(files) > MAX_FILES:
            return ()
        entries = html_entries(files, snapshot.manifest)
        if not entries:
            return ()
        for path in [*entries, *sorted(p for p in files if p not in entries)]:
            content = files[path]
            if not path.lower().endswith(_SCRIPT) or len(content) > MAX_PAGE_BYTES:
                continue
            text = content.decode("utf-8", "replace")
            fetched, decrypted, navigated = (
                FETCHES.search(text),
                DECRYPTS.search(text),
                NAVIGATES.search(text),
            )
            if fetched is None or decrypted is None or navigated is None:
                continue
            return (
                self.finding(
                    f"The package is a web page (`{entries[0]}` is its entry, "
                    f"{len(files)} files in all), and `{path}` fetches a value, decrypts it "
                    "and sends the visitor elsewhere: where it redirects is hidden from the "
                    "package. The registry (and the CDNs that serve its files) used as web "
                    "hosting for a cloaked redirector; it harms people who open the page, "
                    "not whoever installs it.",
                    _evidence(path, text, fetched),
                    _evidence(path, text, decrypted),
                    _evidence(path, text, navigated),
                ),
            )
        return ()


RULES: Final = (HtmlRedirector(),)
