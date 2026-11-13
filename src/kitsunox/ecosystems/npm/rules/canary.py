"""Stage 2 artifact rule (npm): a tiny package whose loaded or installed code calls a host named
by a random id, the out-of-band callback canary of a probe.

Dependency-confusion and SSRF probes publish a package under a name some company uses
internally and make it "phone home" when it is installed or imported. The host they call is a
callback service that names each test by a random id in the first DNS label
(`<id>.oast.fun`, `<id>.oastify.com`, and private ones such as a bug-bounty programme's own
`<id>.ssrf-check.<company>`): the request itself is the result. `static.exfil-endpoint` knows
the public services by name; a private canary domain is unknown to it.
`selectlist-polyfill-lite` 1.0.0-1.0.2 and `hissakdx-wix-ssr-callback-canary` 1.0.0-1.0.2
(2026-10-29/30, npm took all six down) were two-file packages whose `index.js` fetched such a
host at import, nothing else; none was reported (round 11 gap analysis, cluster C1).

The rule fires on a version of at most `MAX_FILES` files (a probe ships its callback and
little else; a library that names a callback host in its tests or docs is bigger, and only
loaded files are read anyway) when a file that loading or installing the package runs
(`load_sources`, `install_sources`) or an install hook's command line holds a host whose first
label is a random id (`CANARY_HOST`: 20-64 letters and digits, at least two of each) as a URL,
a whole quoted host, or a lookup command's argument, and that code uses the network
(`NETWORK_USE`). Hosts `static.exfil-endpoint` already reports (the public OAST services)
are left to it.

MEDIUM, weight 3. A canary that only sends "it ran" is a marker-only probe, unwanted with the
`probe` tag by the owner's ruling (decision 0015 addendum of 2026-11-08); one that also sends
the user, host name or files is malicious. The finding says which host and where; the
reviewer decides which. Measured in `docs/proposals/gap-fixes-round11-N2.md` (P7).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.entry import load_sources
from kitsunox.ecosystems.npm.install import install_commands, install_sources
from kitsunox.rules.static import ExfilEndpoint

MAX_FILES: Final = 6
MAX_EVIDENCE: Final = 3
SNIPPET_RADIUS: Final = 80
# A host whose first label is 20-64 letters and digits, with at least two of each (a random
# id, not a word or a number), under a domain of two or more labels ending in letters.
_HOST: Final = (
    r"(?P<host>(?P<label>(?=(?:[a-z]*[0-9]){2})(?=(?:[0-9]*[a-z]){2})[a-z0-9]{20,64})"
    r"\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})"
)
# Written as a URL (`https://<id>.x.y/...`), as a whole quoted host (`hostname: '<id>.x.y'`), or
# as the argument of a lookup or download command (`nslookup <id>.x.y`, `curl <id>.x.y`).
CANARY_HOST: Final = re.compile(
    r"(?:(?:https?|wss?)://(?:[^/@\s\"'`]*@)?" + _HOST + r"(?![\w-])"
    r"|(?P<q>[\"'`])"
    + _HOST.replace("?P<host>", "?P<qhost>").replace("?P<label>", "?P<qlabel>")
    + r"(?=[\"'`/:])"
    r"|\b(?:nslookup|dig|host|ping|curl|wget)\s+(?:-{1,2}[\w-]+\s+)*"
    + _HOST.replace("?P<host>", "?P<chost>").replace("?P<label>", "?P<clabel>")
    + r"(?![\w-]))",
    re.IGNORECASE,
)
# The code (or command) uses the network: a fetch, an HTTP/DNS/socket module, a browser
# request API, a download or lookup command.
NETWORK_USE: Final = re.compile(
    r"(?<![\w$.])fetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\s*\(|\baxios\b|\bnew\s+WebSocket\b"
    r"|(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s+)[\"'`](?:node:)?(?:https?|http2|net|tls|dns|dgram)[\"'`]"
    r"|\b(?:curl|wget|nslookup|dig|Invoke-WebRequest|Invoke-RestMethod)\b",
)


# A quoted file name with a content hash (`'5f3e...9a4b.worker.js'`) has the shape of a host;
# its last label is a file extension, never a top-level domain we need.
FILE_SUFFIXES: Final = frozenset(
    {
        "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "json", "css", "map", "html", "htm",
        "txt", "md", "png", "jpg", "jpeg", "gif", "svg", "webp", "wasm", "node", "gz", "tgz",
        "zip", "lock", "yml", "yaml", "sh", "py", "woff", "woff2", "ttf", "chunk", "bundle",
    }
)  # fmt: skip


def canary_hosts(text: str) -> list[re.Match[str]]:
    """The callback-canary hosts `text` names (`CANARY_HOST`), without the public OAST hosts
    `static.exfil-endpoint` reports and file names (`FILE_SUFFIXES`)."""
    found = []
    for match in CANARY_HOST.finditer(text):
        host = _host(match)
        if host.rsplit(".", 1)[-1] in FILE_SUFFIXES or ExfilEndpoint.pattern.search(host):
            continue
        found.append(match)
    return found


def _host(match: re.Match[str]) -> str:
    return str(match.group("host") or match.group("qhost") or match.group("chost")).lower()


class CanaryCallback(BaseRule):
    """A tiny package's loaded or installed code calls a random-id callback host (module
    docstring)."""

    id = "npm.canary-callback"
    version = 1
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Tiny package that calls a random-id callback host (a probe's canary)"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        if not files or len(files) > MAX_FILES:
            return ()
        sources = {**load_sources(files), **install_sources(files)}
        texts = {path: data.decode("utf-8", "replace") for path, data in sorted(sources.items())}
        for hook, command in sorted(install_commands(files).items()):
            texts[f"package.json:scripts.{hook}"] = command
        hits: list[tuple[str, int, str, str]] = []
        for path, text in texts.items():
            if not NETWORK_USE.search(text):
                continue
            for match in canary_hosts(text):
                line = text.count("\n", 0, match.start()) + 1
                start = max(0, match.start() - SNIPPET_RADIUS)
                snippet = " ".join(text[start : match.end() + SNIPPET_RADIUS].split())
                hits.append((path, line, snippet, _host(match)))
                break
        if not hits:
            return ()
        hosts = sorted({host for *_, host in hits})
        where = ", ".join(f"`{path}`" for path, *_ in hits)
        return (
            self.finding(
                f"This {len(files)}-file package calls "
                + ", ".join(f"`{h}`" for h in hosts[:MAX_EVIDENCE])
                + f" from code that loading or installing it runs ({where}): a host named by a "
                "random id, the callback canary that dependency-confusion and SSRF probes use "
                "to learn that their package ran. A marker-only callback is unwanted (a "
                "research probe); one that also sends the user, host name or files is "
                "malicious (decision 0015).",
                *(
                    Evidence(
                        kind=EvidenceKind.MANIFEST_FIELD
                        if path.startswith("package.json:")
                        else EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=None if path.startswith("package.json:") else line,
                        line_end=None if path.startswith("package.json:") else line,
                        snippet=snippet[:300],
                    )
                    for path, line, snippet, _ in hits[:MAX_EVIDENCE]
                ),
            ),
        )


RULES: Final = (CanaryCallback(),)
