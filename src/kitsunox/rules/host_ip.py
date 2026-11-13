"""Stage 2 artifact rule: a bare IP address in a JSON setting, joined into a URL that carries
who is running the code.

`static.hardcoded-ip` reads URLs (`http://203.0.113.9:8080`): a scheme, then the address. A
package can keep the parts apart, so that no file holds a URL at all: a JSON settings file
gives `"host": "<public IPv4>"` (and the scheme in another field, `"transport": "http"`), and
code builds the URL at runtime from a scheme it was handed (`${transport}://${host}:${port}`)
and adds the user's name or the machine's hostname to it. `@atedone/workspace-context`
0.0.23-0.0.25 (live, 2026-11, malicious verdict) did exactly that: `lib/default-profile.json`
held the address, and `lib/state.js` built `${transport}://${authority}/${pathname}` with
`?username=` from `USER` / `LOGNAME`, for a shell prompt that fetched from it. No other Stage 2
rule fired on those releases (round 11, `docs/proposals/gap-fixes-round11-N1.md`, P2).

So this rule reads every file of every version (an `ArtifactRule`: the JSON file and the code
are usually unchanged between releases, and the two halves are in different files) and fires
when

- a JSON file (not a lockfile, not under tests, examples or docs) sets a host-like key
  (`HOST_KEY`: `host`, `hostname`, `server`, `ip`, `address`, `addr`, `endpoint`, `domain`) to a
  bare public IPv4 address, optionally with a port, with no scheme; not a well-known public DNS
  resolver or an address documentation uses as an example (`static.hardcoded-ip`'s lists);
- and one JavaScript or TypeScript file of the package (comments and log or error messages
  blanked) both builds a URL from a scheme held in a variable (`${scheme}://`, or
  `scheme + "://"`) and reads who is running it (`USER`, `LOGNAME` or `USERNAME` from the
  environment, `os.userInfo()`, `os.hostname()`).

The address alone is configuration: in a random 25,000 of the live tarballs (round 11), a bare
public IP under such a key was in 16 versions, all of `@mentra/cloud-protocol` (URL test
vectors), and none of them has code that builds a URL from a scheme variable and adds the
user's name. MEDIUM, weight 3.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule
from kitsunox.lang.javascript import language_for, mask_comments_and_messages
from kitsunox.rules.static import EXAMPLE_IPS, PUBLIC_RESOLVERS

MAX_JSON_BYTES: Final = 256 * 1024
MAX_CODE_BYTES: Final = 2 * 1024 * 1024
SNIPPET_RADIUS: Final = 60
# A host-like key set to a bare IPv4 address (an optional port, no scheme), in JSON.
HOST_KEY: Final = re.compile(
    rb'"(?i:host|hostname|server|ip|address|addr|endpoint|domain)"\s*:\s*'
    rb'"((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?"'
)
# A URL built from a scheme held in a variable: `${transport}://`, `proto + "://"`.
SCHEME_VARIABLE: Final = re.compile(r"\$\{\s*[\w$.]+\s*\}://|[\w$\])]\s*\+\s*[\"'`]://")
# Who runs the code: the user's name from the environment, the OS user, the hostname.
IDENTITY: Final = re.compile(
    r"\benv\s*\.\s*(?:USER|LOGNAME|USERNAME)\b|\benv\s*\[\s*[\"'`](?:USER|LOGNAME|USERNAME)[\"'`]"
    r"|[\"'`](?:USER|LOGNAME|USERNAME)[\"'`]|\buserInfo\s*\(|\bhostname\s*\("
)
# Files that hold no configuration a package runs with.
SKIPPED: Final = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|examples?|docs?|demo|node_modules)/"
    r"|(?:^|/)(?:package-lock|npm-shrinkwrap|composer|tsconfig|jsconfig)\.json$"
    r"|\.(?:test|spec)\.[cm]?[jt]sx?$",
    re.IGNORECASE,
)


def _public(address: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return ip.is_global and address not in PUBLIC_RESOLVERS and address not in EXAMPLE_IPS


def bare_host_ips(files: Mapping[str, bytes]) -> list[tuple[str, int, str, str]]:
    """Each JSON file's first host-like key set to a bare public IPv4 address:
    (path, line, address, the line's text)."""
    found = []
    for path in sorted(files):
        content = files[path]
        if not path.lower().endswith(".json") or len(content) > MAX_JSON_BYTES:
            continue
        if SKIPPED.search(path):
            continue
        for match in HOST_KEY.finditer(content):
            address = match.group(1).decode()
            if not _public(address):
                continue
            line = content.count(b"\n", 0, match.start()) + 1
            found.append((path, line, address, match.group(0).decode("utf-8", "replace")))
            break
    return found


def _span(text: str, start: int, end: int) -> tuple[int, str]:
    line = text.count("\n", 0, start) + 1
    around = text[max(0, start - SNIPPET_RADIUS) : end + SNIPPET_RADIUS]
    return line, " ".join(around.split())


def identity_urls(files: Mapping[str, bytes]) -> list[tuple[str, int, str, int, str]]:
    """Code files that build a URL from a scheme variable and read who runs them:
    (path, URL line, snippet, identity line, snippet)."""
    found = []
    for path in sorted(files):
        content = files[path]
        language = language_for(path)
        if language is None or len(content) > MAX_CODE_BYTES or SKIPPED.search(path):
            continue
        if b"://" not in content:
            continue
        text = mask_comments_and_messages(content, language).decode("utf-8", "replace")
        scheme = SCHEME_VARIABLE.search(text)
        identity = IDENTITY.search(text) if scheme else None
        if scheme is None or identity is None:
            continue
        url_line, url_snippet = _span(text, *scheme.span())
        id_line, id_snippet = _span(text, *identity.span())
        found.append((path, url_line, url_snippet, id_line, id_snippet))
    return found


class HostIpIdentity(BaseRule):
    """A JSON setting holds a bare public IP address, and the package's code builds URLs from
    a scheme variable and adds the user's name (module docstring)."""

    id = "static.host-ip-identity"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Bare IP address in a JSON setting, built into a URL with the user's identity"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        hosts = bare_host_ips(files)
        if not hosts:
            return ()
        code = identity_urls(files)
        if not code:
            return ()
        path, line, address, entry = hosts[0]
        code_path, url_line, url_snippet, id_line, id_snippet = code[0]
        return (
            self.finding(
                f"`{path}` sets a host to the public IP address {address} with no scheme, and "
                f"`{code_path}` builds a URL from a scheme held in a variable and reads who is "
                "running it (the user's name or the machine's hostname): a server address "
                "kept out of any URL a scanner would read, where the code sends the user's "
                "identity.",
                Evidence(
                    kind=EvidenceKind.FILE_SPAN,
                    path=path,
                    line_start=line,
                    line_end=line,
                    snippet=entry,
                ),
                Evidence(
                    kind=EvidenceKind.FILE_SPAN,
                    path=code_path,
                    line_start=url_line,
                    line_end=url_line,
                    snippet=url_snippet,
                ),
                Evidence(
                    kind=EvidenceKind.FILE_SPAN,
                    path=code_path,
                    line_start=id_line,
                    line_end=id_line,
                    snippet=id_snippet,
                ),
            ),
        )


RULES: Final = (HostIpIdentity(),)
