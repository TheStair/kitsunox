"""Install code that downloads code from outside the npm registry (Stage 3).

The owner's ruling of 2026-11-10 (decision 0015, strict and final): install code (a hook or a
file it runs; never a command the user starts) that fetches files, scripts or binaries that
are not in the registry tarball is **unwanted**, whoever hosts them. A vendor's `curl ... |
bash` installer of another product, a third-party runtime (python-build-standalone, CPython),
browsers (`playwright install`, `@puppeteer/browsers install` started by the package's own
hook), models or data from another project, another project's release binary (a wrapper that
installs Caddy, cloudflared or Mutagen), `pip`, `cargo`, `go` or `gem install`, `npx <package>`
of a package that isn't a dependency, and **the package's own binary from its own GitHub
release or CDN** (cargo-dist, goreleaser and similar downloaders), checksum or not. The
payload is outside the tarball: neither the static rules nor the tarball-vs-repo comparison
see it. Still benign: the binary in the tarball, the package's own platform packages on the
npm registry (`optionalDependencies`, esbuild-style, also a fallback that fetches such a
package's tarball from the registry), and a declared dependency's own install script, which
npm runs by itself and this rule never reads.

The forms (`FORM_TEXT`), each its own so the owner can weigh them apart:

- **`fetch`**: a download from a third-party host: a `curl`/`wget`/PowerShell command, or a
  download URL (`DOWNLOAD_URL`: a release asset or the release API, a raw repository file, an
  archive, binary or script, a `/dist/` path) in install code that reaches the network;
- **`own`**: the same from the package's own sources (`download_source`): its declared
  repository or any repository of its GitHub owner, its `homepage`'s host (agent H's
  `install_shapes._own_kind`), its vendor's host (`vendor_host`: `@abacus-ai/cli` from
  `static.abacus.ai`), the author's own GitHub account, a GitHub owner the code builds at run
  time, or cargo-dist's `artifactDownloadUrls`;
- **`prebuilt`**: `prebuild-install` or `node-pre-gyp install`, which download a native
  prebuilt from the package's release host;
- **`tool`**: a command that fetches third-party code itself (`TOOL`): `playwright install`,
  `@puppeteer/browsers install`, `camoufox fetch`, `pip install`, `cargo install`, `go install`,
  `gem install`, `skills add`, `huggingface-cli download`;
- **`npx`**: `npx`, `pnpx`, `bunx`, `pnpm dlx`, `yarn dlx` or `npm exec` of a package that is
  neither the package itself nor a dependency installed with it (`dependencies`,
  `optionalDependencies`, `peerDependencies`, bundled): npx downloads and runs it;
- **`guard`**: the same for a package-manager guard (`npx only-allow pnpm`), apart because
  the owner may rule it benign (`GUARDS_COUNT`);
- **`npm`**: `npm install <name>` of packages that are not dependencies (`98router`'s runtime
  under `~/.9router`).

It reads what `npm.install-persistence` reads, the same way (`install_persistence.code_text`):
the install files (JavaScript and TypeScript with comments and messages blanked; shell,
PowerShell and batch scripts with comment and `echo` lines blanked) and the install hooks'
command lines (`echo` messages blanked, and a fallback that runs only when a shipped file is
missing cut: `test -f dist/index.js || npx tsc`). In JavaScript a command string counts only
when it is handed to a runner (`lang.javascript.handed_to_runner`), never when it is printed,
kept in a table or written into a file. A URL in a message is blanked already; a URL the code
keeps (a constant, a table of release assets) counts when the install code reaches the
network.

MEDIUM, weight 3, and never explained away: `npm.install-explained` explains the install
rules only, and since v5 no download shape at all (S2, S6 removed). Only new or changed install
code counts (`ONLY_WHEN_CHANGED`), as for the other install rules. Measured in
`docs/stages/ast.md` and `docs/proposals/precision-round6-R.md`."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.rules.install_persistence import SCRIPT_SUFFIXES, code_text
from kitsunox.ecosystems.npm.rules.install_shapes import URL, _home_host, _own_kind, own_repo
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts, snippet
from kitsunox.lang.javascript import Capability, handed_to_runner, language_for
from kitsunox.lang.shell import mask_script_messages
from kitsunox.stages.ast import CodeChange

MAX_SHOWN: Final = 3
SNIPPET_RADIUS: Final = 70
# Every version whose install code downloads counts, changed or not: under the strict ruling
# each such version is unwanted (measured: +10 unwanted versions, 0 benign more than with
# only changed install code, `docs/proposals/precision-round6-R.md`).
ONLY_WHEN_CHANGED: Final = False

# Where a command starts: the start of a string or a line, or after `&&`, `||`, `;`, `|`, `(`,
# `$(`; a sentence naming one ("Install it with: pip install x") doesn't start a command.
_START: Final = r"(?:^|[\"'`]|&&|\|\||[;|(]|\$\()\s*(?:sudo\s+(?:-\S+\s+)*)?"
_URL: Final = r"https?://[^\s\"'`)<>\\|;]+"
# A download command with a literal URL: curl, wget, PowerShell's web cmdlets and WebClient.
FETCH_COMMAND: Final = re.compile(
    _START
    + r"(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)(?:\.exe)?"
    r"\s[^\n|;&]{0,300}?[\"']?(" + _URL + r")"
    r"|\.Download(?:File|String|Data)(?:Async)?\s*\(\s*[\"']?(" + _URL + r")",
    re.MULTILINE | re.IGNORECASE,
)
_Q: Final = r"[\"'`]"
# The same as an argument list: `spawn("curl", ["-fsSL", url])` with a literal URL.
FETCH_ARGV: Final = re.compile(
    _Q + r"(?:curl|wget)" + _Q + r"\s*,\s*\[\s*(?:" + _Q + r"[^\"'`\n]{0,80}" + _Q
    + r"\s*,\s*){0,8}" + _Q + "(" + _URL + ")"
)  # fmt: skip
# Commands that fetch third-party code themselves.
_TOOLS: Final = (
    r"(?:(?:npx|pnpx|bunx|pnpm\s+(?:exec|dlx)|yarn(?:\s+dlx)?|npm\s+exec)\s+(?:-\S+\s+)*)?"
    r"(?:(?:@playwright/test|playwright(?:-core|-chromium)?|patchright)\s+install"
    r"|(?:@puppeteer/)?browsers\s+install|puppeteer\s+browsers\s+install"
    r"|camoufox(?:-js)?\s+fetch"
    r"|(?:python[\d.]*\s+-m\s+)?pip[\d.]*\s+install|pipx\s+install|uv\s+(?:pip|tool)\s+install"
    r"|cargo\s+(?:install|binstall)|go\s+(?:install|get)|gem\s+install"
    r"|skills\s+add|(?:huggingface-cli|hf)\s+download)\b"
)
TOOL: Final = re.compile(_START + _TOOLS, re.MULTILINE | re.IGNORECASE)
# As an argument list: `spawnSync("npx", ["playwright", "install", "chromium"])`,
# `spawn(python, ["-m", "pip", "install", ...])`, `execFile("cargo", ["install", x])`.
TOOL_ARGV: Final = re.compile(
    _Q + r"(?:playwright(?:-core)?|pip[\d.]*|pipx|cargo|gem)" + _Q + r"\s*,\s*\[?\s*" + _Q
    + r"install" + _Q
    + r"|" + _Q + r"skills" + _Q + r"\s*,\s*" + _Q + r"add" + _Q
    + r"|" + _Q + r"-m" + _Q + r"\s*,\s*" + _Q + r"pip" + _Q + r"\s*,\s*" + _Q + r"install" + _Q
    + r"|" + _Q + r"go" + _Q + r"\s*,\s*\[\s*" + _Q + r"(?:install|get)" + _Q
)  # fmt: skip
# Native prebuilt downloaders: they fetch the package's prebuilt from its release host.
PREBUILT: Final = re.compile(
    _START + r"(?:npx\s+(?:-\S+\s+)*)?(?:prebuild-install|(?:@mapbox/)?node-pre-gyp\s+install)\b",
    re.MULTILINE | re.IGNORECASE,
)
# Playwright's CLI run by path (`run(process.execPath, [cli, "install", "chromium"])`).
BROWSER_ARGV: Final = re.compile(
    _Q + r"install" + _Q + r"\s*,\s*(?:" + _Q + r"--?[\w-]+" + _Q + r"\s*,\s*)*" + _Q
    + r"(?:chromium(?:-headless-shell)?|firefox|webkit|chrome|msedge)" + _Q
)  # fmt: skip
# Install code that reaches the network without the `network` capability: through `curl` or
# `wget` in a child process, PowerShell, the global `fetch` (also passed on: `fetchImpl =
# fetch`, `@qwen-code/cua-sdk`), or an HTTP client package (`follow-redirects`'s `https`,
# `@ghyper9023/u2secure`).
HTTP_PACKAGES: Final = (
    r"follow-redirects|axios|got|node-fetch|undici|request|needle|superagent|make-fetch-happen"
    r"|cross-fetch|minipass-fetch|phin|simple-get|download|ky|bent|wretch"
)
NETWORK_TEXT: Final = re.compile(
    r"\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|DownloadFile|\bfetch\b"
    r"|(?:\brequire\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*)[\"'`](?:"
    + HTTP_PACKAGES
    + r")(?:/[^\"'`]*)?[\"'`]",
    re.IGNORECASE,
)
# A template expression in a URL (`https://github.com/${repo()}/releases`): read as one
# placeholder, so the URL isn't cut at its parenthesis.
_EXPRESSION: Final = re.compile(r"\$\{[^{}\n]{1,80}\}")
# A Windows executable or installer started at install (decision 0015, 2026-11-10: "malicious
# at worst, and unwanted at best"): a `.exe`/`.msi` run by the hook line or a script, `msiexec`,
# PowerShell's `Start-Process` of one; the shells and `node` that run install code are not.
# Windows' own tools and the toolchains a build calls are not an installer
# (`where.exe` to find a binary, `7z.exe` in a `case`, `icacls.exe`, `cargo.exe`).
_SHELLS: Final = (
    r"(?:powershell|pwsh|cmd|node|bash|sh|wsl|conhost|where|7z|7za|cargo|rustc|rustup|git"
    r"|icacls|reg|tar|curl|taskkill|tasklist|npm|npx|python|py|java|dotnet|code|explorer"
    r"|whoami|attrib|robocopy|xcopy|findstr)\.exe"
)
EXE_COMMAND: Final = re.compile(
    _START + r"(?:\.[/\\]|[\w$%{}.-]+[/\\])*(?!" + _SHELLS + r")[\w.-]+\.(?:exe|msi)\b"
    r"|\bmsiexec(?:\.exe)?\s+/[iap]|\bStart-Process\b[^\n]{0,80}?(?:\.exe|\.msi|\$\w*setup)",
    re.MULTILINE | re.IGNORECASE,
)  # fmt: skip
# In JavaScript: a variable given a `.exe`/`.msi` path in the package (`__dirname`, a relative
# path) that a runner is then given.
EXE_VARIABLE: Final = re.compile(
    r"\b(?:const|let|var)\s+([\w$]+)\s*=[^;\n]{0,200}?(?:__dirname|import\.meta|[\"'`]\.\.?/)"
    r"[^;\n]{0,200}?[\w-]\.(?:exe|msi)[\"'`]"
)
# A hook command that runs only when a file the package ships is missing.
FILE_FALLBACK: Final = re.compile(
    r"(?:\btest\s+-[ef]\s+|\[\s+-[ef]\s+)[^|&;]*?\]?\s*\|\|[^;&]*", re.IGNORECASE
)
# An `echo` whose quoted message spans lines in a hook command.
HOOK_ECHO: Final = re.compile(r"""\becho\s+(?:-\w+\s+)*(?:'[^']*'|"(?:[^"\\]|\\.)*")""")
# A runner of a package from the registry, and the package it runs.
_NPX: Final = r"(?:npx|pnpx|bunx|pnpm\s+dlx|yarn\s+dlx|npm\s+exec|bun\s+x)"
_PACKAGE: Final = r"(@?[a-z0-9][\w.-]*(?:/[\w.-]+)?)"
NPX: Final = re.compile(
    _START + _NPX + r"\s+(?:(?:-y|--yes|-q|--quiet|--no-install|--prefer-offline)\s+)*"
    r"(?:--\s+)?" + _PACKAGE,
    re.MULTILINE | re.IGNORECASE,
)
NPX_ARGV: Final = re.compile(
    _Q + r"(?:npx|pnpx|bunx)" + _Q + r"\s*,\s*\[\s*(?:" + _Q + r"-[\w-]+" + _Q + r"\s*,\s*)*"
    + _Q + _PACKAGE + _Q,
    re.IGNORECASE,
)  # fmt: skip
# `npm install <names>` (also `npm i`, `npm add`), with the names it installs.
NPM_INSTALL: Final = re.compile(
    _START + r"npm\s+(?:install|i|add)\s+((?:[^\s\"'`;&|]+\s*){1,12})",
    re.MULTILINE | re.IGNORECASE,
)
NPM_INSTALL_ARGV: Final = re.compile(
    _Q + r"npm" + _Q + r"\s*,\s*\[\s*" + _Q + r"(?:install|i|add)" + _Q
    + r"((?:\s*,\s*" + _Q + r"[^\"'`\n]{1,100}" + _Q + r"){1,12})"
)  # fmt: skip
# A few bin names whose package differs (`npx tsc` runs `typescript`).
BIN_PACKAGES: Final = {
    "tsc": "typescript",
    "node-pre-gyp": "@mapbox/node-pre-gyp",
    "electron-rebuild": "@electron/rebuild",
    "browsers": "@puppeteer/browsers",
}
# Package-manager guards (`npx only-allow pnpm`): the same download, reported as their own form
# (`guard`) so the owner can drop it on its own (`GUARDS_COUNT`).
GUARDS: Final = frozenset({"only-allow"})
GUARDS_COUNT: Final = True
# Packages npm brings with it: `npx node-gyp` needs no download.
NPM_BUNDLED: Final = frozenset({"node-gyp", "npm", "npx", "corepack"})
# What a download URL looks like: a release asset or the release API, a raw repository file,
# an archive, binary or script, a `/dist/` path, a Hugging Face file.
DOWNLOAD_URL: Final = re.compile(
    r"/releases/(?:download|latest)\b|/releases\b|//raw\.githubusercontent\.com/"
    r"|//codeload\.github\.com/|/archive/|/resolve/"
    r"|\.(?:tar\.gz|tgz|tar\.xz|txz|tar\.bz2|tar|zip|7z|gz|xz|bz2|zst|exe|msi|dmg|pkg|deb|rpm"
    r"|appimage|jar|whl|sh|ps1|bin|node|so|dylib|dll|gguf|onnx|safetensors|wasm|sql)(?:[?#]|$)"
    r"|/dist/|/dl(?:/|$)"
    r"|^https?://(?:dl|download|downloads|releases?|cdn|get)\.",
    re.IGNORECASE,
)
# Hosts that are never a download of code from outside the registry: the npm registry and its
# mirrors, the local machine.
REGISTRY_HOSTS: Final = frozenset(
    {
        "registry.npmjs.org",
        "registry.npmmirror.com",
        "registry.npm.taobao.org",
        "registry.yarnpkg.com",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",  # noqa: S104 (a host name compared, nothing bound)
    }
)
# A registry tarball path, whatever the host (`${registry}/@kx/tool-linux-x64/-/...tgz`).
REGISTRY_TARBALL: Final = re.compile(r"/-/[^/]+\.tgz(?:[?#]|$)", re.IGNORECASE)
# Labels that say nothing about whose host it is.
_GENERIC_LABELS: Final = frozenset(
    {
        "www", "cdn", "static", "download", "downloads", "dl", "get", "releases", "release",
        "api", "assets", "files", "registry", "npm", "repo", "cli", "app", "dev", "docs", "com",
        "net", "org", "io",
    }
)  # fmt: skip
_SECOND_LEVEL: Final = frozenset({"co", "com", "net", "org", "gov", "ac", "edu"})
_ALNUM: Final = re.compile(r"[^a-z0-9]")
MIN_TOKEN: Final = 4
_GITHUB_OWNER: Final = re.compile(
    r"https?://(?:(?:www\.)?github\.com|api\.github\.com/repos|raw\.githubusercontent\.com"
    r"|codeload\.github\.com)/([^/?#]+)",
    re.IGNORECASE,
)


def _host(url: str) -> str:
    u = url.lower()
    return u.split("/")[2].split(":")[0].split("@")[-1] if u.count("/") >= 2 else ""


def _main_label(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else host


def organisation_names(manifest: Mapping[str, Any], name: str) -> set[str]:
    """Names the package's own organisation goes by, letters and digits only: its scope (or
    its name, unscoped), its GitHub repository's owner, and its homepage's main domain label."""
    names = set()
    if name.startswith("@"):
        names.add(_ALNUM.sub("", name[1:].split("/", 1)[0].lower()))
    else:
        names.add(_ALNUM.sub("", name.lower()))
    if (repo := own_repo(manifest)) is not None:
        names.add(_ALNUM.sub("", repo[0]))
    if (home := _home_host(manifest)) is not None:
        names.add(_ALNUM.sub("", _main_label(home)))
    return {n for n in names if len(n) >= MIN_TOKEN}


def vendor_host(host: str, manifest: Mapping[str, Any], name: str) -> bool:
    """Whether `host` belongs to the package's own organisation: its main domain label is one
    of `organisation_names`, or starts or ends one (`abacus` in `abacusai`, `statuz` in
    `statuzcli`)."""
    if not host or "${" in host:
        return False
    label = _ALNUM.sub("", _main_label(host))
    if len(label) < MIN_TOKEN or label in _GENERIC_LABELS:
        return False
    return any(
        label == n or n.startswith(label) or n.endswith(label) or label.startswith(n)
        for n in organisation_names(manifest, name)
    )


def github_owner(url: str) -> str | None:
    """The GitHub account a GitHub URL points into (lower case), or None."""
    match = _GITHUB_OWNER.match(url)
    return match.group(1).lower() if match else None


def _author_names(manifest: Mapping[str, Any]) -> set[str]:
    """The `author`'s and `maintainers`' names and their `url`s' GitHub accounts, as GitHub
    account names could be (`Tai Kimura` -> `tai-kimura`)."""
    people = [manifest.get("author")]
    maintainers = manifest.get("maintainers")
    if isinstance(maintainers, list):
        people += maintainers
    names: set[str] = set()
    for person in people:
        if isinstance(person, str):
            text, url = person.split("<", 1)[0].split("(", 1)[0], person
        elif isinstance(person, dict):
            text, url = str(person.get("name") or ""), str(person.get("url") or "")
        else:
            continue
        if len(text.strip()) >= MIN_TOKEN:
            names.add(re.sub(r"\s+", "-", text.strip().lower()))
        if (owner := github_owner(url.strip("() "))) is not None:
            names.add(owner)
    return names


def download_source(url: str, manifest: Mapping[str, Any], name: str) -> str | None:
    """Where a download from `url` comes from: None when it is no download of code from
    outside the registry (the npm registry or a mirror, a registry tarball path, the local
    machine, a page link, a host the code builds at run time); 'own' for the package's own
    sources (its repository or its owner's other repositories, its homepage's host, GitHub's
    asset hosts, its vendor's host, the author's GitHub account, a GitHub owner the code builds
    at run time); 'third-party' otherwise."""
    host = _host(url)
    if not host or "$" in host or host in REGISTRY_HOSTS or REGISTRY_TARBALL.search(url):
        return None
    kind = _own_kind(url, own_repo(manifest), _home_host(manifest))
    if kind in ("registry", "page"):
        return None
    if kind is not None:
        return "own"
    owner = github_owner(url)
    if owner is not None and ("$" in owner or owner in _author_names(manifest)):
        return "own"
    return "own" if vendor_host(host, manifest, name) else "third-party"


def declared(manifest: Mapping[str, Any]) -> set[str]:
    """The packages installed with this one: runtime, optional, peer and bundled
    dependencies."""
    out: set[str] = set()
    for field in ("dependencies", "optionalDependencies", "peerDependencies"):
        value = manifest.get(field)
        if isinstance(value, dict):
            out |= {str(k).lower() for k in value}
    for field in ("bundleDependencies", "bundledDependencies"):
        value = manifest.get(field)
        if isinstance(value, list):
            out |= {str(k).lower() for k in value}
    return out


def _foreign_package(package: str, manifest: Mapping[str, Any], name: str) -> bool:
    """A package `npx` (or `npm install`) would have to download: not this package, not one
    npm brings, not a dependency (directly or through a known bin name)."""
    package = package.lower()
    if package.startswith("@") and package.count("@") > 1:
        package = "@" + package[1:].split("@", 1)[0]
    elif not package.startswith("@"):
        package = package.split("@", 1)[0]
    if not package or package.startswith((".", "/")) or package == name.lower():
        return False
    deps = declared(manifest)
    return (
        package not in NPM_BUNDLED
        and package not in deps
        and BIN_PACKAGES.get(package, package) not in deps
    )


def _npm_names(text: str) -> list[str]:
    return [
        token
        for token in re.split(r"[\s,\"'`]+", text)
        if token and not token.startswith("-") and "=" not in token and "$" not in token
    ]


def hook_text(command: str) -> str:
    """A hook command line as the rule reads it: `echo` messages blanked (also those spanning
    lines), and a fallback that runs only when a shipped file is missing cut."""
    text = HOOK_ECHO.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), command)
    return FILE_FALLBACK.sub("", mask_script_messages(text))


Found = tuple[str, str, int, str]


def downloads(
    install_files: Mapping[str, bytes],
    manifest: Mapping[str, Any],
    name: str,
    network: bool,
) -> list[Found]:
    """What the install code and hook command lines download from outside the npm registry,
    as (form, path, 1-based line, text around it). `network` is whether the install code
    reaches the network (URLs it keeps count only then)."""
    texts = {
        path: code_text(path, data)
        for path, data in sorted(install_files.items())
        if language_for(path) is not None or path.lower().endswith(SCRIPT_SUFFIXES)
    }
    declared_scripts = scripts(manifest)
    for hook in INSTALL_HOOKS:
        if command := declared_scripts.get(hook, "").strip():
            texts[f"package.json:scripts.{hook}"] = hook_text(command)
    found: list[Found] = []
    network = network or any(NETWORK_TEXT.search(t) for t in texts.values())
    for path, text in texts.items():
        found += _text_downloads(path, text, install_files.get(path), manifest, name, network)
    urls = manifest.get("artifactDownloadUrls")  # cargo-dist's installer downloads these
    if network and isinstance(urls, list):
        for url in urls:
            if isinstance(url, str) and download_source(url, manifest, name) is not None:
                found.append(("own", "package.json:artifactDownloadUrls", 1, snippet(url) or url))
                break
    if network and not any(f[0] in ("fetch", "own") for f in found):
        found += _downloader(texts, install_files)
    return found


# The downloader shape (`downloader`): JavaScript install code that reaches the network, writes
# a stream to a file and unpacks it or makes it executable, with its URL built at run time or
# read from data (`msedgedriver`'s host root, `onpod.ai/cli`, `@byteplus/arkcli-probe-*`'s
# bootstrap). A fallback that fetches a platform package from the registry (esbuild's
# installer: it names the registry) is not one.
SINK: Final = re.compile(r"\bcreateWriteStream\s*\(|\bpipeline\s*\(|\.pipe\s*\(")
UNPACK: Final = re.compile(
    r"\bextract\w*\s*\(|\bunzip|\btar\b|AdmZip|\bdecompress\w*\s*\(|\bchmod(?:Sync)?\s*\(",
    re.IGNORECASE,
)
REGISTRY_FALLBACK: Final = re.compile(
    r"registry\.npmjs\.org|npm_config_registry|registry\.npmmirror\.com", re.IGNORECASE
)


def _downloader(texts: Mapping[str, str], install_files: Mapping[str, bytes]) -> list[Found]:
    code = {p: t for p, t in texts.items() if language_for(p) is not None and p in install_files}
    joined = "\n".join(code.values())
    if not UNPACK.search(joined) or REGISTRY_FALLBACK.search(joined):
        return []
    for path, text in code.items():
        if match := SINK.search(text):
            return [("downloader", path, *_where(text, match.start(), match.end()))]
    return []


def _text_downloads(
    path: str,
    text: str,
    data: bytes | None,
    manifest: Mapping[str, Any],
    name: str,
    network: bool,
) -> list[Found]:
    runs = _runs(path, data, text)
    found: list[Found] = []

    def add(form: str, match: re.Match[str]) -> None:
        found.append((form, path, *_where(text, match.start(), match.end())))

    for match in FETCH_COMMAND.finditer(text):
        group = 1 if match.group(1) else 2
        source = download_source(match.group(group), manifest, name)
        if source is not None and runs(match.start(group)):
            add("fetch" if source == "third-party" else "own", match)
    for match in FETCH_ARGV.finditer(text):
        source = download_source(match.group(1), manifest, name)
        if source is not None and runs(match.start()):
            add("fetch" if source == "third-party" else "own", match)
    for match in EXE_COMMAND.finditer(text):
        if language_for(path) is None or runs(match.start()):
            add("exe", match)
    if language_for(path) is not None:
        for match in EXE_VARIABLE.finditer(text):
            if _runner_given(text, match.group(1)):
                add("exe", match)
    for match in BROWSER_ARGV.finditer(text):
        if runs(match.start()):
            add("tool", match)
    for match in PREBUILT.finditer(text):
        if runs(match.end() - 1):
            add("prebuilt", match)
    for match in (*TOOL.finditer(text), *TOOL_ARGV.finditer(text)):
        if runs(match.end() - 1):
            add("tool", match)
    for match in (*NPX.finditer(text), *NPX_ARGV.finditer(text)):
        package = match.group(1)
        if _foreign_package(package, manifest, name) and runs(match.start(1)):
            form = "guard" if package.lower().split("@")[0] in GUARDS else "npx"
            if form == "npx" or GUARDS_COUNT:
                add(form, match)
    for match in (*NPM_INSTALL.finditer(text), *NPM_INSTALL_ARGV.finditer(text)):
        foreign = any(_foreign_package(n, manifest, name) for n in _npm_names(match.group(1)))
        if foreign and runs(match.start(1)):
            add("npm", match)
    if network or path.lower().endswith(SCRIPT_SUFFIXES):
        plain = _EXPRESSION.sub(lambda m: "${" + "x" * (len(m.group(0)) - 3) + "}", text)
        for match in URL.finditer(plain):
            url = match.group(0).rstrip(".,;")
            if DOWNLOAD_URL.search(url):
                source = download_source(url, manifest, name)
                if source is not None:
                    add("fetch" if source == "third-party" else "own", match)
    return found


def _runner_given(text: str, name: str) -> bool:
    """Whether a runner call (`exec*`, `spawn*`, `execa*`, `run*`) takes the variable `name`
    as its first argument."""
    pattern = r"(?<![\w$.])(?:exec\w*|spawn\w*|execa\w*|run\w*)\s*\(\s*" + re.escape(name)
    return re.search(pattern + r"(?![\w$])", text) is not None


def _runs(path: str, data: bytes | None, text: str) -> Callable[[int], bool]:
    """A test of whether the command string at an offset of `text` runs: in JavaScript, when
    it is handed to a runner (`lang.javascript.handed_to_runner`: as an argument, an argument
    list, or a variable a runner is given), not when it is shown, kept as data or written into
    a file; in a hook command line or a script, always (messages are blanked)."""
    language = language_for(path)
    mapped = language is not None and data is not None and len(text.encode("utf-8")) == len(data)

    def runs(offset: int) -> bool:
        if not mapped or data is None or language is None:
            return True
        return handed_to_runner(data, language, len(text[:offset].encode("utf-8")))

    return runs


class InstallDownload(BaseRule):
    """Install code downloads files, scripts or binaries from outside the npm registry (module
    docstring). Added 2026-11-10 (round 6, `docs/proposals/precision-round6-R.md`), for the
    owner's strict ruling of that day."""

    id = "npm.install-download"
    version = 1
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Install code downloads code from outside the npm registry"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        before = change.install_files_before
        if ONLY_WHEN_CHANGED and before is not None and before == change.install_files:
            return ()
        install = change.install
        network = install is not None and Capability.NETWORK in install.capabilities
        found = downloads(
            change.install_files, change.snapshot.manifest, change.snapshot.ref.name, network
        )
        if not found:
            return ()
        forms = sorted({form for form, _, _, _ in found}, key=list(FORM_TEXT).index)
        return (
            self.finding(
                "`npm install` "
                + "; ".join(FORM_TEXT[form] for form in forms)
                + ". The payload is not in the registry tarball, so no rule reads it: unwanted"
                " when an install hook does it (decision 0015, 2026-11-10).",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=f"[{form}] {text}",
                    )
                    for form, path, line, text in _first_per_form(found)[:MAX_SHOWN]
                ),
            ),
        )


FORM_TEXT: Final = {
    "fetch": "downloads from a third-party host (not the package's repository, its owner's "
    "repositories, its homepage or its vendor)",
    "tool": "runs a tool that fetches third-party code (browsers, Python, Rust, Go or Ruby "
    "packages, agent skills, models)",
    "npx": "has npx download and run a package that is not one of its dependencies",
    "npm": "installs packages that are not its dependencies",
    "own": "downloads the package's own files from its own host (its repository's releases, "
    "its homepage or vendor host), outside the registry",
    "downloader": "downloads a file from a host it builds at run time and unpacks it or makes "
    "it executable",
    "prebuilt": "downloads a native prebuilt (`prebuild-install`, `node-pre-gyp install`)",
    "exe": "runs a Windows executable or installer (decision 0015: unwanted at best)",
    "guard": "has npx download and run a package-manager guard (`only-allow`) that is not one "
    "of its dependencies",
}


def _where(text: str, start: int, end: int) -> tuple[int, str]:
    line = text.count("\n", 0, start) + 1
    snippet_text = " ".join(text[max(0, start - SNIPPET_RADIUS) : end + SNIPPET_RADIUS].split())
    return line, snippet_text


def _first_per_form(found: list[Found]) -> list[Found]:
    seen: set[str] = set()
    out = []
    for item in sorted(found, key=lambda f: list(FORM_TEXT).index(f[0])):
        if item[0] not in seen:
            seen.add(item[0])
            out.append(item)
    return out


RULES: Final = (InstallDownload(),)
