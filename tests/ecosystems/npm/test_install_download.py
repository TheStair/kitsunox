"""`npm.install-download` on small, inert install files (nothing here runs or downloads)."""

import json
from typing import Any

import pytest

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.ecosystems.npm.rules.install_download import (
    InstallDownload,
    download_source,
    downloads,
    hook_text,
    vendor_host,
)
from kitsunox.lang.javascript import handed_to_runner
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
RULE = InstallDownload()
OWN: dict[str, Any] = {
    "repository": {"type": "git", "url": "git+https://github.com/kxorg/kx.git"},
    "homepage": "https://kx.dev",
}


def hooked(
    files: dict[str, bytes],
    hook: str = "node setup.js",
    base: bool = False,
    manifest: dict[str, Any] | None = None,
) -> CodeChange:
    meta = {**(manifest or {}), "scripts": {"postinstall": hook}}
    tree = {"package.json": json.dumps(meta).encode(), **files}
    snap = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
        publish=PublishInfo(),
        manifest=meta,
    )
    return code_change(snap, tree, tree if base else None, CACHE, install_sources, "1.0.0")


def forms(
    code: bytes,
    path: str = "setup.js",
    manifest: dict[str, Any] | None = None,
    network: bool = True,
) -> list[str]:
    found = downloads({path: code}, manifest if manifest is not None else OWN, "kx", network)
    return sorted({form for form, *_ in found})


def hook_forms(command: str, manifest: dict[str, Any] | None = None) -> list[str]:
    meta = {**(manifest or {}), "scripts": {"postinstall": command}}
    return sorted({form for form, *_ in downloads({}, meta, "kx", False)})


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/kxorg/kx/releases/download/v1.0.1/kx.tar.gz",  # declared repository
        "https://github.com/kxorg/kx-bin/releases/download/v1/kx.zip",  # same owner
        "https://raw.githubusercontent.com/kxorg/kx/main/install.sh",
        "https://kx.dev/dl/kx-linux.tar.gz",  # homepage host
        "https://objects.githubusercontent.com/x/y.zip",  # GitHub's release asset host
        "https://github.com/${repo}/releases/download/v1/kx.zip",  # an owner built at run time
    ],
)
def test_own_sources(url: str) -> None:
    assert download_source(url, OWN, "kx") == "own"


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/caddyserver/caddy/releases/download/v2/caddy.tar.gz",
        "https://raw.githubusercontent.com/supabase/splinter/abc/splinter.sql",
        "https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip",
        "https://huggingface.co/x/y/resolve/main/model.onnx",
    ],
)
def test_third_party_sources(url: str) -> None:
    assert download_source(url, OWN, "kx") == "third-party"


@pytest.mark.parametrize(
    "url",
    [
        "https://registry.npmjs.org/@kx/linux-x64/-/linux-x64-1.0.1.tgz",
        "https://mirror.example.invalid/@kx/linux-x64/-/linux-x64-1.0.1.tgz",  # a registry path
        "https://github.com/kxorg/kx/issues",  # a page link
        "https://${host}/kx.tar.gz",  # a host built at run time
        "http://localhost:8080/x.zip",
    ],
)
def test_not_a_download_from_outside_the_registry(url: str) -> None:
    assert download_source(url, OWN, "kx") is None


def test_vendor_host_from_scope_name_and_homepage() -> None:
    """The vendor's host when the scope, repository owner or homepage show the same
    organisation (`@abacus-ai/cli` from `static.abacus.ai`): 'own', still a download."""
    assert vendor_host("static.abacus.ai", {}, "@abacus-ai/cli")
    assert vendor_host("cdn.statuz.app", {}, "statuz-cli")
    assert vendor_host("releases.groupdocs.com", {}, "@groupdocs/groupdocs.comparison")
    assert not vendor_host("www.gyan.dev", {}, "@pro-gram/flux")
    assert not vendor_host("cdn.example-tools.com", {}, "kx")  # too short a name to compare
    author = {"author": {"name": "Tai Kimura"}}
    url = "https://raw.githubusercontent.com/Tai-Kimura/jsonui-cli/v1/defs.json"
    assert download_source(url, author, "jui-tools") == "own"


def test_download_urls_in_install_code() -> None:
    """The owner's strict ruling (2026-11-10): own (`own`) and third-party (`fetch`)
    downloads both count, told apart (`@themost/sqlite`: sqlean from `nalgeon/sqlean`)."""
    code = b'const url = "https://github.com/nalgeon/sqlean/releases/download/0.29.0/x.zip";\n'
    assert forms(code) == ["fetch"]
    assert forms(code, network=False) == []  # a URL kept by code that never reaches the network
    own = b'const u = "https://github.com/kxorg/kx/releases/download/v1.0.1/kx.zip";\n'
    assert forms(own) == ["own"]
    page = b'const DOCS = "https://github.com/nalgeon/sqlean/issues"\n'
    assert forms(page) == []  # a page link, not a download
    message = b'console.log("get https://github.com/nalgeon/sqlean/releases/download/x.zip")\n'
    assert forms(message) == []
    registry = b'get("https://registry.npmjs.org/@kx/linux-x64/-/linux-x64-1.0.1.tgz")\n'
    assert forms(registry) == []  # S1's fallback: the package's own platform package
    cargo_dist = {**OWN, "artifactDownloadUrls": ["https://github.com/kxorg/kx/releases/x.tgz"]}
    assert forms(b"run()\n", manifest=cargo_dist) == ["own"]


def test_a_downloader_with_a_host_built_at_run_time() -> None:
    """`msedgedriver@156.0.0` (unwanted) names only its CDN's root; `onpod` builds its URL."""
    code = (
        b'const https = require("https"), fs = require("fs");\n'
        b"https.get(base + file, (res) => res.pipe(fs.createWriteStream(dest)));\n"
        b"extractZip(dest, { dir });\n"
    )
    assert forms(code) == ["downloader"]
    registry = code + b'const REGISTRY = "https://registry.npmjs.org/";\n'
    assert forms(registry) == []  # esbuild's platform-package fallback
    assert forms(code.replace(b"extractZip(dest, { dir });\n", b"")) == []  # no unpack


def test_curl_in_hooks_and_scripts() -> None:
    assert hook_forms("curl -fsSL https://get.other.sh/install.sh | bash") == ["fetch"]
    assert hook_forms("curl -fsSL https://kx.dev/install.sh | bash", OWN) == ["own"]
    script = b"#!/bin/sh\nwget -qO- https://dl.other.io/tool.tar.gz | tar xz\n"
    assert forms(script, "install.sh", network=False) == ["fetch"]
    assert forms(b'echo "or run: curl https://dl.other.io/x.sh | sh"\n', "install.sh") == []
    ps = b"Invoke-WebRequest -Uri https://dl.other.io/x.zip -OutFile x.zip\n"
    assert forms(ps, "install.ps1", network=False) == ["fetch"]


def test_hook_messages_and_fallbacks() -> None:
    """`lilia-mcp@0.1.0`'s postinstall only echoes a hint over two lines;
    `mcp-clickup-server`'s `npx tsc` runs only when its shipped `dist/` is missing."""
    assert hook_forms("echo '\n Run \"npx lilia-setup\" to configure\n'") == []
    assert hook_forms("test -f dist/index.js || npx tsc") == []
    assert "npx" in hook_text("npm run build && npx tsc")


def test_tools_that_fetch_third_party_code() -> None:
    """`playwright install chromium` started by the package's own hook (`phloem-ai`,
    `autorunqa-runner`, unwanted), `pip install`, `npx skills add` (`boost-uxdesign`)."""
    deps = {"dependencies": {"playwright": "^1"}}
    assert hook_forms("playwright install chromium", deps) == ["tool"]
    assert hook_forms("npx playwright install chromium", deps) == ["tool"]
    assert hook_forms("python3 -m pip install -r requirements.txt") == ["tool"]
    argv = b'spawnSync("npx", ["playwright", "install", "chromium"])\n'
    assert forms(argv, manifest={**OWN, **deps}) == ["tool"]
    assert forms(argv) == ["npx", "tool"]  # not a dependency: npx downloads playwright too
    assert forms(b'execSync("cargo install ripgrep")\n') == ["tool"]
    assert forms(b'console.log("Run: npx playwright install chromium")\n') == []
    assert forms(b'const HINT = { cmd: "pip install foo" };\n') == []  # kept as data
    assert forms(b'const HINT = "cargo install kx";\nshow(HINT)\n') == []  # never run
    assert forms(b'const CMD = "cargo install kx";\nexecSync(CMD)\n') == ["tool"]
    assert forms(b'spawnSync(bin, ["skills", "install"])\n') == []  # the package's own CLI
    assert hook_forms("prebuild-install || node-gyp rebuild") == ["prebuilt"]


def test_npx_of_a_package_that_is_not_a_dependency() -> None:
    """npx downloads and runs a package that isn't installed with this one
    (`torlnk@1.11.0`: `npx --yes cmake-js build`); a dependency's bin runs locally."""
    assert hook_forms("npx --yes cmake-js build") == ["npx"]
    assert hook_forms("npx cmake-js build", {"dependencies": {"cmake-js": "^7"}}) == []
    assert hook_forms("npx tsc", {"dependencies": {"typescript": "^5"}}) == []
    assert hook_forms("npx node-gyp rebuild") == []  # npm brings node-gyp
    assert hook_forms("npx kx setup") == []  # the package itself
    assert forms(b'spawn("npx", ["-y", "skills", "add", repo])\n') == ["npx", "tool"]
    written = b'pkg.scripts.test = "npx vitest run";\nwrite(pkg)\n'
    assert forms(written) == []  # written into a file, not run


def test_package_manager_guard_is_its_own_form() -> None:
    """`npx only-allow pnpm` (`vite-plugin-console-banner@0.1.2`, unwanted): its own form, so
    the owner can drop it (`GUARDS_COUNT`)."""
    assert hook_forms("npx only-allow pnpm") == ["guard"]
    assert hook_forms("npx -y only-allow npm") == ["guard"]


def test_npm_install_of_packages_that_are_not_dependencies() -> None:
    """`98router@0.5.112` (unwanted) npm-installs `sql.js` into its own runtime directory."""
    code = b'execSync("npm install sql.js better-sqlite3 --prefix " + dir)\n'
    assert forms(code) == ["npm"]
    deps = {"dependencies": {"sql.js": "^1", "better-sqlite3": "^9"}}
    assert forms(code, manifest=deps) == []
    assert forms(b'execSync("npm install --omit=dev")\n') == []
    assert forms(b"throw new InstallerError(`npm install -g failed: ${e}`)\n") == []


def test_handed_to_runner() -> None:
    code = b'const a = "x y";\nexecSync(a);\nconst b = "z";\nlog(b);\nspawn("p", ["-c", "q"]);\n'
    assert handed_to_runner(code, "javascript", code.index(b"x y"))
    assert not handed_to_runner(code, "javascript", code.index(b'"z"') + 1)
    assert handed_to_runner(code, "javascript", code.index(b'"q"') + 1)
    assert not handed_to_runner(b"x = 1;\n", "javascript", 0)  # not a string


def test_windows_executables_run_at_install() -> None:
    """Decision 0015 (2026-11-10): an install hook that runs a Windows executable is unwanted at
    best (`@pro-gram/drumbuddy`'s bundled `DrumBuddy-Setup.exe`, `rvm-windows`'s
    `Start-Process` of its setup); the shells that run install code are not."""
    js = b"const installer = path.resolve(__dirname, 'payload', 'Setup.exe');\n"
    assert forms(js + b"execFileSync(installer, ['--update-app']);\n") == ["exe"]
    assert forms(js + b"console.log(installer);\n") == []
    ps = b"$setup = Join-Path $PSScriptRoot 'kx-setup.exe'\nStart-Process -FilePath $setup /S\n"
    assert forms(ps, "install.ps1", network=False) == ["exe"]
    assert hook_forms("bin\\setup.exe /S") == ["exe"]
    assert hook_forms("msiexec /i kx.msi /quiet") == ["exe"]
    assert hook_forms("powershell.exe -NoProfile -File install.ps1") == []
    assert hook_forms("node.exe setup.js") == []
    # Windows' own tools and toolchains (`@lifeaitools/build-corpus`'s `where.exe`, a `case`
    # label in `@dream-encode/wp-build-tools`, `locus-cli`'s `cargo.exe`) are no installer.
    assert forms(b'spawnSync("where.exe", ["kx"])\n') == []
    assert forms(b'  "7z.exe"|"7z") zip ;;\n', "build.sh", network=False) == []
    cargo = b'const cargo = win ? "cargo.exe" : "cargo";\nexecFileSync(cargo, ["build"]);\n'
    assert forms(cargo) == []


def test_playwright_cli_run_by_path_and_curl_in_a_child_process() -> None:
    """`@myagentroam/node@0.12.1` runs Playwright's `cli.js install chromium` with `node`;
    `@openlatch/client@0.11.7` downloads its binary with `curl` in a child process (no
    `network` capability)."""
    run = b"run(process.execPath, [cli, 'install', 'chromium', '--no-shell'])\n"
    assert forms(run, network=False) == ["tool"]
    curl = (
        b"const url = `https://github.com/kxorg/kx/releases/download/v${v}/kx.tgz`;\n"
        b'execSync(`curl -fSL -o "${dest}" "${url}"`);\n'
    )
    assert forms(curl, network=False) == ["own"]
    # An HTTP client package (`@ghyper9023/u2secure`: `follow-redirects`), `fetch` passed on
    # (`@qwen-code/cua-sdk`), and a template call in the URL (`@usetrim/trim`: `${repo()}`).
    client = b"const { https } = require('follow-redirects');\n" + curl.split(b"\n")[0] + b"\n"
    assert forms(client, network=False) == ["own"]
    passed = (
        b'const BASE = "https://github.com/kxorg/kx/releases/download";\nf(fetchImpl = fetch)\n'
    )
    assert forms(passed, network=False) == ["own"]
    called = b"const base = `https://github.com/${repo()}/releases/download/${tag}`;\n"
    assert forms(called) == ["own"]


def test_a_command_word_only_shown_is_no_network() -> None:
    """v2 (P2): `@gloom-sh/terminal@0.20.8`'s preinstall returns a help line naming `curl`
    and `irm` installers and never fetches; the URL it keeps is then no download. A command
    word handed to a runner, or anywhere in a hook line or a shell script, still counts."""
    message = (
        b"function missingBunMessage(platform = process.platform) {\n"
        b'  return platform === "win32"\n'
        b'    ? "Install Bun (powershell -c \\"irm bun.sh/install.ps1 | iex\\") or: irm'
        b' https://gloom.sh/install.ps1 | iex"\n'
        b'    : "Install Bun (curl -fsSL https://bun.sh/install | bash) or: curl -fsSL'
        b' https://gloom.sh/install | bash";\n'
        b"}\n"
    )
    assert forms(message, network=False) == []
    assert forms(message) == ["fetch"]  # install code that reaches the network otherwise
    run = b'const u = "https://dl.other.io/x.sh";\nexecSync("curl -fsSL " + u + " | sh");\n'
    assert forms(run, network=False) == ["fetch"]
    shell = b'#!/bin/sh\nmsg="curl"\nX=https://dl.other.io/x.tar.gz\n'
    assert forms(shell, "install.sh", network=False) == ["fetch"]
    fetched = b'const u = "https://dl.other.io/x.tgz";\nawait fetch(u);\n'
    assert forms(fetched, network=False) == ["fetch"]


def test_the_rule_reports_with_evidence_changed_or_not() -> None:
    url = b"https://github.com/mutagen-io/mutagen/releases/download/v1/m.tgz"
    code = b'require("https").get("' + url + b'")\n'
    (finding,) = RULE.evaluate_code(hooked({"setup.js": code}, manifest=OWN))
    assert (finding.rule_id, finding.severity, finding.weight) == (
        "npm.install-download",
        Severity.MEDIUM,
        3.0,
    )
    assert "third-party host" in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [("setup.js", 1)]
    assert finding.evidence[0].snippet is not None
    assert finding.evidence[0].snippet.startswith("[fetch] ")
    # Unchanged install code counts too (`ONLY_WHEN_CHANGED` is off under the strict ruling).
    assert RULE.evaluate_code(hooked({"setup.js": code}, base=True, manifest=OWN)) != ()
    own = code.replace(b"mutagen-io/mutagen", b"kxorg/kx")
    (finding,) = RULE.evaluate_code(hooked({"setup.js": own}, manifest=OWN))
    assert "own host" in finding.explanation
    assert RULE.evaluate_code(hooked({"setup.js": b"run()\n"}, manifest=OWN)) == ()
