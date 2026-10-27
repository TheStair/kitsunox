"""Tier 0 — deterministic detection. No LLM, runs on every change (docs/Plan.md §4).

Two families of signal:

  *Content* rules scan the added lines of each diff hunk for payload-shaped code —
  encoded blobs, shell execution, exfiltration, unbounded loops.
  *Context* rules look at paths and review metadata — which files a change touches, who
  merged it, whether CI passed.

Neither family is worth much alone. A base64 literal is ordinary in a lockfile; an
install script changing is ordinary in any active repo. What distinguishes the five
known incidents is *co-occurrence* — an encoded blob inside an install script, a binary
landing in a test-fixture directory — so `COMBOS` re-scores those pairings above the sum
of their parts.

Tuning is meant to happen in the tables at the top (`SEVERITY_WEIGHT`,
`ESCALATION_THRESHOLD`, the pattern lists), not in the rule bodies.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterator

from kitsunox.model import Change, FileDiff, Finding, Severity

# --------------------------------------------------------------------------- tuning

SEVERITY_WEIGHT: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 8,
    "critical": 15,
}

# Score at or above which a change is escalated to Tier 2. Deliberately low enough that
# a single `high` finding escalates — Tier 2 is cheap relative to a missed incident, and
# §7's cost accounting is what tells us whether this threshold was set sanely.
ESCALATION_THRESHOLD = 8

EVIDENCE_MAX_CHARS = 120

# Tenure below which an author counts as new to a repo. 30 days is not a fine-grained
# threshold — measured on the control corpus, 56% of benign PR authors fall under it,
# because popular repos run on first-time contributors. It is only useful in combination
# (see COMBOS), never alone.
NEW_CONTRIBUTOR_DAYS = 30

# A longer window applies to direct pushes. event-stream's attacker was 5 days and 9
# commits in when he pushed; xz's was 2 years and 431 commits in, which is exactly why
# the long con worked and why no tenure threshold can catch it.
NEW_PUSHER_DAYS = 90
NEW_PUSHER_COMMITS = 25

# How established a repository must be when the author arrives for them to count as a
# newcomer to it. Not fitted to data: founders arrive on day 0, event-stream's attacker
# on day ~2,500, and six months is a plain reading of "an established project".
ESTABLISHED_REPO_DAYS = 180

# --------------------------------------------------------------------------- paths

CI_PATHS = (".github/workflows/", ".github/actions/", ".gitlab-ci", "azure-pipelines")

BUILD_SCRIPT_NAMES = {
    "makefile", "configure", "configure.ac", "cmakelists.txt", "setup.py", "binding.gyp",
    "install.sh", "build.sh", "postinstall.js", "preinstall.js", "setup.cfg", "meson.build",
}
BUILD_SCRIPT_DIRS = ("m4/", "scripts/", "build-aux/")

# Generated output. A human editing these by hand — rather than regenerating them — is
# how tj-actions hid its payload, since nobody reviews a rebuilt bundle line by line.
ARTIFACT_DIRS = ("dist/", "build/", "out/")
ARTIFACT_SUFFIXES = (".min.js", ".bundle.js")

TEST_FIXTURE_DIRS = ("test/", "tests/", "testdata/", "fixtures/", "__fixtures__/", "spec/")

# Third-party code committed into the repository. Its patterns are its upstream author's,
# not this change's: one vendored `node_modules/` tree scored 40 on the first holdout hunt
# from es-abstract and yargs alone. It is reported once per change, not scanned line by
# line. Known evasion, stated: a payload hidden under one of these paths is not scanned.
VENDORED_DIRS = ("node_modules/", "vendor/", "third_party/", "bower_components/")

# Documentation. A commit that changes nothing else cannot change what a consumer runs.
DOC_SUFFIXES = (".md", ".markdown", ".rst", ".txt", ".adoc")
DOC_NAMES = ("readme", "license", "licence", "changelog", "contributing", "authors",
             "notice", "code_of_conduct", "security")

# Prose nothing executes -- not npm, not a runner. A README telling users to add a scope
# to their `.npmrc`, or to `cat ~/.ssh/id_ed25519.pub`, escalated four commits on the
# round-2 targets as credential theft. Instruction files for coding agents are the
# exception: an agent does act on them, so a Markdown file that tells one to read
# ~/.npmrc and post it to a webhook is a payload.
PROSE_SUFFIXES = (".md", ".markdown", ".rst", ".adoc")
AGENT_INSTRUCTION_NAMES = {"agents.md", "claude.md", "gemini.md", "copilot-instructions.md"}

# Binary files that can carry a payload: executables, native modules, archives and raw
# or compressed data. In a JavaScript, TypeScript or Actions repository nothing in this
# list has a reason to arrive without explanation, and none of it can be reviewed as a
# diff. Compressed formats are included because that is exactly what xz's fixtures were.
OPAQUE_BINARY_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".node", ".wasm", ".o", ".a", ".elf", ".jar", ".class",
    ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".lzma", ".zst", ".7z", ".rar",
    ".bin", ".dat",
}

# Images, fonts, documents and media. Routine in any repository -- logos, icons, visual
# snapshot tests -- so they are reported for context but never treated as a capability.
MEDIA_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".avif", ".icns",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".mp3", ".mp4", ".webm", ".ogg", ".wav", ".mov",
    # Office documents: test inputs for a converter (shelfio/aws-lambda-libreoffice) and
    # specs in a docs folder. A consumer of the package never opens them.
    ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods", ".odp", ".rtf",
}

MANIFESTS = {"package.json", "requirements.txt", "pyproject.toml", "gemfile", "cargo.toml", "go.mod"}

# Base64 `integrity` hashes make lockfiles a guaranteed false positive for the
# encoded-blob rule, and their contents are derived from the manifest anyway.
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock",
    "uv.lock", "gemfile.lock", "composer.lock", "go.sum", "pipfile.lock",
    "packages.lock.json", "npm-shrinkwrap.json",
}

# --------------------------------------------------------------------------- patterns

# A base64 run this long is a payload, not an identifier or a hash. Tuned above the
# length of a sha512 integrity field (~88 chars) with margin.
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

# What a base64 literal decodes to, by its first bytes. Bundlers inline WebAssembly, images
# and fonts as base64 -- undici's HTTP parser ships as `AGFzbQ...` ("\0asm") in every
# bundle that includes it -- and those are data, not a script waiting to be decoded and
# run. The reviewdog and tj-actions payloads decoded to shell and Python text.
EMBEDDED_ASSET_MAGIC = {
    b"\x89PNG": "a PNG image", b"\xff\xd8\xff": "a JPEG image", b"GIF8": "a GIF image",
    b"wOFF": "a WOFF font", b"wOF2": "a WOFF2 font", b"OTTO": "an OpenType font",
    # `//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjoz...`: an inline
    # source map, JSON that no runtime executes.
    b'{"version":3': "an inline source map",
}
# WebAssembly is executable, so it only counts as an inlined asset inside a generated
# bundle, where a bundler put it; anywhere else it stays an encoded blob.
EMBEDDED_WASM_MAGIC = b"\x00asm"

# `atob` is a case-sensitive JavaScript name and a whole word: a transliterated Bible in
# anonyco's test data has "atoB" and "aTOB" as words.
DECODE_CALLS = re.compile(
    r"\b(base64\s+(-d|--decode|-D)|(?-i:atob)\b|b64decode|Buffer\.from\s*\([^)]*base64|"
    r"FromBase64String)",
    re.IGNORECASE,
)

# `eval("require")` -- the idiom bundlers use to hide a require from static analysis --
# evaluates a fixed name, not code; it alone escalated a hand-built dist/ commit. An eval
# whose argument is anything other than a bare identifier in quotes still counts.
SHELL_EXEC = re.compile(
    r"(\bchild_process\b|\bexec\.getExecOutput\b|\bexecSync\b|\bspawnSync\b|"
    r"\bsubprocess\.(run|Popen|call)\b|\bos\.system\b|"
    r"\beval\s*\((?!\s*(?P<q>[\"'])[A-Za-z_$][\w$]*(?P=q)\s*\))|\bnew\s+Function\s*\(|"
    r"\|\s*(bash|sh|python3?)\b)"
)

NETWORK_FETCH = re.compile(
    r"\b(curl|wget|urllib\.request|requests\.(get|post)|fetch\s*\(|Invoke-WebRequest)",
    re.IGNORECASE,
)

# Hosts that serve attacker-controlled content or collect out-of-band callbacks, and
# appear in no legitimate build step. The OOB-interaction domains (burpcollaborator,
# canarytokens, interact.sh and friends) are how a large share of npm install-hook
# malware beacons home — often the entire payload is a DNS lookup to one of these.
SUSPICIOUS_HOST = re.compile(
    r"(gist\.githubusercontent\.com|pastebin\.com|transfer\.sh|ngrok\.io|"
    r"burpcollaborator\.net|canarytokens\.com|interact\.sh|oast\.(fun|pro|live|site|online)|"
    r"dnslog\.cn|requestbin\.\w+|pipedream\.net|webhook\.site|\.onion\b)",
    re.IGNORECASE,
)

# A bare dotted quad is only an address when it is *used* as one. `zlib 1.2.0.4` and
# `strcmp(v, "1.2.0.4")` in curl are version numbers, and no amount of octet validation
# separates them from an IP -- 1.2.0.4 is a perfectly valid address. Context does:
# exfiltration writes a scheme, a port, or a fetch verb in front of the address.
ROUTABLE_IP_IN_USE = re.compile(
    r"(?:https?://|ftp://|@|\b(?:curl|wget|nc|telnet|ssh|ping|connect|dial|Dial)\s+"
    r"[\"\']?)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    r"|(?P<ip2>\d{1,3}(?:\.\d{1,3}){3}):\d{2,5}\b",
    re.IGNORECASE,
)

# npm lifecycle hooks that execute automatically on `npm install`, with no user action
# and no review. This is the dominant npm attack vector and it is invisible to every
# path-based build-script check, because it lives inside package.json rather than in a
# file with a recognisable name.
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")

# Output redirection inside an install hook. Legitimate build steps want their logs.
SILENCED = re.compile(r">\s*/dev/null|2>&1|\s-s\s|--silent|>\s*nul\b", re.IGNORECASE)

# Host/user/network reconnaissance — the first stage of a beacon that reports who it
# landed on. Harmless alone, meaningful next to an outbound request.
RECON = re.compile(
    r"\b(hostname|whoami|os\.userInfo|os\.hostname|HOSTNAME|USERPROFILE|"
    r"ifconfig|ipconfig|uname\s+-a|process\.cwd\(\)|USERDOMAIN)\b"
)

# Loopback, RFC1918, link-local and broadcast. Test suites are full of these — axios
# alone added 20+ `127.0.0.1` lines in a single proxy-test PR — and none of them can
# reach an attacker. Exfiltration needs a routable address. The RFC 5737 documentation
# ranges route nowhere by definition: `203.0.113.10` in a Juror-AI test fixture
# escalated a feature commit as credential exfiltration.
PRIVATE_IP = re.compile(
    r"^(0\.|127\.|10\.|192\.168\.|169\.254\.|255\.|172\.(1[6-9]|2\d|3[01])\.|"
    r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)"
)

# Reaching into a credential store or a process's memory, or dumping the whole
# environment. That is theft-shaped in any repository: no ordinary change reads ~/.npmrc
# or /proc/<pid>/mem. Both Actions incidents stole secrets by scraping runner memory.
# The /proc match spans the line rather than requiring a contiguous path, because
# '/proc/' + pid + '/mem' and os.path.join('/proc', pid, 'mem') are trivial evasions of
# a contiguous pattern; word boundaries keep /proc/meminfo and "memory" out.
# Key files are matched as names, not substrings: `config/deploy_id_rsa` is a key an
# action decrypted into its own working tree, and `id_ed25519.pub` is a public key.
SECRET_ACCESS = re.compile(
    r"(\.npmrc|~/\.aws|\.aws/credentials|(?<![\w-])id_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|"
    r"\.git-credentials|\.netrc\b|"
    r"\.docker/config\.json|/proc\b.*\b(mem|maps|environ)\b)"
)
# The whole environment serialised or sent: `JSON.stringify(process.env)`,
# `requests.post(url, json=dict(os.environ))`. Handing it to an ordinary function --
# `normalizeEnv(process.env)` -- is how CI detection works and escalated a 2019 commit;
# collection needs a sink in the same statement. One variable (`process.env.TOKEN`) is
# not the whole environment.
ENV_DUMP = re.compile(
    r"\b(stringify|dumps?|btoa|b64encode|fetch|post|put|send|write\w*|request|urlopen|emit)"
    r"\s*\([^;]*?\b(process\.env|os\.environ)\b(?!\s*[.\[])"
)

# Naming a token. In an Action, GITHUB_TOKEN is the credential the action is supposed to
# use; in an npm repo, NPM_TOKEN is how publishing works. As `secret_access` these matched
# doc comments, test fixtures and `${{ secrets.GITHUB_TOKEN }}`, and were the sole
# evidence for 14 of the 40 alerts in the first Actions hunt. Using a token is not the
# attack -- sending it somewhere is -- so this only counts as one half of the
# credential-exfiltration combo, and sits outside the capability model.
TOKEN_REFERENCE = re.compile(
    r"\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY|"
    r"AWS_ACCESS_KEY_ID|AWS_SECRET|AWS_ACCESS_KEY|ACTIONS_RUNTIME_TOKEN|"
    r"ACTIONS_ID_TOKEN_REQUEST_TOKEN)\b"
)

# `< Infinity` is the colors.js sabotage and has no legitimate use. `while (true)` is a
# different matter: with a break inside it is the standard shape of a C, C++ and Go parse
# loop, and it produced two of the eight false positives on the held-out corpus, both in
# nlohmann/json. It only counts when nothing in the same file can leave the loop.
# Bound to a loop header: `if (startIndex < Infinity && ...)` is a range check, and a
# bundled copy of one fired on a holdout initial-release commit.
UNBOUNDED_LOOP = re.compile(r"\b(for|while)\s*\(.*<\s*Infinity")
WHILE_FOREVER = re.compile(r"while\s*\(\s*(true|1)\s*\)|\bloop\s*\{|for\s*\(\s*;\s*;\s*\)")
LOOP_ESCAPE = re.compile(r"\b(break|return|goto|exit|panic|throw|yield)\b")

DEPENDENCY_ADDED = re.compile(r"^\s*[\"']?(?P<name>[\w@./-]+)[\"']?\s*[:=]\s*[\"'][\^~>=<\d]")

# Sections of package.json whose entries are packages. The line pattern alone matched any
# key with a version-shaped value -- `"version": "13.7.0"`, `"node": ">=20"` -- and was the
# only evidence for one holdout alert and thirty bullets of another.
DEPENDENCY_SECTIONS = {
    "dependencies", "devdependencies", "peerdependencies", "optionaldependencies",
    "bundleddependencies", "bundledependencies", "overrides", "resolutions",
}
# Keys that take a version-shaped value and are not packages. Used where a hunk does not
# show which section a line sits in.
NOT_DEPENDENCIES = {
    "version", "name", "node", "npm", "yarn", "pnpm", "bun", "deno", "vscode", "python",
    "requires-python", "edition", "rust-version", "go", "packagemanager",
}
JSON_SECTION_OPEN = re.compile(r'^\s*"(?P<key>[^"]+)"\s*:\s*[{\[]\s*$')
JSON_SECTION_CLOSE = re.compile(r"^\s*[}\]],?\s*$")

# The whole environment handed to a child process -- `env=dict(os.environ)`,
# `{env: process.env}` -- is how a subprocess inherits PATH. It is not collection, and it
# was the sole high finding of one holdout alert. The environment *sent* somewhere still is.
ENV_PASS_THROUGH = re.compile(
    r"\benv\s*[=:]\s*(dict\s*\(\s*|\{\s*\*\*\s*|\{\s*\.\.\.\s*)?(os\.environ|process\.env)\b"
)

# --------------------------------------------------------------------------- helpers


def _added_lines(file: FileDiff) -> Iterator[tuple[int, str]]:
    """Yield (line number in the new file, text) for each added line of a patch.

    Only added lines are scanned. Removed lines are what a change took *away*, which
    can't be the payload — and scanning them would double-count every revert.
    """
    lineno = 0
    for raw in file.patch.split("\n"):
        header = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)", raw)
        if header:
            lineno = int(header.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            yield lineno, raw[1:]
            lineno += 1
        elif not raw.startswith("-"):
            lineno += 1


def _removed_lines(file: FileDiff) -> Iterator[str]:
    """Yield the text of each line a patch removed."""
    for raw in file.patch.split("\n"):
        if raw.startswith("-") and not raw.startswith("---"):
            yield raw[1:]


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].lower()


def _evidence(text: str) -> str:
    text = text.strip()
    return text[:EVIDENCE_MAX_CHARS] + ("..." if len(text) > EVIDENCE_MAX_CHARS else "")


def _is_ci(path: str) -> bool:
    return any(seg in path.lower() for seg in CI_PATHS)


def _is_build_script(path: str) -> bool:
    low = path.lower()
    return _basename(path) in BUILD_SCRIPT_NAMES or low.startswith(BUILD_SCRIPT_DIRS)


def _is_artifact(path: str) -> bool:
    low = path.lower()
    return low.startswith(ARTIFACT_DIRS) or low.endswith(ARTIFACT_SUFFIXES)


def _binary_kind(path: str) -> str:
    """'opaque', 'media' or 'other' for a binary file, by name alone.

    A file with no extension at all is opaque: a dropped executable is usually named
    `run`, `helper` or `payload`, not `payload.exe`.
    """
    name = _basename(path)
    if "." not in name.lstrip("."):
        return "opaque"
    suffix = "." + name.rsplit(".", 1)[-1]
    if suffix in OPAQUE_BINARY_SUFFIXES:
        return "opaque"
    if suffix in MEDIA_SUFFIXES:
        return "media"
    return "other"


def _is_test_fixture(path: str) -> bool:
    return any(seg in path.lower() for seg in TEST_FIXTURE_DIRS)


def _is_vendored(path: str) -> bool:
    low = "/" + path.lower()
    return any("/" + seg in low for seg in VENDORED_DIRS)


def _is_doc(path: str) -> bool:
    # A doc name only counts without a code suffix: `src/security.js` is code, and
    # `CMakeLists.txt` is a build script whatever its suffix says.
    name = _basename(path)
    if name in BUILD_SCRIPT_NAMES:
        return False
    return (name.endswith(DOC_SUFFIXES) or path.lower().startswith("docs/")
            or ("." not in name and name in DOC_NAMES))


def _is_prose(path: str) -> bool:
    name = _basename(path)
    return (name.endswith(PROSE_SUFFIXES) or ("." not in name and name in DOC_NAMES)) \
        and name not in AGENT_INSTRUCTION_NAMES


def _embedded_asset(blob: str, in_bundle: bool) -> str | None:
    """What kind of inlined asset a base64 literal is, or None if it is not one."""
    try:
        head = base64.b64decode(blob[:16])
    except (binascii.Error, ValueError):
        return None
    if in_bundle and head.startswith(EMBEDDED_WASM_MAGIC):
        return "a WebAssembly module"
    return next((kind for magic, kind in EMBEDDED_ASSET_MAGIC.items()
                 if head.startswith(magic)), None)


def _secret_access(text: str) -> str | None:
    """The credential-store or environment-dump text on this line, if any."""
    match = SECRET_ACCESS.search(text)
    if match:
        return match.group(0)
    match = ENV_DUMP.search(text)
    if match and not ENV_PASS_THROUGH.search(text):
        return match.group(0)
    return None


# A four-part version number is indistinguishable from an IP address by shape alone:
# `"version": "==3.4.0.3"` in psf/requests' Pipfile.lock was the only false positive in
# the whole direct-push control sample. Context is what separates them.
VERSION_CONTEXT = re.compile(r"(==|>=|<=|~=|\bv|version|release|tag)\s*[\"']?$", re.IGNORECASE)


def _suspicious_host(text: str) -> str | None:
    """The paste/tunnel host, or routable IP used as an address, on this line."""
    named = SUSPICIOUS_HOST.search(text)
    if named:
        return named.group(0)  # a named paste/tunnel host, no ambiguity
    match = ROUTABLE_IP_IN_USE.search(text)
    if not match:
        return None
    ip = match.group("ip") or match.group("ip2")
    return None if PRIVATE_IP.match(ip) else ip


def _hits_suspicious_host(text: str) -> bool:
    """True for a paste/tunnel host, or a routable IP being used as an address."""
    return _suspicious_host(text) is not None


def _scannable(file: FileDiff) -> bool:
    # Source maps are derived like lockfiles and never executed, but embed copies of every
    # bundled dependency's source: one map was a single line holding a `for (... <
    # Infinity ...)` from a library, and escalated an initial release as sabotage.
    return (not file.is_binary and _basename(file.path) not in LOCKFILES
            and not file.path.lower().endswith(".map") and not _is_prose(file.path)
            and not _is_vendored(file.path) and bool(file.patch))


# --------------------------------------------------------------------------- content rules


def _install_hook_rules(change: Change) -> list[Finding]:
    """Inspect npm lifecycle hooks declared in package.json.

    These run automatically on `npm install`, before any human reads a line of the code,
    and they are where most npm package malware lives. Measured on the ASE 2026 corpus,
    67% of malicious packages declare one — so the hook's *existence* is far too common
    to accuse on its own (node-gyp builds declare them too). What the hook actually does
    is the signal.
    """
    findings: list[Finding] = []
    for file in change.files:
        # A vendored package's own hooks do not run when this repository is installed.
        if _basename(file.path) != "package.json" or file.is_binary or _is_vendored(file.path):
            continue
        body = "".join(
            ln[1:] + "\n" for ln in file.patch.split("\n")
            if ln.startswith("+") and not ln.startswith("+++")
        )
        try:
            scripts = (json.loads(body) or {}).get("scripts") or {}
        except (json.JSONDecodeError, AttributeError):
            continue
        if not isinstance(scripts, dict):
            continue

        for hook in INSTALL_HOOKS:
            command = scripts.get(hook)
            if not isinstance(command, str) or not command.strip():
                continue

            def hit(rule_id: str, severity: Severity, rationale: str) -> None:
                findings.append(
                    Finding(
                        rule_id=rule_id, severity=severity, rationale=rationale,
                        file_path=file.path, evidence=_evidence(f"{hook}: {command}"),
                    )
                )

            hit(
                "content.install_hook", "low",
                f"package.json declares a '{hook}' script, which npm executes "
                "automatically on install with no review and no user action.",
            )
            if NETWORK_FETCH.search(command) or _hits_suspicious_host(command):
                hit(
                    "content.install_hook_network", "high",
                    f"The '{hook}' hook reaches the network at install time, pulling "
                    "unreviewed content onto every consumer's machine.",
                )
            if SHELL_EXEC.search(command) or re.search(r"\bnode\s+(-e|--eval|\S+\.js)", command):
                hit(
                    "content.install_hook_exec", "medium",
                    f"The '{hook}' hook executes code rather than running a declared "
                    "build tool.",
                )
            if B64_BLOB.search(command) or DECODE_CALLS.search(command):
                hit(
                    "content.install_hook_obfuscated", "critical",
                    f"The '{hook}' hook carries or decodes an encoded payload. There is "
                    "no legitimate reason for install-time code to be obfuscated.",
                )
            if SILENCED.search(command):
                hit(
                    "content.install_hook_silenced", "medium",
                    f"The '{hook}' hook discards its own output. Build steps want their "
                    "logs; hiding them conceals what ran.",
                )
            if RECON.search(command):
                hit(
                    "content.install_hook_recon", "medium",
                    f"The '{hook}' hook collects host or user identity — the first stage "
                    "of a beacon reporting where it landed.",
                )
    return findings


def _content_rules(change: Change) -> list[Finding]:
    findings: list[Finding] = []
    for file in change.files:
        # Vendored source is reported once, by _context_rules. An opaque binary is not
        # explained by being vendored -- nobody reviews a .wasm wherever it sits.
        if _is_vendored(file.path) and not (
            file.is_binary and _binary_kind(file.path) == "opaque"
        ):
            continue
        if file.is_binary and file.change_type == "added":
            kind = _binary_kind(file.path)
            in_fixtures = _is_test_fixture(file.path)
            if kind == "media":
                # Reported so the investigator sees it, but a distinct rule id keeps it out
                # of the capability model: as `binary_added` it would count as concealment,
                # and a logo + a new dependency + one subprocess call would score
                # 1 + 1 + 1 + a three-category bonus of 6 = 9 and escalate.
                findings.append(
                    Finding(
                        rule_id="content.asset_added",
                        severity="low",
                        rationale="An image, font or media asset was added. Routine, and "
                        "listed only so the full set of binary additions is visible.",
                        file_path=file.path,
                    )
                )
            else:
                # Opaque binaries escalate on their own anywhere: in a JS, TS or Actions
                # repository an executable, native module or archive has no reason to
                # appear unexplained. Unrecognised binary types keep the older behaviour.
                severity: Severity = "high" if (kind == "opaque" or in_fixtures) else "medium"
                if kind == "opaque" and in_fixtures:
                    rationale = (
                        "An opaque binary was added under a test-fixture path, where a "
                        "corrupt-looking blob is unremarkable and review least likely."
                    )
                elif kind == "opaque":
                    rationale = (
                        "An executable, native module, archive or raw data file was added. "
                        "It cannot be reviewed as a diff, and source repositories rarely "
                        "need one."
                    )
                else:
                    rationale = (
                        "A binary file was added. Binary content cannot be reviewed as a "
                        "diff."
                    )
                findings.append(
                    Finding(
                        rule_id="content.binary_added",
                        severity=severity,
                        rationale=rationale,
                        precedent="xz-utils (CVE-2024-3094), 2024" if in_fixtures else "",
                        file_path=file.path,
                    )
                )
        if not _scannable(file):
            continue
        is_ci_config = _is_ci(file.path)
        in_sensitive = is_ci_config or _is_build_script(file.path) or _is_artifact(file.path)
        # Checked once per file: a `while (true)` with a break somewhere in the same
        # added code is an ordinary loop, not a hang.
        has_escape = any(LOOP_ESCAPE.search(t) for _, t in _added_lines(file))
        baseline = file.baseline or ""
        # A bundle GitHub did show a diff for still moves its dependencies around: the
        # `child_process`, `execSync` and `atob` in three round-2 rebuilds (setup-zig
        # twice, one minified line in Horus) were each on a line the same diff removed.
        # Without the recovered previous version, the removed lines stand in for it.
        # Known evasion, the same as a rebuild's: replacing an existing `execSync(...)`
        # line with a hostile one inside a bundle.
        if file.baseline is None and _is_artifact(file.path):
            baseline = "\n".join(t for t in _removed_lines(file))
        # A generated bundle whose diff was too large for GitHub to show is a rebuild: tens
        # of thousands of lines of bundled dependencies. Their `child_process`, `fetch`,
        # `Buffer.from(x, 'base64')` and `Object.keys(process.env)` are the dependencies'
        # own, and on the first holdout re-hunt they escalated four ordinary dependency
        # upgrades in one repository. In a rebuild only payload-shaped content counts: an
        # encoded script, an exfiltration host, a credential store or process memory, a
        # loop that cannot end. A hand-edited bundle -- tj-actions' -- has a small diff
        # GitHub does show, and keeps every rule. Known evasion: a payload built only from
        # generic primitives inside a large rebuild.
        rebuilt_bundle = file.baseline is not None and _is_artifact(file.path)

        def novel(found: str | re.Match | None) -> bool:
            """Whether a hit is new to the file. Only answerable when `fetch.py` read the
            previous version to rebuild an omitted diff -- a regenerated bundle -- and
            that is where it matters: rebuilding moves every line of a bundle, and the
            `child_process` its dependencies always contained is not news."""
            if found is None:
                return False
            text = found if isinstance(found, str) else found.group(0)
            return not baseline or text not in baseline

        for lineno, text in _added_lines(file):
            def hit(rule_id: str, severity: Severity, rationale: str,
                    precedent: str = "") -> None:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        rationale=rationale,
                        precedent=precedent,
                        file_path=file.path,
                        line=lineno,
                        evidence=_evidence(text),
                    )
                )

            blob = B64_BLOB.search(text)
            asset = _embedded_asset(blob.group(0), _is_artifact(file.path)) if blob else None
            if asset and novel(blob):
                # Outside the capability model, like content.asset_added.
                hit(
                    "content.embedded_asset",
                    "low",
                    f"A base64 literal that decodes to {asset} was added -- inlined data, "
                    "listed so every encoded addition is visible.",
                )
            elif novel(blob):
                hit(
                    "content.encoded_blob",
                    "high" if in_sensitive else "medium",
                    "A long base64 literal was added. Encoded content cannot be reviewed "
                    "as a diff, which is what makes it a delivery mechanism.",
                    "reviewdog/action-setup and tj-actions/changed-files, 2025",
                )
            if not rebuilt_bundle and novel(DECODE_CALLS.search(text)):
                hit(
                    "content.decode_call",
                    "medium",
                    "Code that decodes an encoded string was added — benign on its own, "
                    "but the other half of an encoded-payload pair.",
                )
            if not rebuilt_bundle and novel(SHELL_EXEC.search(text)):
                # Not elevated inside CI config: a workflow's whole job is to run shell,
                # so `child_process` in a publish workflow is unremarkable. It stays
                # notable in build/install scripts and generated bundles.
                hit(
                    "content.shell_exec",
                    "high" if (in_sensitive and not is_ci_config) else "low",
                    "A shell/eval execution primitive was added. Ordinary in application "
                    "code and in CI, hard to justify inside a build script or a bundle.",
                )
            if novel(_suspicious_host(text)):
                hit(
                    "content.suspicious_host",
                    "high",
                    "A reference to a paste/tunnel service or a bare IP was added — the "
                    "exfiltration endpoint in both 2025 Actions compromises was a gist.",
                )
            elif in_sensitive and not rebuilt_bundle and novel(NETWORK_FETCH.search(text)):
                hit(
                    "content.network_in_build",
                    "medium",
                    "A network fetch was added to CI config, a build script, or a "
                    "generated bundle, pulling unreviewed content into the build.",
                )
            secret = SECRET_ACCESS.search(text) if rebuilt_bundle else _secret_access(text)
            if isinstance(secret, re.Match):
                secret = secret.group(0)
            # A repository's own `.npmrc` naming itself in a comment is not reaching into
            # anyone's credential store.
            if secret == _basename(file.path):
                secret = None
            if novel(secret):
                hit(
                    "content.secret_access",
                    "high",
                    "Added code reads a credential store, another process's memory, or "
                    "the whole environment -- the collection step of a secret theft.",
                    "reviewdog/action-setup and tj-actions/changed-files, 2025",
                )
            elif not rebuilt_bundle and novel(TOKEN_REFERENCE.search(text)):
                hit(
                    "content.token_reference",
                    "low",
                    "Added code names a CI or registry token. Ordinary on its own -- it is "
                    "how actions and publishing authenticate -- and recorded so that a token "
                    "sent to an attacker-controlled host is caught as exfiltration.",
                )
            if novel(UNBOUNDED_LOOP.search(text)) or (
                novel(WHILE_FOREVER.search(text)) and not has_escape
            ):
                # `high` because it measured clean: zero hits across 45 benign PRs. A
                # deliberately non-terminating loop is rare in reviewed code, and it is
                # the *only* signal colors.js ever emits.
                hit(
                    "content.unbounded_loop",
                    "high",
                    "A loop with no reachable termination was added. Sabotage needs no "
                    "payload — hanging every consumer on import is sufficient.",
                    "colors.js, 2022",
                )
    return findings


def _added_dependencies(file: FileDiff) -> list[tuple[int, str]]:
    """(line, name) for each package a manifest's diff adds.

    In package.json a line counts only inside a dependency section -- tracked through the
    hunk's own context lines -- or, where the hunk does not show its section, when its key
    is not one of the known version-valued settings. A name the same diff removes is a
    version bump, not an addition.
    """
    removed: set[str] = set()
    added: list[tuple[int, str]] = []
    is_json = _basename(file.path) == "package.json"
    lineno, section = 0, None
    for raw in file.patch.split("\n"):
        header = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)", raw)
        if header:
            lineno, section = int(header.group(1)), None
            continue
        text = raw[1:]
        if raw.startswith("-"):
            match = DEPENDENCY_ADDED.match(text)
            if match:
                removed.add(match.group("name"))
            continue
        if is_json:
            opened = JSON_SECTION_OPEN.match(text)
            if opened:
                section = opened.group("key").lower()
            elif JSON_SECTION_CLOSE.match(text):
                section = ""  # left a section; which one we are back in is not shown
        if raw.startswith("+"):
            match = DEPENDENCY_ADDED.match(text)
            if match:
                name = match.group("name")
                if section:
                    counts = section in DEPENDENCY_SECTIONS
                else:
                    counts = name.lower() not in NOT_DEPENDENCIES
                if counts:
                    added.append((lineno, name))
        lineno += 1
    return [(n, name) for n, name in added if name not in removed]


def _dependency_rules(change: Change) -> list[Finding]:
    """One finding per manifest, naming every package it adds."""
    findings = []
    for file in change.files:
        if _basename(file.path) not in MANIFESTS or not _scannable(file):
            continue
        added = _added_dependencies(file)
        if added:
            findings.append(Finding(
                rule_id="content.dependency_added",
                severity="low",
                rationale="A dependency was added. Extremely common and benign by itself, "
                "but when malicious code lives in the dependency this is the only "
                "git-visible trace an attack leaves.",
                precedent="event-stream / flatmap-stream, 2018",
                file_path=file.path,
                line=added[0][0],
                evidence=_evidence(", ".join(name for _, name in added)),
            ))
    return findings


# --------------------------------------------------------------------------- context rules


def _context_rules(change: Change) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule_id: str, severity: Severity, rationale: str, path: str | None = None,
            precedent: str = "") -> None:
        findings.append(
            Finding(rule_id=rule_id, severity=severity, rationale=rationale,
                    precedent=precedent, file_path=path)
        )

    for file in change.files:
        if _is_ci(file.path):
            add(
                "context.ci_touched", "medium",
                "A CI workflow definition was modified — CI runs with repository secrets, "
                "so tampering here is equivalent to code execution with credentials.",
                file.path,
            )
        if _is_build_script(file.path):
            add(
                "context.build_script_touched", "medium",
                "A build or install script was modified. These execute on every consumer's "
                "machine, outside any review of the shipped source.",
                file.path, "xz-utils (CVE-2024-3094), 2024",
            )
        if _is_artifact(file.path):
            add(
                "context.artifact_modified", "low",
                "A generated/bundled artifact was modified. Nobody reviews a rebuilt bundle "
                "line by line, so an edit here survives review by default.",
                file.path, "tj-actions/changed-files, 2025",
            )
        if (file.patch_omitted and file.change_type != "removed"
                and not _is_vendored(file.path) and _basename(file.path) not in LOCKFILES):
            add(
                "context.diff_unavailable", "low",
                f"GitHub withheld this file's diff ({file.additions} lines added) and it "
                "could not be rebuilt, so Tier 0 never read it. Absence of findings here "
                "is not evidence of absence.",
                file.path,
            )

    vendored = [f for f in change.files
                if _is_vendored(f.path) and f.change_type != "removed"]
    if vendored:
        add(
            "context.vendored_code", "low",
            f"{len(vendored)} third-party file(s) committed under a vendored path. Their "
            "contents are upstream code and are not scanned; what they contain is only as "
            "trustworthy as where they were copied from.",
            vendored[0].path,
        )

    if change.source == "pr":
        if change.merged_by_author:
            add(
                "context.self_merged", "medium",
                "The pull request was merged by its own author, so no independent party "
                "approved the code before it landed.",
            )
        if change.approving_review_count == 0:
            add(
                "context.no_approvals", "medium",
                "The pull request was merged with zero approving reviews.",
            )
        if change.is_first_time_contributor and any(
            _is_ci(f.path) or _is_build_script(f.path) for f in change.files
        ):
            add(
                "context.newcomer_touches_build", "high",
                "A first-time contributor's first change modifies CI or build tooling, "
                "which is disproportionate access for an unestablished account.",
                None, "event-stream, 2018",
            )

    if change.checks_passed is False:
        add(
            "context.merged_with_failing_checks", "medium",
            "The change landed with failing checks, suggesting review was bypassed.",
        )

    tenure, prior = change.author_tenure_days, change.author_prior_commits
    if tenure is not None:
        if tenure < NEW_CONTRIBUTOR_DAYS:
            add(
                "context.new_contributor", "info",
                f"The author's first commit to this repo was {tenure} day(s) before this "
                "change. Ordinary for a reviewed pull request — 56% of the control "
                "sample — so this carries no weight by itself.",
            )
        # Tenure matters differently depending on privilege. A brand-new contributor
        # opening a PR gets reviewed; a brand-new maintainer pushing straight to the
        # default branch does not. That second shape is AV-800, "Become a Maintainer".
        # Three conditions beyond short tenure. It must be a real direct push: a commit
        # that landed through a pull request was reviewed -- 9 of the first npm hunt's 25
        # alerts were squash merges mislabelled as pushes. And the repository must already
        # have been established when the author arrived, or every founder qualifies.
        arrival = change.author_arrival_days
        if (
            change.source == "push"
            and change.pr_number is None
            and tenure < NEW_PUSHER_DAYS
            and (prior is None or prior < NEW_PUSHER_COMMITS)
            and arrival is not None
            and arrival >= ESTABLISHED_REPO_DAYS
        ):
            add(
                "context.new_maintainer_direct_push", "medium",
                f"An author with {tenure} day(s) and {prior} prior commit(s) in this repo "
                "pushed directly to the default branch, bypassing review entirely. "
                "Maintainership recently granted and immediately exercised is the "
                "shape of a handover being abused.",
                None, "event-stream, 2018",
            )

    return findings


# --------------------------------------------------------------------------- combinations

# (rule A, rule B) -> (combined rule id, severity, rationale). Scored in addition to the
# individual findings: the pairing is the signal, not either half.
COMBOS: dict[tuple[str, str], tuple[str, Severity, str]] = {
    ("content.encoded_blob", "context.build_script_touched"): (
        "combo.encoded_payload_in_build_script", "critical",
        "An encoded blob was added to a build or install script — unreviewable "
        "content placed where it will execute on every consumer.",
    ),
    ("content.encoded_blob", "context.artifact_modified"): (
        "combo.encoded_payload_in_artifact", "critical",
        "An encoded blob was added to a generated bundle, where it cannot plausibly have "
        "come from the reviewed source.",
    ),
    ("content.encoded_blob", "context.ci_touched"): (
        "combo.encoded_payload_in_ci", "critical",
        "An encoded blob was added to CI configuration, which runs with repository secrets.",
    ),
    ("content.encoded_blob", "content.shell_exec"): (
        "combo.encoded_payload_executed", "critical",
        "An encoded blob and a shell/eval primitive were added together — decode-and-run, "
        "the canonical obfuscated-payload shape.",
    ),
    ("content.secret_access", "content.suspicious_host"): (
        "combo.credential_exfiltration", "critical",
        "Code that reads credentials was added alongside a paste/tunnel endpoint: "
        "collection and exfiltration in the same change.",
    ),
    ("content.token_reference", "content.suspicious_host"): (
        "combo.credential_exfiltration", "critical",
        "Code that handles a CI or registry token was added alongside a paste/tunnel "
        "endpoint: the token may be leaving.",
    ),
    ("content.dependency_added", "context.new_maintainer_direct_push"): (
        "combo.new_maintainer_adds_dependency", "high",
        "A recently-arrived maintainer pushed a new dependency straight to the default "
        "branch. Neither half is remarkable — 13% of benign changes add a dependency, "
        "56% of authors are new — but the pairing fired on 1 of 45 benign changes. "
        "Any malicious code would live in the dependency rather than this diff, so "
        "Tier 0 cannot adjudicate it: this exists to escalate, not to convict.",
    ),
}


# Each evidence rule contributes a capability, in the sense GuardDog uses: malware needs
# to *do* something (execute, reach the network, read secrets) and to *hide* or *deliver*
# it. One capability is ordinary — plenty of honest code executes subprocesses or makes
# requests. Several distinct capabilities in one change is the shape of an attack chain,
# and that is what `CATEGORY_BONUS` scores, independently of the named pairs in `COMBOS`.
RULE_CATEGORY: dict[str, str] = {
    "content.encoded_blob": "obfuscation",
    "content.decode_call": "obfuscation",
    "content.install_hook_obfuscated": "obfuscation",
    "content.shell_exec": "execution",
    "content.install_hook_exec": "execution",
    "content.install_hook": "execution",
    "content.network_in_build": "network",
    "content.suspicious_host": "network",
    "content.install_hook_network": "network",
    "content.secret_access": "collection",
    "content.install_hook_recon": "collection",
    "content.install_hook_silenced": "concealment",
    "content.binary_added": "concealment",
    "content.unbounded_loop": "sabotage",
    "content.dependency_added": "delivery",
}

# Added to the evidence score by distinct capability count. Two capabilities is common
# enough in honest code to stay below the bar on its own; three or more is an attack
# chain. Deliberately sub-linear at the top so a sprawling package cannot accumulate its
# way past the threshold without any individually meaningful signal.
CATEGORY_BONUS: dict[int, int] = {0: 0, 1: 0, 2: 2, 3: 6, 4: 10}
MAX_CATEGORY_BONUS = 12


def _category_bonus(findings: list[Finding]) -> int:
    categories = {
        RULE_CATEGORY[f.rule_id] for f in findings if f.rule_id in RULE_CATEGORY
    }
    # `delivery` alone is meaningless: 93% of malicious packages add a dependency, and so
    # do 13% of benign changes. It only counts alongside something that acts.
    if categories <= {"delivery"}:
        return 0
    return CATEGORY_BONUS.get(len(categories), MAX_CATEGORY_BONUS)


# Pairs whose rationale is about one file -- a blob *in* a build script, *in* a bundle, *in*
# CI config, decoded *and* executed. Matched change-wide, a blob in dist/ plus any workflow
# edit anywhere in the commit read as "an encoded blob was added to CI configuration".
SAME_FILE_COMBOS = {
    ("content.encoded_blob", "context.build_script_touched"),
    ("content.encoded_blob", "context.artifact_modified"),
    ("content.encoded_blob", "context.ci_touched"),
    ("content.encoded_blob", "content.shell_exec"),
}


def _combo_rules(findings: list[Finding]) -> list[Finding]:
    out = []
    for (a, b), (rule_id, severity, rationale) in COMBOS.items():
        b_files = {f.file_path for f in findings if f.rule_id == b}
        if not b_files:
            continue
        anchor = next(
            (f for f in findings if f.rule_id == a
             and ((a, b) not in SAME_FILE_COMBOS or f.file_path in b_files)),
            None,
        )
        if anchor is not None:
            out.append(
                Finding(
                    rule_id=rule_id, severity=severity, rationale=rationale,
                    file_path=anchor.file_path, line=anchor.line, evidence=anchor.evidence,
                )
            )
    return out


# --------------------------------------------------------------------------- entry points


def scan(change: Change) -> list[Finding]:
    """Run every Tier 0 rule over a change. Order is content, context, then combinations
    (which are derived from the first two)."""
    findings = (_content_rules(change) + _dependency_rules(change)
                + _install_hook_rules(change) + _context_rules(change))
    return findings + _combo_rules(findings)


def _dedup(findings: list[Finding]) -> list[Finding]:
    """One finding per rule. A minified bundle can trip a single pattern on hundreds of
    lines; without this, one noisy file outweighs a genuine combination of independent
    signals."""
    return list({f.rule_id: f for f in findings}.values())


def score(findings: list[Finding]) -> int:
    """Total weighted score — evidence plus circumstance, including the capability bonus.

    Used for *ranking* changes against each other, which is what a whole-repo scan needs.
    The bonus has to be included or this can come out *below* `evidence_score`, and a
    change combining several capabilities — the shape we most want at the top of a
    ranking — would sort below a noisier one that combines none.
    """
    deduped = _dedup(findings)
    evidence = [f for f in deduped if not f.rule_id.startswith("context.")]
    return sum(SEVERITY_WEIGHT[f.severity] for f in deduped) + _category_bonus(evidence)


def evidence_score(findings: list[Finding]) -> int:
    """Weighted score of `content.*` and `combo.*` findings only — what the change
    actually contains, ignoring where it landed and who merged it.

    Measured on 45 benign PRs, circumstance rules fire constantly: CI touched 31%,
    self-merged 20%, no approvals 18%. Three of those stack past any useful threshold on
    a completely ordinary maintenance commit, which is how `psf/requests#6968` — a
    Makefile tweak merged by its own author — escalated with zero payload evidence.

    So circumstance corroborates, it doesn't accuse. It sharpens the ranking and gives
    Tier 2 context to reason about, but only content can cross the escalation bar.
    """
    evidence = [f for f in _dedup(findings) if not f.rule_id.startswith("context.")]
    return sum(SEVERITY_WEIGHT[f.severity] for f in evidence) + _category_bonus(evidence)


def should_escalate(findings: list[Finding]) -> bool:
    """Whether this change warrants a Tier 2 LLM call."""
    return evidence_score(findings) >= ESCALATION_THRESHOLD


# --------------------------------------------------------------------------- tags

# Tag integrity for GitHub Actions. A consumer's workflow runs whatever its pinned tag
# points at, so an attacker who can move a tag never needs to touch the default branch.
# These checks are pure: the caller asks `tags_to_check` which commits need a
# reachability lookup (`fetch.on_any_branch`), performs it, and passes the answers to
# `tag_findings`. A False answer means the commit is on no branch at all.
#
# Rule ids use the `tag.` prefix rather than `context.`. `evidence_score` ignores
# `context.` findings because circumstances like a missing approval are true of a third
# of ordinary changes. A rewritten release tag is not a circumstance; it is direct
# evidence of tampering, and it must be able to escalate on its own.

# A full release tag: v1.2.3, 1.2.3, or v35.7.7-sec. These are immutable by convention.
SEMVER_FULL = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$")
# A floating tag: v4 or v4.2. These are moved deliberately to track the latest release.
FLOATING_TAG = re.compile(r"^v?(\d+)(?:\.(\d+))?$")
# Floating tags are what consumers actually pin, but an old action can carry dozens.
# Checking the newest few bounds the compare calls to a handful per repository.
MAX_FLOATING_CHECKED = 5
# Distinct off-branch release commits among those checked that make it a repository's
# convention rather than an anomaly. Two, not one: a single off-branch tag is the shape
# being hunted.
OFF_BRANCH_CONVENTION = 2


def _floating_tags(tags: list[tuple[str, str]]) -> list[tuple[str, str]]:
    floating = [(name, sha) for name, sha in tags if FLOATING_TAG.match(name)]
    floating.sort(
        key=lambda t: tuple(int(g or 0) for g in FLOATING_TAG.match(t[0]).groups()),
        reverse=True,
    )
    return floating[:MAX_FLOATING_CHECKED]


def _moved_tags(tags: list[tuple[str, str]], snapshot: dict[str, str] | None) -> list[tuple[str, str, str]]:
    """(name, old sha, new sha) for full release tags that changed since the snapshot."""
    if not snapshot:
        return []
    return [
        (name, snapshot[name], sha)
        for name, sha in tags
        if SEMVER_FULL.match(name) and name in snapshot and snapshot[name] != sha
    ]


def tags_to_check(tags: list[tuple[str, str]], snapshot: dict[str, str] | None) -> set[str]:
    """Commits whose default-branch reachability `tag_findings` will need."""
    return {sha for _, sha in _floating_tags(tags)} | {new for _, _, new in _moved_tags(tags, snapshot)}


def tag_findings(
    tags: list[tuple[str, str]],
    snapshot: dict[str, str] | None,
    reachable: dict[str, bool | None],
) -> dict[str, list[Finding]]:
    """Tag-integrity findings, keyed by the commit they point at."""
    out: dict[str, list[Finding]] = {}

    def add(sha: str, finding: Finding) -> None:
        out.setdefault(sha, []).append(finding)

    # Version collapse: release tags from different major.minor lines on one commit. v1,
    # v1.2 and v1.2.3 sharing a commit is ordinary, so floating tags are ignored; two
    # patch releases sharing one is a plausible republish, so only differing major.minor
    # counts.
    by_sha: dict[str, list[str]] = {}
    for name, sha in tags:
        if SEMVER_FULL.match(name):
            by_sha.setdefault(sha, []).append(name)
    for sha, names in by_sha.items():
        versions = {SEMVER_FULL.match(n).groups() for n in names}
        lines = {v[:2] for v in versions}
        # One release published under parallel names -- DeLaGuardo/setup-clojure tags
        # every release as both 3.7.0 and 13.7.0 -- shares minor and patch across every
        # major. A rewrite drags in tags whose minor and patch differ.
        alias_scheme = len({v[1:] for v in versions}) == 1
        if len(lines) >= 2 and not alias_scheme:
            shown = ", ".join(sorted(names)[:8]) + (" ..." if len(names) > 8 else "")
            add(sha, Finding(
                rule_id="tag.version_collapse",
                severity="critical",
                rationale=f"{len(names)} release tags from {len(lines)} different version "
                "lines all point at this one commit. Distinct releases cannot share code "
                "this way; the tags were rewritten to deliver it.",
                precedent="tj-actions/changed-files, 2025",
                evidence=_evidence(shown),
            ))

    moved = _moved_tags(tags, snapshot)
    for name, old, new in moved:
        add(new, Finding(
            rule_id="tag.moved",
            severity="critical",
            rationale=f"Release tag {name} pointed at {old[:10]} at the last hunt and now "
            f"points at {new[:10]}. Release tags are immutable by convention; anyone "
            "pinning it now runs different code without changing a line of their own.",
            precedent="tj-actions/changed-files, 2025",
            evidence=_evidence(f"{name}: {old[:10]} -> {new[:10]}"),
        ))

    floating = _floating_tags(tags)
    candidates = list(floating)
    candidates += [(name, new) for name, _, new in moved]
    names_by_sha: dict[str, list[str]] = {}
    for name, sha in candidates:
        if reachable.get(sha) is False:
            names_by_sha.setdefault(sha, []).append(name)

    # Some projects publish every release from a build commit on no branch -- a release
    # workflow compiles dist/, commits it on top of main and tags that. Five of the first
    # holdout hunt's alerts were one such repository's last five releases. Off-branch is
    # then the convention, not a deviation, and the commit's own content has to speak for
    # it. One off-branch commit among on-branch releases is still flagged, and a tag that
    # *moved* there always is.
    off_branch_releases = {sha for _, sha in floating if reachable.get(sha) is False}
    convention = len(off_branch_releases) >= OFF_BRANCH_CONVENTION
    moved_to = {new for _, _, new in moved}
    for sha, names in names_by_sha.items():
        shown = ", ".join(sorted(set(names)))
        if convention and sha not in moved_to:
            add(sha, Finding(
                rule_id="context.off_branch_release",
                severity="low",
                rationale=f"Tag {shown} points at a commit on no branch, as do "
                f"{len(off_branch_releases)} of the {len(floating)} recent releases checked: "
                "this repository publishes from off-branch build commits by convention. Not "
                "evidence on its own; what the commit contains is scanned as usual.",
                evidence=_evidence(f"{shown} -> {sha[:10]}"),
            ))
            continue
        add(sha, Finding(
            rule_id="tag.on_no_branch",
            severity="high",
            rationale=f"Tag {shown} points at a commit that is on no "
            "branch at all -- not the default branch, not a release branch. What consumers "
            "run was never merged anywhere a reviewer would look.",
            precedent="reviewdog/action-setup, 2025",
            evidence=_evidence(f"{shown} -> {sha[:10]}"),
        ))

    return out


def only_docs(change: Change) -> bool:
    """Whether every file the change touches is documentation."""
    return bool(change.files) and all(_is_doc(f.path) for f in change.files)


def file_role(file: FileDiff) -> str:
    """The one role a file plays, by the same classification the rules use -- so a report
    can say "7 files: 1 CI, 6 docs" in the rules' own terms. First match wins, in order
    of how much the role matters to a reviewer."""
    if _is_vendored(file.path):
        return "vendored"
    if file.is_binary:
        return "binary"
    if _is_ci(file.path):
        return "CI"
    if _basename(file.path) in ("action.yml", "action.yaml"):
        return "action"  # what a consumer's `uses:` runs
    if _is_build_script(file.path):
        return "build"
    if _is_artifact(file.path):
        return "bundle"
    if _basename(file.path) in MANIFESTS or _basename(file.path) in LOCKFILES:
        return "manifest"
    if _is_doc(file.path):
        return "docs"
    if _is_test_fixture(file.path):
        return "tests"
    return "source"


def qualify_off_branch(findings: list[Finding], change: Change,
                       parent_on_branch: bool | None) -> list[Finding]:
    """Downgrade `tag.on_no_branch` when the tagged commit cannot change what runs.

    An off-branch commit whose parent is on a branch, and which itself changes nothing
    but documentation, ships reviewed code with a different README. jidicula's v1.0, a
    2020 README edit, was such a commit. The parent's reachability is required: without
    it, an attacker could stack a docs-only commit on top of an off-branch payload.
    """
    if parent_on_branch is not True or not only_docs(change):
        return findings
    return [
        Finding(
            rule_id="context.off_branch_docs_only", severity="low",
            rationale="A tag points at a commit on no branch, but that commit only changes "
            "documentation on top of a commit that is on a branch, so consumers run "
            "reviewed code.",
            evidence=f.evidence,
        ) if f.rule_id == "tag.on_no_branch" else f
        for f in findings
    ]
