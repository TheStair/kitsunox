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

DECODE_CALLS = re.compile(
    r"\b(base64\s+(-d|--decode|-D)|atob|b64decode|Buffer\.from\s*\([^)]*base64|"
    r"FromBase64String)",
    re.IGNORECASE,
)

SHELL_EXEC = re.compile(
    r"(\bchild_process\b|\bexec\.getExecOutput\b|\bexecSync\b|\bspawnSync\b|"
    r"\bsubprocess\.(run|Popen|call)\b|\bos\.system\b|\beval\s*\(|\bnew\s+Function\s*\(|"
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
    r"dnslog\.cn|requestbin\.\w+|pipedream\.net|webhook\.site|\.onion\b|"
    r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b)",
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
# reach an attacker. Exfiltration needs a routable address.
PRIVATE_IP = re.compile(
    r"^(0\.|127\.|10\.|192\.168\.|169\.254\.|255\.|172\.(1[6-9]|2\d|3[01])\.)"
)

SECRET_ACCESS = re.compile(
    r"(NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET|AWS_ACCESS_KEY|\.npmrc|~/\.aws|id_rsa|"
    r"/proc/\S*/(mem|maps|environ)|process\.env\s*\)|os\.environ\s*\))"
)

UNBOUNDED_LOOP = re.compile(r"(<\s*Infinity|while\s*\(\s*(true|1)\s*\))")

DEPENDENCY_ADDED = re.compile(r"^\s*[\"']?[\w@./-]+[\"']?\s*[:=]\s*[\"'][\^~>=<\d]")

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


def _is_test_fixture(path: str) -> bool:
    return any(seg in path.lower() for seg in TEST_FIXTURE_DIRS)


# A four-part version number is indistinguishable from an IP address by shape alone:
# `"version": "==3.4.0.3"` in psf/requests' Pipfile.lock was the only false positive in
# the whole direct-push control sample. Context is what separates them.
VERSION_CONTEXT = re.compile(r"(==|>=|<=|~=|\bv|version|release|tag)\s*[\"']?$", re.IGNORECASE)


def _hits_suspicious_host(text: str) -> bool:
    """True for a paste/tunnel host or a *routable* IP literal."""
    match = SUSPICIOUS_HOST.search(text)
    if not match:
        return False
    ip = match.group("ip")
    if ip is None:
        return True  # a named paste/tunnel host, no ambiguity
    if PRIVATE_IP.match(ip):
        return False
    return not VERSION_CONTEXT.search(text[: match.start("ip")])


def _scannable(file: FileDiff) -> bool:
    return not file.is_binary and _basename(file.path) not in LOCKFILES and bool(file.patch)


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
        if _basename(file.path) != "package.json" or file.is_binary:
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
        if file.is_binary and file.change_type == "added":
            in_fixtures = _is_test_fixture(file.path)
            findings.append(
                Finding(
                    rule_id="content.binary_added",
                    severity="high" if in_fixtures else "medium",
                    rationale=(
                        "An opaque binary file was added under a test-fixture path, where "
                        "a corrupt-looking blob is unremarkable and review least likely."
                        if in_fixtures else
                        "An opaque binary file was added. Binary content cannot be reviewed "
                        "as a diff."
                    ),
                    precedent="xz-utils (CVE-2024-3094), 2024" if in_fixtures else "",
                    file_path=file.path,
                )
            )
        if not _scannable(file):
            continue
        is_ci_config = _is_ci(file.path)
        in_sensitive = is_ci_config or _is_build_script(file.path) or _is_artifact(file.path)
        is_manifest = _basename(file.path) in MANIFESTS

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

            if B64_BLOB.search(text):
                hit(
                    "content.encoded_blob",
                    "high" if in_sensitive else "medium",
                    "A long base64 literal was added. Encoded content cannot be reviewed "
                    "as a diff, which is what makes it a delivery mechanism.",
                    "reviewdog/action-setup and tj-actions/changed-files, 2025",
                )
            if DECODE_CALLS.search(text):
                hit(
                    "content.decode_call",
                    "medium",
                    "Code that decodes an encoded string was added — benign on its own, "
                    "but the other half of an encoded-payload pair.",
                )
            if SHELL_EXEC.search(text):
                # Not elevated inside CI config: a workflow's whole job is to run shell,
                # so `child_process` in a publish workflow is unremarkable. It stays
                # notable in build/install scripts and generated bundles.
                hit(
                    "content.shell_exec",
                    "high" if (in_sensitive and not is_ci_config) else "low",
                    "A shell/eval execution primitive was added. Ordinary in application "
                    "code and in CI, hard to justify inside a build script or a bundle.",
                )
            if _hits_suspicious_host(text):
                hit(
                    "content.suspicious_host",
                    "high",
                    "A reference to a paste/tunnel service or a bare IP was added — the "
                    "exfiltration endpoint in both 2025 Actions compromises was a gist.",
                )
            elif NETWORK_FETCH.search(text) and in_sensitive:
                hit(
                    "content.network_in_build",
                    "medium",
                    "A network fetch was added to CI config, a build script, or a "
                    "generated bundle, pulling unreviewed content into the build.",
                )
            if SECRET_ACCESS.search(text):
                hit(
                    "content.secret_access",
                    "high",
                    "Added code reaches for credentials, process memory, or the "
                    "environment — the target of a CI-secret theft.",
                )
            if UNBOUNDED_LOOP.search(text):
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
            if is_manifest and DEPENDENCY_ADDED.match(text):
                hit(
                    "content.dependency_added",
                    "low",
                    "A dependency was added. Extremely common and benign by itself, but "
                    "when malicious code lives in the dependency this is the only "
                    "git-visible trace an attack leaves.",
                    "event-stream / flatmap-stream, 2018",
                )
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
        if (
            change.source == "push"
            and tenure < NEW_PUSHER_DAYS
            and (prior is None or prior < NEW_PUSHER_COMMITS)
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


def _combo_rules(findings: list[Finding]) -> list[Finding]:
    fired = {f.rule_id for f in findings}
    out = []
    for (a, b), (rule_id, severity, rationale) in COMBOS.items():
        if a in fired and b in fired:
            anchor = next(f for f in findings if f.rule_id == a)
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
    findings = _content_rules(change) + _install_hook_rules(change) + _context_rules(change)
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
