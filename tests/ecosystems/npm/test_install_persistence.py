"""`npm.install-persistence` on small, inert install files (nothing here runs)."""

import json

import pytest

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.ecosystems.npm.rules.install_persistence import (
    InstallPersistence,
    code_text,
    persistence,
)
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
RULE = InstallPersistence()


def hooked(files: dict[str, bytes], hook: str = "node setup.js", base: bool = False) -> CodeChange:
    tree = {"package.json": json.dumps({"scripts": {"postinstall": hook}}).encode(), **files}
    snap = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
        publish=PublishInfo(),
        manifest={"scripts": {"postinstall": hook}},
    )
    return code_change(snap, tree, tree if base else None, CACHE, install_sources, "1.0.0")


def forms(code: bytes, path: str = "setup.js") -> list[str]:
    return sorted({form for form, *_ in persistence({path: code}, {})})


@pytest.mark.parametrize(
    "code",
    [
        b'const dir = path.join(os.homedir(), ".claude", "skills")\nfs.cpSync(src, dir)\n',
        b"const home = os.homedir();\nfs.writeFileSync(path.join(home, '.codex', 'c.toml'), t)\n",
        b'let e=l.homedir();return l.join(e,".claude","settings.json")',
        b"fs.mkdirSync(`${os.homedir()}/.cursor/skills`)\n",
        b'copy(src, "~/.agents/skills/kx")\n',
        b"const dir = process.env.CLAUDE_CONFIG_DIR || fallback\n",
        b'join(homedir(), target === "codex" ? ".codex" : ".agents", "skills")\n',
        b"const h = home();\nwrite(path.join(h, '.gemini', 'GEMINI.md'))\n",
        b'const KJ = path.join(os.homedir(), ".claude.json");\n',
    ],
)
def test_user_wide_agent_configuration(code: bytes) -> None:
    """Owner, 2026-11-09: install code writing skills, hooks, settings or MCP servers into
    user-wide agent locations is unwanted (`@josetra/wacon`, `@karajan-family/code`,
    `@ciandt-flow/flow-ai-obs`'s minified `dist/setup.js`)."""
    assert forms(code) == ["agent"]


@pytest.mark.parametrize(
    "code",
    [
        b'const dir = path.join(process.env.INIT_CWD, ".claude", "skills")\n',  # the project
        b"// copies into ~/.claude/skills when you run `kx init`\nrun()\n",  # a comment
        b'console.log("Run kx install to add skills to ~/.claude/skills")\n',  # a message
        b'throw new Error("cannot write ~/.codex/config.toml")\n',
        b'log.warn("CLAUDE_CONFIG_DIR is not set")\n',
        b"const HELP = 'set CODEX_HOME to move it'\n",  # names the variable, doesn't read it
    ],
)
def test_project_writes_comments_and_messages_are_not_user_wide(code: bytes) -> None:
    assert forms(code) == []


def test_shell_rc_path_and_system_packages() -> None:
    """Owner, 2026-11-09: shell rc edits (`@xfe-repo/cli`, `tfv`), persistent PATH changes
    (`@visual-z/xeno`) and system package installs (`streamgrab`, `@ohos-ports/zerox`) by an
    install hook are unwanted."""
    rc = b"fs.appendFileSync(path.join(os.homedir(), '.zshrc'), line)\n"
    assert forms(rc) == ["shell-rc"]
    windows = b"execSync(`[Environment]::SetEnvironmentVariable('PATH', '${p}', 'User')`)\n"
    assert forms(windows) == ["path"]
    assert forms(b'execSync("setx PATH \\"%PATH%;C:\\\\kx\\"")\n') == ["path"]
    for command in (
        b'execSync("sudo apt-get install -y ffmpeg")\n',
        b'installPackage("brew install ghostscript", "Ghostscript")\n',
        b'run("command -v cmake || sudo -n dnf install cmake")\n',
        b'spawnSync("winget", ["install", "x"]); run("choco install x -y")\n',
    ):
        assert forms(command) == ["system-package"], command
    assert forms(b"sudo apt-get install -y libvips\n", "install.sh") == ["system-package"]


@pytest.mark.parametrize(
    "code",
    [
        b'console.log("Install it with: brew install gifsicle")\n',
        b"const hint = 'Optional: sudo apt-get install poppler-utils'\n",  # a sentence
        b'if (!found) fail("missing cmake (try: brew install cmake)")\n',
    ],
)
def test_naming_a_package_manager_is_not_running_one(code: bytes) -> None:
    assert forms(code) == []


def test_shell_files_mask_comments_and_echo_lines() -> None:
    script = b'# sudo apt-get install x\necho "then: brew install y"\nmkdir -p "$HOME/.claude"\n'
    assert forms(script, "install.sh") == ["agent"]
    assert code_text("install.sh", script).splitlines()[0].strip() == ""
    assert forms(b"brew install y\n", "README.md") == []  # not code


def test_the_hook_command_line_counts() -> None:
    found = persistence({}, {"postinstall": "sudo apt-get install -y cmake"})
    assert [f for f, *_ in found] == ["system-package"]
    found = persistence({}, {"postinstall": "echo 'source x' >> ~/.bashrc"})
    assert [f for f, *_ in found] == ["shell-rc"]


def test_the_rule_reports_each_form_once_with_evidence() -> None:
    code = (
        b"const home = os.homedir()\n"
        b'fs.cpSync(src, path.join(home, ".claude", "skills"))\n'
        b'execSync("sudo apt-get install -y git-lfs")\n'
    )
    (finding,) = RULE.evaluate_code(hooked({"setup.js": code}))
    assert (finding.rule_id, finding.severity, finding.weight) == (
        "npm.install-persistence",
        Severity.MEDIUM,
        3.0,
    )
    assert "user-wide configuration" in finding.explanation
    assert "installs system packages" in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [
        ("setup.js", 2),
        ("setup.js", 3),
    ]
    # Only install code that is new or changed counts (`ONLY_WHEN_CHANGED`).
    assert RULE.evaluate_code(hooked({"setup.js": code}, base=True)) == ()
    assert RULE.evaluate_code(hooked({"setup.js": b"run()\n"})) == ()
