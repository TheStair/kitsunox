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
        b'function p(){let e=l.homedir();return l.join(e,".claude","settings.json")}'
        b"l.writeFileSync(p(),s)",
        b"fs.mkdirSync(`${os.homedir()}/.cursor/skills`)\n",
        b'copy(src, "~/.agents/skills/kx")\n',
        b"const dir = process.env.CLAUDE_CONFIG_DIR || fallback\nfs.cpSync(src, dir)\n",
        b'cpSync(src, join(homedir(), target === "codex" ? ".codex" : ".agents", "skills"))\n',
        b"const h = home();\nwriteFile(path.join(h, '.gemini', 'GEMINI.md'), t)\n",
        b'const KJ = path.join(os.homedir(), ".claude.json");\nsaveJson(KJ, config);\n',
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


@pytest.mark.parametrize(
    "code",
    [
        # `@mearl/native-host` (benign): checks whether Codex's config exists
        b'let home=process.env.CODEX_HOME||path3.join(os.homedir(),".codex");'
        b'diag({home,filePresent:fs3.existsSync(path3.join(home,"config.toml"))})',
        # `aiimpactmeter` (benign): reads local usage logs
        b"const roots = [path.join(home, '.codex')];\nfor (const r of roots) fs.readdirSync(r)\n",
        # `nansen-cli` (benign): looks for an installed skill
        b'const home = os.homedir();\nconst locations = [join(home, ".claude", "skills", "x")];\n'
        b"const installed = locations.some((p) => existsSync(p));\n",
    ],
)
def test_v5_reading_agent_configuration_is_not_writing_it(code: bytes) -> None:
    """v5 (round 6 S, S1): a user-wide agent path counts only when the install code's value
    for it reaches a write (`lang.flow`)."""
    assert forms(code) == []


def test_v5_an_installer_the_analysis_cannot_read_counts() -> None:
    """`wkappbot-code@0.3.11` (unwanted): its postinstall runs its own CLI's `install`, which
    is not an install file, and names `~/.claude` only to read it (`unfollowed_installer`)."""
    code = (
        b"const home = os.homedir();\nif (existsSync(join(home, '.claude'))) remote = true;\n"
        b'const args = [CLI, "install"];\nspawn(process.execPath, args, {detached: true});\n'
    )
    assert forms(code) == ["agent"]


def test_v5_a_shell_rc_name_that_reaches_a_write() -> None:
    """`coding-friend-cli@1.43.0` (unwanted): `getRcPath()` returns `join(home, ".zshrc")`,
    and `ensureShellCompletion()`, hundreds of lines on, writes the completion block to it."""
    far = b"\n".join(b"const pad%d = %d;" % (i, i) for i in range(120))
    code = (
        b'function getRcPath() { const home = homedir(); return join(home, ".zshrc"); }\n'
        + far
        + b"\nfunction ensure() { const rc = getRcPath(); writeFileSync(rc, block); }\n"
    )
    assert forms(code) == ["shell-rc"]
    assert forms(code.replace(b"writeFileSync(rc, block)", b"readFileSync(rc)")) == []


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


def test_an_agents_own_cli_installing_user_wide() -> None:
    """`anolisa-tokenless@0.9.3` (unwanted): its install script runs `claude plugin install`."""
    assert forms(b'"$CLAUDE_BIN" plugin marketplace add "$SRC"\n', "install.sh") == ["agent"]
    assert forms(b"claude mcp add --scope user kx -- node s.js\n", "install.sh") == ["agent"]
    assert forms(b'spawnSync("claude", ["plugin", "install", id])\n') == ["agent"]
    assert forms(b"claude mcp add kx -- node s.js\n", "install.sh") == []  # project scope
    assert forms(b'echo "then run: claude plugin install kx"\n', "install.sh") == []


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
    assert RULE.evaluate_code(hooked({"setup.js": b"run()\n"})) == ()


def test_unchanged_install_code_counts_for_agent_installs_not_path_or_packages() -> None:
    """v6 (round 8 R): the `agent` form counts on every version whose install code does it
    (`@aswless_854771076/ai_short_studio_cli@0.1.236`, unwanted: an unchanged postinstall that
    copies skills into `~/.codex/skills`); `path` and `system-package` need new or changed
    install code."""
    agent = b'const home = os.homedir()\nfs.cpSync(src, path.join(home, ".codex", "skills"))\n'
    (finding,) = RULE.evaluate_code(hooked({"setup.js": agent}, base=True))
    assert finding.rule_version == 7
    assert [(e.path, e.line_start) for e in finding.evidence] == [("setup.js", 2)]
    both = agent + b'execSync("sudo apt-get install -y git-lfs")\n'
    (finding,) = RULE.evaluate_code(hooked({"setup.js": both}, base=True))
    assert "user-wide configuration" in finding.explanation
    assert "installs system packages" not in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [("setup.js", 2)]
    system = b'execSync("sudo apt-get install -y git-lfs")\n'
    assert RULE.evaluate_code(hooked({"setup.js": system}, base=True)) == ()
    path = b'execSync("setx PATH \\"%PATH%;C:\\\\kx\\"")\n'
    assert RULE.evaluate_code(hooked({"setup.js": path}, base=True)) == ()


def test_unchanged_install_code_counts_for_shell_startup_writes() -> None:
    """v7 (round 9 Q4): the `shell-rc` form counts on unchanged install code too. `botmux`
    3.59.2-3.59.5 (unwanted) append a PATH line to the user's shell start-up files from a
    global install's postinstall that is the same in every release."""
    rc = b"echo 'export PATH=\"$HOME/.kx/bin:$PATH\"' >> ~/.bashrc\n"
    (finding,) = RULE.evaluate_code(hooked({"install.sh": rc}, "sh install.sh", True))
    assert finding.rule_version == 7
    assert "shell start-up files" in finding.explanation
    js = (
        b"const home = os.homedir()\nconst rc = path.join(home, '.zshrc')\n"
        b"fs.appendFileSync(rc, 'export PATH=\"$HOME/.kx/bin:$PATH\"\\n')\n"
    )
    assert RULE.evaluate_code(hooked({"setup.js": js}, base=True)) != ()
    read = b"const home = os.homedir()\nconst rc = fs.readFileSync(path.join(home, '.zshrc'))\n"
    assert RULE.evaluate_code(hooked({"setup.js": read}, base=True)) == ()


def test_script_text_keeps_its_lines() -> None:
    """Round 4 G: `code_text` reads scripts with `lang.shell.mask_script_messages`. The old
    pattern's `^\\s*` ran from a blank line into the comment after it and blanked the newline,
    so every later line was one off (`node-sword-interface`'s `build_sword.sh`: the changed
    `git clone` line read as the next one)."""
    script = b"fi\n\n# CLONE\ngit clone https://x.invalid/a sword\n"
    masked = code_text("build.sh", script)
    assert masked.split("\n")[3] == "git clone https://x.invalid/a sword"


def test_message_through_a_print_function_is_not_a_write() -> None:
    """`@ornexus/neocortex@4.61.5`'s `install.sh:1482` tells the user how to save a key in
    `~/.bashrc` through its own `info` function; nothing writes the file."""
    script = (
        b'info() { echo -e "  $1"; }\n'
        b'info "Para persistir: echo \'export K=\\"$k\\"\' >> ~/.bashrc"\n'
    )
    assert forms(script, "install.sh") == []


def test_an_echo_that_writes_the_rc_file_is_a_write() -> None:
    script = b"echo 'export PATH=\"$HOME/.kx/bin:$PATH\"' >> ~/.zshrc\n"
    assert forms(script, "install.sh") == ["shell-rc"]


@pytest.mark.parametrize(
    "code",
    [
        # `@juyoungsuh/hanx`: advice in a ternary inside `console.log`
        b"console.log(p==='darwin'?'Optional: brew install poppler':'sudo apt-get install x')\n",
        # `argonauts-code@0.2.0`: one command per distribution in a table
        b'const COMMANDS = [[["debian"], ["apt-get update", "apt-get install xz-utils"]]];\n',
        # `northstar-browser`: a table of package managers
        b"const MANAGERS = { apt: { install: 'sudo apt install' } };\n",
        # `wyrm-mcp@9.4.2`, `symbiot`: returned hints
        b"function hint(pm) { switch (pm) { case 'apt': return `sudo apt-get install ${x}`; } }\n",
        b'function o() { return { cmd: "brew install ollama" }; }\n',
        # `uniwind-pro@1.9.2`: help text pushed line by line
        b"lines.push('  1. Install it:', '     sudo apt-get install -y gnome-keyring')\n",
        b"console.log(` Run: ${t.accent('sudo apt install build-essential')}`)\n",
    ],
)
def test_a_command_string_only_shown_or_kept_as_data_is_not_an_install(code: bytes) -> None:
    """v2 (round 5): a system-package command that JavaScript install code only prints,
    returns or keeps in a table never runs."""
    assert forms(code) == []


@pytest.mark.parametrize(
    "code",
    [
        b'execSync(p === "darwin" ? "brew install x" : "sudo apt-get install -y x")\n',
        b'const cmd = "sudo apt-get install -y ghostscript";\nexecSync(cmd)\n',
        b'console.log(execSync("brew install x").toString())\n',  # printed, but run first
        # `gebangautoupload@1.1.4`, `streamgrab@1.3.4` (unwanted): argument lists
        b'warn("Install: brew install python");\nrun("sudo", ["apt-get", "install", "-y", "x"])\n',
        b"const r = spawnSync('brew', ['install', ...packages], { stdio: 'inherit' })\n",
        # `free-anthropic-claude@5.0.3` (vm-day1): a command string in an argument list
        b"cp[['exec','File','Sync'].join('')]('/bin/bash', ['-c', 'brew install python3'])\n",
        b'run("winget", ["install", "--id", "Python.Python.3.12", "--silent"])\n',
    ],
)
def test_a_command_the_install_code_may_run_still_counts(code: bytes) -> None:
    assert forms(code) == ["system-package"]


@pytest.mark.parametrize(
    ("code", "path"),
    [
        # `signoff-cli`, `dsh-signoff` (unwanted, owner 2026-11-10): `lib/bootstrap.js`
        (b'spawnSync("git", ["config", "--global", "core.hooksPath", d], {})\n', "b.js"),
        (b"execSync('git config --global core.hooksPath ~/.kx/hooks')\n", "b.js"),
        (b"execSync(`git config --system credential.helper ${helper}`)\n", "b.js"),
        (
            b'execFileSync("git", ["config", "--global", "--add", "url.s://x.insteadOf", u])\n',
            "b.js",
        ),
        (b'git(["config", "set", "--global", "init.templateDir", tpl])\n', "b.js"),
        (b'git config --global include.path "$HOME/.kx/gitconfig"\n', "setup.sh"),
        (b"git -C /tmp config --global core.hooksPath /opt/kx/hooks\n", "setup.sh"),
        (b"git config --file ~/.gitconfig core.sshCommand 'ssh -i k'\n", "setup.sh"),
        (b"printf '[core]\\n\\thooksPath = x\\n' >> ~/.gitconfig\n", "setup.sh"),
        (b'fs.appendFileSync(path.join(os.homedir(), ".gitconfig"), "[include]")\n', "b.js"),
        (b'const p = join(homedir(), ".gitconfig");\nfs.writeFileSync(p, text)\n', "b.js"),
    ],
)
def test_changing_the_global_git_configuration(code: bytes, path: str) -> None:
    """v3 (owner, 2026-11-10: a silent system or user setting change at install is unwanted):
    a global or system git setting that runs code or redirects data in every repository."""
    assert forms(code, path) == ["git-config"]


@pytest.mark.parametrize(
    ("code", "path"),
    [
        # `@acertijosapps/android-viewer`, `@brighterly/lib-assessment`, `clavarium` (benign):
        # the project's own repository
        (b"git config core.hooksPath .githooks || exit 0\n", "setup.sh"),
        (b'spawnSync("git", ["config", "core.hooksPath", ".husky"])\n', "b.js"),
        (b"git -c core.hooksPath=/dev/null commit -m x\n", "setup.sh"),  # one command
        # reads and removals
        (b'spawnSync("git", ["config", "--global", "--get", "core.hooksPath"])\n', "b.js"),
        (b"execSync('git config --global --unset core.hooksPath')\n", "b.js"),
        (b"git config --global --list\n", "setup.sh"),
        (b'const name = fs.readFileSync(join(os.homedir(), ".gitconfig"), "utf8")\n', "b.js"),
        # keys that change nothing git runs
        (b"git config --global user.email ci@example.invalid\n", "setup.sh"),
        (b"git config --global alias.st status\n", "setup.sh"),
        (b"git config --global --add safe.directory /work\n", "setup.sh"),
        # v4 (owner 2026-11-10): settings a development tool makes for itself are benign
        (b"run('git config --global alias.up \"!sh ./x.sh\"')\n", "b.js"),
        (b'spawnSync("git", ["config", "--global", "--add", "safe.directory", "*"])\n', "b.js"),
        (b"git -C /tmp config --global http.proxy http://127.0.0.1:9\n", "setup.sh"),
        (b"git config --global core.editor 'code --wait'\n", "setup.sh"),
        (b'spawnSync("git", ["config", "--global", "gpg.program", "gpg2"])\n', "b.js"),
        (b"git config --global merge.tool vimdiff\n", "setup.sh"),
        # shown, not run
        (b'console.log("run: git config --global core.hooksPath ~/.kx/hooks")\n', "b.js"),
        (b"const STEPS = ['git config --global core.hooksPath ~/.kx/hooks'];\n", "b.js"),
        (b'echo "git config --global core.hooksPath ~/.kx/hooks"\n', "setup.sh"),
    ],
)
def test_project_settings_reads_and_messages_are_not_global_changes(code: bytes, path: str) -> None:
    assert forms(code, path) == []


def git_forms(files: dict[str, bytes]) -> list[str]:
    return [form for form, *_ in persistence(files, {})]


def test_a_global_change_only_a_caller_switches_on() -> None:
    """`@arifbiswas/git-pre-push@1.0.0` (benign): `installHook(cwd, isGlobal = false)` sets the
    global `core.hooksPath` only `if (isGlobal)`; the postinstall calls `installHook(dir)` and
    only the CLI (not install code) passes `true`."""
    installer = (
        b"function installHook(cwd = process.cwd(), isGlobal = false) {\n"
        b"  if (isGlobal) {\n"
        b'    runGit(`config --global core.hooksPath "${dir}"`);\n'
        b"  }\n"
        b"}\n"
        b"module.exports = { installHook };\n"
    )
    hook = b"const { installHook } = require('./installer');\ninstallHook(process.env.INIT_CWD);\n"
    files = {"installer.js": installer, "setup.js": hook}
    assert git_forms(files) == []
    assert git_forms({**files, "setup.js": hook + b"installHook(d, false);\n"}) == []
    for call in (b"installHook(d, true);\n", b"installHook(...args);\n", b"[a].map(installHook)\n"):
        assert git_forms({**files, "setup.js": hook + call}) == ["git-config"], call
    # A guard that isn't an off-by-default parameter keeps it (`signoff`'s `--from-install`).
    always = installer.replace(b"isGlobal = false", b"isGlobal")
    assert git_forms({**files, "installer.js": always}) == ["git-config"]
    arrow = (
        b"const set = (g = false) => "
        b"{ if (ok && g) { run('git config --global core.hooksPath x') } }\n"
    )
    assert git_forms({"setup.js": arrow + b"set()\n"}) == []
    assert git_forms({"setup.js": arrow + b"set(1)\n"}) == ["git-config"]
    typed = (
        b"function f(g: boolean = false) "
        b"{ if (g) { run('git config --global core.hooksPath x') } }\n"
    )
    assert git_forms({"setup.ts": typed}) == []
    assert git_forms({"setup.ts": typed + b"f(true)\n"}) == ["git-config"]


@pytest.mark.parametrize(
    "code",
    [
        b'x("config ' + b"--a " * 400 + b'")\n',
        b'x("config ' + b"--global " * 4000 + b'")\n',
        b'x(["config", ' + b'"--a", ' * 400 + b"])\n",
        b'x(["config", ' + b'"--global", ' * 4000 + b"])\n",
    ],
    ids=["dashes", "scopes", "argv-dashes", "argv-scopes"],
)
def test_long_option_runs_match_in_linear_time(code: bytes) -> None:
    """An option could match two ways (`-` + `-a` or `--` + `a`), so a run of them backtracked
    exponentially; options before the scope can't be the scope, so `--global` runs aren't
    quadratic either."""
    assert forms(code) == []


def test_the_hook_command_line_changing_git_globally() -> None:
    found = persistence({}, {"postinstall": "git config --global core.hooksPath ./hooks"})
    assert [f for f, *_ in found] == ["git-config"]
    assert persistence({}, {"postinstall": "git config core.hooksPath ./hooks || true"}) == []


def test_the_rule_names_the_git_change() -> None:
    code = b'spawnSync("git", ["config", "--global", "core.hooksPath", dir])\n'
    (finding,) = RULE.evaluate_code(hooked({"setup.js": code}))
    assert finding.rule_version == 7
    assert "global git configuration" in finding.explanation
    assert finding.evidence[0].path == "setup.js"
