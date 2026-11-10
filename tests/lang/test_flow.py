"""`lang.flow`: where a path value goes in small, inert JavaScript (nothing here runs)."""

import re

import pytest

from kitsunox.lang.flow import Write, reaches_write, unfollowed_installer

SEED = re.compile(rb'"\.claude"|"~/\.claude[^"]*"')


def flow(files: dict[str, bytes], seed: re.Pattern[bytes] = SEED) -> Write | None:
    code = {path: (data, "javascript") for path, data in files.items()}
    seeds = {path: [m.span() for m in seed.finditer(data)] for path, data in files.items()}
    return reaches_write(code, {p: s for p, s in seeds.items() if s})


@pytest.mark.parametrize(
    "code",
    [
        # direct, through a variable, a function's return, a parameter, `for ... of`
        b'fs.writeFileSync(join(os.homedir(), ".claude", "x"), s)',
        b'const d = join(os.homedir(), ".claude"); fs.mkdirSync(d, {recursive: true})',
        b'function dir() { return join(os.homedir(), ".claude") }\nfs.cpSync(src, dir())',
        b'function put(t) { fs.copyFileSync(src, t) }\nput(join(os.homedir(), ".claude"))',
        b'const all = [join(os.homedir(), ".claude")];\n'
        b"for (const t of all) fs.rmSync(t), fs.mkdirSync(t)",
        # a property, an options object handed to a library, a container filled by a helper
        b'const C = {home: join(os.homedir(), ".claude")};\nfs.writeFileSync(C.home + "/s", s)',
        b'installSkills({target: join(os.homedir(), ".claude")})',
        b"function add(list, d) { list.push(d) }\nconst found = []\n"
        b'add(found, join(os.homedir(), ".claude"))\nfor (const f of found) fs.renameSync(tmp, f)',
        # a shell command that writes it, a callback-held function value
        b'const d = join(os.homedir(), ".claude"); execSync(`cp -r skills ${d}`)',
        b'function dirs() { return [join(os.homedir(), ".claude")] }\n'
        b"const ts = (opts.dirs ?? dirs)(); for (const t of ts) fs.cpSync(s, t)",
        b'fs.openSync(join(os.homedir(), ".claude", "l"), "a")',
    ],
)
def test_a_path_that_reaches_a_write(code: bytes) -> None:
    assert flow({"setup.js": code}) is not None


@pytest.mark.parametrize(
    "code",
    [
        # reads: `@mearl/native-host`, `aiimpactmeter`, `symbiot` (all benign)
        b'const home = join(os.homedir(), ".claude"); if (fs.existsSync(home)) log(home)',
        b'readClaudeProjects(join(os.homedir(), ".claude", "projects"), out)',
        b'const d = join(os.homedir(), ".claude"); for (const f of fs.readdirSync(d)) count++',
        b'const p = join(os.homedir(), ".claude"); console.log(`skills go to ${p}`)',
        b'const p = join(os.homedir(), ".claude"); process.stdout.write(p)',
        # content, not destination; a regex's exec; a program that doesn't write
        b'const p = join(os.homedir(), ".claude"); fs.writeFileSync(log, p)',
        b'const p = join(os.homedir(), ".claude"); PATTERN.exec(p)',
        b'const p = join(os.homedir(), ".claude"); spawnSync("git", ["-C", p, "status"])',
        b'const s = new Set(); s.add(join(os.homedir(), ".claude")); s.has(x)',
        # behind an opt-in switch the user sets (`basinfy@1.3.13`)
        b'if (process.env.KX_SETUP === "1") { fs.cpSync(s, join(os.homedir(), ".claude")) }',
    ],
)
def test_a_path_that_is_only_read(code: bytes) -> None:
    assert flow({"setup.js": code}) is None


def test_npm_own_variables_are_not_an_opt_in() -> None:
    code = b'if (process.env.npm_config_global === "true") fs.cpSync(s, join(h, ".claude"))'
    assert flow({"setup.js": code}) is not None


def test_names_follow_into_other_files() -> None:
    files = {
        "lib.js": b'export const CLIENTS = [{home: join(os.homedir(), ".claude")}]\n',
        "setup.js": b"for (const c of CLIENTS) fs.mkdirSync(path.join(c.home, 'skills'))\n",
    }
    found = flow(files)
    assert found is not None and found.path == "setup.js" and found.text.startswith("fs.mkdirSync")


def test_too_many_uses_count_as_a_write() -> None:
    uses = b"".join(b"f(d);" for _ in range(1200))
    assert flow({"setup.js": b'const d = join(os.homedir(), ".claude");' + uses}) is not None


@pytest.mark.parametrize(
    ("files", "found"),
    [
        # `wkappbot-code`: its postinstall runs its own CLI's `install`, which isn't an install file
        ({"post.js": b'const a = [CLI, "install"]; spawn(process.execPath, a)'}, True),
        # `local-mcp`: a downloaded binary configures the clients
        ({"setup.js": b'spawnSync(bin, ["--configure-clients", "--json"])'}, True),
        # `@agentonweb/terminal-host`: the script it runs is an install file, read by the flow
        (
            {
                "post.js": b"spawnSync(process.execPath, [new URL('./lib/cli.js'), 'setup'])",
                "lib/cli.js": b"",
            },
            False,
        ),
        ({"setup.js": b'spawnSync("npm", ["install", "--no-save"])'}, False),  # a tool
        ({"setup.js": b'spawnSync(bin, ["--version"])'}, False),
    ],
)
def test_unfollowed_installer(files: dict[str, bytes], found: bool) -> None:
    code = {path: (data, "javascript") for path, data in files.items()}
    assert (unfollowed_installer(code) is not None) is found
