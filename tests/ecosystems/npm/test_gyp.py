"""`ecosystems.npm.gyp`: the commands gyp files make `node-gyp rebuild` run, read as data."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from kitsunox.ecosystems.npm.gyp import (
    MAX_COMMAND_BYTES,
    MAX_COMMANDS,
    MAX_GYP_BYTES,
    MAX_GYP_FILES,
    MAX_TOTAL_BYTES,
    UNREAD,
    expansions,
    gyp_commands,
)
from kitsunox.ecosystems.npm.install import install_sources


def gyp(text: str) -> list[str]:
    return gyp_commands({"binding.gyp": text.encode()})


def test_expansion_followed_by_text_is_extracted() -> None:
    """Round 4 B's gap: an expansion whose `)` is followed by more text, not a quote."""
    assert gyp('{"targets": [{"target_name": "<!(node payload.js):x"}]}') == ["node payload.js"]
    assert gyp("{'v': 'a <!(node p.js) b'}") == ["node p.js"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("{'v': '\\x3c!(node p.js)'}", ["node p.js"]),  # a Python escape gyp decodes
        ("{'v': '\\u003c!(node p.js)'}", ["node p.js"]),
        ("{'v': '\\074!(node p.js)'}", ["node p.js"]),
        ("{'v': '<!(no' 'de p.js)'}", ["node p.js"]),  # adjacent strings are one
        ("{'v': '<!(echo <!(node p.js))'}", ["echo <!(node p.js)", "node p.js"]),
        ("{'v': '>!@(node p.js) ^!(sh x.sh)'}", ["node p.js", "sh x.sh"]),  # later phases
        ("{'v': '<!pymod_do_main(mod a b)'}", ["pymod_do_main mod a b"]),
        ("{'v': \"<!(['node', 'p.js'])\"}", ["node p.js"]),  # the list form
        ("{'<!(node p.js)': 'v'}", ["node p.js"]),  # in a key
        ("{'v': '''<!(node p.js)'''}", ["node p.js"]),
        ("{'v': r'<!(node p.js)'}", ["node p.js"]),
    ],
)
def test_expansions_however_embedded(text: str, expected: list[str]) -> None:
    assert gyp(text) == expected


def test_bracket_matching_as_gyp_does() -> None:
    """gyp counts every bracket kind and ignores quotes (`FindEnclosingBracketGroup`)."""
    assert expansions("<!(node -p \"require('x').include\")") == [
        "node -p \"require('x').include\""
    ]
    assert expansions('<!(node -e "a[0]({})")tail') == ['node -e "a[0]({})"']
    assert expansions("<!(node p.js") == ["node p.js"]  # never closed: the rest
    assert expansions("<(var) <@(list) <|(files a b)") == []  # no `!`: not a command


def test_comments_are_not_commands() -> None:
    assert gyp("{# '<!(node p.js)'\n 'a': 'b # <!(node q.js)'}") == ["node q.js"]


def test_actions_with_brackets_and_variables() -> None:
    """An action's list may hold `]`; a variable it uses is replaced by its definitions, and
    node-gyp's `module_root_dir` is the package root."""
    text = """{
      'variables': {'cmd%': ['node', 'p.js'], 'other': '<(cmd) --x'},
      'targets': [{'actions': [
        {'action_name': 'a', 'action': ['<@(cmd)']},
        {'action_name': 'b', 'action': ['node', '-e', 'a[0]', '<(module_root_dir)/x.js']},
        {'action_name': 'c', 'action': ['<(other)', '<(unknown)']},
      ]}],
    }"""
    assert gyp(text) == ["node p.js", "node -e a[0] ./x.js", "node p.js --x <(unknown)"]


def test_included_and_dependency_gyp_files_are_read() -> None:
    files = {
        "binding.gyp": b"{'includes': ['sub/common.gypi'],"
        b" 'targets': [{'dependencies': ['deps/z/z.gyp:z', '../outside.gyp:o']}]}",
        "sub/common.gypi": b"{'variables': {'x': '<!(node a.js)'}}",
        "deps/z/z.gyp": b"{'targets': [{'actions': [{'action': ['sh', 'b.sh']}]}]}",
        "outside.gyp": b"{'v': '<!(node never.js)'}",
        "unnamed.gypi": b"{'v': '<!(node never.js)'}",
    }
    assert gyp_commands(files) == ["sh b.sh", "node a.js"]


def test_gyp_files_read_are_bounded() -> None:
    files = {"binding.gyp": repr({"includes": [f"f{i}.gypi" for i in range(30)]}).encode()}
    files |= {f"f{i}.gypi": f"{{'v': '<!(node {i}.js)'}}".encode() for i in range(30)}
    assert len(gyp_commands(files)) == MAX_GYP_FILES - 1


def test_unparsed_files_are_scanned_raw() -> None:
    """gyp would reject these, but what they hold is still listed."""
    assert gyp("{'a': '<!(node p.js)x', ") == ["node p.js"]
    assert gyp('{\'a\': "<!(node -p \\"x\\")" + \'unterminated}') == ['node -p "x"']
    assert gyp("{'action': ['node', 'p.js'] ") == ["node p.js"]
    assert gyp("[" * 500 + "'<!(node p.js)'" + "]" * 500) == ["node p.js"]  # too deep


def test_oversized_gyp_file_is_unread_not_empty() -> None:
    assert gyp(" " * (MAX_GYP_BYTES + 1)) == [UNREAD]


def test_no_gyp_file_no_commands() -> None:
    assert gyp_commands({"package.json": b"{}"}) == []
    assert gyp("{'targets': [{'sources': ['a.cc'], 'defines': ['X=1']}]}") == []
    assert gyp("{'v': '\\N{LATIN SMALL LETTER A}\\N{NO SUCH NAME} \\q \\U00110000'}") == []


def test_suffixed_expansion_code_is_install_code() -> None:
    """The extracted command names a package file, which becomes install code."""
    files = {
        "binding.gyp": b'{"targets": [{"target_name": "<!(node payload.js):x"}]}',
        "payload.js": b"require('child_process')",
        "index.js": b"",
    }
    assert sorted(install_sources(files)) == ["payload.js"]


@pytest.mark.parametrize(
    "text",
    [
        "{'v': '" + "<!(" * 80_000 + "'}",  # unclosed, nested: each runs to the end
        "{'v': '" + "<!(" * 40_000 + ")" * 40_000 + "'}",
        "{'v': " + "'<!(a)' " * 25_000 + "}",  # adjacent strings, joined once
        "[" + "'<!(x)', " * 25_000 + "]",
    ],
    ids=["unclosed", "nested", "adjacent", "many"],
)
def test_hostile_gyp_files_are_bounded(text: str) -> None:
    """Nested or unclosed expansions stay within `MAX_COMMANDS` / `MAX_TOTAL_BYTES`."""
    commands = gyp(text)
    assert len(commands) <= MAX_COMMANDS + 1
    assert sum(len(c) for c in commands) <= 2 * MAX_TOTAL_BYTES + MAX_GYP_BYTES


def test_self_referencing_variables_are_bounded() -> None:
    loop = " ".join(["<(a)"] * 2_000)
    text = "{'variables': {'a': '" + loop + "'}, 'targets': [{'actions': [{'action': ['<(a)']}]}]}"
    (command,) = gyp(text)
    assert len(command) <= MAX_COMMAND_BYTES


@given(st.text(alphabet="<!@()[]{}'\"\\#:, xnode.js\n", max_size=300))
def test_arbitrary_gyp_text_never_crashes(text: str) -> None:
    commands = gyp(text)
    assert all(isinstance(c, str) and c for c in commands)
