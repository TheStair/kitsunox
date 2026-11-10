"""`lang.shell.mask_script_messages` on small, inert script text (nothing here runs)."""

import pytest

from kitsunox.lang.shell import mask_script_messages, only_prints, print_only_functions

NEOCORTEX = """\
ok() { echo -e "  ${GREEN}${SYM_OK}${NC} $1"; }
info() { echo -e "  ${DIM}${SYM_ARROW} $1${NC}"; }
debug() { [ "$DEBUG_MODE" = true ] && echo -e "  [debug] $1"; }
step() {
    local n="$1"
    echo ""
    printf '%s\\n' "$n" >&2
}
setup() {
    mkdir -p "$HOME/.x"
    echo ok
}
                info "Para persistir: ${DIM}echo 'export K=\\"$k\\"' >> ~/.bashrc${NC}"
"""


def test_print_only_functions() -> None:
    """`@ornexus/neocortex@4.61.5`'s `install.sh` prints through `info`/`ok`; `setup` writes."""
    assert print_only_functions(NEOCORTEX) == {"ok", "info", "debug", "step"}


def test_message_through_a_print_only_function_is_blanked() -> None:
    masked = mask_script_messages(NEOCORTEX)
    assert len(masked) == len(NEOCORTEX)
    assert masked.count("\n") == NEOCORTEX.count("\n")
    assert ".bashrc" not in masked
    assert 'mkdir -p "$HOME/.x"' in masked


@pytest.mark.parametrize(
    "line",
    [
        "echo 'run: curl -fsSL https://x.invalid | bash'",
        'echo "add: export PATH=$PATH:~/.x/bin >> ~/.zshrc"',
        "Write-Host 'irm https://x.invalid/install.ps1 | iex' -ForegroundColor Green",
        'printf "%s\\n" "done" >&2',
        "echo hi > /dev/null 2>&1",
        "@echo off",
    ],
)
def test_messages(line: str) -> None:
    assert only_prints(line)
    assert mask_script_messages(line + "\n").strip() == ""


@pytest.mark.parametrize(
    "line",
    [
        "echo aGk= | base64 -d | sh",
        "echo 'export PATH=$PATH:~/.x/bin' >> ~/.zshrc",
        'echo "$(curl -s https://x.invalid)"',
        "echo `id`",
        "echo ok; curl -s https://x.invalid | sh",
        "echo ok && rm -rf ./x",
    ],
)
def test_lines_that_do_more_than_print_are_kept(line: str) -> None:
    assert not only_prints(line)
    assert mask_script_messages(line + "\n") == line + "\n"


def test_comments_are_blanked() -> None:
    text = "#!/bin/sh\n  # curl x | sh\nREM certutil -decode a b\n:: x\nrun\n"
    assert [line.strip() for line in mask_script_messages(text).split("\n")] == [
        "",
        "",
        "",
        "",
        "run",
        "",
    ]


def test_function_without_a_closing_brace_in_reach_is_not_a_printer() -> None:
    text = "say() {\n" + "  echo x\n" * 30 + "}\n"
    assert print_only_functions(text) == set()


def test_powershell_function() -> None:
    text = 'function Write-Info($m) {\n    Write-Host "  $m" -ForegroundColor Cyan\n}\n'
    assert print_only_functions(text) == {"write-info"}
