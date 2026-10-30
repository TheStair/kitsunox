from pathlib import Path

import pytest

from kitsunox.util.env import env_value

NAME = "KITSUNOX_TEST_SETTING"


def test_environment_wins_over_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"{NAME}=from-file\n")
    monkeypatch.setenv(NAME, "from-env")
    assert env_value(NAME, dotenv) == "from-env"
    monkeypatch.setenv(NAME, "")  # empty counts as unset
    assert env_value(NAME, dotenv) == "from-file"


def test_dotenv_syntax(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(NAME, raising=False)
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        f"# {NAME}=commented\nOTHER=1\n{NAME}_LONGER=no\nexport {NAME} = 'a=b c'\n"
        f'{NAME}="https://x/y?z=1"\n'
    )
    assert env_value(NAME, dotenv) == "https://x/y?z=1"  # the last assignment wins
    dotenv.write_text(f"export {NAME} = 'a=b c'\n")
    assert env_value(NAME, dotenv) == "a=b c"
    dotenv.write_text(f"{NAME}=\n")
    assert env_value(NAME, dotenv) is None


def test_missing_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(NAME, raising=False)
    assert env_value(NAME, tmp_path / "absent") is None
