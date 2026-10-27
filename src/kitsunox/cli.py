"""Command-line entry point. Pipeline commands are added as each stage lands."""

from typing import Annotated

import typer

from kitsunox import __version__

app = typer.Typer(help="Flag likely software supply chain attacks in recent npm releases.")


def _print_version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_print_version, is_eager=True, help="Show version and exit."
        ),
    ] = False,
) -> None:
    """Kitsunox supply chain attack triage pipeline."""
