"""Command-line entry point for vuln-proof-claw."""

from __future__ import annotations

import typer

from vuln_proof_claw import __version__

app = typer.Typer(
    add_completion=False,
    help="Evidence-driven autonomous Web and API security testing platform.",
    invoke_without_command=True,
    no_args_is_help=True,
)


@app.callback()
def root(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the installed version and exit.",
        is_eager=True,
    ),
) -> None:
    """Run vuln-proof-claw."""
    if version:
        typer.echo(__version__)
        raise typer.Exit


def main() -> None:
    """Start the command-line application."""
    app()


if __name__ == "__main__":
    main()
