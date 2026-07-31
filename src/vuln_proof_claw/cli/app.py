"""Typer command-line application."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from vuln_proof_claw.cli.doctor import diagnose
from vuln_proof_claw.cli.version import print_version

app = typer.Typer(
    add_completion=False,
    help="Evidence-driven autonomous Web and API security testing platform.",
    invoke_without_command=True,
    no_args_is_help=True,
)


@app.callback()
def root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the installed version and exit.",
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Run vuln-proof-claw."""
    if version:
        print_version()
        raise typer.Exit


@app.command("doctor")
def doctor_command(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the stable machine-readable v1 report."),
    ] = False,
) -> None:
    """Check local configuration and required dependencies."""
    report = diagnose()
    if json_output:
        typer.echo(json.dumps(report.as_dict(), separators=(",", ":"), sort_keys=True))
    else:
        for check in report.checks:
            marker = "ok" if check.ready else "failed"
            typer.echo(f"[{marker}] {check.name}: {check.code}")
        typer.echo("doctor: ready" if report.ready else "doctor: not ready")
    if not report.ready:
        raise typer.Exit(code=1)


def main() -> None:
    """Start the command-line application."""
    app()
