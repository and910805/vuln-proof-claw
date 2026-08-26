"""Typer command-line application."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from vuln_proof_claw.cli.doctor import diagnose
from vuln_proof_claw.cli.version import print_version
from vuln_proof_claw.execution.preflight import run_preflight
from vuln_proof_claw.reporting.bundle import verify_disclosure_bundle

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


@app.command("preflight")
def preflight_command(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the stable machine-readable v1 report."),
    ] = False,
) -> None:
    """Execute each security tool and report which binary actually answered."""
    report = run_preflight()
    if json_output:
        typer.echo(json.dumps(report.as_dict(), separators=(",", ":"), sort_keys=True))
    else:
        for result in report.results:
            marker = "ok" if result.ready else "failed"
            location = result.resolved_path or "not found"
            typer.echo(f"[{marker}] {result.name}: {result.code} ({location})")
        typer.echo("preflight: ready" if report.ready else "preflight: not ready")
    if not report.ready:
        raise typer.Exit(code=1)


@app.command("verify-bundle")
def verify_bundle_command(
    bundle: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True, resolve_path=True),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the stable machine-readable v1 result."),
    ] = False,
) -> None:
    """Verify a ProofClaw disclosure bundle without network access."""
    result = verify_disclosure_bundle(bundle)
    if json_output:
        typer.echo(json.dumps(result.as_dict(), separators=(",", ":"), sort_keys=True))
    elif result.valid:
        typer.echo(
            f"bundle: valid ({result.files_checked} files, engagement {result.engagement_id})"
        )
        typer.echo(f"archive sha256: {result.archive_sha256}")
    else:
        typer.echo("bundle: invalid")
        for error in result.errors:
            typer.echo(f"[failed] {error}")
    if not result.valid:
        raise typer.Exit(code=1)


def main() -> None:
    """Start the command-line application."""
    app()
