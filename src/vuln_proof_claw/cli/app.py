"""Typer command-line application."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from vuln_proof_claw.cli.doctor import diagnose
from vuln_proof_claw.cli.mission import (
    create_from_definition,
    mission_status,
    set_mission_state,
    validate_definition,
)
from vuln_proof_claw.cli.version import print_version
from vuln_proof_claw.config.engagement import (
    EngagementDefinitionError,
    load_engagement_definition,
)
from vuln_proof_claw.config.settings import load_settings
from vuln_proof_claw.domain.enums import MissionState
from vuln_proof_claw.domain.identifiers import MissionId
from vuln_proof_claw.persistence.session import (
    create_engine_from_settings,
    create_session_factory,
)
from vuln_proof_claw.reporting.bundle import verify_disclosure_bundle

app = typer.Typer(
    add_completion=False,
    help="Evidence-driven autonomous Web and API security testing platform.",
    invoke_without_command=True,
    no_args_is_help=True,
)
mission_app = typer.Typer(
    add_completion=False,
    help="Manage long-running autonomous research missions.",
    no_args_is_help=True,
)
app.add_typer(mission_app, name="mission")


def _emit(document: dict[str, object], *, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(document, separators=(",", ":"), sort_keys=True))
        return
    for key, value in document.items():
        if key == "schema_version":
            continue
        typer.echo(f"{key}: {value}")


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


JsonOption = Annotated[
    bool,
    typer.Option("--json", help="Emit the stable machine-readable v1 document."),
]
DefinitionArgument = Annotated[
    Path,
    typer.Argument(exists=True, dir_okay=False, readable=True, resolve_path=True),
]


@mission_app.command("validate")
def mission_validate_command(
    definition: DefinitionArgument,
    json_output: JsonOption = False,
) -> None:
    """Check an engagement definition and show the scope it authorizes."""
    report = validate_definition(definition)
    _emit(report.as_dict(), json_output=json_output)
    if not report.valid:
        raise typer.Exit(code=1)


@mission_app.command("create")
def mission_create_command(
    definition: DefinitionArgument,
    json_output: JsonOption = False,
) -> None:
    """Register an engagement and its mission from an authorization file."""
    try:
        parsed = load_engagement_definition(definition)
    except EngagementDefinitionError as error:
        typer.echo(f"[failed] {error}")
        raise typer.Exit(code=1) from error

    engine = create_engine_from_settings(load_settings())
    try:
        with create_session_factory(engine).begin() as session:
            report = create_from_definition(session, parsed)
    finally:
        engine.dispose()

    _emit(report.as_dict(), json_output=json_output)
    if not report.created:
        raise typer.Exit(code=1)


@mission_app.command("status")
def mission_status_command(
    mission_id: Annotated[str, typer.Argument(help="Mission identifier.")],
    json_output: JsonOption = False,
) -> None:
    """Show what the agent is doing and what it has found."""
    engine = create_engine_from_settings(load_settings())
    try:
        with create_session_factory(engine).begin() as session:
            report = mission_status(session, MissionId(mission_id))
    finally:
        engine.dispose()

    if report is None:
        typer.echo("[failed] mission_not_found")
        raise typer.Exit(code=1)
    _emit(report.as_dict(), json_output=json_output)


@mission_app.command("pause")
def mission_pause_command(
    mission_id: Annotated[str, typer.Argument(help="Mission identifier.")],
) -> None:
    """Stop scheduling new cycles without discarding mission state."""
    _apply_state(mission_id, state=MissionState.PAUSED)
    typer.echo("mission: paused")


@mission_app.command("resume")
def mission_resume_command(
    mission_id: Annotated[str, typer.Argument(help="Mission identifier.")],
) -> None:
    """Resume a paused mission."""
    _apply_state(mission_id, state=MissionState.RUNNING)
    typer.echo("mission: running")


@mission_app.command("stop")
def mission_stop_command(
    mission_id: Annotated[str, typer.Argument(help="Mission identifier.")],
    kill_switch: Annotated[
        bool,
        typer.Option("--kill-switch", help="Also engage the irreversible kill switch."),
    ] = False,
) -> None:
    """Stop a mission, optionally engaging the kill switch."""
    _apply_state(mission_id, state=MissionState.STOPPED, kill_switch_engaged=kill_switch or None)
    typer.echo("mission: stopped")


def _apply_state(
    mission_id: str,
    *,
    state: MissionState,
    kill_switch_engaged: bool | None = None,
) -> None:
    engine = create_engine_from_settings(load_settings())
    try:
        with create_session_factory(engine).begin() as session:
            updated = set_mission_state(
                session,
                MissionId(mission_id),
                state=state,
                kill_switch_engaged=kill_switch_engaged,
            )
    finally:
        engine.dispose()
    if updated is None:
        typer.echo("[failed] mission_not_found")
        raise typer.Exit(code=1)


def main() -> None:
    """Start the command-line application."""
    app()
