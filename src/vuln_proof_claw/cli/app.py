"""Typer command-line application."""

from __future__ import annotations

import json
import signal
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from threading import Event
from typing import Annotated

import typer
from sqlalchemy.orm import Session

from vuln_proof_claw.agent.authsession import IdentitySessions
from vuln_proof_claw.agent.controller import (
    DEFAULT_WATCHDOG_SECONDS,
    MissionController,
    MissionControllerError,
)
from vuln_proof_claw.agent.differential import IdentityRole
from vuln_proof_claw.agent.executor import HttpCaptureExecutor
from vuln_proof_claw.agent.planner import DeterministicPlanner
from vuln_proof_claw.agent.recon import SpaReconnaissance
from vuln_proof_claw.agent.runner import MissionRunner, RunnerConfig
from vuln_proof_claw.agent.sweep import DifferentialSweep, SweepPolicy, SweepProber
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
from vuln_proof_claw.config.identities import (
    IdentityBundle,
    IdentityDefinitionError,
    load_identity_bundle,
    resolve_credentials,
)
from vuln_proof_claw.config.settings import load_settings
from vuln_proof_claw.domain.autonomous import Mission, MissionBudget
from vuln_proof_claw.domain.enums import MissionState
from vuln_proof_claw.domain.identifiers import EngagementId, MissionId
from vuln_proof_claw.execution.pinned_auth_http import PinnedAuthTransport
from vuln_proof_claw.execution.pinned_http import PinnedHttpTransport
from vuln_proof_claw.observability.logging import configure_logging
from vuln_proof_claw.persistence.autonomous_repositories import MissionRepository
from vuln_proof_claw.persistence.repositories import ScopeRepository
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


def _probing_roles(bundle: IdentityBundle) -> tuple[str, str | None, str | None]:
    """Pick the identities a sweep compares, from the roles the bundle declares.

    Taking them from the file rather than from flags means the comparison cannot be
    pointed at an identity the authorization package never covered.
    """
    users = [
        identity.name
        for identity in bundle.identities
        if identity.identity_role is IdentityRole.USER
    ]
    privileged = next(
        (
            identity.name
            for identity in bundle.identities
            if identity.identity_role is IdentityRole.PRIVILEGED
        ),
        None,
    )
    if not users:
        # No credentialled identity: probe anonymously. Only the rules that judge a
        # single response can fire, which is the honest limit of what an unauthenticated
        # pass can establish — and it is the pass that needs no account on the target.
        anonymous = next(
            (
                identity.name
                for identity in bundle.identities
                if identity.identity_role is IdentityRole.ANONYMOUS
            ),
            None,
        )
        if anonymous is None:
            raise IdentityDefinitionError(
                "a sweep needs an identity with role 'user' or 'anonymous'"
            )
        return (anonymous, None, privileged)
    return (users[0], users[1] if len(users) > 1 else None, privileged)


def _sweep_rate(budget: MissionBudget, requested: int | None) -> int:
    """Return the probe rate, never above what the engagement authorizes.

    The engagement's own per-domain limit is the default and the ceiling. A command
    line flag may slow a sweep down; it must not be able to speed one past the number
    the authorization package set.
    """
    authorized = budget.requests_per_minute_per_domain
    if requested is None:
        return authorized
    return min(requested, authorized)


def _build_prober(
    path: Path, *, scope: object, rate: int
) -> tuple[SweepProber, tuple[str, ...]]:
    bundle = load_identity_bundle(path)
    credentials, literals = resolve_credentials(bundle)
    owner, other, privileged = _probing_roles(bundle)
    sessions = IdentitySessions(
        transport=PinnedAuthTransport(scope),  # type: ignore[arg-type]
        bundle=bundle,
        credentials=credentials,
        scope=scope,  # type: ignore[arg-type]
    )
    prober = SweepProber(
        sweep=DifferentialSweep(
            sessions=sessions,
            base_url=bundle.base_url,
            policy=SweepPolicy(requests_per_minute=rate),
        ),
        owner=owner,
        other=other,
        privileged=privileged,
    )
    return (prober, literals)


@mission_app.command("run")
def mission_run_command(  # noqa: PLR0913, PLR0917 - Typer binds these as named flags
    mission_id: Annotated[str, typer.Argument(help="Mission identifier.")],
    watchdog_seconds: Annotated[
        int,
        typer.Option("--watchdog", help="Seconds before a silent run is reaped."),
    ] = DEFAULT_WATCHDOG_SECONDS,
    max_failures: Annotated[
        int,
        typer.Option("--max-failures", help="Consecutive failures before giving up."),
    ] = 10,
    recon_base_url: Annotated[
        str | None,
        typer.Option(
            "--recon",
            help="Entry URL whose scripts are read to recover the API inventory.",
        ),
    ] = None,
    identities: Annotated[
        Path | None,
        typer.Option(
            "--identities",
            exists=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Identity bundle enabling differential probing of the recovered surface.",
        ),
    ] = None,
    rate: Annotated[
        int | None,
        typer.Option(
            "--rate",
            help="Probe requests per minute. Defaults to, and is capped by, the "
            "engagement's own per-domain limit.",
        ),
    ] = None,
    probe_mutating: Annotated[
        bool,
        typer.Option(
            "--probe-mutating",
            help="Also probe state-changing endpoints with an empty body. Off by default.",
        ),
    ] = False,
) -> None:
    """Run a mission continuously until interrupted.

    Ctrl+C (or SIGTERM) asks for a clean stop: the current cycle finishes rather than
    being torn open. A failing cycle backs off and retries instead of ending the run, so
    the process is expected to survive transient database and network faults unattended.
    """
    settings = load_settings()
    configure_logging(log_format=settings.logging.format, level=settings.logging.level)
    stop = Event()

    def request_stop(signum: int, _frame: object) -> None:
        typer.echo(f"\nsignal {signum} received; stopping after this cycle")
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    with suppress(AttributeError, ValueError):
        signal.signal(signal.SIGTERM, request_stop)

    engine = create_engine_from_settings(load_settings())
    session_factory = create_session_factory(engine)

    @contextmanager
    def controller_factory() -> Iterator[MissionController]:
        with session_factory() as session:
            engagement_id = _engagement_of(session, mission_id)
            scope = ScopeRepository(session).get(engagement_id)
            if scope is None:
                raise MissionControllerError("engagement_scope_unavailable")
            prober = None
            if identities is not None:
                budget = _mission_of(session, mission_id).budget
                prober, literals = _build_prober(
                    identities, scope=scope, rate=_sweep_rate(budget, rate)
                )
                if literals:
                    typer.echo(
                        "[warning] passwords are literal in the identity file for: "
                        + ", ".join(literals)
                    )
            yield MissionController(
                session,
                MissionId(mission_id),
                planner=DeterministicPlanner(),
                executor=HttpCaptureExecutor(
                    session,
                    PinnedHttpTransport(scope),
                    engagement_id=engagement_id,
                ),
                actor=f"agent:runner:{mission_id[:8]}",
                reconnaissance=(
                    SpaReconnaissance(
                        transport=PinnedAuthTransport(scope),
                        scope=scope,
                        base_url=recon_base_url,
                    )
                    if recon_base_url
                    else None
                ),
                prober=prober,
                probe_mutating=probe_mutating,
            )

    runner = MissionRunner(
        controller_factory=controller_factory,
        config=RunnerConfig(
            watchdog_seconds=watchdog_seconds,
            maximum_consecutive_failures=max_failures,
        ),
    )
    typer.echo(f"mission {mission_id} running continuously (Ctrl+C to stop)")
    try:
        report = runner.run_forever(stop)
    finally:
        engine.dispose()

    typer.echo(
        f"stopped: {report.stopped_because}  "
        f"cycles completed {report.cycles_completed}, failed {report.cycles_failed}"
    )
    if report.last_error:
        typer.echo(f"last message: {report.last_error}")
    if report.stopped_because in {"fatal", "failure_limit"}:
        raise typer.Exit(code=1)


def _mission_of(session: Session, mission_id: str) -> Mission:
    stored = MissionRepository(session).get(MissionId(mission_id))
    if stored is None:
        raise MissionControllerError("mission_not_found")
    return stored.entity


def _engagement_of(session: Session, mission_id: str) -> EngagementId:
    return _mission_of(session, mission_id).engagement_id


def main() -> None:
    """Start the command-line application."""
    app()
