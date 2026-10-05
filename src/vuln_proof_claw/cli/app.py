"""Typer command-line application."""

from __future__ import annotations

import json
import signal
import ssl
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Annotated

import typer
from sqlalchemy.orm import Session

from vuln_proof_claw.agent.authsession import (
    AuthenticationError,
    IdentitySessions,
    ProbeError,
)
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
    CredentialResolution,
    IdentityBundle,
    IdentityDefinitionError,
    inspect_credentials,
    load_identity_bundle,
)
from vuln_proof_claw.config.settings import load_settings
from vuln_proof_claw.domain.autonomous import Mission, MissionBudget
from vuln_proof_claw.domain.enums import MissionState
from vuln_proof_claw.domain.identifiers import EngagementId, MissionId
from vuln_proof_claw.execution.pinned_auth_http import (
    PinnedAuthTransport,
    unverified_tls_context,
)
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


def _probing_roles(
    bundle: IdentityBundle, *, available: set[str] | None = None
) -> tuple[str, str | None, str | None]:
    """Pick the identities a sweep compares, from the roles the bundle declares.

    Taking them from the file rather than from flags means the comparison cannot be
    pointed at an identity the authorization package never covered. ``available``
    narrows that to the identities whose credentials have actually been supplied, so a
    bundle declaring an admin nobody has filled in degrades to the comparisons it can
    still make instead of failing.
    """
    usable = (
        bundle.identities
        if available is None
        else tuple(i for i in bundle.identities if i.name in available)
    )
    users = [
        identity.name
        for identity in usable
        if identity.identity_role is IdentityRole.USER
    ]
    privileged = next(
        (
            identity.name
            for identity in usable
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
                for identity in usable
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


@dataclass(frozen=True, slots=True)
class _Probing:
    """The probing collaborators a run builds from one identity bundle."""

    prober: SweepProber
    resolution: CredentialResolution
    sessions: IdentitySessions
    discovery_identity: str
    """Whose session reconnaissance should look through.

    The most privileged identity available, because discovery is about seeing the
    whole surface: an administrator's pages list what a user's never mention, and an
    inventory is only as complete as the account that fetched it.
    """


def _build_prober(
    path: Path, *, scope: object, rate: int, tls: ssl.SSLContext | None = None
) -> _Probing:
    bundle = load_identity_bundle(path)
    # Deliberately the lenient form. A credential nobody has filled in yet is a normal
    # state for an agent meant to run unattended for days: it should do the work that
    # identity is not needed for and say what it is waiting on, not refuse to start.
    resolution = inspect_credentials(bundle)
    credentials = resolution.resolved
    supplied = {identity.name for identity in bundle.identities if identity.credentials is None}
    supplied |= set(credentials)
    owner, other, privileged = _probing_roles(bundle, available=supplied)
    sessions = IdentitySessions(
        # Probing reaches only the engagement's own targets, so no asset origins here:
        # reading a CDN's code is reconnaissance, and this is the part that asks
        # questions of a host.
        transport=PinnedAuthTransport(scope, ssl_context=tls),  # type: ignore[arg-type]
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
    return _Probing(
        prober=prober,
        resolution=resolution,
        sessions=sessions,
        discovery_identity=privileged or owner,
    )


def _discovery_session(
    probing: _Probing,
) -> Callable[[], tuple[tuple[str, str], ...]]:
    """Return a supplier of the cookie header reconnaissance should fetch with.

    Authenticating lazily, on the first request, keeps a run that never reaches
    reconnaissance from sending a login nobody asked for. A failure is reported and
    then treated as "no session": discovery degrades to the anonymous view rather than
    taking the cycle down, which is the same bargain every other optional capability
    in the loop makes.
    """
    state: dict[str, bool] = {"tried": False}

    def headers() -> tuple[tuple[str, str], ...]:
        if not state["tried"]:
            state["tried"] = True
            try:
                probing.sessions.authenticate(probing.discovery_identity)
                typer.echo(
                    f"[note] discovery is looking through '"
                    f"{probing.discovery_identity}'"
                )
            except (AuthenticationError, ProbeError) as error:
                typer.echo(
                    f"[warning] could not authenticate "
                    f"'{probing.discovery_identity}' for discovery: {error} — "
                    "continuing anonymously"
                )
        return probing.sessions.cookie_header(probing.discovery_identity)

    return headers


@mission_app.command("credentials")
def mission_credentials_command(
    identities: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True, resolve_path=True),
    ],
    json_output: JsonOption = False,
) -> None:
    """Show which credentials an identity bundle needs and which are still missing.

    Prints variable names and never a value, so the output is safe to paste into a
    ticket or a log.
    """
    try:
        bundle = load_identity_bundle(identities)
    except IdentityDefinitionError as error:
        typer.echo(f"[failed] {error}")
        raise typer.Exit(code=1) from error

    resolution = inspect_credentials(bundle)
    document: dict[str, object] = {
        "schema_version": "v1",
        "base_url": bundle.base_url,
        "complete": resolution.complete,
        "identities": [
            {
                "identity": slot.identity,
                "role": slot.role,
                "satisfied": slot.satisfied,
                "literal_in_file": slot.literal_in_file,
                "waiting_for": list(slot.pending_variables),
            }
            for slot in resolution.slots
        ],
    }
    if json_output:
        typer.echo(json.dumps(document, separators=(",", ":"), sort_keys=True))
        raise typer.Exit(code=0 if resolution.complete else 1)

    anonymous = [i.name for i in bundle.identities if i.credentials is None]
    if anonymous:
        typer.echo(f"no credentials needed: {', '.join(anonymous)}")
    for slot in resolution.slots:
        if slot.satisfied:
            source = "literal in file" if slot.literal_in_file else "from environment"
            typer.echo(f"[ok     ] {slot.identity} ({slot.role}) — {source}")
        else:
            typer.echo(
                f"[pending] {slot.identity} ({slot.role}) — set "
                + ", ".join(slot.pending_variables)
            )
    if not resolution.complete:
        typer.echo("\nsupply the variables above, then re-run this command to confirm.")
    raise typer.Exit(code=0 if resolution.complete else 1)


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
    asset_origin: Annotated[
        list[str] | None,
        typer.Option(
            "--asset-origin",
            help="Host whose static code may be read although it is not a target, "
            "for applications that serve their own JavaScript from a CDN. "
            "Grants reading only: never a probe target. Repeatable.",
        ),
    ] = None,
    insecure_tls: Annotated[
        bool,
        typer.Option(
            "--insecure-tls",
            help="Do not verify the target's TLS certificate. For published test "
            "systems with self-signed certificates. Evidence gathered this way is "
            "not protected against interception and should say so when reported.",
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

    origins = frozenset(asset_origin or ())
    tls = unverified_tls_context() if insecure_tls else None
    if insecure_tls:
        typer.echo(
            "[warning] TLS certificate verification is disabled; evidence from this "
            "run is not protected against interception"
        )
    if origins:
        typer.echo(f"[note] reading static code from: {', '.join(sorted(origins))}")

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
            session_headers: Callable[[], tuple[tuple[str, str], ...]] | None = None
            if identities is not None:
                budget = _mission_of(session, mission_id).budget
                probing = _build_prober(
                    identities, scope=scope, rate=_sweep_rate(budget, rate), tls=tls
                )
                prober = probing.prober
                resolution = probing.resolution
                if resolution.literals:
                    typer.echo(
                        "[warning] passwords are literal in the identity file for: "
                        + ", ".join(resolution.literals)
                    )
                for slot in resolution.pending:
                    typer.echo(
                        f"[pending] identity '{slot.identity}' ({slot.role}) is waiting "
                        f"for: {', '.join(slot.pending_variables)} — "
                        "running without it until supplied"
                    )
                # Discovery looks through the same session probing uses. Without this,
                # reconnaissance sees what an anonymous caller sees, which on an
                # application behind a login is the login page and nothing else.
                session_headers = _discovery_session(probing)
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
                        transport=PinnedAuthTransport(
                            scope, ssl_context=tls, read_only_origins=origins
                        ),
                        scope=scope,
                        base_url=recon_base_url,
                        asset_origins=origins,
                        session_headers=session_headers,
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
