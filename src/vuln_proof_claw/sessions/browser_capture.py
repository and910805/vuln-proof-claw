"""Capture a browser authentication session and persist it to the registry.

A disposable, egress-restricted browser worker performs a form login and returns
the resulting storage state. This coordinator scope-checks the login target,
runs the worker through an injected seam, and commits the captured state as
tamper-evident session material through :class:`AuthenticationSessionService`.
Login credentials are used only to establish the session; they never enter the
audit trail or the persisted material.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.orm import Session

from vuln_proof_claw.audit import record_audit_event
from vuln_proof_claw.config.models import DockerConfig
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EngagementId
from vuln_proof_claw.domain.models import AuthenticationSession
from vuln_proof_claw.execution.docker_runtime import SubprocessDockerCommandRunner
from vuln_proof_claw.execution.manager import WorkerExecutionUnavailableError
from vuln_proof_claw.execution.session_envelope import (
    SESSION_REQUEST_ENV,
    LoginInstruction,
    SessionCaptureEnvelope,
)
from vuln_proof_claw.persistence.repositories import ScopeRepository, Stored
from vuln_proof_claw.policy.scope import evaluate_scope, normalize_target
from vuln_proof_claw.sessions.service import (
    AuthenticationSessionError,
    AuthenticationSessionService,
)

_SYSTEM_ACTOR = "system:browser-session-capture"


class BrowserSessionCaptureError(Exception):
    """Safe, stable failure raised by the browser session-capture boundary."""


class BrowserSessionRunner(Protocol):
    """Runs one login in a disposable browser and returns its captured envelope."""

    @property
    def identity(self) -> str:
        """Return the immutable browser image identity."""

    async def run(self, instruction: LoginInstruction) -> SessionCaptureEnvelope:
        """Execute the login and return the parsed capture envelope."""


def parse_session_envelope(stdout: str) -> SessionCaptureEnvelope:
    """Return the last line of worker stdout that parses as a session envelope."""
    for line in reversed(stdout.splitlines()):
        candidate = line.strip()
        if not candidate:
            continue
        try:
            return SessionCaptureEnvelope.model_validate_json(candidate)
        except ValueError:
            continue
    raise BrowserSessionCaptureError("browser_session_envelope_missing")


class DockerBrowserSessionRunner:
    """Run the hardened disposable browser image and return its session envelope.

    The container drops all Linux capabilities, gains no new privileges, and is
    attached only to the isolated worker network, so it can reach the engagement
    target but never the public internet. Unlike the HTTP worker it keeps a
    writable root because a browser engine needs scratch space.
    """

    def __init__(self, config: DockerConfig) -> None:
        if not config.runtime_enabled:
            raise WorkerExecutionUnavailableError("docker worker runtime is disabled")
        self._config = config
        self._runner = SubprocessDockerCommandRunner(config.cli_path)

    @property
    def identity(self) -> str:
        return f"docker-browser:{self._config.browser_image}"

    async def run(self, instruction: LoginInstruction) -> SessionCaptureEnvelope:
        create = await self._runner.run(
            [
                "create",
                "--network", self._config.worker_network,
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "512",
                "--memory", "1024m",
                "--cpus", "2.0",
                "--shm-size", "256m",
                "--label", f"{self._config.ownership_label}=true",
                "--env", f"{SESSION_REQUEST_ENV}={instruction.model_dump_json()}",
                self._config.browser_image,
            ]
        )
        if create.returncode != 0:
            raise BrowserSessionCaptureError("browser_create_failed")
        reference = create.stdout.strip()
        if not reference:
            raise BrowserSessionCaptureError("browser_create_returned_empty_reference")
        try:
            started = await self._runner.run(["start", reference])
            if started.returncode != 0:
                raise BrowserSessionCaptureError("browser_start_failed")
            await self._runner.run(["wait", reference])
            logs = await self._runner.run(["logs", reference])
            if logs.returncode != 0:
                raise BrowserSessionCaptureError("browser_logs_failed")
            return parse_session_envelope(logs.stdout)
        finally:
            await self._runner.run(["rm", "--force", "--volumes", reference])


class BrowserSessionCaptureCoordinator:
    """Scope-check, run a disposable browser, and persist the captured session."""

    def __init__(self, session: Session, runner: BrowserSessionRunner) -> None:
        self._session = session
        self._runner = runner

    async def capture(  # noqa: PLR0913 - explicit fields keep the capture unambiguous
        self,
        engagement_id: EngagementId,
        *,
        label: str,
        login: LoginInstruction,
        created_by: str,
        expires_at: datetime,
        at: datetime | None = None,
    ) -> Stored[AuthenticationSession]:
        timestamp = (at or datetime.now(UTC)).astimezone(UTC)
        self._require_in_scope(engagement_id, login, at=timestamp)

        try:
            envelope = await self._runner.run(login)
        except BrowserSessionCaptureError:
            raise
        except Exception as error:
            raise BrowserSessionCaptureError("browser_runtime_failure") from error

        if envelope.status != "succeeded" or envelope.storage_state_json is None:
            error_code = envelope.error_code or "browser_session_capture_failed"
            self._audit_failure(engagement_id, error_code, at=timestamp)
            raise BrowserSessionCaptureError(error_code)

        material = envelope.storage_state_json.encode("utf-8")
        secret_key_names = (*envelope.cookie_names, *envelope.storage_keys)
        try:
            return AuthenticationSessionService(self._session).capture(
                engagement_id,
                label=label,
                material=material,
                secret_key_names=secret_key_names,
                created_by=created_by,
                expires_at=expires_at,
                at=timestamp,
            )
        except AuthenticationSessionError as error:
            raise BrowserSessionCaptureError(str(error)) from error

    def _require_in_scope(
        self,
        engagement_id: EngagementId,
        login: LoginInstruction,
        *,
        at: datetime,
    ) -> None:
        scope = ScopeRepository(self._session).get(engagement_id)
        if scope is None:
            raise BrowserSessionCaptureError("scope_not_found")
        try:
            normalized = str(normalize_target(login.url))
        except DomainValidationError as error:
            raise BrowserSessionCaptureError("login_target_invalid") from error
        if not evaluate_scope(normalized, scope, at=at).allowed:
            raise BrowserSessionCaptureError("login_target_out_of_scope")

    def _audit_failure(self, engagement_id: EngagementId, error_code: str, *, at: datetime) -> None:
        record_audit_event(
            self._session,
            engagement_id,
            "auth_session.capture_failed",
            _SYSTEM_ACTOR,
            {"error_code": error_code},
            at=at,
        )
