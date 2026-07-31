"""Safe local environment diagnostics."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Literal

import httpx
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError

from vuln_proof_claw.config.settings import (
    WILDCARD_API_HOSTS,
    Settings,
    load_settings,
)
from vuln_proof_claw.persistence.session import create_engine

_DOCTOR_DATABASE_TIMEOUT_SECONDS = 3


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One credential-free environment diagnostic."""

    name: Literal["configuration", "api", "database", "docker"]
    ready: bool
    code: str

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": "ready" if self.ready else "not_ready",
            "code": self.code,
        }


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Stable v1 diagnostic report."""

    checks: tuple[DoctorCheck, ...]

    @property
    def ready(self) -> bool:
        return all(check.ready for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "v1",
            "status": "ready" if self.ready else "not_ready",
            "checks": [check.as_dict() for check in self.checks],
        }


def _api_liveness_url(settings: Settings) -> str:
    host = settings.api.host
    if host in WILDCARD_API_HOSTS:
        host = "127.0.0.1"
    elif ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{settings.api.port}/api/v1/health/live"


def check_api(settings: Settings) -> DoctorCheck:
    """Check the local API without following redirects."""
    try:
        response = httpx.get(
            _api_liveness_url(settings),
            follow_redirects=False,
            timeout=2.0,
        )
    except httpx.HTTPError:
        return DoctorCheck("api", False, "api_unreachable")
    if response.status_code != httpx.codes.OK:
        return DoctorCheck("api", False, "api_unhealthy")
    try:
        payload = response.json()
    except ValueError:
        return DoctorCheck("api", False, "api_invalid_response")
    if payload.get("schema_version") != "v1" or payload.get("status") != "ok":
        return DoctorCheck("api", False, "api_invalid_response")
    return DoctorCheck("api", True, "api_live")


def check_database(settings: Settings) -> DoctorCheck:
    """Check database connectivity and always dispose the temporary engine."""
    try:
        engine = create_engine(_doctor_database_url(settings))
    except SQLAlchemyError:
        return DoctorCheck("database", False, "database_configuration_invalid")
    try:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return DoctorCheck("database", False, "database_unavailable")
        return DoctorCheck("database", True, "database_ready")
    finally:
        engine.dispose()


def _doctor_database_url(settings: Settings) -> URL:
    database_url = make_url(settings.database.url.get_secret_value())
    if database_url.get_backend_name() == "postgresql":
        return database_url.update_query_dict(
            {"connect_timeout": str(_DOCTOR_DATABASE_TIMEOUT_SECONDS)}
        )
    return database_url


def check_docker() -> DoctorCheck:
    """Check whether the Docker CLI is discoverable without executing it."""
    if shutil.which("docker") is None:
        return DoctorCheck("docker", False, "docker_cli_not_found")
    return DoctorCheck("docker", True, "docker_cli_found")


def run_doctor(settings: Settings) -> DoctorReport:
    """Run all diagnostics with already validated settings."""
    return DoctorReport(
        checks=(
            DoctorCheck("configuration", True, "configuration_valid"),
            check_api(settings),
            check_database(settings),
            check_docker(),
        )
    )


def diagnose() -> DoctorReport:
    """Load settings safely and run diagnostics without leaking validation input."""
    try:
        settings = load_settings()
    except ValidationError:
        return DoctorReport(
            checks=(
                DoctorCheck("configuration", False, "configuration_invalid"),
                DoctorCheck("api", False, "skipped_invalid_configuration"),
                DoctorCheck("database", False, "skipped_invalid_configuration"),
                check_docker(),
            )
        )
    return run_doctor(settings)
