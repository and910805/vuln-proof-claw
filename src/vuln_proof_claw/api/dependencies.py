"""API dependency contracts and readiness probes."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol, cast

import structlog
from fastapi import Request
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from vuln_proof_claw.config.settings import Settings

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Internal result with only safe, stable status codes."""

    name: str
    ready: bool
    code: str


class ReadinessProbe(Protocol):
    """Synchronous dependency probe run outside the event loop."""

    def check(self) -> ProbeResult:
        """Return a safe readiness result."""


class DatabaseReadinessProbe:
    """Check database connectivity without exposing connection details."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def check(self) -> ProbeResult:
        try:
            with self._engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError as error:
            logger.warning(
                "database_readiness_failed",
                error_type=type(error).__name__,
            )
            return ProbeResult("database", False, "database_unavailable")
        return ProbeResult("database", True, "database_ready")


class StaticReadinessProbe:
    """Represent a startup failure as a safe readiness result."""

    def __init__(self, *, name: str, code: str) -> None:
        self._result = ProbeResult(name, False, code)

    def check(self) -> ProbeResult:
        return self._result


class ReadinessService:
    """Aggregate configuration and dependency readiness."""

    def __init__(self, settings: Settings, database_probe: ReadinessProbe) -> None:
        self._settings = settings
        self._database_probe = database_probe

    async def check(self) -> tuple[ProbeResult, ...]:
        config_result = ProbeResult(
            name="configuration",
            ready=True,
            code=f"configuration_ready_{self._settings.app.environment.value}",
        )
        database_result = await asyncio.to_thread(self._database_probe.check)
        return config_result, database_result


def get_readiness_service(request: Request) -> ReadinessService:
    """Resolve the lifespan-managed readiness service."""
    return cast("ReadinessService", request.app.state.readiness_service)
