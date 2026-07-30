"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from vuln_proof_claw import __version__
from vuln_proof_claw.api.dependencies import (
    DatabaseReadinessProbe,
    ReadinessProbe,
    ReadinessService,
    StaticReadinessProbe,
)
from vuln_proof_claw.api.routes.health import router as health_router
from vuln_proof_claw.config.settings import Settings, load_settings
from vuln_proof_claw.observability.logging import configure_logging
from vuln_proof_claw.persistence.session import create_engine_from_settings

logger = structlog.get_logger(__name__)


def create_app(
    settings: Settings | None = None,
    *,
    database_probe: ReadinessProbe | None = None,
) -> FastAPI:
    """Create an API instance with isolated lifespan-managed dependencies."""
    app_settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(
            log_format=app_settings.logging.format,
            level=app_settings.logging.level,
        )
        engine: Engine | None = None
        probe = database_probe
        if probe is None:
            try:
                engine = create_engine_from_settings(app_settings)
                probe = DatabaseReadinessProbe(engine)
            except SQLAlchemyError as error:
                logger.warning(
                    "database_engine_initialization_failed",
                    error_type=type(error).__name__,
                )
                probe = StaticReadinessProbe(
                    name="database",
                    code="database_configuration_invalid",
                )
        app.state.settings = app_settings
        app.state.readiness_service = ReadinessService(app_settings, probe)
        try:
            yield
        finally:
            if engine is not None:
                engine.dispose()

    app = FastAPI(
        title="vuln-proof-claw API",
        summary="Evidence-driven Web and API security testing control plane.",
        version=__version__,
        lifespan=lifespan,
    )
    app.include_router(health_router, prefix="/api/v1")
    return app
