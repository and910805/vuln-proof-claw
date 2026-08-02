"""Fail-closed command entry point for the isolated Engine gateway service."""

from __future__ import annotations

import uvicorn

from vuln_proof_claw.config.settings import load_settings
from vuln_proof_claw.engine.app import EngineServerConfigurationError, create_engine_app
from vuln_proof_claw.engine.docker_backend import DockerEngineBackend
from vuln_proof_claw.observability.logging import configure_logging


def main() -> None:
    settings = load_settings()
    configure_logging(
        log_format=settings.logging.format,
        level=settings.logging.level,
    )
    try:
        backend = (
            DockerEngineBackend(settings.docker_engine_backend)
            if settings.docker_engine_backend.enabled
            else None
        )
        app = create_engine_app(settings.engine_server, backend=backend)
    except EngineServerConfigurationError as error:
        raise SystemExit(str(error)) from error
    uvicorn.run(
        app,
        host=settings.engine_server.host,
        port=settings.engine_server.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
