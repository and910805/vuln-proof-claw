"""Liveness and readiness endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from vuln_proof_claw import __version__
from vuln_proof_claw.api.dependencies import ReadinessService, get_readiness_service
from vuln_proof_claw.api.schemas.health import (
    LivenessResponse,
    ReadinessCheck,
    ReadinessResponse,
)

router = APIRouter(prefix="/health", tags=["health"])


@router.get(
    "/live",
    response_model=LivenessResponse,
    summary="Process liveness",
)
def liveness() -> LivenessResponse:
    """Return success when the API process can serve requests."""
    return LivenessResponse(version=__version__)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
    summary="Dependency readiness",
)
async def readiness(
    response: Response,
    service: Annotated[ReadinessService, Depends(get_readiness_service)],
) -> ReadinessResponse:
    """Check safe configuration and database readiness."""
    results = await service.check()
    ready = all(result.ready for result in results)
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(
        status="ready" if ready else "not_ready",
        checks=tuple(
            ReadinessCheck(
                name=result.name,
                status="ready" if result.ready else "not_ready",
                code=result.code,
            )
            for result in results
        ),
    )
