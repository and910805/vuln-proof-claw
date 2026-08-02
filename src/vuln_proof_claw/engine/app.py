"""Authenticated FastAPI boundary for privileged Engine lifecycle operations."""

from __future__ import annotations

import asyncio
import base64
import hmac
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette import status

from vuln_proof_claw import __version__
from vuln_proof_claw.config.models import EngineServerConfig
from vuln_proof_claw.engine.backend import (
    DisabledEngineBackend,
    EngineBackendError,
    EngineBackendErrorCode,
    PrivilegedEngineBackend,
)
from vuln_proof_claw.execution.engine_gateway import (
    AckResponse,
    ContainerCreateRequest,
    ContainerInventoryRequest,
    ContainerReferenceRequest,
    ContainerRemoveRequest,
    ContainerStopRequest,
    ContainerWaitRequest,
    EmptyRequest,
    GatewayModel,
    InventoryResponse,
    OwnedContainerResponse,
    ReadyResponse,
    ReferenceResponse,
    WaitResponse,
)

logger = structlog.get_logger(__name__)
class EngineServerConfigurationError(Exception):
    """Raised before startup when the privileged listener is not explicitly enabled."""


class GatewayRequestError(Exception):
    """Safe HTTP failure generated before privileged backend access."""

    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code


class OperationAdmission:
    """Bound concurrent privileged calls and reject an exhausted queue."""

    def __init__(self, *, limit: int, queue_timeout_seconds: float) -> None:
        self._semaphore = asyncio.Semaphore(limit)
        self._queue_timeout_seconds = queue_timeout_seconds

    async def run[Result](self, operation: Callable[[], Awaitable[Result]]) -> Result:
        try:
            async with asyncio.timeout(self._queue_timeout_seconds):
                await self._semaphore.acquire()
        except TimeoutError as error:
            raise EngineBackendError(EngineBackendErrorCode.BUSY) from error
        try:
            return await operation()
        finally:
            self._semaphore.release()


def create_engine_app(
    config: EngineServerConfig,
    *,
    backend: PrivilegedEngineBackend | None = None,
) -> FastAPI:
    """Create the isolated gateway only from explicit authenticated configuration."""
    if not config.enabled or config.token is None:
        raise EngineServerConfigurationError("engine_server_disabled")
    engine = backend or DisabledEngineBackend()
    admission = OperationAdmission(
        limit=config.maximum_concurrent_operations,
        queue_timeout_seconds=config.queue_timeout_seconds,
    )
    expected_authorization = f"Bearer {config.token.get_secret_value()}"

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        del application
        try:
            yield
        finally:
            await engine.aclose()

    async def authenticate(request: Request) -> None:
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied, expected_authorization):
            raise GatewayRequestError(401, "engine_gateway_unauthorized")

    authenticated = [Depends(authenticate)]
    app = FastAPI(
        title="vuln-proof-claw Engine gateway",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.exception_handler(GatewayRequestError)
    async def request_error_handler(
        request: Request,
        error: GatewayRequestError,
    ) -> JSONResponse:
        del request
        headers = (
            {"WWW-Authenticate": "Bearer"}
            if error.status_code == status.HTTP_401_UNAUTHORIZED
            else None
        )
        return JSONResponse(
            status_code=error.status_code,
            content={"code": error.code},
            headers=headers,
        )

    @app.post("/v1/health/ready", dependencies=authenticated)
    async def ready(request: Request) -> ReadyResponse:
        await _parse_request(request, EmptyRequest, maximum_bytes=config.maximum_request_bytes)
        await _run_backend(admission, engine.check_ready)
        return ReadyResponse(ready=True)

    @app.post("/v1/containers/create", dependencies=authenticated)
    async def create(request: Request) -> ReferenceResponse:
        message = await _parse_request(
            request,
            ContainerCreateRequest,
            maximum_bytes=config.maximum_request_bytes,
        )
        reference = await _run_backend(
            admission,
            lambda: engine.create(message.to_container_spec()),
        )
        return ReferenceResponse(reference=reference)

    @app.post("/v1/containers/start", dependencies=authenticated)
    async def start(request: Request) -> AckResponse:
        message = await _parse_request(
            request,
            ContainerReferenceRequest,
            maximum_bytes=config.maximum_request_bytes,
        )
        await _run_backend(admission, lambda: engine.start(message.reference))
        return AckResponse(acknowledged=True)

    @app.post("/v1/containers/wait", dependencies=authenticated)
    async def wait(request: Request) -> WaitResponse:
        message = await _parse_request(
            request,
            ContainerWaitRequest,
            maximum_bytes=config.maximum_request_bytes,
        )
        result = await _run_backend(
            admission,
            lambda: engine.wait(
                message.reference,
                maximum_output_bytes=message.maximum_output_bytes,
            ),
        )
        if len(result.output) > message.maximum_output_bytes:
            raise GatewayRequestError(502, "engine_backend_output_limit_exceeded")
        return WaitResponse(
            exit_code=result.exit_code,
            output_base64=base64.b64encode(result.output).decode("ascii"),
        )

    @app.post("/v1/containers/stop", dependencies=authenticated)
    async def stop(request: Request) -> AckResponse:
        message = await _parse_request(
            request,
            ContainerStopRequest,
            maximum_bytes=config.maximum_request_bytes,
        )
        await _run_backend(
            admission,
            lambda: engine.stop(
                message.reference,
                grace_seconds=message.grace_seconds,
            ),
        )
        return AckResponse(acknowledged=True)

    @app.post("/v1/containers/remove", dependencies=authenticated)
    async def remove(request: Request) -> AckResponse:
        message = await _parse_request(
            request,
            ContainerRemoveRequest,
            maximum_bytes=config.maximum_request_bytes,
        )
        await _run_backend(
            admission,
            lambda: engine.remove(
                message.reference,
                force=message.force,
                volumes=message.volumes,
            ),
        )
        return AckResponse(acknowledged=True)

    @app.post("/v1/containers/inventory", dependencies=authenticated)
    async def inventory(request: Request) -> InventoryResponse:
        message = await _parse_request(
            request,
            ContainerInventoryRequest,
            maximum_bytes=config.maximum_request_bytes,
        )
        containers = await _run_backend(
            admission,
            lambda: engine.list_owned(labels=message.labels),
        )
        return InventoryResponse(
            containers=tuple(
                OwnedContainerResponse(
                    reference=container.reference,
                    labels=dict(container.labels),
                )
                for container in containers
            )
        )

    return app


async def _parse_request[
    Message: GatewayModel
](request: Request, model: type[Message], *, maximum_bytes: int) -> Message:
    content_type = request.headers.get("content-type", "").split(";", maxsplit=1)[0]
    if content_type.casefold() != "application/json":
        raise GatewayRequestError(415, "engine_gateway_content_type_invalid")
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            parsed_length = int(declared_length)
        except ValueError as error:
            raise GatewayRequestError(400, "engine_gateway_content_length_invalid") from error
        if parsed_length < 0:
            raise GatewayRequestError(400, "engine_gateway_content_length_invalid")
        if parsed_length > maximum_bytes:
            raise GatewayRequestError(413, "engine_gateway_request_limit_exceeded")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum_bytes:
            raise GatewayRequestError(413, "engine_gateway_request_limit_exceeded")
        body.extend(chunk)
    try:
        return model.model_validate_json(bytes(body))
    except (ValidationError, ValueError) as error:
        raise GatewayRequestError(422, "engine_gateway_request_invalid") from error


async def _run_backend[Result](
    admission: OperationAdmission,
    operation: Callable[[], Awaitable[Result]],
) -> Result:
    try:
        return await admission.run(operation)
    except EngineBackendError as error:
        status_code = {
            EngineBackendErrorCode.BUSY: 503,
            EngineBackendErrorCode.CONFLICT: 409,
            EngineBackendErrorCode.NOT_FOUND: 404,
            EngineBackendErrorCode.OUTPUT_LIMIT: 502,
            EngineBackendErrorCode.REJECTED: 400,
            EngineBackendErrorCode.UNAVAILABLE: 503,
        }[error.code]
        raise GatewayRequestError(status_code, error.code.value) from error
    except Exception as error:
        logger.error("engine_backend_unexpected_failure", error_type=type(error).__name__)
        raise GatewayRequestError(503, "engine_backend_unavailable") from error
