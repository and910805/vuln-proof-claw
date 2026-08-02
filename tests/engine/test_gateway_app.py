"""Fail-closed Engine gateway server and real client/server contract tests."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from tests.execution.test_docker_runtime import REFERENCE, successful_response
from tests.execution.test_engine_gateway import TOKEN, spec
from tests.execution.test_engine_gateway import config as client_config
from vuln_proof_claw.config.models import EngineServerConfig
from vuln_proof_claw.engine.app import EngineServerConfigurationError, create_engine_app
from vuln_proof_claw.engine.backend import EngineBackendError, EngineBackendErrorCode
from vuln_proof_claw.execution.docker_runtime import (
    ContainerWaitResult,
    OwnedContainer,
    RestrictedContainerSpec,
)
from vuln_proof_claw.execution.engine_gateway import HttpDockerEngineGateway


def server_config(**changes: object) -> EngineServerConfig:
    values: dict[str, object] = {
        "enabled": True,
        "token": SecretStr(TOKEN),
    }
    values.update(changes)
    return EngineServerConfig(**values)


class RecordingBackend:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.spec: RestrictedContainerSpec | None = None
        self.failure: Exception | None = None
        self.wait_result = ContainerWaitResult(
            exit_code=0,
            output=successful_response().model_dump_json().encode(),
        )
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True

    async def check_ready(self) -> None:
        self._record("ready")

    async def create(self, value: RestrictedContainerSpec) -> str:
        self.spec = value
        self._record("create")
        return REFERENCE

    async def start(self, reference: str) -> None:
        assert reference == REFERENCE
        self._record("start")

    async def wait(self, reference: str, *, maximum_output_bytes: int) -> ContainerWaitResult:
        assert reference == REFERENCE
        assert maximum_output_bytes > 0
        self._record("wait")
        return self.wait_result

    async def stop(self, reference: str, *, grace_seconds: int) -> None:
        assert reference == REFERENCE
        assert grace_seconds == 5
        self._record("stop")

    async def remove(self, reference: str, *, force: bool, volumes: bool) -> None:
        assert reference == REFERENCE
        assert force
        assert volumes
        self._record("remove")

    async def list_owned(self, *, labels: Mapping[str, str]) -> tuple[OwnedContainer, ...]:
        assert labels == {"owner": "runtime"}
        self._record("inventory")
        return (OwnedContainer(reference=REFERENCE, labels=(("owner", "runtime"),)),)

    def _record(self, operation: str) -> None:
        self.calls.append(operation)
        if self.failure is not None:
            raise self.failure


async def test_real_gateway_client_completes_the_server_contract() -> None:
    backend = RecordingBackend()
    app = create_engine_app(server_config(), backend=backend)
    transport = httpx.ASGITransport(app=app)

    async with HttpDockerEngineGateway(
        client_config(url="http://127.0.0.1:8081"),
        transport=transport,
    ) as gateway:
        await gateway.check_ready()
        reference = await gateway.create(spec())
        await gateway.start(reference)
        waited = await gateway.wait(reference, maximum_output_bytes=1024 * 1024)
        await gateway.stop(reference, grace_seconds=5)
        await gateway.remove(reference, force=True, volumes=True)
        containers = await gateway.list_owned(labels={"owner": "runtime"})

    assert backend.calls == [
        "ready",
        "create",
        "start",
        "wait",
        "stop",
        "remove",
        "inventory",
    ]
    assert backend.spec == spec()
    assert waited.output == successful_response().model_dump_json().encode()
    assert containers[0].label_map == {"owner": "runtime"}


async def test_authentication_happens_before_request_parsing_or_backend_access() -> None:
    backend = RecordingBackend()
    app = create_engine_app(server_config(), backend=backend)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://engine.test",
    ) as client:
        response = await client.post(
            "/v1/containers/start",
            content=b"not-json-and-possibly-sensitive",
            headers={"content-type": "text/plain", "authorization": "Bearer wrong"},
        )

    assert response.status_code == 401
    assert response.json() == {"code": "engine_gateway_unauthorized"}
    assert response.headers["www-authenticate"] == "Bearer"
    assert backend.calls == []


@pytest.mark.parametrize(
    ("headers", "content", "status_code", "code"),
    [
        ({"content-type": "text/plain"}, b"{}", 415, "engine_gateway_content_type_invalid"),
        (
            {"content-type": "application/json", "content-length": "invalid"},
            b"{}",
            400,
            "engine_gateway_content_length_invalid",
        ),
        (
            {"content-type": "application/json"},
            b'{"reference":"value","unexpected":true}',
            422,
            "engine_gateway_request_invalid",
        ),
    ],
)
async def test_invalid_requests_are_rejected_with_stable_codes(
    headers: dict[str, str],
    content: bytes,
    status_code: int,
    code: str,
) -> None:
    backend = RecordingBackend()
    headers["authorization"] = f"Bearer {TOKEN}"
    app = create_engine_app(server_config(), backend=backend)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://engine.test",
    ) as client:
        response = await client.post("/v1/containers/start", content=content, headers=headers)

    assert response.status_code == status_code
    assert response.json() == {"code": code}
    assert backend.calls == []


async def test_streamed_request_limit_is_enforced() -> None:
    backend = RecordingBackend()
    app = create_engine_app(
        server_config(maximum_request_bytes=64 * 1024),
        backend=backend,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://engine.test",
    ) as client:
        response = await client.post(
            "/v1/containers/start",
            content=b"x" * (64 * 1024 + 1),
            headers={
                "authorization": f"Bearer {TOKEN}",
                "content-type": "application/json",
            },
        )

    assert response.status_code == 413
    assert response.json() == {"code": "engine_gateway_request_limit_exceeded"}
    assert backend.calls == []


@pytest.mark.parametrize(
    ("backend_error", "status_code", "code"),
    [
        (EngineBackendError(EngineBackendErrorCode.BUSY), 503, "engine_backend_busy"),
        (EngineBackendError(EngineBackendErrorCode.CONFLICT), 409, "engine_backend_conflict"),
        (EngineBackendError(EngineBackendErrorCode.NOT_FOUND), 404, "engine_backend_not_found"),
        (EngineBackendError(EngineBackendErrorCode.REJECTED), 400, "engine_backend_rejected"),
        (EngineBackendError(EngineBackendErrorCode.UNAVAILABLE), 503, "engine_backend_unavailable"),
        (RuntimeError("private daemon path and credentials"), 503, "engine_backend_unavailable"),
    ],
)
async def test_backend_failures_are_reduced_to_safe_codes(
    backend_error: Exception,
    status_code: int,
    code: str,
) -> None:
    backend = RecordingBackend()
    backend.failure = backend_error
    app = create_engine_app(server_config(), backend=backend)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://engine.test",
    ) as client:
        response = await client.post(
            "/v1/health/ready",
            json={},
            headers={"authorization": f"Bearer {TOKEN}"},
        )

    assert response.status_code == status_code
    assert response.json() == {"code": code}
    assert "private" not in response.text


async def test_default_backend_fails_closed() -> None:
    app = create_engine_app(server_config())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://engine.test",
    ) as client:
        response = await client.post(
            "/v1/health/ready",
            json={},
            headers={"authorization": f"Bearer {TOKEN}"},
        )
    assert response.status_code == 503
    assert response.json() == {"code": "engine_backend_unavailable"}


async def test_backend_output_limit_is_verified_again_at_the_server_boundary() -> None:
    backend = RecordingBackend()
    backend.wait_result = ContainerWaitResult(exit_code=0, output=b"oversized")
    app = create_engine_app(server_config(), backend=backend)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://engine.test",
    ) as client:
        response = await client.post(
            "/v1/containers/wait",
            json={"reference": REFERENCE, "maximum_output_bytes": 1},
            headers={"authorization": f"Bearer {TOKEN}"},
        )
    assert response.status_code == 502
    assert response.json() == {"code": "engine_backend_output_limit_exceeded"}


async def test_concurrent_backend_operations_are_bounded() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    class BlockingBackend(RecordingBackend):
        async def check_ready(self) -> None:
            entered.set()
            await release.wait()

    app = create_engine_app(
        server_config(maximum_concurrent_operations=1, queue_timeout_seconds=0.01),
        backend=BlockingBackend(),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://engine.test",
    ) as client:
        headers = {"authorization": f"Bearer {TOKEN}"}
        first = asyncio.create_task(client.post("/v1/health/ready", json={}, headers=headers))
        await entered.wait()
        second = await client.post("/v1/health/ready", json={}, headers=headers)
        release.set()
        first_response = await first

    assert first_response.status_code == 200
    assert second.status_code == 503
    assert second.json() == {"code": "engine_backend_busy"}


def test_server_configuration_and_secret_representations_fail_closed() -> None:
    with pytest.raises(ValidationError, match="requires an authentication token"):
        EngineServerConfig(enabled=True)
    with pytest.raises(EngineServerConfigurationError, match="disabled"):
        create_engine_app(EngineServerConfig())

    assert TOKEN not in repr(server_config())
    assert spec().request_payload.decode() not in repr(spec())


async def test_application_lifespan_closes_the_privileged_backend() -> None:
    backend = RecordingBackend()
    app = create_engine_app(server_config(), backend=backend)
    async with app.router.lifespan_context(app):
        assert not backend.closed
    assert backend.closed
