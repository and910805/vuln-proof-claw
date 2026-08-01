"""Authenticated Engine gateway client tests using HTTPX's in-memory transport."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from tests.execution.test_docker_runtime import IMAGE, REFERENCE, WORKER_ID, successful_response
from tests.execution.test_protocol import NOW, request
from vuln_proof_claw.config.models import EngineGatewayConfig
from vuln_proof_claw.execution.docker_runtime import (
    DockerWorkerRuntime,
    RestrictedContainerSpec,
    RestrictedRuntimePolicy,
)
from vuln_proof_claw.execution.engine_gateway import (
    ContainerCreateRequest,
    EngineGatewayError,
    HttpDockerEngineGateway,
)

TOKEN = "engine-token-" + "x" * 32


def config(**changes: object) -> EngineGatewayConfig:
    values: dict[str, object] = {
        "url": "https://engine.example.test",
        "token": SecretStr(TOKEN),
    }
    values.update(changes)
    return EngineGatewayConfig(**values)


def spec() -> RestrictedContainerSpec:
    runtime_identity = "docker:worker@sha256:value#policy-sha256:value"
    return RestrictedContainerSpec(
        name=f"vpc-worker-{WORKER_ID}",
        image=IMAGE,
        network="vuln-proof-claw-workers",
        user="10002:10002",
        labels=(
            ("io.vuln-proof-claw.created-at", NOW.isoformat()),
            ("io.vuln-proof-claw.managed-by", "worker-runtime"),
            ("io.vuln-proof-claw.request-id", request().request_id),
            ("io.vuln-proof-claw.runtime-identity", runtime_identity),
            ("io.vuln-proof-claw.worker-id", str(WORKER_ID)),
        ),
        request_payload=request().model_dump_json().encode(),
        timeout_seconds=300,
        memory_bytes=512 * 1024 * 1024,
        nano_cpus=1_000_000_000,
        process_limit=128,
        tmpfs=(
            ("/tmp", "rw,noexec,nosuid,nodev,size=16m"),  # noqa: S108 - container path
            ("/work", "rw,noexec,nosuid,nodev,size=64m"),
        ),
    )


def json_response(payload: object, *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


def static_transport(response: httpx.Response) -> httpx.MockTransport:
    def handler(_: httpx.Request) -> httpx.Response:
        return response

    return httpx.MockTransport(handler)


async def test_complete_gateway_lifecycle_is_authenticated_and_strict() -> None:
    paths: list[str] = []
    bodies: list[dict[str, object]] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        assert http_request.headers["authorization"] == f"Bearer {TOKEN}"
        assert http_request.headers["accept"] == "application/json"
        assert http_request.headers["user-agent"] == "vuln-proof-claw-engine-gateway"
        paths.append(http_request.url.path)
        body = json.loads(http_request.content)
        bodies.append(body)
        if http_request.url.path.endswith("/health/ready"):
            return json_response({"ready": True})
        if http_request.url.path.endswith("/create"):
            return json_response({"reference": REFERENCE})
        if http_request.url.path.endswith("/wait"):
            return json_response(
                {
                    "exit_code": 0,
                    "output_base64": base64.b64encode(b"worker-output").decode(),
                }
            )
        if http_request.url.path.endswith("/inventory"):
            return json_response(
                {
                    "containers": [
                        {
                            "reference": REFERENCE,
                            "labels": {"owner": "runtime"},
                        }
                    ]
                }
            )
        return json_response({"acknowledged": True})

    async with HttpDockerEngineGateway(
        config(),
        transport=httpx.MockTransport(handler),
    ) as gateway:
        await gateway.check_ready()
        reference = await gateway.create(spec())
        await gateway.start(reference)
        waited = await gateway.wait(reference, maximum_output_bytes=1024)
        await gateway.stop(reference, grace_seconds=5)
        await gateway.remove(reference, force=True, volumes=True)
        inventory = await gateway.list_owned(labels={"owner": "runtime"})

    assert reference == REFERENCE
    assert waited.exit_code == 0
    assert waited.output == b"worker-output"
    assert inventory[0].label_map == {"owner": "runtime"}
    assert REFERENCE not in repr(waited)
    assert paths == [
        "/v1/health/ready",
        "/v1/containers/create",
        "/v1/containers/start",
        "/v1/containers/wait",
        "/v1/containers/stop",
        "/v1/containers/remove",
        "/v1/containers/inventory",
    ]
    assert bodies[0] == {}
    create_body = bodies[1]
    assert create_body["read_only_root"] is True
    assert create_body["capability_drop"] == ["ALL"]
    assert create_body["no_new_privileges"] is True
    assert base64.b64decode(str(create_body["request_payload_base64"])) == spec().request_payload
    assert bodies[5] == {"reference": REFERENCE, "force": True, "volumes": True}


async def test_gateway_integrates_with_docker_worker_runtime() -> None:
    received_create: dict[str, object] = {}

    def handler(http_request: httpx.Request) -> httpx.Response:
        body = json.loads(http_request.content)
        if http_request.url.path.endswith("/create"):
            received_create.update(body)
            return json_response({"reference": REFERENCE})
        if http_request.url.path.endswith("/wait"):
            encoded = base64.b64encode(successful_response().model_dump_json().encode()).decode()
            return json_response({"exit_code": 0, "output_base64": encoded})
        return json_response({"acknowledged": True})

    async with HttpDockerEngineGateway(
        config(),
        transport=httpx.MockTransport(handler),
    ) as gateway:
        runtime = DockerWorkerRuntime(
            gateway,
            RestrictedRuntimePolicy(
                image=IMAGE,
                network="vuln-proof-claw-workers",
            ),
            clock=lambda: NOW,
        )
        reference = await runtime.create(request(), worker_id=WORKER_ID)
        await runtime.start(reference)
        response = await runtime.wait(reference)
        await runtime.destroy(reference)

    assert response == successful_response()
    assert received_create["image"] == IMAGE
    assert received_create["network"] == "vuln-proof-claw-workers"
    assert received_create["user"] == "10002:10002"


@pytest.mark.parametrize(
    ("status_code", "code"),
    [
        (400, "engine_gateway_request_rejected"),
        (401, "engine_gateway_unauthorized"),
        (403, "engine_gateway_unauthorized"),
        (409, "engine_gateway_conflict"),
        (500, "engine_gateway_unavailable"),
    ],
)
async def test_http_failures_are_reduced_to_safe_codes(
    status_code: int,
    code: str,
) -> None:
    def handler(http_request: httpx.Request) -> httpx.Response:
        del http_request
        return httpx.Response(status_code, text="private daemon failure and socket path")

    async with HttpDockerEngineGateway(
        config(),
        transport=httpx.MockTransport(handler),
    ) as gateway:
        with pytest.raises(EngineGatewayError, match=code) as captured:
            await gateway.start(REFERENCE)
    assert "private" not in str(captured.value)


async def test_network_failure_is_safe() -> None:
    def handler(http_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private gateway address", request=http_request)

    async with HttpDockerEngineGateway(
        config(),
        transport=httpx.MockTransport(handler),
    ) as gateway:
        with pytest.raises(EngineGatewayError, match="engine_gateway_unavailable") as captured:
            await gateway.start(REFERENCE)
    assert "address" not in str(captured.value)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not-json"),
        httpx.Response(200, content=b"{", headers={"content-type": "application/json"}),
        json_response({"acknowledged": True, "unexpected": "field"}),
        httpx.Response(
            200,
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "invalid"},
        ),
        httpx.Response(
            200,
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "-1"},
        ),
    ],
)
async def test_invalid_gateway_responses_fail_closed(response: httpx.Response) -> None:
    async with HttpDockerEngineGateway(
        config(),
        transport=httpx.MockTransport(lambda _: response),
    ) as gateway:
        with pytest.raises(EngineGatewayError, match="engine_gateway_response"):
            await gateway.start(REFERENCE)


async def test_declared_and_streamed_response_limits_are_enforced() -> None:
    oversized = b"x" * (64 * 1024 + 1)
    responses = (
        httpx.Response(
            200,
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "65537"},
        ),
        httpx.Response(200, content=oversized, headers={"content-type": "application/json"}),
    )
    for response in responses:
        async with HttpDockerEngineGateway(
            config(maximum_response_bytes=64 * 1024),
            transport=static_transport(response),
        ) as gateway:
            with pytest.raises(EngineGatewayError, match="response_limit_exceeded"):
                await gateway.start(REFERENCE)


@pytest.mark.parametrize(
    "encoded",
    [
        "not-valid-base64!",
        base64.b64encode(b"x" * 33).decode(),
    ],
)
async def test_wait_rejects_invalid_or_oversized_decoded_output(encoded: str) -> None:
    response = json_response({"exit_code": 1, "output_base64": encoded})
    async with HttpDockerEngineGateway(
        config(),
        transport=static_transport(response),
    ) as gateway:
        with pytest.raises(EngineGatewayError, match=r"response_invalid|output_limit"):
            await gateway.wait(REFERENCE, maximum_output_bytes=32)


async def test_remove_cannot_weaken_force_or_volume_cleanup() -> None:
    called = False

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return json_response({"acknowledged": True})

    async with HttpDockerEngineGateway(
        config(),
        transport=httpx.MockTransport(handler),
    ) as gateway:
        with pytest.raises(EngineGatewayError, match="remove_policy_invalid"):
            await gateway.remove(REFERENCE, force=False, volumes=True)
    assert not called


def test_gateway_requires_configuration_and_wire_models_forbid_escape_fields() -> None:
    with pytest.raises(EngineGatewayError, match="not_configured"):
        HttpDockerEngineGateway(EngineGatewayConfig())

    payload = ContainerCreateRequest(
        name=spec().name,
        image=spec().image,
        network=spec().network,
        user=spec().user,
        labels=dict(spec().labels),
        request_payload_base64=base64.b64encode(spec().request_payload).decode(),
        timeout_seconds=spec().timeout_seconds,
        memory_bytes=spec().memory_bytes,
        nano_cpus=spec().nano_cpus,
        process_limit=spec().process_limit,
        read_only_root=True,
        capability_drop=("ALL",),
        no_new_privileges=True,
        init=True,
        tmpfs=dict(spec().tmpfs),
    ).model_dump()
    payload["privileged"] = True
    with pytest.raises(ValidationError):
        ContainerCreateRequest.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("memory_bytes", -1),
        ("capability_drop", []),
        ("read_only_root", False),
        ("tmpfs", {"/work": "rw"}),
        ("labels", {}),
        ("request_payload_base64", "not-base64!"),
    ],
)
def test_gateway_create_contract_revalidates_privileged_spec(
    field: str,
    value: object,
) -> None:
    original = ContainerCreateRequest(
        name=spec().name,
        image=spec().image,
        network=spec().network,
        user=spec().user,
        labels=dict(spec().labels),
        request_payload_base64=base64.b64encode(spec().request_payload).decode(),
        timeout_seconds=spec().timeout_seconds,
        memory_bytes=spec().memory_bytes,
        nano_cpus=spec().nano_cpus,
        process_limit=spec().process_limit,
        read_only_root=True,
        capability_drop=("ALL",),
        no_new_privileges=True,
        init=True,
        tmpfs=dict(spec().tmpfs),
    ).model_dump()
    original[field] = value

    with pytest.raises(ValidationError):
        ContainerCreateRequest.model_validate(original)
