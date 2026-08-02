"""Narrow Docker Engine Unix-socket backend tests without daemon access."""

from __future__ import annotations

import asyncio
import json
import struct
from dataclasses import replace

import httpx
import pytest
from pydantic import ValidationError

from tests.execution.test_engine_gateway import spec
from vuln_proof_claw.config.models import DockerEngineBackendConfig
from vuln_proof_claw.engine.backend import EngineBackendError, EngineBackendErrorCode
from vuln_proof_claw.engine.docker_backend import (
    DockerEngineBackend,
    UnixDockerStdinTransport,
    _DockerRawStreamParser,
)

CONTAINER_ID = "b" * 64
IMAGE = spec().image
NETWORK = spec().network


def config(**changes: object) -> DockerEngineBackendConfig:
    values: dict[str, object] = {
        "enabled": True,
        "allowed_image": IMAGE,
        "allowed_network": NETWORK,
    }
    values.update(changes)
    return DockerEngineBackendConfig(**values)


def inspect_payload(*, labels: dict[str, str] | None = None) -> dict[str, object]:
    return {
        "Id": CONTAINER_ID,
        "Config": {
            "Image": IMAGE,
            "User": spec().user,
            "Labels": labels or dict(spec().labels),
        },
        "HostConfig": {
            "NetworkMode": NETWORK,
            "Privileged": False,
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
        },
    }


def json_response(status_code: int, payload: object) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


def raw_frame(payload: bytes) -> bytes:
    return b"\x01\0\0\0" + struct.pack(">I", len(payload)) + payload


class RecordingStdin:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []
        self.failure: Exception | None = None

    async def send(self, reference: str, payload: bytes) -> None:
        self.calls.append((reference, payload))
        if self.failure is not None:
            raise self.failure


class DockerApi:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.inspect = inspect_payload()
        self.create_status = 201
        self.start_status = 204
        self.stop_status = 304
        self.remove_status = 204
        self.logs = raw_frame(b"worker-") + raw_frame(b"response")

    def __call__(self, request: httpx.Request) -> httpx.Response:  # noqa: PLR0911, PLR0912
        self.requests.append(request)
        path = request.url.path
        if path == "/_ping":
            return httpx.Response(200, content=b"OK")
        if path == "/version":
            return json_response(200, {"ApiVersion": "1.51"})
        if path == "/v1.44/info":
            return json_response(
                200,
                {"OSType": "linux", "SecurityOptions": ["name=seccomp,profile=builtin"]},
            )
        if path == f"/v1.44/networks/{NETWORK}":
            return json_response(200, {"Name": NETWORK, "Internal": True})
        if path.startswith("/v1.44/images/"):
            return json_response(200, {})
        if path == "/v1.44/containers/create":
            return json_response(self.create_status, {"Id": CONTAINER_ID})
        if path == "/v1.44/containers/json":
            return json_response(
                200,
                [{"Id": CONTAINER_ID, "Labels": dict(spec().labels)}],
            )
        if path.endswith("/json"):
            return json_response(200, self.inspect)
        if path.endswith("/start"):
            return httpx.Response(self.start_status)
        if path.endswith("/wait"):
            return json_response(200, {"StatusCode": 0, "Error": {"Message": ""}})
        if path.endswith("/logs"):
            return httpx.Response(200, content=self.logs)
        if path.endswith("/stop"):
            return httpx.Response(self.stop_status)
        if request.method == "DELETE":
            return httpx.Response(self.remove_status)
        raise AssertionError(f"unexpected Docker request: {request.method} {path}")


async def test_complete_docker_lifecycle_uses_only_fixed_hardened_fields() -> None:
    api = DockerApi()
    stdin = RecordingStdin()
    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(api),
        stdin_transport=stdin,
    ) as backend:
        await backend.check_ready()
        reference = await backend.create(spec())
        await backend.start(reference)
        waited = await backend.wait(reference, maximum_output_bytes=1024)
        await backend.stop(reference, grace_seconds=5)
        inventory = await backend.list_owned(
            labels={"io.vuln-proof-claw.managed-by": "worker-runtime"}
        )
        await backend.remove(reference, force=True, volumes=True)

    assert reference == CONTAINER_ID
    assert stdin.calls == [(CONTAINER_ID, spec().request_payload)]
    assert waited.exit_code == 0
    assert waited.output == b"worker-response"
    assert inventory[0].reference == CONTAINER_ID
    create_request = next(
        request for request in api.requests if request.url.path.endswith("/containers/create")
    )
    payload = json.loads(create_request.content)
    assert payload["Image"] == IMAGE
    assert payload["User"] == spec().user
    assert "Cmd" not in payload
    assert "Entrypoint" not in payload
    assert "Env" not in payload
    host = payload["HostConfig"]
    assert host["Binds"] == []
    assert host["CapAdd"] == []
    assert host["CapDrop"] == ["ALL"]
    assert host["Privileged"] is False
    assert host["ReadonlyRootfs"] is True
    assert host["NetworkMode"] == NETWORK
    assert host["MemorySwap"] == host["Memory"]
    assert create_request.url.params["name"] == spec().name


async def test_create_conflict_is_idempotent_only_for_the_exact_owned_spec() -> None:
    api = DockerApi()
    api.create_status = 409
    stdin = RecordingStdin()
    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(api),
        stdin_transport=stdin,
    ) as backend:
        assert await backend.create(spec()) == CONTAINER_ID
    assert stdin.calls == []

    api.inspect = inspect_payload(labels={"io.vuln-proof-claw.managed-by": "other"})
    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(api),
        stdin_transport=stdin,
    ) as backend:
        with pytest.raises(EngineBackendError, match="engine_backend_conflict"):
            await backend.create(spec())


async def test_failed_stdin_attach_removes_the_new_container() -> None:
    api = DockerApi()
    stdin = RecordingStdin()
    stdin.failure = EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(api),
        stdin_transport=stdin,
    ) as backend:
        with pytest.raises(EngineBackendError, match="engine_backend_unavailable"):
            await backend.create(spec())
    assert any(request.method == "DELETE" for request in api.requests)


async def test_unexpected_stdin_failure_is_safe_and_also_cleans_up() -> None:
    api = DockerApi()
    stdin = RecordingStdin()
    stdin.failure = RuntimeError("private socket and daemon details")
    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(api),
        stdin_transport=stdin,
    ) as backend:
        with pytest.raises(EngineBackendError, match="engine_backend_unavailable") as captured:
            await backend.create(spec())
    assert "private" not in str(captured.value)
    assert any(request.method == "DELETE" for request in api.requests)


@pytest.mark.parametrize(
    ("status_code", "code"),
    [
        (400, EngineBackendErrorCode.REJECTED),
        (404, EngineBackendErrorCode.NOT_FOUND),
        (409, EngineBackendErrorCode.CONFLICT),
        (500, EngineBackendErrorCode.UNAVAILABLE),
    ],
)
async def test_docker_statuses_are_reduced_to_safe_codes(
    status_code: int,
    code: EngineBackendErrorCode,
) -> None:
    api = DockerApi()
    api.start_status = status_code
    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(api),
        stdin_transport=RecordingStdin(),
    ) as backend:
        with pytest.raises(EngineBackendError) as captured:
            await backend.start(CONTAINER_ID)
    assert captured.value.code is code


async def test_foreign_or_weakened_containers_cannot_be_operated() -> None:
    api = DockerApi()
    weakened = inspect_payload()
    host_config = weakened["HostConfig"]
    assert isinstance(host_config, dict)
    host_config["Privileged"] = True
    api.inspect = weakened
    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(api),
        stdin_transport=RecordingStdin(),
    ) as backend:
        with pytest.raises(EngineBackendError, match="engine_backend_rejected"):
            await backend.start(CONTAINER_ID)
        with pytest.raises(EngineBackendError, match="engine_backend_rejected"):
            await backend.remove(CONTAINER_ID, force=True, volumes=True)
    assert not any(request.method == "DELETE" for request in api.requests)


async def test_reference_and_policy_injection_are_rejected_before_transport() -> None:
    api = DockerApi()
    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(api),
        stdin_transport=RecordingStdin(),
    ) as backend:
        with pytest.raises(EngineBackendError, match="engine_backend_rejected"):
            await backend.start("../../containers/foreign")
        with pytest.raises(EngineBackendError, match="engine_backend_rejected"):
            await backend.list_owned(labels={})
        with pytest.raises(EngineBackendError, match="engine_backend_rejected"):
            await backend.list_owned(labels={"foreign.label": "value"})
        with pytest.raises(EngineBackendError, match="engine_backend_rejected"):
            await backend.create(replace(spec(), network="bridge"))
        with pytest.raises(EngineBackendError, match="engine_backend_rejected"):
            await backend.create(replace(spec(), read_only_root=False))
        with pytest.raises(EngineBackendError, match="engine_backend_rejected"):
            await backend.create(replace(spec(), capability_drop=()))
    assert api.requests == []


@pytest.mark.parametrize(
    ("version", "info", "network"),
    [
        ("1.43", {"OSType": "linux", "SecurityOptions": ["name=seccomp"]}, True),
        ("invalid", {"OSType": "linux", "SecurityOptions": ["name=seccomp"]}, True),
        ("1.51", {"OSType": "windows", "SecurityOptions": ["name=seccomp"]}, True),
        ("1.51", {"OSType": "linux", "SecurityOptions": []}, True),
        ("1.51", {"OSType": "linux", "SecurityOptions": ["name=seccomp"]}, False),
    ],
)
async def test_readiness_requires_compatible_linux_seccomp_and_internal_network(
    version: str,
    info: dict[str, object],
    network: bool,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/_ping":
            return httpx.Response(200, content=b"OK")
        if request.url.path == "/version":
            return json_response(200, {"ApiVersion": version})
        if request.url.path.endswith("/info"):
            return json_response(200, info)
        if "/networks/" in request.url.path:
            return json_response(200, {"Name": NETWORK, "Internal": network})
        return json_response(200, {})

    async with DockerEngineBackend(
        config(),
        transport=httpx.MockTransport(handler),
        stdin_transport=RecordingStdin(),
    ) as backend:
        with pytest.raises(EngineBackendError):
            await backend.check_ready()


def test_raw_stream_parser_is_incremental_strict_and_bounded() -> None:
    framed = raw_frame(b"hello") + raw_frame(b"-world")
    parser = _DockerRawStreamParser(maximum_output_bytes=11)
    for byte in framed:
        parser.feed(bytes([byte]))
    assert parser.finish() == b"hello-world"

    oversized = _DockerRawStreamParser(maximum_output_bytes=4)
    with pytest.raises(EngineBackendError, match="output_limit_exceeded"):
        oversized.feed(raw_frame(b"12345"))

    invalid = _DockerRawStreamParser(maximum_output_bytes=10)
    with pytest.raises(EngineBackendError, match="unavailable"):
        invalid.feed(b"\x02\0\0\0\0\0\0\x01x")

    incomplete = _DockerRawStreamParser(maximum_output_bytes=10)
    incomplete.feed(raw_frame(b"abc")[:-1])
    with pytest.raises(EngineBackendError, match="unavailable"):
        incomplete.finish()

    excessive_framing = _DockerRawStreamParser(maximum_output_bytes=1)
    with pytest.raises(EngineBackendError, match="output_limit_exceeded"):
        excessive_framing.feed(b"x" * (64 * 1024 + 2))


async def test_docker_responses_are_bounded_before_parsing() -> None:
    oversized = b"x" * (64 * 1024 + 1)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/_ping"
        return httpx.Response(200, content=oversized)

    async with DockerEngineBackend(
        config(maximum_response_bytes=64 * 1024),
        transport=httpx.MockTransport(handler),
        stdin_transport=RecordingStdin(),
    ) as backend:
        with pytest.raises(EngineBackendError, match="engine_backend_unavailable"):
            await backend.check_ready()


async def test_unix_attach_transport_sends_only_fixed_request_and_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Reader:
        async def read(self, maximum: int) -> bytes:
            del maximum
            return b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\n\r\n"

    class Writer:
        def __init__(self) -> None:
            self.writes: list[bytes] = []
            self.eof = False

        def write(self, value: bytes) -> None:
            self.writes.append(value)

        async def drain(self) -> None:
            return None

        def can_write_eof(self) -> bool:
            return True

        def write_eof(self) -> None:
            self.eof = True

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    writer = Writer()

    async def open_socket(path: str) -> tuple[Reader, Writer]:
        assert path == "/run/docker.sock"
        return Reader(), writer

    monkeypatch.setattr(asyncio, "open_unix_connection", open_socket, raising=False)
    transport = UnixDockerStdinTransport(
        "/run/docker.sock",
        "v1.44",
        timeout_seconds=1,
    )
    await transport.send(CONTAINER_ID, b"worker-request")

    assert writer.writes[1] == b"worker-request"
    assert b"/v1.44/containers/" + CONTAINER_ID.encode() + b"/attach" in writer.writes[0]
    assert b"stdout=0" in writer.writes[0]
    assert b"stderr=0" in writer.writes[0]
    assert writer.eof


def test_backend_configuration_fails_closed() -> None:
    with pytest.raises(ValidationError, match="allowed image and network"):
        DockerEngineBackendConfig(enabled=True)
    with pytest.raises(ValidationError, match="digest-pinned"):
        DockerEngineBackendConfig(allowed_image="worker:latest")
    with pytest.raises(ValidationError, match="must be absolute"):
        DockerEngineBackendConfig(socket_path="docker.sock")
    with pytest.raises(EngineBackendError, match="unavailable"):
        DockerEngineBackend(DockerEngineBackendConfig())
