"""Narrow Docker Engine API adapter over a local Unix socket."""

from __future__ import annotations

import asyncio
import json
import re
import struct
from collections.abc import Mapping
from contextlib import suppress
from typing import Protocol
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vuln_proof_claw.config.models import DockerEngineBackendConfig
from vuln_proof_claw.engine.backend import EngineBackendError, EngineBackendErrorCode
from vuln_proof_claw.execution.docker_runtime import (
    ContainerWaitResult,
    OwnedContainer,
    RestrictedContainerSpec,
)
from vuln_proof_claw.execution.engine_gateway import ContainerCreateRequest

_CONTAINER_ID_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_CONTAINER_NAME_PATTERN = re.compile(
    r"^vpc-worker-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
)
_API_VERSION_PATTERN = re.compile(r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)$")
_MINIMUM_API_VERSION = (1, 44)
_OWNER_LABEL = "io.vuln-proof-claw.managed-by"
_OWNER_VALUE = "worker-runtime"
_OWNERSHIP_LABELS = frozenset(
    {
        "io.vuln-proof-claw.created-at",
        _OWNER_LABEL,
        "io.vuln-proof-claw.request-id",
        "io.vuln-proof-claw.runtime-identity",
        "io.vuln-proof-claw.worker-id",
    }
)
_MAXIMUM_ATTACH_HEADERS = 16 * 1024
_RAW_STREAM_HEADER_BYTES = 8
_MAXIMUM_RAW_STREAM_OVERHEAD = 64 * 1024
_MAXIMUM_LABEL_VALUE_LENGTH = 4096
_CONTROL_CHARACTER_LIMIT = 32
type _QueryValue = str | int | float | bool | None


class _DockerModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class _CreateResponse(_DockerModel):
    identifier: str = Field(alias="Id", pattern=r"^[a-f0-9]{64}$")


class _VersionResponse(_DockerModel):
    api_version: str = Field(alias="ApiVersion")


class _InfoResponse(_DockerModel):
    operating_system: str = Field(alias="OSType")
    security_options: tuple[str, ...] = Field(alias="SecurityOptions")


class _NetworkResponse(_DockerModel):
    name: str = Field(alias="Name")
    internal: bool = Field(alias="Internal")


class _WaitError(_DockerModel):
    message: str = Field(default="", alias="Message", repr=False)


class _WaitResponse(_DockerModel):
    status_code: int = Field(alias="StatusCode")
    error: _WaitError | None = Field(default=None, alias="Error", repr=False)


class _ContainerConfig(_DockerModel):
    image: str = Field(alias="Image")
    user: str = Field(alias="User")
    labels: dict[str, str] = Field(alias="Labels")


class _ContainerHostConfig(_DockerModel):
    network_mode: str = Field(alias="NetworkMode")
    privileged: bool = Field(alias="Privileged")
    readonly_rootfs: bool = Field(alias="ReadonlyRootfs")
    capability_drop: tuple[str, ...] = Field(alias="CapDrop")
    security_options: tuple[str, ...] = Field(alias="SecurityOpt")


class _InspectResponse(_DockerModel):
    identifier: str = Field(alias="Id", pattern=r"^[a-f0-9]{64}$")
    config: _ContainerConfig = Field(alias="Config")
    host_config: _ContainerHostConfig = Field(alias="HostConfig")


class _ListResponse(_DockerModel):
    identifier: str = Field(alias="Id", pattern=r"^[a-f0-9]{64}$")
    labels: dict[str, str] = Field(alias="Labels")


class DockerStdinTransport(Protocol):
    """Fixed-purpose transport for Docker's HTTP connection-hijack attach endpoint."""

    async def send(self, reference: str, payload: bytes) -> None:
        """Attach only stdin, write the bounded Worker request, and signal EOF."""


class UnixDockerStdinTransport:
    """Minimal local Unix-socket implementation of Docker attach stdin."""

    def __init__(self, socket_path: str, api_version: str, *, timeout_seconds: int) -> None:
        self._socket_path = socket_path
        self._api_version = api_version
        self._timeout_seconds = timeout_seconds

    async def send(self, reference: str, payload: bytes) -> None:
        _require_container_id(reference)
        path = (
            f"/{self._api_version}/containers/{reference}/attach"
            "?stdin=1&stdout=0&stderr=0&stream=1&logs=0"
        )
        request = (
            f"POST {path} HTTP/1.1\r\n"
            "Host: docker\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: tcp\r\n"
            "Content-Length: 0\r\n\r\n"
        ).encode("ascii")
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self._timeout_seconds):
                open_unix_connection = getattr(asyncio, "open_unix_connection", None)
                if open_unix_connection is None:
                    raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
                reader, writer = await open_unix_connection(self._socket_path)
                writer.write(request)
                await writer.drain()
                headers = await _read_attach_headers(reader)
                status_line = headers.split(b"\r\n", maxsplit=1)[0]
                if not status_line.startswith(b"HTTP/1.1 101 "):
                    raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
                writer.write(payload)
                await writer.drain()
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
        except EngineBackendError:
            raise
        except (OSError, TimeoutError) as error:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE) from error
        finally:
            if writer is not None:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()


class DockerEngineBackend:
    """Reviewed fixed-field Docker lifecycle adapter for disposable Workers."""

    def __init__(
        self,
        config: DockerEngineBackendConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        stdin_transport: DockerStdinTransport | None = None,
    ) -> None:
        if not config.enabled or config.allowed_image is None or config.allowed_network is None:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
        self._config = config
        self._allowed_image = config.allowed_image
        self._allowed_network = config.allowed_network
        engine_transport = transport or httpx.AsyncHTTPTransport(uds=config.socket_path)
        self._client = httpx.AsyncClient(
            base_url="http://docker",
            transport=engine_transport,
            timeout=httpx.Timeout(config.request_timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "vuln-proof-claw-engine-backend"},
        )
        self._stdin = stdin_transport or UnixDockerStdinTransport(
            config.socket_path,
            config.api_version,
            timeout_seconds=config.request_timeout_seconds,
        )

    async def __aenter__(self) -> DockerEngineBackend:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def check_ready(self) -> None:
        status_code, ping = await self._request("GET", "/_ping")
        if status_code != httpx.codes.OK or ping != b"OK":
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
        version = await self._request_model("GET", "/version", _VersionResponse)
        match = _API_VERSION_PATTERN.fullmatch(version.api_version)
        if match is None or (
            int(match.group("major")),
            int(match.group("minor")),
        ) < _MINIMUM_API_VERSION:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
        info = await self._request_model("GET", self._path("/info"), _InfoResponse)
        if info.operating_system != "linux" or not any(
            option.startswith("name=seccomp") for option in info.security_options
        ):
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
        await self._validate_runtime_assets()

    async def create(self, spec: RestrictedContainerSpec) -> str:
        self._require_allowed_spec(spec)
        await self._validate_runtime_assets()
        response_status, response_body = await self._request(
            "POST",
            self._path("/containers/create"),
            params={"name": spec.name},
            json_body=_create_payload(spec),
        )
        if response_status == httpx.codes.CONFLICT:
            existing = await self._inspect(spec.name, allow_name=True)
            if existing.config.labels != spec.label_map:
                raise EngineBackendError(EngineBackendErrorCode.CONFLICT)
            self._validate_owned(existing)
            return existing.identifier
        self._require_status(response_status, {httpx.codes.CREATED})
        created = _parse_model(response_body, _CreateResponse)
        try:
            await self._stdin.send(created.identifier, spec.request_payload)
        except EngineBackendError:
            await self._remove_direct(created.identifier)
            raise
        except Exception as error:
            await self._remove_direct(created.identifier)
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE) from error
        return created.identifier

    async def start(self, reference: str) -> None:
        await self._assert_owned(reference)
        status_code, _ = await self._request(
            "POST",
            self._path(f"/containers/{reference}/start"),
        )
        self._require_status(status_code, {httpx.codes.NO_CONTENT})

    async def wait(self, reference: str, *, maximum_output_bytes: int) -> ContainerWaitResult:
        await self._assert_owned(reference)
        wait = await self._request_model(
            "POST",
            self._path(f"/containers/{reference}/wait"),
            _WaitResponse,
            params={"condition": "not-running"},
            unbounded_read=True,
        )
        if wait.error is not None and wait.error.message:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
        output = await self._read_logs(reference, maximum_output_bytes=maximum_output_bytes)
        return ContainerWaitResult(exit_code=wait.status_code, output=output)

    async def stop(self, reference: str, *, grace_seconds: int) -> None:
        await self._assert_owned(reference)
        status_code, _ = await self._request(
            "POST",
            self._path(f"/containers/{reference}/stop"),
            params={"t": grace_seconds},
        )
        self._require_status(
            status_code,
            {httpx.codes.NO_CONTENT, httpx.codes.NOT_MODIFIED},
        )

    async def remove(self, reference: str, *, force: bool, volumes: bool) -> None:
        if not force or not volumes:
            raise EngineBackendError(EngineBackendErrorCode.REJECTED)
        try:
            await self._assert_owned(reference)
        except EngineBackendError as error:
            if error.code is EngineBackendErrorCode.NOT_FOUND:
                return
            raise
        await self._remove_direct(reference)

    async def list_owned(self, *, labels: Mapping[str, str]) -> tuple[OwnedContainer, ...]:
        if (
            labels.get(_OWNER_LABEL) != _OWNER_VALUE
            or not labels
            or len(labels) > len(_OWNERSHIP_LABELS)
            or not set(labels).issubset(_OWNERSHIP_LABELS)
            or any(
                not value
                or len(value) > _MAXIMUM_LABEL_VALUE_LENGTH
                or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value)
                for value in labels.values()
            )
        ):
            raise EngineBackendError(EngineBackendErrorCode.REJECTED)
        filters = json.dumps(
            {"label": [f"{key}={value}" for key, value in sorted(labels.items())]},
            separators=(",", ":"),
        )
        listed = await self._request_models(
            "GET",
            self._path("/containers/json"),
            _ListResponse,
            params={"all": "true", "filters": filters},
        )
        owned: list[OwnedContainer] = []
        for item in listed:
            inspected = await self._assert_owned(item.identifier)
            if not all(inspected.config.labels.get(key) == value for key, value in labels.items()):
                raise EngineBackendError(EngineBackendErrorCode.REJECTED)
            owned.append(
                OwnedContainer(
                    reference=inspected.identifier,
                    labels=tuple(sorted(inspected.config.labels.items())),
                )
            )
        return tuple(owned)

    async def _assert_owned(self, reference: str) -> _InspectResponse:
        _require_container_id(reference)
        inspected = await self._inspect(reference)
        self._validate_owned(inspected)
        return inspected

    async def _inspect(self, reference: str, *, allow_name: bool = False) -> _InspectResponse:
        if allow_name:
            if not _CONTAINER_NAME_PATTERN.fullmatch(reference):
                raise EngineBackendError(EngineBackendErrorCode.REJECTED)
        else:
            _require_container_id(reference)
        return await self._request_model(
            "GET",
            self._path(f"/containers/{reference}/json"),
            _InspectResponse,
        )

    def _validate_owned(self, inspected: _InspectResponse) -> None:
        host = inspected.host_config
        if (
            inspected.config.labels.get(_OWNER_LABEL) != _OWNER_VALUE
            or inspected.config.image != self._allowed_image
            or host.network_mode != self._allowed_network
            or host.privileged
            or not host.readonly_rootfs
            or "ALL" not in host.capability_drop
            or not any(value.startswith("no-new-privileges") for value in host.security_options)
        ):
            raise EngineBackendError(EngineBackendErrorCode.REJECTED)

    def _require_allowed_spec(self, spec: RestrictedContainerSpec) -> None:
        if spec.image != self._allowed_image or spec.network != self._allowed_network:
            raise EngineBackendError(EngineBackendErrorCode.REJECTED)
        try:
            ContainerCreateRequest.from_container_spec(spec)
        except ValidationError as error:
            raise EngineBackendError(EngineBackendErrorCode.REJECTED) from error

    async def _validate_runtime_assets(self) -> None:
        network = await self._request_model(
            "GET",
            self._path(f"/networks/{_quoted(self._allowed_network)}"),
            _NetworkResponse,
        )
        if network.name != self._allowed_network or not network.internal:
            raise EngineBackendError(EngineBackendErrorCode.REJECTED)
        await self._request_model(
            "GET",
            self._path(f"/images/{_quoted(self._allowed_image)}/json"),
            _DockerModel,
        )

    async def _remove_direct(self, reference: str) -> None:
        _require_container_id(reference)
        status_code, _ = await self._request(
            "DELETE",
            self._path(f"/containers/{reference}"),
            params={"force": "true", "v": "true"},
        )
        self._require_status(status_code, {httpx.codes.NO_CONTENT, httpx.codes.NOT_FOUND})

    async def _read_logs(self, reference: str, *, maximum_output_bytes: int) -> bytes:
        _require_container_id(reference)
        parser = _DockerRawStreamParser(maximum_output_bytes=maximum_output_bytes)
        try:
            async with self._client.stream(
                "GET",
                self._path(f"/containers/{reference}/logs"),
                params={
                    "stdout": "true",
                    "stderr": "false",
                    "timestamps": "false",
                    "follow": "false",
                    "tail": "all",
                },
            ) as response:
                self._require_status(response.status_code, {httpx.codes.OK})
                async for chunk in response.aiter_bytes():
                    parser.feed(chunk)
        except EngineBackendError:
            raise
        except httpx.HTTPError as error:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE) from error
        return parser.finish()

    async def _request_model[Response: _DockerModel](
        self,
        method: str,
        path: str,
        model: type[Response],
        *,
        params: Mapping[str, _QueryValue] | None = None,
        unbounded_read: bool = False,
    ) -> Response:
        status_code, body = await self._request(
            method,
            path,
            params=params,
            unbounded_read=unbounded_read,
        )
        self._require_status(status_code, {httpx.codes.OK, httpx.codes.CREATED})
        return _parse_model(body, model)

    async def _request_models[Response: _DockerModel](
        self,
        method: str,
        path: str,
        model: type[Response],
        *,
        params: Mapping[str, _QueryValue] | None = None,
    ) -> tuple[Response, ...]:
        status_code, body = await self._request(method, path, params=params)
        self._require_status(status_code, {httpx.codes.OK})
        try:
            return tuple(model.model_validate(item) for item in json.loads(body))
        except (TypeError, ValidationError, ValueError) as error:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE) from error

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, _QueryValue] | None = None,
        json_body: Mapping[str, object] | None = None,
        unbounded_read: bool = False,
    ) -> tuple[int, bytes]:
        try:
            async with self._client.stream(
                method,
                path,
                params=params,
                json=json_body,
                timeout=None if unbounded_read else self._config.request_timeout_seconds,
            ) as response:
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        parsed_length = int(declared)
                    except ValueError as error:
                        raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE) from error
                    if parsed_length < 0 or parsed_length > self._config.maximum_response_bytes:
                        raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > self._config.maximum_response_bytes:
                        raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
                    body.extend(chunk)
                return response.status_code, bytes(body)
        except EngineBackendError:
            raise
        except httpx.HTTPError as error:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE) from error

    def _path(self, suffix: str) -> str:
        return f"/{self._config.api_version}{suffix}"

    @staticmethod
    def _require_status(status_code: int, allowed: set[int]) -> None:
        if status_code in allowed:
            return
        if status_code == httpx.codes.NOT_FOUND:
            code = EngineBackendErrorCode.NOT_FOUND
        elif status_code == httpx.codes.CONFLICT:
            code = EngineBackendErrorCode.CONFLICT
        elif httpx.codes.is_client_error(status_code):
            code = EngineBackendErrorCode.REJECTED
        else:
            code = EngineBackendErrorCode.UNAVAILABLE
        raise EngineBackendError(code)


class _DockerRawStreamParser:
    def __init__(self, *, maximum_output_bytes: int) -> None:
        self._maximum_output_bytes = maximum_output_bytes
        self._maximum_wire_bytes = maximum_output_bytes + _MAXIMUM_RAW_STREAM_OVERHEAD
        self._wire_bytes = 0
        self._buffer = bytearray()
        self._output = bytearray()

    def feed(self, chunk: bytes) -> None:
        self._wire_bytes += len(chunk)
        if self._wire_bytes > self._maximum_wire_bytes:
            raise EngineBackendError(EngineBackendErrorCode.OUTPUT_LIMIT)
        self._buffer.extend(chunk)
        while len(self._buffer) >= _RAW_STREAM_HEADER_BYTES:
            stream_type = self._buffer[0]
            if stream_type != 1 or self._buffer[1:4] != b"\0\0\0":
                raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
            frame_size = struct.unpack(">I", self._buffer[4:_RAW_STREAM_HEADER_BYTES])[0]
            if frame_size > self._maximum_output_bytes - len(self._output):
                raise EngineBackendError(EngineBackendErrorCode.OUTPUT_LIMIT)
            if len(self._buffer) < _RAW_STREAM_HEADER_BYTES + frame_size:
                return
            self._output.extend(
                self._buffer[
                    _RAW_STREAM_HEADER_BYTES : _RAW_STREAM_HEADER_BYTES + frame_size
                ]
            )
            del self._buffer[: _RAW_STREAM_HEADER_BYTES + frame_size]

    def finish(self) -> bytes:
        if self._buffer:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
        return bytes(self._output)


async def _read_attach_headers(reader: asyncio.StreamReader) -> bytes:
    headers = bytearray()
    while b"\r\n\r\n" not in headers:
        chunk = await reader.read(1024)
        if not chunk or len(headers) + len(chunk) > _MAXIMUM_ATTACH_HEADERS:
            raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
        headers.extend(chunk)
    return bytes(headers)


def _create_payload(spec: RestrictedContainerSpec) -> Mapping[str, object]:
    return {
        "Image": spec.image,
        "User": spec.user,
        "Labels": spec.label_map,
        "AttachStdin": True,
        "AttachStdout": True,
        "AttachStderr": True,
        "OpenStdin": True,
        "StdinOnce": True,
        "Tty": False,
        "NetworkDisabled": False,
        "HostConfig": {
            "AutoRemove": False,
            "Binds": [],
            "CapAdd": [],
            "CapDrop": list(spec.capability_drop),
            "Init": spec.init,
            "Memory": spec.memory_bytes,
            "MemorySwap": spec.memory_bytes,
            "NanoCpus": spec.nano_cpus,
            "NetworkMode": spec.network,
            "OomKillDisable": False,
            "PidsLimit": spec.process_limit,
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": spec.read_only_root,
            "SecurityOpt": ["no-new-privileges=true"],
            "Tmpfs": dict(spec.tmpfs),
            "LogConfig": {
                "Type": "json-file",
                "Config": {"max-file": "1", "max-size": "2m"},
            },
        },
    }


def _parse_model[Response: _DockerModel](body: bytes, model: type[Response]) -> Response:
    try:
        return model.model_validate_json(body)
    except (ValidationError, ValueError) as error:
        raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE) from error


def _require_container_id(reference: str) -> None:
    if not _CONTAINER_ID_PATTERN.fullmatch(reference):
        raise EngineBackendError(EngineBackendErrorCode.REJECTED)


def _quoted(value: str) -> str:
    return quote(value, safe="")
