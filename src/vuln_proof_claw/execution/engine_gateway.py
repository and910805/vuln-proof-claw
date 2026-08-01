"""Authenticated, bounded HTTP client for the privileged Docker Engine gateway."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal, TypeVar

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from vuln_proof_claw.config.models import EngineGatewayConfig
from vuln_proof_claw.execution.docker_runtime import (
    ContainerWaitResult,
    OwnedContainer,
    RestrictedContainerSpec,
)
from vuln_proof_claw.execution.protocol import WorkerRequest

_JSON_CONTENT_TYPES = frozenset({"application/json", "application/problem+json"})
_OWNERSHIP_LABELS = frozenset(
    {
        "io.vuln-proof-claw.created-at",
        "io.vuln-proof-claw.managed-by",
        "io.vuln-proof-claw.request-id",
        "io.vuln-proof-claw.runtime-identity",
        "io.vuln-proof-claw.worker-id",
    }
)
_REQUIRED_TMPFS_OPTIONS = frozenset({"noexec", "nodev", "nosuid", "rw"})
_CONTAINER_TEMP_PATH = PurePosixPath("/", "tmp").as_posix()


class EngineGatewayError(Exception):
    """Stable gateway failure that never exposes transport or response details."""


class GatewayModel(BaseModel):
    """Strict immutable wire model shared with a future Engine service."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class EmptyRequest(GatewayModel):
    pass


class ContainerCreateRequest(GatewayModel):
    name: str = Field(
        pattern=r"^vpc-worker-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
    )
    image: str = Field(
        pattern=r"^[a-z0-9][a-z0-9._:/-]{0,180}@sha256:[a-f0-9]{64}$"
    )
    network: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    user: str = Field(pattern=r"^[1-9][0-9]*:[1-9][0-9]*$")
    labels: dict[str, str] = Field(min_length=5, max_length=5)
    request_payload_base64: str = Field(max_length=1_398_104)
    timeout_seconds: int = Field(ge=1, le=10_800)
    memory_bytes: int = Field(ge=64 * 1024 * 1024, le=32_768 * 1024 * 1024)
    nano_cpus: int = Field(ge=1, le=32_000_000_000)
    process_limit: int = Field(ge=16, le=4096)
    read_only_root: Literal[True]
    capability_drop: tuple[Literal["ALL"]]
    no_new_privileges: Literal[True]
    init: Literal[True]
    tmpfs: dict[str, str] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def validate_bindings_and_storage(self) -> ContainerCreateRequest:
        if set(self.labels) != _OWNERSHIP_LABELS:
            raise ValueError("container ownership labels are incomplete")
        if self.labels["io.vuln-proof-claw.managed-by"] != "worker-runtime":
            raise ValueError("container owner label is invalid")
        worker_id = self.labels["io.vuln-proof-claw.worker-id"]
        if self.name != f"vpc-worker-{worker_id}":
            raise ValueError("container name and Worker label do not match")
        try:
            created_at = datetime.fromisoformat(
                self.labels["io.vuln-proof-claw.created-at"]
            )
            payload = base64.b64decode(self.request_payload_base64, validate=True)
            worker_request = WorkerRequest.model_validate_json(payload)
        except (binascii.Error, ValidationError, ValueError) as error:
            raise ValueError("container request payload or creation label is invalid") from error
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ValueError("container creation label must be timezone-aware")
        if worker_request.request_id != self.labels["io.vuln-proof-claw.request-id"]:
            raise ValueError("container request and label do not match")
        if set(self.tmpfs) != {_CONTAINER_TEMP_PATH, "/work"}:
            raise ValueError("container tmpfs paths are incomplete")
        for options in self.tmpfs.values():
            option_names = {value.split("=", maxsplit=1)[0] for value in options.split(",")}
            if not _REQUIRED_TMPFS_OPTIONS.issubset(option_names):
                raise ValueError("container tmpfs options are unsafe")
        return self


class ContainerReferenceRequest(GatewayModel):
    reference: str = Field(min_length=1, max_length=4096)


class ContainerStopRequest(ContainerReferenceRequest):
    grace_seconds: int = Field(ge=1, le=30)


class ContainerRemoveRequest(ContainerReferenceRequest):
    force: Literal[True]
    volumes: Literal[True]


class ContainerWaitRequest(ContainerReferenceRequest):
    maximum_output_bytes: int = Field(ge=1, le=16 * 1024 * 1024)


class ContainerInventoryRequest(GatewayModel):
    labels: dict[str, str]


class ReferenceResponse(GatewayModel):
    reference: str = Field(min_length=1, max_length=4096)


class AckResponse(GatewayModel):
    acknowledged: Literal[True]


class WaitResponse(GatewayModel):
    exit_code: int
    output_base64: str


class OwnedContainerResponse(GatewayModel):
    reference: str = Field(min_length=1, max_length=4096)
    labels: dict[str, str]


class InventoryResponse(GatewayModel):
    containers: tuple[OwnedContainerResponse, ...]


class ReadyResponse(GatewayModel):
    ready: Literal[True]


ResponseModel = TypeVar("ResponseModel", bound=GatewayModel)


class HttpDockerEngineGateway:
    """Concrete RestrictedDockerEngine client with authenticated bounded exchanges."""

    def __init__(
        self,
        config: EngineGatewayConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not config.ready or config.url is None or config.token is None:
            raise EngineGatewayError("engine_gateway_not_configured")
        self._maximum_response_bytes = config.maximum_response_bytes
        verify: bool | str = str(config.ca_bundle) if config.ca_bundle is not None else True
        self._client = httpx.AsyncClient(
            base_url=config.url,
            headers={
                "Authorization": f"Bearer {config.token.get_secret_value()}",
                "Accept": "application/json",
                "User-Agent": "vuln-proof-claw-engine-gateway",
            },
            timeout=httpx.Timeout(config.timeout_seconds),
            transport=transport,
            verify=verify,
            follow_redirects=False,
            trust_env=False,
        )

    async def __aenter__(self) -> HttpDockerEngineGateway:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def check_ready(self) -> None:
        await self._exchange(
            "POST",
            "/v1/health/ready",
            EmptyRequest(),
            ReadyResponse,
        )

    async def create(self, spec: RestrictedContainerSpec) -> str:
        request = ContainerCreateRequest(
            name=spec.name,
            image=spec.image,
            network=spec.network,
            user=spec.user,
            labels=dict(spec.labels),
            request_payload_base64=base64.b64encode(spec.request_payload).decode("ascii"),
            timeout_seconds=spec.timeout_seconds,
            memory_bytes=spec.memory_bytes,
            nano_cpus=spec.nano_cpus,
            process_limit=spec.process_limit,
            read_only_root=spec.read_only_root,
            capability_drop=spec.capability_drop,
            no_new_privileges=spec.no_new_privileges,
            init=spec.init,
            tmpfs=dict(spec.tmpfs),
        )
        response = await self._exchange(
            "POST",
            "/v1/containers/create",
            request,
            ReferenceResponse,
        )
        return response.reference

    async def start(self, reference: str) -> None:
        await self._exchange(
            "POST",
            "/v1/containers/start",
            ContainerReferenceRequest(reference=reference),
            AckResponse,
        )

    async def wait(self, reference: str, *, maximum_output_bytes: int) -> ContainerWaitResult:
        response = await self._exchange(
            "POST",
            "/v1/containers/wait",
            ContainerWaitRequest(
                reference=reference,
                maximum_output_bytes=maximum_output_bytes,
            ),
            WaitResponse,
        )
        try:
            output = base64.b64decode(response.output_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise EngineGatewayError("engine_gateway_response_invalid") from error
        if len(output) > maximum_output_bytes:
            raise EngineGatewayError("engine_gateway_output_limit_exceeded")
        return ContainerWaitResult(exit_code=response.exit_code, output=output)

    async def stop(self, reference: str, *, grace_seconds: int) -> None:
        await self._exchange(
            "POST",
            "/v1/containers/stop",
            ContainerStopRequest(reference=reference, grace_seconds=grace_seconds),
            AckResponse,
        )

    async def remove(self, reference: str, *, force: bool, volumes: bool) -> None:
        if not force or not volumes:
            raise EngineGatewayError("engine_gateway_remove_policy_invalid")
        await self._exchange(
            "POST",
            "/v1/containers/remove",
            ContainerRemoveRequest(reference=reference, force=True, volumes=True),
            AckResponse,
        )

    async def list_owned(self, *, labels: Mapping[str, str]) -> tuple[OwnedContainer, ...]:
        response = await self._exchange(
            "POST",
            "/v1/containers/inventory",
            ContainerInventoryRequest(labels=dict(labels)),
            InventoryResponse,
        )
        return tuple(
            OwnedContainer(
                reference=container.reference,
                labels=tuple(sorted(container.labels.items())),
            )
            for container in response.containers
        )

    async def _exchange(
        self,
        method: str,
        path: str,
        request: GatewayModel,
        response_type: type[ResponseModel],
    ) -> ResponseModel:
        try:
            async with self._client.stream(
                method,
                path,
                json=request.model_dump(mode="json"),
            ) as response:
                self._validate_status(response.status_code)
                content_type = response.headers.get("content-type", "").split(";", maxsplit=1)[0]
                if content_type.casefold() not in _JSON_CONTENT_TYPES:
                    raise EngineGatewayError("engine_gateway_response_content_type_invalid")
                declared_length = response.headers.get("content-length")
                if declared_length is not None:
                    try:
                        parsed_length = int(declared_length)
                        if parsed_length < 0:
                            raise EngineGatewayError(
                                "engine_gateway_response_length_invalid"
                            )
                        if parsed_length > self._maximum_response_bytes:
                            raise EngineGatewayError("engine_gateway_response_limit_exceeded")
                    except ValueError as error:
                        raise EngineGatewayError(
                            "engine_gateway_response_length_invalid"
                        ) from error
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self._maximum_response_bytes:
                        raise EngineGatewayError("engine_gateway_response_limit_exceeded")
        except EngineGatewayError:
            raise
        except httpx.HTTPError as error:
            raise EngineGatewayError("engine_gateway_unavailable") from error
        try:
            return response_type.model_validate_json(bytes(body))
        except (ValidationError, ValueError) as error:
            raise EngineGatewayError("engine_gateway_response_invalid") from error

    @staticmethod
    def _validate_status(status_code: int) -> None:
        if httpx.codes.is_success(status_code):
            return
        if status_code in {httpx.codes.UNAUTHORIZED, httpx.codes.FORBIDDEN}:
            raise EngineGatewayError("engine_gateway_unauthorized")
        if status_code == httpx.codes.CONFLICT:
            raise EngineGatewayError("engine_gateway_conflict")
        if httpx.codes.is_client_error(status_code):
            raise EngineGatewayError("engine_gateway_request_rejected")
        raise EngineGatewayError("engine_gateway_unavailable")
