"""Restricted Docker worker adapter over a narrow privileged engine boundary."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Protocol

from pydantic import ValidationError

from vuln_proof_claw.config.models import DockerConfig
from vuln_proof_claw.domain.identifiers import WorkerId
from vuln_proof_claw.execution.manager import RuntimeResource
from vuln_proof_claw.execution.protocol import WorkerRequest, WorkerResponse

_IMAGE_DIGEST_MARKER = "@sha256:"
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_IMAGE_REPOSITORY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,180}$")
_NETWORK_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_WORKER_ID_PATTERN = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
)
_NON_ROOT_USER_PATTERN = re.compile(r"^[1-9][0-9]*:[1-9][0-9]*$")
_FORBIDDEN_NETWORKS = frozenset({"bridge", "control-plane", "host", "none"})
_MAXIMUM_IMAGE_REFERENCE_LENGTH = 255
_CONTROL_CHARACTER_LIMIT = 32
_HARD_MAXIMUM_TIMEOUT_SECONDS = 10_800
_HARD_MAXIMUM_MEMORY_MEGABYTES = 32_768
_HARD_MAXIMUM_CPU_COUNT = 32
_HARD_MAXIMUM_PROCESS_LIMIT = 4_096
_HARD_MAXIMUM_REQUEST_BYTES = 1024 * 1024
_HARD_MAXIMUM_OUTPUT_BYTES = 16 * 1024 * 1024
_HARD_MAXIMUM_TMPFS_MEGABYTES = 1_024
_HARD_MAXIMUM_STOP_GRACE_SECONDS = 30
_OWNER_LABEL = "io.vuln-proof-claw.managed-by"
_OWNER_VALUE = "worker-runtime"
_WORKER_LABEL = "io.vuln-proof-claw.worker-id"
_REQUEST_LABEL = "io.vuln-proof-claw.request-id"
_RUNTIME_LABEL = "io.vuln-proof-claw.runtime-identity"
_CREATED_LABEL = "io.vuln-proof-claw.created-at"
_CONTAINER_TEMP_PATH = PurePosixPath("/", "tmp").as_posix()


class DockerRuntimeError(Exception):
    """Stable runtime error that does not expose engine or container details."""


@dataclass(frozen=True, slots=True)
class RestrictedRuntimePolicy:
    """Immutable ceilings and allowlists for all disposable Docker workers."""

    image: str
    network: str
    allowed_capabilities: frozenset[str] = frozenset({"http_client"})
    user: str = "10002:10002"
    maximum_timeout_seconds: int = 1_800
    maximum_memory_megabytes: int = 2_048
    maximum_cpu_count: float = 2.0
    maximum_process_limit: int = 256
    maximum_request_bytes: int = 256 * 1024
    maximum_output_bytes: int = 1024 * 1024
    task_tmpfs_megabytes: int = 64
    stop_grace_seconds: int = 5

    def __post_init__(self) -> None:
        _validate_digest_pinned_image(self.image)
        if not _NETWORK_PATTERN.fullmatch(self.network):
            raise ValueError("worker network name is invalid")
        if self.network.casefold() in _FORBIDDEN_NETWORKS:
            raise ValueError("worker network must be dedicated and isolated")
        if not _NON_ROOT_USER_PATTERN.fullmatch(self.user):
            raise ValueError("worker user must be non-root")
        if any(
            not value.strip()
            or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value)
            for value in self.allowed_capabilities
        ):
            raise ValueError("allowed worker capabilities must not be blank")
        positive_limits = (
            self.maximum_timeout_seconds,
            self.maximum_memory_megabytes,
            self.maximum_cpu_count,
            self.maximum_process_limit,
            self.maximum_request_bytes,
            self.maximum_output_bytes,
            self.task_tmpfs_megabytes,
            self.stop_grace_seconds,
        )
        if any(not math.isfinite(value) or value <= 0 for value in positive_limits):
            raise ValueError("worker policy limits must be positive")
        bounded_limits = (
            self.maximum_timeout_seconds <= _HARD_MAXIMUM_TIMEOUT_SECONDS,
            self.maximum_memory_megabytes <= _HARD_MAXIMUM_MEMORY_MEGABYTES,
            self.maximum_cpu_count <= _HARD_MAXIMUM_CPU_COUNT,
            self.maximum_process_limit <= _HARD_MAXIMUM_PROCESS_LIMIT,
            self.maximum_request_bytes <= _HARD_MAXIMUM_REQUEST_BYTES,
            self.maximum_output_bytes <= _HARD_MAXIMUM_OUTPUT_BYTES,
            self.task_tmpfs_megabytes <= _HARD_MAXIMUM_TMPFS_MEGABYTES,
            self.stop_grace_seconds <= _HARD_MAXIMUM_STOP_GRACE_SECONDS,
        )
        if not all(bounded_limits):
            raise ValueError("worker policy limit exceeds the hard ceiling")

    @property
    def identity(self) -> str:
        """Bind the runtime identity to its image and security-relevant policy."""
        canonical = json.dumps(
            {
                "allowed_capabilities": sorted(self.allowed_capabilities),
                "image": self.image,
                "limits": {
                    "cpu": self.maximum_cpu_count,
                    "memory": self.maximum_memory_megabytes,
                    "output": self.maximum_output_bytes,
                    "pids": self.maximum_process_limit,
                    "request": self.maximum_request_bytes,
                    "timeout": self.maximum_timeout_seconds,
                },
                "network": self.network,
                "tmpfs": self.task_tmpfs_megabytes,
                "user": self.user,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        return f"docker:{self.image}#policy-sha256:{digest}"


@dataclass(frozen=True, slots=True)
class RestrictedContainerSpec:
    """Complete, non-extensible container request accepted by the engine gateway."""

    name: str
    image: str
    network: str
    user: str
    labels: tuple[tuple[str, str], ...]
    request_payload: bytes = field(repr=False)
    timeout_seconds: int = 0
    memory_bytes: int = 0
    nano_cpus: int = 0
    process_limit: int = 0
    read_only_root: bool = True
    capability_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    init: bool = True
    tmpfs: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.request_payload:
            raise ValueError("container name and request payload are required")
        if len(dict(self.labels)) != len(self.labels):
            raise ValueError("container labels must be unique")

    @property
    def label_map(self) -> Mapping[str, str]:
        return dict(self.labels)


@dataclass(frozen=True, slots=True)
class ContainerWaitResult:
    """Bounded container stdout and exit status returned by the engine gateway."""

    exit_code: int
    output: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class OwnedContainer:
    """One application-owned container returned by a filtered engine inventory."""

    reference: str = field(repr=False)
    labels: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not self.reference.strip():
            raise ValueError("container reference must not be empty")
        if len(dict(self.labels)) != len(self.labels):
            raise ValueError("container labels must be unique")

    @property
    def label_map(self) -> Mapping[str, str]:
        return dict(self.labels)


class RestrictedDockerEngine(Protocol):
    """Privileged operations exposed by a socket proxy or execution service."""

    async def create(self, spec: RestrictedContainerSpec) -> str:
        """Create a stopped container from the complete restricted spec."""

    async def start(self, reference: str) -> None:
        """Start one container."""

    async def wait(self, reference: str, *, maximum_output_bytes: int) -> ContainerWaitResult:
        """Wait and return no more than the requested number of stdout bytes."""

    async def stop(self, reference: str, *, grace_seconds: int) -> None:
        """Stop one container within the bounded grace period."""

    async def remove(self, reference: str, *, force: bool, volumes: bool) -> None:
        """Remove one container and its anonymous volumes idempotently."""

    async def list_owned(self, *, labels: Mapping[str, str]) -> tuple[OwnedContainer, ...]:
        """List containers matching every immutable ownership label."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


class DockerWorkerRuntime:
    """WorkerRuntime implementation that only emits restricted container specs."""

    def __init__(
        self,
        engine: RestrictedDockerEngine,
        policy: RestrictedRuntimePolicy,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._engine = engine
        self._policy = policy
        self._clock = clock

    @property
    def identity(self) -> str:
        return self._policy.identity

    async def create(self, request: WorkerRequest, *, worker_id: WorkerId) -> str:
        self._validate_request(request)
        if not _WORKER_ID_PATTERN.fullmatch(worker_id):
            raise DockerRuntimeError("worker_id_invalid")
        timestamp = self._aware_now()
        payload = request.model_dump_json().encode()
        if len(payload) > self._policy.maximum_request_bytes:
            raise DockerRuntimeError("worker_request_limit_exceeded")
        runtime_uid, runtime_gid = self._policy.user.split(":", maxsplit=1)
        spec = RestrictedContainerSpec(
            name=f"vpc-worker-{worker_id}",
            image=self._policy.image,
            network=self._policy.network,
            user=self._policy.user,
            labels=tuple(
                sorted(
                    {
                        _OWNER_LABEL: _OWNER_VALUE,
                        _CREATED_LABEL: timestamp.isoformat(),
                        _REQUEST_LABEL: request.request_id,
                        _RUNTIME_LABEL: self.identity,
                        _WORKER_LABEL: str(worker_id),
                    }.items()
                )
            ),
            request_payload=payload,
            timeout_seconds=request.limits.timeout_seconds,
            memory_bytes=request.limits.memory_megabytes * 1024 * 1024,
            nano_cpus=int(request.limits.cpu_count * 1_000_000_000),
            process_limit=request.limits.process_limit,
            tmpfs=(
                (
                    "/work",
                    "rw,noexec,nosuid,nodev,"
                    f"size={self._policy.task_tmpfs_megabytes}m,"
                    f"uid={runtime_uid},gid={runtime_gid}",
                ),
                (
                    _CONTAINER_TEMP_PATH,
                    "rw,noexec,nosuid,nodev,size=16m,"
                    f"uid={runtime_uid},gid={runtime_gid}",
                ),
            ),
        )
        try:
            reference = await self._engine.create(spec)
        except Exception as error:
            raise DockerRuntimeError("docker_create_failed") from error
        if not reference.strip():
            raise DockerRuntimeError("docker_create_returned_empty_reference")
        return reference

    async def start(self, runtime_reference: str) -> None:
        try:
            await self._engine.start(runtime_reference)
        except Exception as error:
            raise DockerRuntimeError("docker_start_failed") from error

    async def wait(self, runtime_reference: str) -> WorkerResponse:
        try:
            result = await self._engine.wait(
                runtime_reference,
                maximum_output_bytes=self._policy.maximum_output_bytes,
            )
        except Exception as error:
            raise DockerRuntimeError("docker_wait_failed") from error
        if len(result.output) > self._policy.maximum_output_bytes:
            raise DockerRuntimeError("worker_output_limit_exceeded")
        try:
            response = WorkerResponse.model_validate_json(result.output)
        except (UnicodeDecodeError, ValidationError, ValueError) as error:
            raise DockerRuntimeError("worker_response_invalid") from error
        if response.exit_code != result.exit_code:
            raise DockerRuntimeError("worker_exit_code_mismatch")
        return response

    async def cancel(self, runtime_reference: str) -> None:
        try:
            await self._engine.stop(
                runtime_reference,
                grace_seconds=self._policy.stop_grace_seconds,
            )
        except Exception as error:
            raise DockerRuntimeError("docker_stop_failed") from error

    async def destroy(self, runtime_reference: str) -> None:
        try:
            await self._engine.remove(runtime_reference, force=True, volumes=True)
        except Exception as error:
            raise DockerRuntimeError("docker_destroy_failed") from error

    async def list_resources(self) -> tuple[RuntimeResource, ...]:
        try:
            containers = await self._engine.list_owned(
                labels={_OWNER_LABEL: _OWNER_VALUE, _RUNTIME_LABEL: self.identity}
            )
            return tuple(self._resource(container) for container in containers)
        except Exception as error:
            raise DockerRuntimeError("docker_inventory_failed") from error

    def _resource(self, container: OwnedContainer) -> RuntimeResource:
        labels = container.label_map
        if (
            labels.get(_OWNER_LABEL) != _OWNER_VALUE
            or labels.get(_RUNTIME_LABEL) != self.identity
        ):
            raise DockerRuntimeError("docker_inventory_ownership_mismatch")
        try:
            worker_id = WorkerId(labels[_WORKER_LABEL])
            request_id = labels[_REQUEST_LABEL]
            created_at = datetime.fromisoformat(labels[_CREATED_LABEL])
        except (KeyError, TypeError, ValueError) as error:
            raise DockerRuntimeError("docker_inventory_labels_invalid") from error
        if not _WORKER_ID_PATTERN.fullmatch(worker_id) or self._has_control(request_id):
            raise DockerRuntimeError("docker_inventory_labels_invalid")
        return RuntimeResource(
            worker_id=worker_id,
            request_id=request_id,
            reference=container.reference,
            created_at=created_at,
        )

    def _validate_request(self, request: WorkerRequest) -> None:
        limits = request.limits
        if self._has_control(request.request_id):
            raise DockerRuntimeError("worker_request_id_invalid")
        if not set(request.capabilities).issubset(self._policy.allowed_capabilities):
            raise DockerRuntimeError("worker_capability_not_allowed")
        if (
            limits.timeout_seconds > self._policy.maximum_timeout_seconds
            or limits.memory_megabytes > self._policy.maximum_memory_megabytes
            or limits.cpu_count > self._policy.maximum_cpu_count
            or limits.process_limit > self._policy.maximum_process_limit
        ):
            raise DockerRuntimeError("worker_resource_limit_exceeded")

    @staticmethod
    def _has_control(value: str) -> bool:
        return any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value)

    def _aware_now(self) -> datetime:
        timestamp = self._clock()
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise DockerRuntimeError("docker_runtime_clock_must_be_timezone_aware")
        return timestamp


def _validate_digest_pinned_image(image: str) -> None:
    if (
        len(image) > _MAXIMUM_IMAGE_REFERENCE_LENGTH
        or image.count(_IMAGE_DIGEST_MARKER) != 1
    ):
        raise ValueError("worker image must be pinned by sha256 digest")
    repository, digest = image.split(_IMAGE_DIGEST_MARKER, maxsplit=1)
    if (
        not _IMAGE_REPOSITORY_PATTERN.fullmatch(repository)
        or not _SHA256_PATTERN.fullmatch(digest)
    ):
        raise ValueError("worker image must be pinned by sha256 digest")


def restricted_policy_from_config(config: DockerConfig) -> RestrictedRuntimePolicy:
    """Build a validated policy only when the dangerous runtime is explicitly enabled."""
    if not config.runtime_enabled:
        raise DockerRuntimeError("docker_runtime_disabled")
    try:
        return RestrictedRuntimePolicy(
            image=config.worker_image,
            network=config.worker_network,
            allowed_capabilities=frozenset(config.allowed_capabilities),
            maximum_timeout_seconds=config.default_timeout_seconds,
            maximum_memory_megabytes=config.maximum_memory_megabytes,
            maximum_cpu_count=config.maximum_cpu_count,
            maximum_process_limit=config.maximum_process_limit,
            maximum_request_bytes=config.maximum_request_bytes,
            maximum_output_bytes=config.maximum_output_bytes,
            task_tmpfs_megabytes=config.task_tmpfs_megabytes,
            stop_grace_seconds=config.stop_grace_seconds,
        )
    except ValueError as error:
        raise DockerRuntimeError("docker_runtime_policy_invalid") from error
