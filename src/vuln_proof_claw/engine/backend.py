"""Narrow privileged backend contract owned by the Engine gateway process."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Never, Protocol

from vuln_proof_claw.execution.docker_runtime import (
    ContainerWaitResult,
    OwnedContainer,
    RestrictedContainerSpec,
)


class EngineBackendErrorCode(StrEnum):
    """Safe categories exposed to the gateway HTTP mapping."""

    BUSY = "engine_backend_busy"
    CONFLICT = "engine_backend_conflict"
    NOT_FOUND = "engine_backend_not_found"
    REJECTED = "engine_backend_rejected"
    UNAVAILABLE = "engine_backend_unavailable"


class EngineBackendError(Exception):
    """Expected backend failure with no daemon or host details."""

    def __init__(self, code: EngineBackendErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


class PrivilegedEngineBackend(Protocol):
    """Only operations the isolated gateway may perform against its Engine."""

    async def check_ready(self) -> None:
        """Raise a safe error unless the Engine and policy are ready."""

    async def create(self, spec: RestrictedContainerSpec) -> str:
        """Create one stopped restricted container idempotently by name."""

    async def start(self, reference: str) -> None:
        """Start one owned container."""

    async def wait(self, reference: str, *, maximum_output_bytes: int) -> ContainerWaitResult:
        """Wait and return bounded stdout."""

    async def stop(self, reference: str, *, grace_seconds: int) -> None:
        """Stop one owned container."""

    async def remove(self, reference: str, *, force: bool, volumes: bool) -> None:
        """Remove one owned container and anonymous storage idempotently."""

    async def list_owned(self, *, labels: Mapping[str, str]) -> tuple[OwnedContainer, ...]:
        """List only containers matching all ownership labels."""


class DisabledEngineBackend:
    """Fail closed until a separately reviewed Engine implementation is injected."""

    async def check_ready(self) -> None:
        self._unavailable()

    async def create(self, spec: RestrictedContainerSpec) -> str:
        del spec
        self._unavailable()

    async def start(self, reference: str) -> None:
        del reference
        self._unavailable()

    async def wait(self, reference: str, *, maximum_output_bytes: int) -> ContainerWaitResult:
        del reference, maximum_output_bytes
        self._unavailable()

    async def stop(self, reference: str, *, grace_seconds: int) -> None:
        del reference, grace_seconds
        self._unavailable()

    async def remove(self, reference: str, *, force: bool, volumes: bool) -> None:
        del reference, force, volumes
        self._unavailable()

    async def list_owned(self, *, labels: Mapping[str, str]) -> tuple[OwnedContainer, ...]:
        del labels
        self._unavailable()

    @staticmethod
    def _unavailable() -> Never:
        raise EngineBackendError(EngineBackendErrorCode.UNAVAILABLE)
