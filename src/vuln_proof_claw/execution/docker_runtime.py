"""A concrete, hardened, fail-closed Docker worker runtime.

This adapter fills the :class:`~vuln_proof_claw.execution.manager.WorkerRuntime`
seam with real disposable containers. It stays disabled until an operator
explicitly enables it, launches every worker with all Linux capabilities
dropped, a read-only root filesystem, no new privileges, resource ceilings, and
attachment only to the isolated worker network, and always attempts teardown.

The runtime never opens egress to the public internet: workers are attached to
the internal worker network, so the only reachable targets are the ones an
operator places on that network. Container references are labelled so the
orphan-runtime janitor can reclaim leaked containers after a restart.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pydantic import ValidationError

from vuln_proof_claw.config.models import DockerConfig
from vuln_proof_claw.execution.manager import (
    DisabledWorkerManager,
    LifecycleWorkerManager,
    WorkerExecutionUnavailableError,
    WorkerManager,
    WorkerManagerError,
)
from vuln_proof_claw.execution.protocol import WorkerRequest, WorkerResponse

_LABEL_VALUE = "true"
_REQUEST_ENV = "VULN_PROOF_CLAW_WORKER_REQUEST"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Captured result of one Docker CLI invocation."""

    returncode: int
    stdout: str
    stderr: str


class DockerCommandRunner(Protocol):
    """Narrow boundary over the Docker CLI so the runtime stays unit-testable."""

    async def run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        """Run one Docker subcommand and capture its result."""


class SubprocessDockerCommandRunner:
    """Invoke the Docker CLI as a subprocess with a fixed, argument-only contract."""

    def __init__(self, cli_path: str = "docker") -> None:
        self._cli_path = cli_path

    async def run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: float | None = None,
    ) -> CommandResult:
        process = await asyncio.create_subprocess_exec(
            self._cli_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout_seconds,
            )
        except (TimeoutError, asyncio.CancelledError):
            process.kill()
            await process.wait()
            raise
        return CommandResult(
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=stdout.decode("utf-8", "replace"),
            stderr=stderr.decode("utf-8", "replace"),
        )


class DockerWorkerRuntime:
    """Launch and reclaim hardened disposable-worker containers over the Docker CLI."""

    def __init__(self, config: DockerConfig, runner: DockerCommandRunner) -> None:
        if not config.runtime_enabled:
            raise WorkerExecutionUnavailableError("docker worker runtime is disabled")
        self._config = config
        self._runner = runner

    @property
    def identity(self) -> str:
        return f"docker:{self._config.worker_image}"

    async def create(self, request: WorkerRequest) -> str:
        """Create, but do not start, one hardened container bound to the worker network."""
        limits = request.limits
        args = [
            "create",
            "--network",
            self._config.worker_network,
            "--cap-drop",
            "ALL",
            "--read-only",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(limits.process_limit),
            "--memory",
            f"{limits.memory_megabytes}m",
            "--cpus",
            str(limits.cpu_count),
            "--label",
            self._label(),
            "--env",
            f"{_REQUEST_ENV}={request.model_dump_json()}",
            self._config.worker_image,
        ]
        result = await self._runner.run(args)
        if result.returncode != 0:
            raise WorkerManagerError("docker_create_failed")
        reference = result.stdout.strip()
        if not reference:
            raise WorkerManagerError("docker_create_returned_empty_reference")
        return reference

    async def start(self, runtime_reference: str) -> None:
        result = await self._runner.run(["start", runtime_reference])
        if result.returncode != 0:
            raise WorkerManagerError("docker_start_failed")

    async def wait(self, runtime_reference: str) -> WorkerResponse:
        """Block until the container exits, then parse the terminal response.

        The worker may print diagnostic lines before its terminal response, so the
        last line that parses as a :class:`WorkerResponse` is authoritative.
        """
        await self._runner.run(["wait", runtime_reference])
        logs = await self._runner.run(["logs", runtime_reference])
        if logs.returncode != 0:
            raise WorkerManagerError("docker_logs_failed")
        for line in reversed(logs.stdout.splitlines()):
            candidate = line.strip()
            if not candidate:
                continue
            try:
                return WorkerResponse.model_validate_json(candidate)
            except ValidationError:
                continue
        raise WorkerManagerError("worker_response_invalid")

    async def cancel(self, runtime_reference: str) -> None:
        result = await self._runner.run(["stop", "--time", "5", runtime_reference])
        if result.returncode != 0:
            raise WorkerManagerError("docker_stop_failed")

    async def destroy(self, runtime_reference: str) -> None:
        result = await self._runner.run(["rm", "--force", "--volumes", runtime_reference])
        if result.returncode != 0:
            raise WorkerManagerError("docker_remove_failed")

    async def list_owned(self) -> tuple[str, ...]:
        """Return the ids of every container this platform still owns by label."""
        result = await self._runner.run(
            ["ps", "--all", "--quiet", "--filter", f"label={self._label()}"]
        )
        if result.returncode != 0:
            raise WorkerManagerError("docker_list_failed")
        return tuple(line.strip() for line in result.stdout.splitlines() if line.strip())

    def _label(self) -> str:
        return f"{self._config.ownership_label}={_LABEL_VALUE}"


def create_worker_runtime(config: DockerConfig) -> DockerWorkerRuntime:
    """Build the concrete runtime; raises when the runtime is not enabled."""
    return DockerWorkerRuntime(config, SubprocessDockerCommandRunner(config.cli_path))


def build_worker_manager(config: DockerConfig) -> WorkerManager:
    """Return a live manager only when execution is enabled, else a fail-closed stub."""
    if not config.runtime_enabled:
        return DisabledWorkerManager()
    return LifecycleWorkerManager(create_worker_runtime(config))
