"""Bounded argv builders for disposable Worker execution."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from vuln_proof_claw.tooling.contracts import (
    NmapParameters,
    PythonExecuteParameters,
    ShellCommandParameters,
    ToolInvocation,
)


class ToolExecutionError(ValueError):
    """Raised when a request cannot be converted into an allowed Worker argv."""


def build_worker_argv(
    invocation: ToolInvocation,
    *,
    allowed_commands: frozenset[str] = frozenset(),
    python_executable: str = "python",
    nmap_executable: str = "nmap",
) -> tuple[str, ...]:
    """Build exact argv; callers must execute it with ``shell=False`` in an isolated Worker."""
    parameters = invocation.parameters
    if isinstance(parameters, ShellCommandParameters):
        if parameters.executable not in allowed_commands:
            raise ToolExecutionError("command_not_allowed")
        return (parameters.executable, *parameters.arguments)
    if isinstance(parameters, PythonExecuteParameters):
        return (python_executable, "-I", "-S", "-c", parameters.source, *parameters.arguments)
    if isinstance(parameters, NmapParameters):
        hostname = urlsplit(invocation.target).hostname
        if hostname is None:
            raise ToolExecutionError("nmap_target_invalid")
        argv = [
            nmap_executable,
            "-n",
            "-sT",
            "-Pn",
            "--max-retries",
            "2",
            "--host-timeout",
            f"{parameters.timeout_seconds}s",
            "-p",
            ",".join(str(port) for port in parameters.ports),
        ]
        if parameters.service_detection:
            argv.append("-sV")
        if parameters.scripts:
            argv.extend(("--script", ",".join(parameters.scripts)))
        argv.append(hostname)
        return tuple(argv)
    raise ToolExecutionError("tool_has_no_worker_runner")


def require_disposable_workdir(path: Path, worker_root: Path) -> Path:
    """Reject command execution outside the runtime-owned disposable directory."""
    resolved = path.resolve()
    root = worker_root.resolve()
    if resolved == root or root not in resolved.parents:
        raise ToolExecutionError("worker_directory_not_disposable")
    return resolved
