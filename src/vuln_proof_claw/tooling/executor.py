"""Bounded argv builders for disposable Worker execution."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Final
from urllib.parse import urlsplit

from vuln_proof_claw.tooling.contracts import (
    HttpxParameters,
    NmapParameters,
    PythonExecuteParameters,
    ShellCommandParameters,
    ToolInvocation,
)

# One flag per probe name the contract offers. Long forms on purpose: the argv
# ends up in the audit trail, and a reviewer should not have to know that
# ``-td`` means tech detection.
_HTTPX_PROBE_FLAGS: Final = MappingProxyType(
    {
        "status_code": "-status-code",
        "content_length": "-content-length",
        "title": "-title",
        "web_server": "-web-server",
        "tech_detect": "-tech-detect",
        "tls_grab": "-tls-grab",
        "response_time": "-response-time",
    }
)


class ToolExecutionError(ValueError):
    """Raised when a request cannot be converted into an allowed Worker argv."""


def build_worker_argv(
    invocation: ToolInvocation,
    *,
    allowed_commands: frozenset[str] = frozenset(),
    python_executable: str = "python",
    nmap_executable: str = "nmap",
    httpx_executable: str = "httpx",
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
    if isinstance(parameters, HttpxParameters):
        argv = [
            httpx_executable,
            # The target is passed inline. httpx also reads a target file, and
            # that flag is deliberately unreachable from this contract: a file
            # is a second place a target could come from, and only one of them
            # is the target the approval bound.
            "-target",
            invocation.target,
            "-json",
            "-silent",
            "-no-color",
            "-method",
            parameters.method,
            "-timeout",
            str(parameters.timeout_seconds),
            "-retries",
            str(parameters.retries),
            "-rate-limit",
            str(parameters.rate_limit_per_second),
        ]
        # No -follow-redirects: httpx does not follow by default, and leaving it
        # that way keeps one action bound to one target.
        argv.extend(_HTTPX_PROBE_FLAGS[probe] for probe in parameters.probes)
        return tuple(argv)
    raise ToolExecutionError("tool_has_no_worker_runner")


def require_disposable_workdir(path: Path, worker_root: Path) -> Path:
    """Reject command execution outside the runtime-owned disposable directory."""
    resolved = path.resolve()
    root = worker_root.resolve()
    if resolved == root or root not in resolved.parents:
        raise ToolExecutionError("worker_directory_not_disposable")
    return resolved
