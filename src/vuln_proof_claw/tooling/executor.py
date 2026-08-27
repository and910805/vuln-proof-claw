"""Bounded argv builders for disposable Worker execution."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Final
from urllib.parse import urlsplit

from vuln_proof_claw.tooling.contracts import (
    HttpxParameters,
    NmapParameters,
    NucleiParameters,
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


# Each entry is one thing nuclei does with no flag at all, and the flag that
# stops it. The table is the threat model: a reviewer reads the reason, and a
# test asserts every switch reaches the argv, so removing one is a visible
# change rather than a quiet widening.
NUCLEI_DEFAULT_LEAKS: Final = MappingProxyType(
    {
        "-disable-update-check": (
            "Calls api.pdtm.sh before scanning, carrying a stable machine id, OS, "
            "arch and the fact that a scan is starting."
        ),
        "-no-stdin": (
            "Reads additional targets from stdin, so a target can enter the run "
            "without appearing in argv or in the approved parameters."
        ),
        "-no-httpx": (
            "Probes a schemeless target over both http and https, turning one "
            "approved endpoint into at least two."
        ),
        "-system-resolvers": (
            "Resolves through Cloudflare and Google public resolvers instead of "
            "the host's, disclosing every target hostname to two third parties."
        ),
        "-disable-redirects": (
            "Templates may follow redirects themselves, and a redirect points at "
            "a target the approval never named."
        ),
        "-silent": "Prints a banner and progress into the captured output.",
        "-no-color": "Wraps the captured output in ANSI escapes.",
        "-jsonl": (
            "Defaults to a human-readable line format that no parser can read "
            "without guessing."
        ),
    }
)

NUCLEI_REQUIRED_SWITCHES: Final = tuple(NUCLEI_DEFAULT_LEAKS)

# nuclei reads two inputs argv cannot describe: $HOME/.config/nuclei/config.yaml,
# which can set ANY option including -proxy, -headless, -code and -list; and the
# environment, from which cloud upload arms itself with no flag on the command
# line. A digest over the parameters therefore does not pin the behaviour unless
# the Worker also applies this. Values are the required setting; None means the
# variable must be absent.
NUCLEI_WORKER_ENVIRONMENT: Final = MappingProxyType(
    {
        # Point HOME at the disposable directory so the config file, the
        # template tree and the resume state cannot outlive the Worker or be
        # pre-seeded to redirect the run.
        "HOME": "<worker_directory>",
        "NUCLEI_TEMPLATES_DIR": "<pinned_template_corpus>",
        "DISABLE_UPDATE_CHECK": "true",
        "ENABLE_CLOUD_UPLOAD": None,
        "DISABLE_CLOUD_UPLOAD_WRN": None,
        "PDCP_API_KEY": None,
        "PDCP_TEAM_ID": None,
    }
)


def build_worker_argv(  # noqa: PLR0913 - one executable path per wired tool
    invocation: ToolInvocation,
    *,
    allowed_commands: frozenset[str] = frozenset(),
    python_executable: str = "python",
    nmap_executable: str = "nmap",
    httpx_executable: str = "httpx",
    nuclei_executable: str = "nuclei",
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
    if isinstance(parameters, NucleiParameters):
        return _nuclei_argv(invocation, parameters, nuclei_executable)
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


def _nuclei_argv(
    invocation: ToolInvocation,
    parameters: NucleiParameters,
    executable: str,
) -> tuple[str, ...]:
    """Build a nuclei argv in which every default that leaks is switched off.

    nuclei's out-of-the-box behaviour is unusually broad for a tool given one
    target, and none of it needs a flag to happen. Each entry in
    ``NUCLEI_REQUIRED_SWITCHES`` names one such default and the flag that closes
    it, so the table is the threat model rather than a comment about it.

    Two of nuclei's inputs are outside argv entirely -- its config file and its
    environment -- so an argv review alone does not describe the run. Those are
    ``NUCLEI_WORKER_ENVIRONMENT``'s job, and a Worker that ignores it can still
    be redirected by a config file this function never sees.
    """
    argv = [executable, *NUCLEI_REQUIRED_SWITCHES]
    argv.extend(("-target", invocation.target))
    argv.extend(("-severity", ",".join(parameters.severities)))
    if parameters.template_ids:
        argv.extend(("-template-id", ",".join(parameters.template_ids)))
    if parameters.tags:
        argv.extend(("-tags", ",".join(parameters.tags)))
    # Always present, because the exclusions that are never optional are always
    # in it -- see NucleiParameters.effective_exclude_tags.
    argv.extend(("-exclude-tags", ",".join(parameters.effective_exclude_tags)))
    if parameters.interactsh_server is None:
        # No server named, so out-of-band detection is off. -no-interactsh also
        # excludes the templates that depend on it, which is what stops them
        # silently reporting nothing found when they simply could not run.
        argv.append("-no-interactsh")
    else:
        argv.extend(("-interactsh-server", parameters.interactsh_server))
    argv.extend(("-rate-limit", str(parameters.rate_limit_per_second)))
    argv.extend(("-concurrency", str(parameters.concurrency)))
    argv.extend(("-bulk-size", str(parameters.bulk_size)))
    argv.extend(("-timeout", str(parameters.timeout_seconds)))
    argv.extend(("-retries", str(parameters.retries)))
    argv.extend(("-max-host-error", str(parameters.max_host_error)))
    return tuple(argv)


def require_disposable_workdir(path: Path, worker_root: Path) -> Path:
    """Reject command execution outside the runtime-owned disposable directory."""
    resolved = path.resolve()
    root = worker_root.resolve()
    if resolved == root or root not in resolved.parents:
        raise ToolExecutionError("worker_directory_not_disposable")
    return resolved
