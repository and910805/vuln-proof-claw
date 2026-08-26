"""Verify that security tools actually run, not merely that they are installed.

Checking for a name on PATH is not enough. Two unrelated programs can share a
name, and the wrong one may exit zero while doing nothing - a scan then reports
no findings and the run looks like a clean target. Every probe here executes the
tool, records which path resolved and which version answered, and requires an
expected marker in the output before calling the tool ready.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - a probe is only meaningful if it runs the tool
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

PROBE_TIMEOUT_SECONDS: Final = 20


@dataclass(frozen=True, slots=True)
class CommandOutput:
    """Result of running one probe command."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def combined(self) -> str:
        return f"{self.stdout}\n{self.stderr}"


class CommandRunner(Protocol):
    """Run an argument vector and return its output."""

    def __call__(self, argv: Sequence[str], *, timeout: int) -> CommandOutput: ...


@dataclass(frozen=True, slots=True)
class ToolProbe:
    """One tool and the marker that proves it really answered."""

    name: str
    argv: tuple[str, ...]
    expect: str

    def __post_init__(self) -> None:
        if not self.argv:
            raise ValueError("probe argv must not be empty")
        if not self.expect:
            raise ValueError("probe expect marker must not be empty")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """What one probe established about one tool."""

    name: str
    ready: bool
    code: str
    resolved_path: str | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": "ready" if self.ready else "not_ready",
            "code": self.code,
            "resolved_path": self.resolved_path or "",
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Stable machine-readable preflight result."""

    results: tuple[ProbeResult, ...]

    @property
    def ready(self) -> bool:
        return all(result.ready for result in self.results)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "v1",
            "status": "ready" if self.ready else "not_ready",
            "tools": [result.as_dict() for result in self.results],
        }


DEFAULT_PROBES: Final = (
    ToolProbe("curl", ("curl", "--version"), "curl"),
    ToolProbe("nmap", ("nmap", "--version"), "Nmap version"),
    ToolProbe("nuclei", ("nuclei", "-version"), "nuclei"),
    ToolProbe("ffuf", ("ffuf", "-V"), "ffuf"),
    # The Debian python3-httpx package installs a program of the same name that
    # accepts none of these flags, so the marker has to come from the scanner.
    ToolProbe("httpx", ("httpx", "-version"), "projectdiscovery"),
    ToolProbe("wpscan", ("wpscan", "--version"), "WPScan"),
)


def _default_runner(argv: Sequence[str], *, timeout: int) -> CommandOutput:
    # nosec B603 - argv comes from the fixed probe table above, never from a
    # caller or a target, and the shell is not involved.
    completed = subprocess.run(  # noqa: S603  # nosec B603
        list(argv),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
    return CommandOutput(completed.returncode, completed.stdout, completed.stderr)


def probe_tool(
    probe: ToolProbe,
    *,
    runner: CommandRunner | None = None,
    resolve: object = None,
    timeout: int = PROBE_TIMEOUT_SECONDS,
) -> ProbeResult:
    """Execute one probe and report whether the tool genuinely answered."""
    which = shutil.which if resolve is None else resolve
    resolved = which(probe.argv[0])  # type: ignore[operator]
    if resolved is None:
        return ProbeResult(probe.name, False, "not_on_path")

    run = _default_runner if runner is None else runner
    try:
        output = run(probe.argv, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ProbeResult(probe.name, False, "probe_timed_out", resolved)
    except OSError as error:
        return ProbeResult(probe.name, False, "probe_failed", resolved, str(error))

    haystack = output.combined.lower()
    if probe.expect.lower() not in haystack:
        # Exit code zero is not proof of anything here: a look-alike program can
        # succeed while ignoring the flags the scanner needs.
        return ProbeResult(
            probe.name,
            False,
            "wrong_program_on_path",
            resolved,
            _first_line(output.combined),
        )
    return ProbeResult(probe.name, True, "ready", resolved, _first_line(output.combined))


def run_preflight(
    probes: Iterable[ToolProbe] = DEFAULT_PROBES,
    *,
    runner: CommandRunner | None = None,
    resolve: object = None,
) -> PreflightReport:
    """Execute every probe and return the report."""
    return PreflightReport(
        tuple(probe_tool(probe, runner=runner, resolve=resolve) for probe in probes)
    )


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:200]
    return ""
