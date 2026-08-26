"""Tests for tool probes that execute rather than only look on PATH."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence

import pytest

from vuln_proof_claw.execution.preflight import (
    DEFAULT_PROBES,
    CommandOutput,
    CommandRunner,
    ToolProbe,
    probe_tool,
    run_preflight,
)

PROBE = ToolProbe("httpx", ("httpx", "-version"), "projectdiscovery")


def resolves_to(path: str | None) -> Callable[[str], str | None]:
    def resolve(name: str) -> str | None:
        return path

    return resolve


def returns(output: CommandOutput) -> CommandRunner:
    def runner(argv: Sequence[str], *, timeout: int) -> CommandOutput:
        assert argv == PROBE.argv
        assert timeout > 0
        return output

    return runner


def raises(error: BaseException) -> CommandRunner:
    def runner(argv: Sequence[str], *, timeout: int) -> CommandOutput:
        raise error

    return runner


def test_a_probe_needs_an_argv_and_a_marker() -> None:
    with pytest.raises(ValueError, match="argv"):
        ToolProbe("x", (), "marker")
    with pytest.raises(ValueError, match="marker"):
        ToolProbe("x", ("x",), "")


def test_missing_tool_is_reported_as_not_on_path() -> None:
    result = probe_tool(PROBE, runner=returns(CommandOutput(0, "", "")), resolve=resolves_to(None))
    assert result.ready is False
    assert result.code == "not_on_path"
    assert result.resolved_path is None


def test_a_look_alike_that_exits_zero_is_not_ready() -> None:
    # The Debian python3-httpx program answers successfully while ignoring the
    # scanner's flags, which is exactly the case a PATH check cannot catch.
    result = probe_tool(
        PROBE,
        runner=returns(CommandOutput(0, "", "Error: No such option: -version")),
        resolve=resolves_to("/usr/bin/httpx"),
    )
    assert result.ready is False
    assert result.code == "wrong_program_on_path"
    assert result.resolved_path == "/usr/bin/httpx"
    assert "No such option" in result.detail


def test_the_expected_program_is_ready_and_its_path_is_recorded() -> None:
    result = probe_tool(
        PROBE,
        runner=returns(CommandOutput(0, "projectdiscovery.io httpx v1.10.0", "")),
        resolve=resolves_to("/root/go/bin/httpx"),
    )
    assert result.ready is True
    assert result.code == "ready"
    assert result.resolved_path == "/root/go/bin/httpx"
    assert "v1.10.0" in result.detail


def test_the_marker_may_arrive_on_stderr() -> None:
    result = probe_tool(
        PROBE,
        runner=returns(CommandOutput(1, "", "ProjectDiscovery httpx")),
        resolve=resolves_to("/root/go/bin/httpx"),
    )
    assert result.ready is True


def test_a_probe_that_hangs_is_reported_as_timed_out() -> None:
    result = probe_tool(
        PROBE,
        runner=raises(subprocess.TimeoutExpired(cmd="httpx", timeout=1)),
        resolve=resolves_to("/root/go/bin/httpx"),
    )
    assert result.ready is False
    assert result.code == "probe_timed_out"


def test_an_unlaunchable_binary_is_reported_as_failed() -> None:
    result = probe_tool(
        PROBE,
        runner=raises(OSError("Exec format error")),
        resolve=resolves_to("/root/go/bin/httpx"),
    )
    assert result.ready is False
    assert result.code == "probe_failed"
    assert "Exec format error" in result.detail


def test_the_report_is_not_ready_when_any_tool_fails() -> None:
    def runner(argv: Sequence[str], *, timeout: int) -> CommandOutput:
        if argv[0] == "curl":
            return CommandOutput(0, "curl 8.5.0", "")
        return CommandOutput(0, "", "")

    report = run_preflight(runner=runner, resolve=resolves_to("/usr/bin/tool"))
    assert report.ready is False
    ready_names = {result.name for result in report.results if result.ready}
    assert ready_names == {"curl"}
    assert report.as_dict()["status"] == "not_ready"


def test_the_default_probe_set_covers_the_tools_that_have_bitten_us() -> None:
    names = {probe.name for probe in DEFAULT_PROBES}
    assert {"httpx", "wpscan", "nuclei", "ffuf"} <= names


def test_the_httpx_probe_looks_for_the_scanner_not_just_the_name() -> None:
    httpx_probe = next(probe for probe in DEFAULT_PROBES if probe.name == "httpx")
    assert httpx_probe.expect.lower() == "projectdiscovery"
