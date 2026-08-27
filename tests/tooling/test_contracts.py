from __future__ import annotations

import pytest
from pydantic import ValidationError

from vuln_proof_claw.tooling.contracts import (
    NmapParameters,
    PasswordTestParameters,
    validate_tool_invocation,
)
from vuln_proof_claw.tooling.executor import ToolExecutionError, build_worker_argv


def test_nmap_contract_is_canonical_and_builds_bounded_connect_scan() -> None:
    invocation = validate_tool_invocation(
        "nmap",
        "https://api.example.test:443/v1",
        {
            "ports": [443, 80, 443],
            "service_detection": True,
            "scripts": ["http-title"],
            "timeout_seconds": 120,
        },
    )

    argv = build_worker_argv(invocation, nmap_executable="/usr/bin/nmap")

    assert isinstance(invocation.parameters, NmapParameters)
    assert invocation.parameters.ports == (80, 443)
    assert len(invocation.parameter_digest) == 64
    assert argv == (
        "/usr/bin/nmap",
        "-n",
        "-sT",
        "-Pn",
        "--max-retries",
        "2",
        "--host-timeout",
        "120s",
        "-p",
        "80,443",
        "-sV",
        "--script",
        "http-title",
        "api.example.test",
    )


def test_shell_contract_never_parses_a_shell_expression_and_requires_allowlist() -> None:
    with pytest.raises(ValidationError):
        validate_tool_invocation(
            "shell_command",
            "https://api.example.test/v1",
            {"executable": "curl && whoami", "arguments": []},
        )

    invocation = validate_tool_invocation(
        "shell_command",
        "https://api.example.test/v1",
        {"executable": "curl", "arguments": ["--version"]},
    )
    with pytest.raises(ToolExecutionError, match="command_not_allowed"):
        build_worker_argv(invocation)
    assert build_worker_argv(invocation, allowed_commands=frozenset({"curl"})) == (
        "curl",
        "--version",
    )


def test_password_contract_accepts_secret_references_not_unbounded_pair_space() -> None:
    invocation = validate_tool_invocation(
        "password_test",
        "https://api.example.test/v1/login",
        {
            "protocol": "http_form",
            "usernames": ["admin", "reviewer"],
            "secret_refs": ["vault://engagement/password-1"],
            "maximum_attempts": 2,
            "attempts_per_minute": 2,
        },
    )
    assert isinstance(invocation.parameters, PasswordTestParameters)
    assert invocation.parameters.maximum_attempts == 2

    with pytest.raises(ValidationError):
        validate_tool_invocation(
            "password_test",
            "https://api.example.test/v1/login",
            {
                "protocol": "http_form",
                "usernames": ["admin"],
                "secret_refs": ["vault://engagement/password-1"],
                "maximum_attempts": 2,
            },
        )
