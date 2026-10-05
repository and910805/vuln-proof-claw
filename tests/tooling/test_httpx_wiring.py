"""The httpx contract and the argv it produces.

The argv assertions are exact rather than "contains", because the security
property here is what is *absent*: a target file, a port list, extra paths, a
proxy, a redirect flag. A containment assertion cannot see a flag that should
not be there, so it would pass while the tool reached somewhere nobody approved.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vuln_proof_claw.tooling.contracts import HttpxParameters, validate_tool_invocation
from vuln_proof_claw.tooling.executor import build_worker_argv
from vuln_proof_claw.tooling.registry import IntegrationState, get_tool

TARGET = "https://api.example.test:443/v1"


def invoke(**parameters: object) -> object:
    return validate_tool_invocation("httpx", TARGET, dict(parameters))


def test_the_contract_is_canonical_and_builds_one_bounded_single_target_probe() -> None:
    invocation = validate_tool_invocation(
        "httpx",
        TARGET,
        {
            "probes": ["title", "web_server", "title"],
            "method": "HEAD",
            "timeout_seconds": 20,
            "retries": 2,
            "rate_limit_per_second": 25,
        },
    )

    argv = build_worker_argv(invocation, httpx_executable="/usr/bin/httpx")

    assert isinstance(invocation.parameters, HttpxParameters)
    # Deduplicated and sorted, so the same request in another order digests alike.
    assert invocation.parameters.probes == ("title", "web_server")
    assert len(invocation.parameter_digest) == 64
    assert argv == (
        "/usr/bin/httpx",
        "-target",
        TARGET,
        "-json",
        "-silent",
        "-no-color",
        "-method",
        "HEAD",
        "-timeout",
        "20",
        "-retries",
        "2",
        "-rate-limit",
        "25",
        "-title",
        "-web-server",
    )


def test_the_argv_can_never_reach_a_target_the_approval_did_not_name() -> None:
    # Each of these flags is a second place a target could come from. The
    # contract offers none of them, so none can appear -- and this is the
    # assertion that would catch a future parameter reintroducing one.
    argv = build_worker_argv(validate_tool_invocation("httpx", TARGET, {}))

    forbidden = {
        "-l",
        "-list",
        "-ports",
        "-p",
        "-path",
        "-paths",
        "-proxy",
        "-http-proxy",
        "-follow-redirects",
        "-fr",
        "-follow-host-redirects",
        "-o",
        "-output",
        "-srd",
        "-store-response-dir",
    }
    assert forbidden.isdisjoint(argv)
    # Exactly one target, and it is the approved one.
    assert argv.count(TARGET) == 1


def test_the_default_probe_set_is_the_one_the_parser_reads() -> None:
    # A default that omits a probe silently removes a whole finding family: the
    # parser reads webserver, tech and tls, and none of those fields appear in
    # the JSON unless their flag was passed.
    argv = build_worker_argv(validate_tool_invocation("httpx", TARGET, {}))

    assert {"-web-server", "-tech-detect", "-tls-grab"} <= set(argv)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("probes", []),
        ("probes", ["not_a_probe"]),
        ("method", "POST"),
        ("timeout_seconds", 0),
        ("timeout_seconds", 61),
        ("retries", -1),
        ("retries", 4),
        ("rate_limit_per_second", 0),
        ("rate_limit_per_second", 151),
    ],
)
def test_out_of_contract_parameters_are_refused(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        invoke(**{field: value})


def test_an_unknown_parameter_is_refused_rather_than_ignored() -> None:
    # extra="forbid" is what stops a caller smuggling a flag past the review:
    # a parameter the contract does not know must not be silently dropped.
    with pytest.raises(ValidationError):
        invoke(follow_redirects=True)


def test_the_registry_agrees_that_httpx_can_actually_run() -> None:
    # The manifest is what a planner and the MCP client read. Claiming
    # WORKER_READY while build_worker_argv raises would advertise a tool that
    # cannot run; claiming CATALOGED while it works hides a wired tool.
    manifest = get_tool("httpx")

    assert manifest is not None
    assert manifest.integration_state is IntegrationState.WORKER_READY
    assert build_worker_argv(validate_tool_invocation("httpx", TARGET, {}))
