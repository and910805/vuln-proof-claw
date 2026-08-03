from vuln_proof_claw.tooling.registry import IntegrationState, get_tool, list_tools


def test_registry_exposes_requested_and_expanding_scanner_capabilities() -> None:
    tools = list_tools(lambda executable: f"/tools/{executable}" if executable == "nmap" else None)
    by_name = {tool.name: tool for tool in tools}

    assert len(tools) >= 23
    assert {"shell_command", "python_execute", "nmap", "password_test", "exploit_poc"} <= set(
        by_name
    )
    assert by_name["nmap"].installed is True
    assert by_name["nmap"].integration_state is IntegrationState.WORKER_READY
    assert by_name["nuclei"].installed is False
    assert by_name["password_test"].installed is None
    assert get_tool(" NMAP ") == get_tool("nmap")
