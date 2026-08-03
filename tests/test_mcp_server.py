from __future__ import annotations

from typing import Any

from vuln_proof_claw.mcp_server import ProofClawApiClient, handle_message


class FakeClient(ProofClawApiClient):
    def __init__(self) -> None:
        pass

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return {"name": name, "arguments": arguments}


def test_mcp_initializes_lists_tools_and_returns_structured_content() -> None:
    client = FakeClient()
    initialized = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
        client,
    )
    listed = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, client)
    called = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "proofclaw_health", "arguments": {}},
        },
        client,
    )

    assert initialized is not None
    assert initialized["result"]["serverInfo"]["name"] == "vuln-proof-claw"
    assert listed is not None
    assert len(listed["result"]["tools"]) == 9
    assert {
        "proofclaw_list_tools",
        "proofclaw_create_tool_plan",
        "proofclaw_next_autonomous_step",
    } <= {tool["name"] for tool in listed["result"]["tools"]}
    assert called is not None
    assert called["result"]["structuredContent"]["name"] == "proofclaw_health"
