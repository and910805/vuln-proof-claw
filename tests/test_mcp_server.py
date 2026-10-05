"""Tests for the stdio MCP adapter that Claude Code talks to.

This is the whole integration surface, so the tests exercise it the way a
client does: real JSON-RPC messages in, real HTTP requests out through a mock
transport, and no listening API anywhere.
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from vuln_proof_claw.mcp_server import (
    TOOLS,
    ProofClawApiClient,
    handle_message,
    main,
)

ENGAGEMENT = "eng-1"


class Recorder:
    """Collect the requests the adapter makes and answer them."""

    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[httpx.Request] = []
        self._responder = responder

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return self._responder(request)

        return httpx.MockTransport(handler)


def json_ok(payload: Any) -> Callable[[httpx.Request], httpx.Response]:
    def responder(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    return responder


def client_for(
    responder: Callable[[httpx.Request], httpx.Response],
    monkeypatch: pytest.MonkeyPatch,
    *,
    url: str | None = None,
    token: str | None = None,
) -> tuple[ProofClawApiClient, Recorder]:
    monkeypatch.delenv("PROOFCLAW_API_URL", raising=False)
    monkeypatch.delenv("PROOFCLAW_API_TOKEN", raising=False)
    if url is not None:
        monkeypatch.setenv("PROOFCLAW_API_URL", url)
    if token is not None:
        monkeypatch.setenv("PROOFCLAW_API_TOKEN", token)
    recorder = Recorder(responder)
    return ProofClawApiClient(transport=recorder.transport()), recorder


def call(client: ProofClawApiClient, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    response = handle_message(message, client)
    assert response is not None
    return response


def test_the_default_base_url_is_local(monkeypatch: pytest.MonkeyPatch) -> None:
    client, recorder = client_for(json_ok({"status": "ready"}), monkeypatch)
    client.call_tool("proofclaw_health", {})
    assert str(recorder.requests[0].url) == "http://127.0.0.1:8000/api/v1/health/ready"


def test_a_trailing_slash_in_the_configured_url_is_not_doubled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, recorder = client_for(
        json_ok({"status": "ready"}), monkeypatch, url="http://api.test:9000/"
    )
    client.call_tool("proofclaw_health", {})
    assert str(recorder.requests[0].url) == "http://api.test:9000/api/v1/health/ready"


def test_a_configured_token_becomes_a_bearer_header(monkeypatch: pytest.MonkeyPatch) -> None:
    client, recorder = client_for(json_ok({}), monkeypatch, token="s3cret")  # noqa: S106 - fixture value
    client.call_tool("proofclaw_health", {})
    assert recorder.requests[0].headers["authorization"] == "Bearer s3cret"


def test_no_token_means_no_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    client, recorder = client_for(json_ok({}), monkeypatch)
    client.call_tool("proofclaw_health", {})
    assert "authorization" not in recorder.requests[0].headers


def test_an_assessment_carries_the_idempotency_key(monkeypatch: pytest.MonkeyPatch) -> None:
    client, recorder = client_for(json_ok({"action_id": "a-1"}), monkeypatch)
    client.call_tool(
        "proofclaw_run_assessment",
        {
            "engagement_id": ENGAGEMENT,
            "target": "https://example.test",
            "idempotency_key": "key-1",
            "mode": "active-safe",
            "preset": "deep",
        },
    )
    request = recorder.requests[0]
    assert request.method == "POST"
    assert request.url.path == f"/api/v1/engagements/{ENGAGEMENT}/assessments"
    assert request.headers["idempotency-key"] == "key-1"
    assert json.loads(request.content) == {
        "target": "https://example.test",
        "mode": "active-safe",
        "preset": "deep",
    }


def test_an_assessment_defaults_to_the_passive_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    # The safer mode has to be the default when the caller leaves it out.
    client, recorder = client_for(json_ok({}), monkeypatch)
    client.call_tool(
        "proofclaw_run_assessment",
        {"engagement_id": ENGAGEMENT, "target": "https://example.test", "idempotency_key": "k"},
    )
    body = json.loads(recorder.requests[0].content)
    assert body["mode"] == "passive"
    assert body["preset"] == "standard"


def test_an_assessment_without_an_idempotency_key_is_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, recorder = client_for(json_ok({}), monkeypatch)
    response = call(
        client,
        "proofclaw_run_assessment",
        {"engagement_id": ENGAGEMENT, "target": "https://example.test"},
    )
    assert response["result"]["isError"] is True
    assert recorder.requests == []


def test_an_automation_plan_does_not_repeat_the_engagement_in_the_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, recorder = client_for(json_ok({"tasks": []}), monkeypatch)
    client.call_tool(
        "proofclaw_create_automation_plan",
        {
            "engagement_id": ENGAGEMENT,
            "target": "https://example.test",
            "checks": ["cors"],
            "review_reason": "requested",
        },
    )
    body = json.loads(recorder.requests[0].content)
    assert "engagement_id" not in body
    assert body["checks"] == ["cors"]


def test_getting_one_assessment_uses_its_action_id(monkeypatch: pytest.MonkeyPatch) -> None:
    client, recorder = client_for(json_ok({"state": "succeeded"}), monkeypatch)
    client.call_tool(
        "proofclaw_get_assessment",
        {"engagement_id": ENGAGEMENT, "action_id": "act-9"},
    )
    assert recorder.requests[0].url.path.endswith(f"/{ENGAGEMENT}/assessments/act-9")


def test_listing_findings_reduces_the_report(monkeypatch: pytest.MonkeyPatch) -> None:
    report = {"engagement_id": ENGAGEMENT, "findings": [{"title": "traversal"}], "extra": "noise"}
    client, _ = client_for(json_ok(report), monkeypatch)
    result = client.call_tool("proofclaw_list_findings", {"engagement_id": ENGAGEMENT})
    assert result == {"engagement_id": ENGAGEMENT, "findings": [{"title": "traversal"}]}


def test_listing_findings_survives_a_report_without_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = client_for(json_ok({"engagement_id": ENGAGEMENT}), monkeypatch)
    result = client.call_tool("proofclaw_list_findings", {"engagement_id": ENGAGEMENT})
    assert result == {"engagement_id": ENGAGEMENT, "findings": []}


def test_an_unknown_tool_is_refused_without_calling_the_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Rejecting only after fetching meant an unrecognised name still reached
    # the control plane.
    client, recorder = client_for(json_ok({}), monkeypatch)
    with pytest.raises(ValueError, match="unknown tool"):
        client.call_tool("proofclaw_delete_everything", {"engagement_id": ENGAGEMENT})
    assert recorder.requests == []


def test_an_api_error_status_is_raised_with_its_body(monkeypatch: pytest.MonkeyPatch) -> None:
    def responder(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"detail": "scope denied"})

    client, _ = client_for(responder, monkeypatch)
    with pytest.raises(RuntimeError, match="409"):
        client.call_tool("proofclaw_health", {})


def test_a_non_json_error_body_is_still_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def responder(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="<html>gateway</html>")

    client, _ = client_for(responder, monkeypatch)
    with pytest.raises(RuntimeError, match="gateway"):
        client.call_tool("proofclaw_health", {})


def test_a_redirect_is_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Following one would let the control plane's answer be replaced by
    # whatever the redirect target chooses to return.
    def responder(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://elsewhere.test/"})

    client, recorder = client_for(responder, monkeypatch)
    with pytest.raises(RuntimeError, match="302"):
        client.call_tool("proofclaw_health", {})
    assert len(recorder.requests) == 1


def test_an_unreachable_api_is_a_tool_error_not_a_dead_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client, _ = client_for(responder, monkeypatch)
    response = call(client, "proofclaw_health", {})
    assert response["result"]["isError"] is True
    assert "connection refused" in response["result"]["content"][0]["text"]


def test_initialize_echoes_the_requested_protocol_version() -> None:
    client = ProofClawApiClient(transport=httpx.MockTransport(lambda _r: httpx.Response(200)))
    response = handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1.2.3"}},
        client,
    )
    assert response is not None
    assert response["result"]["protocolVersion"] == "1.2.3"
    assert "scope" in response["result"]["instructions"]


def test_initialize_without_params_still_answers() -> None:
    client = ProofClawApiClient(transport=httpx.MockTransport(lambda _r: httpx.Response(200)))
    response = handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, client)
    assert response is not None
    assert response["result"]["serverInfo"]["name"] == "vuln-proof-claw"


def test_the_initialized_notification_gets_no_reply() -> None:
    client = ProofClawApiClient(transport=httpx.MockTransport(lambda _r: httpx.Response(200)))
    assert handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}, client) is None


def test_ping_is_answered_with_an_empty_result() -> None:
    client = ProofClawApiClient(transport=httpx.MockTransport(lambda _r: httpx.Response(200)))
    response = handle_message({"jsonrpc": "2.0", "id": 4, "method": "ping"}, client)
    assert response == {"jsonrpc": "2.0", "id": 4, "result": {}}


def test_the_advertised_tool_surface_is_pinned() -> None:
    # A count would go red without saying which tool moved. Pinning the names
    # means removing a tool, or shipping one the dispatch does not know, is a
    # readable failure rather than an off-by-one.
    assert {str(tool["name"]) for tool in TOOLS} == {
        "proofclaw_health",
        "proofclaw_run_assessment",
        "proofclaw_create_automation_plan",
        "proofclaw_list_tools",
        "proofclaw_create_tool_plan",
        "proofclaw_next_autonomous_step",
        "proofclaw_get_assessment",
        "proofclaw_get_report",
        "proofclaw_list_findings",
    }


def test_every_advertised_tool_has_a_closed_schema() -> None:
    for tool in TOOLS:
        schema = tool["inputSchema"]
        assert schema["additionalProperties"] is False, tool["name"]
        assert tool["description"]


def test_the_advertised_tools_match_what_the_client_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = client_for(json_ok({"findings": []}), monkeypatch)
    for tool in TOOLS:
        arguments = {"engagement_id": ENGAGEMENT}
        for required in tool["inputSchema"].get("required", []):
            arguments.setdefault(required, "placeholder")
        client.call_tool(str(tool["name"]), arguments)


def test_an_unknown_method_with_an_id_gets_method_not_found() -> None:
    client = ProofClawApiClient(transport=httpx.MockTransport(lambda _r: httpx.Response(200)))
    response = handle_message({"jsonrpc": "2.0", "id": 9, "method": "resources/list"}, client)
    assert response is not None
    assert response["error"]["code"] == -32601


def test_an_unknown_notification_gets_no_reply() -> None:
    client = ProofClawApiClient(transport=httpx.MockTransport(lambda _r: httpx.Response(200)))
    assert handle_message({"jsonrpc": "2.0", "method": "resources/changed"}, client) is None


def test_main_answers_line_by_line_and_survives_bad_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PROOFCLAW_API_URL", raising=False)
    monkeypatch.delenv("PROOFCLAW_API_TOKEN", raising=False)
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        "{not json",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n".join(lines) + "\n"))
    written = io.StringIO()
    monkeypatch.setattr(sys, "stdout", written)

    main()

    replies = [json.loads(line) for line in written.getvalue().splitlines()]
    # The notification is silent, so three messages produce three replies.
    assert [reply.get("id") for reply in replies] == [1, None, 2]
    assert replies[1]["error"]["code"] == -32700
    assert len(replies[2]["result"]["tools"]) == len(TOOLS)


def test_a_successful_call_returns_both_text_and_structured_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This is what the caller actually receives on success: the same payload
    # twice, once as text for display and once structured for a program.
    report = {"engagement_id": ENGAGEMENT, "findings": [{"title": "traversal"}]}
    client, _ = client_for(json_ok(report), monkeypatch)
    response = call(client, "proofclaw_get_report", {"engagement_id": ENGAGEMENT})

    result = response["result"]
    assert "isError" not in result
    assert result["structuredContent"] == report
    assert json.loads(result["content"][0]["text"]) == report


def test_the_text_form_is_stable_for_diffing(monkeypatch: pytest.MonkeyPatch) -> None:
    # Keys are sorted so two runs of the same engagement produce comparable text.
    client, _ = client_for(json_ok({"b": 2, "a": 1}), monkeypatch)
    response = call(client, "proofclaw_get_report", {"engagement_id": ENGAGEMENT})
    assert response["result"]["content"][0]["text"] == '{"a": 1, "b": 2}'
