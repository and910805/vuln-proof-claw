from __future__ import annotations

from pathlib import Path

from tests.api.test_console import console_client
from tests.api.test_workflow import _create_engagement
from vuln_proof_claw.tooling.registry import IntegrationState, get_tool


async def test_automation_plan_creates_role_separated_audited_actions(tmp_path: Path) -> None:
    async with console_client(tmp_path / "automation.db") as client:
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/automation-plans",
            json={
                "target": "https://api.example.test/v1/users/7?limit=10",
                "checks": ["cors", "authentication", "authorization", "input_validation"],
                "mutations": [
                    {"location": "query", "name": "limit", "strategy": "boundary"}
                ],
                "review_reason": "Review documented inputs",
            },
        )
        audit = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")

    assert created.status_code == 201
    assert created.json()["planner"] == "deterministic-planner-v1"
    assert created.json()["verifier"] == "deterministic-verifier-v1"
    assert len(created.json()["actions"]) == 4
    assert len(created.json()["mutation_plan_digest"]) == 64
    assert audit.json()["items"][0]["event_type"] == "automation.plan_created"


async def test_verifier_flags_cors_and_requires_reviewed_input_mutations(tmp_path: Path) -> None:
    digest = "a" * 64
    async with console_client(tmp_path / "verifier.db") as client:
        engagement_id = await _create_engagement(client)
        rejected = await client.post(
            f"/api/v1/engagements/{engagement_id}/automation-plans",
            json={
                "target": "https://api.example.test/v1",
                "checks": ["input_validation"],
            },
        )
        verified = await client.post(
            "/api/v1/automation/verify",
            json={
                "check": "cors",
                "supplied_origin": "https://origin.example.test",
                "baseline": {
                    "status_code": 200,
                    "headers": {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": "true",
                    },
                    "body_digest": digest,
                    "body_size": 12,
                },
            },
        )

    assert rejected.status_code == 422
    assert rejected.json()["detail"] == "input_validation_requires_reviewed_mutations"
    assert verified.json()["outcome"] == "candidate"
    assert verified.json()["verifier"] == "deterministic-verifier-v1"


async def test_tool_catalog_and_policy_bound_tool_plans(tmp_path: Path) -> None:
    async with console_client(tmp_path / "tool-plans.db") as client:
        engagement_id = await _create_engagement(client, auto_execute_l1=True)
        catalog = await client.get("/api/v1/automation/tools")
        nmap = await client.post(
            f"/api/v1/engagements/{engagement_id}/tool-plans",
            json={
                "tool": "nmap",
                "target": "https://api.example.test/v1",
                "parameters": {"ports": [443], "timeout_seconds": 60},
                "idempotency_key": "nmap-api-v1",
            },
        )
        poc = await client.post(
            f"/api/v1/engagements/{engagement_id}/tool-plans",
            json={
                "tool": "exploit_poc",
                "target": "https://api.example.test/v1",
                "parameters": {
                    "poc_id": "registry://poc/CVE-2026-12345",
                    "artifact_sha256": "a" * 64,
                    "cve": "CVE-2026-12345",
                    "success_signal": "reviewed-marker",
                },
                "idempotency_key": "poc-review-v1",
            },
        )
        # sqlmap stands in for a tool that is catalogued but has no adapter.
        # nuclei used to play this part and no longer can: wiring it made the
        # case pass for the wrong reason. Any still-CATALOGED name works, and
        # the assertion below pins the state so this cannot rot silently again.
        stand_in = get_tool("sqlmap")
        assert stand_in is not None
        assert stand_in.integration_state is IntegrationState.CATALOGED
        unavailable = await client.post(
            f"/api/v1/engagements/{engagement_id}/tool-plans",
            json={
                "tool": "sqlmap",
                "target": "https://api.example.test/v1",
                "parameters": {},
                "idempotency_key": "sqlmap-v1",
            },
        )
        autonomous = await client.post(
            "/api/v1/automation/next-step",
            json={"pending_approvals": 1, "queued_actions": 2},
        )

    names = {item["name"] for item in catalog.json()["tools"]}
    assert catalog.status_code == 200
    assert {"shell_command", "python_execute", "nmap", "password_test", "exploit_poc"} <= names
    assert nmap.status_code == 201
    assert nmap.json()["state"] == "queued"
    assert nmap.json()["risk_level"] == "L1"
    assert poc.status_code == 201
    assert poc.json()["state"] == "pending_approval"
    assert unavailable.status_code == 409
    assert unavailable.json()["detail"] == "tool_adapter_not_ready"
    assert autonomous.json()["decision"] == "wait_for_approval"
