"""Integration coverage for the control-plane workflow API."""

from __future__ import annotations

from pathlib import Path

from httpx import AsyncClient

from tests.api.test_console import console_client


async def _create_engagement(
    client: AsyncClient,
    *,
    maximum_risk: str = "L3",
    auto_execute_l1: bool = False,
) -> str:
    project = await client.post("/api/v1/projects", json={"name": "Acme"})
    engagement = await client.post(
        f"/api/v1/projects/{project.json()['id']}/engagements",
        json={
            "name": "Authorized assessment",
            "starts_at": "2026-08-01T00:00:00Z",
            "ends_at": "2027-08-02T00:00:00Z",
            "maximum_risk": maximum_risk,
            "auto_execute_l1": auto_execute_l1,
            "scope": {
                "allowed_hostnames": ["api.example.test"],
                "allowed_ports": [443],
                "allowed_schemes": ["https"],
                "allowed_paths": ["/v1"],
                "denied_paths": ["/v1/admin"],
            },
        },
    )
    assert engagement.status_code == 201
    return str(engagement.json()["id"])


async def _create_task(client: AsyncClient, engagement_id: str) -> tuple[str, str]:
    flow = await client.post(
        f"/api/v1/engagements/{engagement_id}/flows",
        json={"objective": "  Inventory public API endpoints  "},
    )
    task = await client.post(
        f"/api/v1/flows/{flow.json()['id']}/tasks",
        json={"title": "  Capture the API root  "},
    )
    assert flow.status_code == 201
    assert task.status_code == 201
    return str(flow.json()["id"]), str(task.json()["id"])


async def test_workflow_can_be_created_queried_and_audited(tmp_path: Path) -> None:
    async with console_client(tmp_path / "workflow.db") as client:
        engagement_id = await _create_engagement(client)
        flow_id, task_id = await _create_task(client, engagement_id)
        created = await client.post(
            f"/api/v1/tasks/{task_id}/http-actions",
            json={
                "action_type": "Public Page Read",
                "method": "GET",
                "target": "HTTPS://API.EXAMPLE.TEST:443/v1",
                "headers": {"Accept": "application/json"},
                "idempotency_key": "capture-api-root-v1",
            },
        )
        flows = await client.get(f"/api/v1/engagements/{engagement_id}/flows")
        tasks = await client.get(f"/api/v1/flows/{flow_id}/tasks")
        actions = await client.get(f"/api/v1/engagements/{engagement_id}/actions")
        fetched = await client.get(f"/api/v1/actions/{created.json()['id']}")
        audit = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")
        dashboard = await client.get("/api/v1/dashboard/summary")
        report = await client.get(f"/api/v1/engagements/{engagement_id}/report")

    assert created.status_code == 201
    assert created.json()["action_type"] == "public_page_read"
    assert created.json()["normalized_target"] == "https://api.example.test:443/v1"
    assert created.json()["risk_level"] == "L0"
    assert created.json()["state"] == "queued"
    assert created.json()["policy_reason"] == "automatic_policy_allow"
    assert created.json()["requires_dns_recheck"] is True
    assert flows.json()["items"][0]["objective"] == "Inventory public API endpoints"
    assert tasks.json()["items"][0]["title"] == "Capture the API root"
    assert actions.json()["total"] == 1
    assert actions.json()["items"][0]["id"] == created.json()["id"]
    assert fetched.json()["id"] == created.json()["id"]
    assert audit.json()["total"] == 4
    assert [item["event_type"] for item in audit.json()["items"]] == [
        "policy.decision",
        "action.proposed",
        "task.created",
        "flow.created",
    ]
    assert audit.json()["items"][0]["payload"]["reason"] == "automatic_policy_allow"
    assert dashboard.json()["counts"]["active_actions"] == 1
    assert report.json()["counts"]["actions"] == 1


async def test_action_idempotency_replays_exact_request_and_rejects_drift(
    tmp_path: Path,
) -> None:
    action = {
        "action_type": "public_page_read",
        "target": "https://api.example.test/v1",
        "idempotency_key": "same-operation",
    }
    async with console_client(tmp_path / "idempotency.db") as client:
        engagement_id = await _create_engagement(client)
        _, task_id = await _create_task(client, engagement_id)
        first = await client.post(f"/api/v1/tasks/{task_id}/http-actions", json=action)
        replay = await client.post(f"/api/v1/tasks/{task_id}/http-actions", json=action)
        action["target"] = "https://api.example.test/v1/users"
        conflict = await client.post(f"/api/v1/tasks/{task_id}/http-actions", json=action)
        audit = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")

    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "idempotency_key_conflict"
    assert audit.json()["total"] == 4


async def test_policy_persists_denied_and_approval_required_outcomes(tmp_path: Path) -> None:
    async with console_client(tmp_path / "policy-outcomes.db") as client:
        engagement_id = await _create_engagement(client, maximum_risk="L2")
        _, task_id = await _create_task(client, engagement_id)
        denied = await client.post(
            f"/api/v1/tasks/{task_id}/http-actions",
            json={
                "action_type": "public_page_read",
                "target": "https://api.example.test/v1/admin",
                "idempotency_key": "denied-path",
            },
        )
        pending = await client.post(
            f"/api/v1/tasks/{task_id}/http-actions",
            json={
                "action_type": "exploit_attempt",
                "target": "https://api.example.test/v1/users",
                "idempotency_key": "approval-needed",
            },
        )
        permanent = await client.post(
            f"/api/v1/tasks/{task_id}/http-actions",
            json={
                "action_type": "cover_tracks",
                "target": "https://api.example.test/v1",
                "idempotency_key": "permanent-deny",
            },
        )

    assert denied.status_code == 201
    assert denied.json()["state"] == "denied"
    assert denied.json()["policy_reason"] == "path_denied"
    assert pending.json()["state"] == "pending_approval"
    assert pending.json()["policy_reason"] == "explicit_approval_required"
    assert permanent.json()["state"] == "denied"
    assert permanent.json()["policy_reason"] == "system_permanent_deny"


async def test_workflow_rejects_missing_parents_and_unsafe_http_headers(tmp_path: Path) -> None:
    async with console_client(tmp_path / "workflow-validation.db") as client:
        missing_flow = await client.post(
            "/api/v1/engagements/01999999-9999-7999-8999-999999999999/flows",
            json={"objective": "test"},
        )
        engagement_id = await _create_engagement(client)
        _, task_id = await _create_task(client, engagement_id)
        unsafe = await client.post(
            f"/api/v1/tasks/{task_id}/http-actions",
            json={
                "action_type": "public_page_read",
                "target": "https://api.example.test/v1",
                "headers": {"Authorization": "Bearer secret"},
                "idempotency_key": "unsafe-header",
            },
        )

    assert missing_flow.status_code == 404
    assert unsafe.status_code == 422
    assert unsafe.json()["detail"] == "request header is not allowed: authorization"
