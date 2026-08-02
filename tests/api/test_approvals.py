"""Authentication, approval-decision, and cancellation API coverage."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from tests.api.test_console import console_client
from tests.api.test_workflow import _create_engagement, _create_task
from vuln_proof_claw.api.app import create_app
from vuln_proof_claw.config.models import ApiConfig, DatabaseConfig, WebConfig
from vuln_proof_claw.config.settings import Settings
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.session import create_engine

OPERATOR_TOKEN = "operator-token-00000000000000000001"  # noqa: S105 - test credential
APPROVER_TOKEN = "approver-token-00000000000000000001"  # noqa: S105 - test credential
EVIDENCE_READER_TOKEN = "evidence-reader-00000000000000000001"  # noqa: S105
OPERATOR_HEADERS = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}
APPROVER_HEADERS = {"Authorization": f"Bearer {APPROVER_TOKEN}"}
EVIDENCE_READER_HEADERS = {"Authorization": f"Bearer {EVIDENCE_READER_TOKEN}"}


def authenticated_settings(database_path: Path) -> Settings:
    return Settings(
        api=ApiConfig(
            authentication_ready=True,
            operator_identity="operator@example.test",
            approver_identity="security-lead@example.test",
            evidence_reader_identity="evidence-reader@example.test",
            operator_token=SecretStr(OPERATOR_TOKEN),
            approver_token=SecretStr(APPROVER_TOKEN),
            evidence_reader_token=SecretStr(EVIDENCE_READER_TOKEN),
        ),
        database=DatabaseConfig(url=SecretStr(f"sqlite:///{database_path}")),
        web=WebConfig(enabled=False),
    )


@asynccontextmanager
async def authenticated_client(database_path: Path) -> AsyncIterator[AsyncClient]:
    settings = authenticated_settings(database_path)
    engine = create_engine(settings.database.url.get_secret_value())
    Base.metadata.create_all(engine)
    engine.dispose()
    app = create_app(settings)
    async with app.router.lifespan_context(app), AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


async def _pending_action(client: AsyncClient) -> tuple[str, str]:
    client.headers.update(OPERATOR_HEADERS)
    engagement_id = await _create_engagement(client, maximum_risk="L2")
    _, task_id = await _create_task(client, engagement_id)
    response = await client.post(
        f"/api/v1/tasks/{task_id}/http-actions",
        json={
            "action_type": "exploit_attempt",
            "target": "https://api.example.test/v1/users",
            "idempotency_key": f"approval-{task_id}",
        },
    )
    assert response.status_code == 201
    assert response.json()["state"] == "pending_approval"
    return engagement_id, str(response.json()["id"])


async def test_authentication_protects_api_and_separates_roles(tmp_path: Path) -> None:
    async with authenticated_client(tmp_path / "auth.db") as client:
        health = await client.get("/api/v1/health/live")
        anonymous = await client.get("/api/v1/projects")
        operator_create = await client.post(
            "/api/v1/projects",
            json={"name": "Operator project"},
            headers=OPERATOR_HEADERS,
        )
        approver_read = await client.get("/api/v1/projects", headers=APPROVER_HEADERS)
        approver_create = await client.post(
            "/api/v1/projects",
            json={"name": "Unauthorized mutation"},
            headers=APPROVER_HEADERS,
        )
        evidence_reader_create = await client.post(
            "/api/v1/projects",
            json={"name": "Unauthorized evidence-reader mutation"},
            headers=EVIDENCE_READER_HEADERS,
        )

    assert health.status_code == 200
    assert anonymous.status_code == 401
    assert anonymous.headers["www-authenticate"] == "Bearer"
    assert operator_create.status_code == 201
    assert approver_read.status_code == 200
    assert approver_create.status_code == 401
    assert approver_create.json()["detail"] == "operator_authentication_required"
    assert evidence_reader_create.status_code == 401
    assert evidence_reader_create.json()["detail"] == "operator_authentication_required"


async def test_approver_can_grant_single_use_bound_approval(tmp_path: Path) -> None:
    async with authenticated_client(tmp_path / "approve.db") as client:
        engagement_id, action_id = await _pending_action(client)
        operator_attempt = await client.post(
            f"/api/v1/actions/{action_id}/approval-decision",
            json={"decision": "approve"},
            headers=OPERATOR_HEADERS,
        )
        approved = await client.post(
            f"/api/v1/actions/{action_id}/approval-decision",
            json={"decision": "approve", "reason": "Authorized validation"},
            headers=APPROVER_HEADERS,
        )
        approval = await client.get(
            f"/api/v1/actions/{action_id}/approval",
            headers=APPROVER_HEADERS,
        )
        replay = await client.post(
            f"/api/v1/actions/{action_id}/approval-decision",
            json={"decision": "approve"},
            headers=APPROVER_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events",
            headers=OPERATOR_HEADERS,
        )

    assert operator_attempt.status_code == 401
    assert approved.status_code == 200
    assert approved.json()["state"] == "queued"
    assert approved.json()["approval"]["permitted_executions"] == 1
    assert approved.json()["approval"]["consumed_executions"] == 0
    assert approved.json()["approval"]["approver"] == "security-lead@example.test"
    assert approval.json() == approved.json()["approval"]
    assert replay.status_code == 409
    assert replay.json()["detail"] == "action_not_pending_approval"
    assert audit.json()["items"][0]["event_type"] == "approval.granted"
    assert audit.json()["items"][0]["actor"] == "security-lead@example.test"
    proposed = next(
        item for item in audit.json()["items"] if item["event_type"] == "action.proposed"
    )
    assert proposed["actor"] == "operator@example.test"


async def test_approver_can_deny_and_operator_can_cancel(tmp_path: Path) -> None:
    async with authenticated_client(tmp_path / "deny-cancel.db") as client:
        engagement_id, denied_action_id = await _pending_action(client)
        denied = await client.post(
            f"/api/v1/actions/{denied_action_id}/approval-decision",
            json={"decision": "deny", "reason": "Too invasive"},
            headers=APPROVER_HEADERS,
        )
        cancel_engagement_id, cancellable_id = await _pending_action(client)
        approver_cancel = await client.post(
            f"/api/v1/actions/{cancellable_id}/cancel",
            json={"reason": "wrong role"},
            headers=APPROVER_HEADERS,
        )
        cancelled = await client.post(
            f"/api/v1/actions/{cancellable_id}/cancel",
            json={"reason": "Objective changed"},
            headers=OPERATOR_HEADERS,
        )
        cancel_replay = await client.post(
            f"/api/v1/actions/{cancellable_id}/cancel",
            json={},
            headers=OPERATOR_HEADERS,
        )
        denial_audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events",
            headers=OPERATOR_HEADERS,
        )
        cancel_audit = await client.get(
            f"/api/v1/engagements/{cancel_engagement_id}/audit-events",
            headers=OPERATOR_HEADERS,
        )

    assert denied.status_code == 200
    assert denied.json()["state"] == "denied"
    assert approver_cancel.status_code == 401
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"
    assert cancel_replay.status_code == 409
    assert cancel_replay.json()["detail"] == "action_already_terminal"
    denial_events = [item["event_type"] for item in denial_audit.json()["items"]]
    cancel_events = [item["event_type"] for item in cancel_audit.json()["items"]]
    assert "approval.denied" in denial_events
    assert "action.cancelled" in cancel_events


async def test_approval_mutation_stays_disabled_without_authentication(tmp_path: Path) -> None:
    async with console_client(tmp_path / "local-approval.db") as client:
        response = await client.post(
            "/api/v1/actions/01999999-9999-7999-8999-999999999999/approval-decision",
            json={"decision": "approve"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "authentication_not_ready"


async def test_approval_preset_is_created_by_approver_and_applied_by_operator(
    tmp_path: Path,
) -> None:
    async with authenticated_client(tmp_path / "preset.db") as client:
        engagement_id, action_id = await _pending_action(client)
        preset = await client.post(
            f"/api/v1/engagements/{engagement_id}/approval-presets",
            json={
                "name": "Reviewed exploit validation",
                "action_types": ["exploit_attempt"],
                "target_prefixes": ["https://api.example.test/v1/"],
                "maximum_risk": "L2",
                "approval_ttl_seconds": 600,
            },
            headers=APPROVER_HEADERS,
        )
        duplicate = await client.post(
            f"/api/v1/engagements/{engagement_id}/approval-presets",
            json={
                "name": "Reviewed exploit validation",
                "action_types": ["exploit_attempt"],
                "target_prefixes": ["https://api.example.test/v1/"],
                "maximum_risk": "L2",
            },
            headers=APPROVER_HEADERS,
        )
        applied = await client.post(
            f"/api/v1/actions/{action_id}/apply-approval-preset",
            json={"preset_id": preset.json()["id"]},
            headers=OPERATOR_HEADERS,
        )
        listed = await client.get(
            f"/api/v1/engagements/{engagement_id}/approval-presets",
            headers=OPERATOR_HEADERS,
        )

    assert preset.status_code == 201
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "approval_preset_name_conflict"
    assert preset.json()["created_by"] == "security-lead@example.test"
    assert applied.status_code == 200
    assert applied.json()["state"] == "queued"
    assert applied.json()["approval"]["permitted_executions"] == 1
    assert listed.json()["total"] == 1
