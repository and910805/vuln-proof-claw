"""End-to-end API coverage for the passive URL assessment preview."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from httpx import ASGITransport, AsyncClient

from tests.api.test_approvals import (
    APPROVER_HEADERS,
    OPERATOR_HEADERS,
    authenticated_client,
    authenticated_settings,
)
from tests.api.test_workflow import _create_engagement
from vuln_proof_claw.api.app import create_app
from vuln_proof_claw.config.models import AssessmentConfig
from vuln_proof_claw.execution.http_capture import (
    CaptureTransportError,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureResponse,
)
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.session import create_engine


class FakeAssessmentTransport:
    identity = "test-pinned-http/v1"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[HttpCaptureRequest, HttpCaptureLimits]] = []

    def send(
        self, request: HttpCaptureRequest, limits: HttpCaptureLimits
    ) -> HttpCaptureResponse:
        self.calls.append((request, limits))
        if self.fail:
            raise CaptureTransportError("test_transport_failed")
        return HttpCaptureResponse(
            status_code=200,
            final_target=request.target,
            headers=(
                ("Content-Type", "text/html"),
                ("Server", "nginx/1.24.0"),
                ("Set-Cookie", "sessionid=secret; Path=/"),
            ),
            body=b"<!doctype html><title>Target</title>",
            duration_ms=12,
        )


@asynccontextmanager
async def assessment_client(
    database_path: Path,
    transport: FakeAssessmentTransport,
) -> AsyncIterator[AsyncClient]:
    settings = authenticated_settings(database_path).model_copy(
        update={"assessment": AssessmentConfig(enabled=True)}
    )
    engine = create_engine(settings.database.url.get_secret_value())
    Base.metadata.create_all(engine)
    engine.dispose()
    app = create_app(settings, assessment_transport_factory=lambda _scope: transport)
    async with app.router.lifespan_context(app), AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


async def test_assessment_creates_evidence_findings_report_and_audit_idempotently(
    tmp_path: Path,
) -> None:
    transport = FakeAssessmentTransport()
    async with assessment_client(tmp_path / "assessment.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        endpoint = f"/api/v1/engagements/{engagement_id}/assessments"
        missing_key = await client.post(
            endpoint,
            json={"target": "https://api.example.test/v1"},
        )
        blank_key = await client.post(
            endpoint,
            json={"target": "https://api.example.test/v1"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "   "},
        )
        headers = {**OPERATOR_HEADERS, "Idempotency-Key": "baseline-root"}
        created = await client.post(
            endpoint,
            json={"target": "https://api.example.test/v1"},
            headers=headers,
        )
        replay = await client.post(
            endpoint,
            json={"target": "https://api.example.test/v1"},
            headers=headers,
        )
        fetched = await client.get(
            f"{endpoint}/{created.json()['action_id']}",
            headers=OPERATOR_HEADERS,
        )
        conflict = await client.post(
            endpoint,
            json={"target": "https://api.example.test/v1/users"},
            headers=headers,
        )
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report",
            headers=OPERATOR_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events",
            headers=OPERATOR_HEADERS,
        )
        dashboard = await client.get("/api/v1/dashboard/summary", headers=OPERATOR_HEADERS)

    assert missing_key.status_code == 422
    assert blank_key.status_code == 422
    assert blank_key.json()["detail"] == "idempotency_key_must_not_be_blank"
    assert created.status_code == 201
    assert created.json()["state"] == "succeeded"
    assert len(created.json()["evidence_ids"]) == 1
    assert created.json()["findings_count"] == 8
    assert created.json()["report_url"].endswith("/report")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["action_id"] == created.json()["action_id"]
    assert fetched.status_code == 200
    assert fetched.json()["finding_ids"] == created.json()["finding_ids"]
    assert conflict.status_code == 409
    assert len(transport.calls) == 1
    assert report.json()["counts"] == {"actions": 1, "evidence": 1, "findings": 8}
    assert dashboard.json()["execution_available"] is True
    event_types = [item["event_type"] for item in audit.json()["items"]]
    assert event_types[:2] == ["assessment.completed", "assessment.created"]


async def test_assessment_rejects_wrong_role_scope_and_disabled_execution(tmp_path: Path) -> None:
    transport = FakeAssessmentTransport()
    async with assessment_client(tmp_path / "denied.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        endpoint = f"/api/v1/engagements/{engagement_id}/assessments"
        wrong_role = await client.post(
            endpoint,
            json={"target": "https://api.example.test/v1"},
            headers={**APPROVER_HEADERS, "Idempotency-Key": "wrong-role"},
        )
        outside_scope = await client.post(
            endpoint,
            json={"target": "https://other.example.test/"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "outside"},
        )

    assert wrong_role.status_code == 401
    assert outside_scope.status_code == 201
    assert outside_scope.json()["state"] == "denied"
    assert len(transport.calls) == 0

    async with authenticated_client(tmp_path / "disabled.db") as client:
        disabled = await client.post(
            "/api/v1/engagements/00000000-0000-7000-8000-000000000001/assessments",
            json={"target": "https://example.test/"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "disabled"},
        )
    assert disabled.status_code == 503
    assert disabled.json()["detail"] == "assessment_execution_not_ready"


async def test_assessment_commits_safe_failed_state_when_transport_fails(tmp_path: Path) -> None:
    transport = FakeAssessmentTransport(fail=True)
    async with assessment_client(tmp_path / "failed.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        response = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": "https://api.example.test/v1"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "failure"},
        )
        replay = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": "https://api.example.test/v1"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "failure"},
        )
        fetched = await client.get(
            f"/api/v1/engagements/{engagement_id}/assessments/{response.json()['action_id']}",
            headers=OPERATOR_HEADERS,
        )
        actions = await client.get(
            f"/api/v1/engagements/{engagement_id}/actions",
            headers=OPERATOR_HEADERS,
        )

    assert response.status_code == 201
    assert response.json()["state"] == "failed"
    assert response.json()["error_code"] == "test_transport_failed"
    assert response.json()["evidence_ids"] == []
    assert replay.status_code == 200
    assert replay.json()["error_code"] == "test_transport_failed"
    assert fetched.json()["error_code"] == "test_transport_failed"
    assert len(transport.calls) == 1
    assert actions.json()["items"][0]["state"] == "failed"
