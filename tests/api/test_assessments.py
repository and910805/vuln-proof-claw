"""End-to-end API coverage for the passive URL assessment preview."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tests.api.test_approvals import (
    APPROVER_HEADERS,
    OPERATOR_HEADERS,
    authenticated_client,
    authenticated_settings,
)
from tests.api.test_workflow import _create_engagement
from vuln_proof_claw.api.app import create_app
from vuln_proof_claw.config.models import AssessmentConfig
from vuln_proof_claw.domain.identifiers import ActionId, EvidenceId
from vuln_proof_claw.execution.http_capture import (
    CaptureTransportError,
    HttpCaptureCoordinator,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureResponse,
    HttpCaptureResult,
    capture_parameter_digest,
)
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.models import EvidencePayloadRecord, FindingRecord
from vuln_proof_claw.persistence.repositories import ActionRepository
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


class LinkedAssessmentTransport(FakeAssessmentTransport):
    def send(
        self, request: HttpCaptureRequest, limits: HttpCaptureLimits
    ) -> HttpCaptureResponse:
        self.calls.append((request, limits))
        links = {
            "/v1": '<a href="/v1/one">One</a><a href="/v1/two">Two</a>',
            "/v1/one": '<a href="/v1/three">Three</a>',
            "/v1/two": '<a href="/v1">Root</a>',
            "/v1/three": "<title>Done</title>",
        }
        path = request.target.removeprefix("https://api.example.test:443")
        return HttpCaptureResponse(
            status_code=200,
            final_target=request.target,
            headers=(("Content-Type", "text/html"),),
            body=links[path].encode(),
            duration_ms=2,
        )


class OpenApiAssessmentTransport(FakeAssessmentTransport):
    def send(
        self, request: HttpCaptureRequest, limits: HttpCaptureLimits
    ) -> HttpCaptureResponse:
        self.calls.append((request, limits))
        path = request.target.removeprefix("https://api.example.test:443")
        if path == "/v1/openapi.json":
            body = json.dumps(
                {
                    "openapi": "3.1.0",
                    "info": {"title": "Protected API"},
                    "servers": [{"url": "/v1"}],
                    "security": [{"bearerAuth": []}],
                    "paths": {
                        "/profile": {"get": {"operationId": "getProfile"}},
                        "/users": {"post": {"operationId": "createUser"}},
                    },
                }
            ).encode()
        else:
            body = b'{"name":"unexpectedly public"}'
        return HttpCaptureResponse(
            status_code=200,
            final_target=request.target,
            headers=(("Content-Type", "application/json"),),
            body=body,
            duration_ms=2,
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


async def test_the_report_discloses_each_finding_s_cwe_and_stated_basis(
    tmp_path: Path,
) -> None:
    """The two fields that make a shipped finding auditable rather than readable.

    ``cwe_id`` is what an external consumer keys on, and ``verification_method``
    is the claim's stated basis -- the domain refuses a HIGH or CRITICAL finding
    that never states one, so a report omitting it hides the guarantee. Both
    were stored and round-tripped for several versions without ever leaving the
    system, which no test noticed because every test read the database.
    """
    transport = FakeAssessmentTransport()
    async with assessment_client(tmp_path / "disclosure.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": "https://api.example.test/v1"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "disclosure"},
        )
        report = await client.get(f"/api/v1/engagements/{engagement_id}/report")

    findings = report.json()["findings"]
    assert findings
    for item in findings:
        assert item["cwe_id"] == item["vulnerability_class"], item["title"]
        assert item["cwe_id"].startswith("CWE-"), item["title"]
        assert item["verification_method"] == "observed", item["title"]


async def test_assessment_preserves_query_in_action_and_capture_metadata(tmp_path: Path) -> None:
    database_path = tmp_path / "query-assessment.db"
    transport = FakeAssessmentTransport()
    async with assessment_client(database_path, transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": "https://api.example.test/v1/items?page=2&sort=asc"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "query-assessment"},
        )

    assert created.status_code == 201
    assert created.json()["state"] == "succeeded"
    assert len(transport.calls) == 1
    request = transport.calls[0][0]
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        with Session(engine) as session:
            stored = ActionRepository(session).get(ActionId(created.json()["action_id"]))
            assert stored is not None
            action = stored.entity
            assert action.normalized_target == request.target
            assert action.query == request.query == "page=2&sort=asc"
            assert action.parameter_digest == capture_parameter_digest(request)
            payload = session.get(EvidencePayloadRecord, created.json()["evidence_ids"][0])
            assert payload is not None
            metadata = json.loads(payload.canonical_metadata)
            raw_capture = json.loads(payload.raw_content)
            assert metadata["normalized_parameters"]["query"] == action.query
            assert raw_capture["request"]["query"] == action.query
    finally:
        engine.dispose()


async def test_assessment_uses_persisted_capture_instead_of_returned_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class MisleadingCoordinator(HttpCaptureCoordinator):
        def capture(
            self,
            request: HttpCaptureRequest,
            *,
            limits: HttpCaptureLimits | None = None,
            at: datetime | None = None,
            evidence_id: EvidenceId | None = None,
        ) -> HttpCaptureResult:
            result = super().capture(request, limits=limits, at=at, evidence_id=evidence_id)
            assert result.response is not None
            return replace(
                result,
                response=HttpCaptureResponse(
                    status_code=503,
                    final_target=result.response.final_target,
                    headers=(("Content-Type", "text/plain"),),
                    body=b"temporary error",
                    duration_ms=1,
                ),
            )

    monkeypatch.setattr(
        "vuln_proof_claw.assessment.service.HttpCaptureCoordinator",
        MisleadingCoordinator,
    )
    async with assessment_client(
        tmp_path / "persisted-response.db", FakeAssessmentTransport()
    ) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": "https://api.example.test/v1"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "persisted-response"},
        )
        audit = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")

    assert created.status_code == 201
    assert created.json()["findings_count"] == 8
    completed = next(
        item for item in audit.json()["items"] if item["event_type"] == "assessment.completed"
    )
    assert completed["payload"]["status_code"] == 200


async def test_assessment_refuses_invalid_persisted_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class CorruptingCoordinator(HttpCaptureCoordinator):
        def capture(
            self,
            request: HttpCaptureRequest,
            *,
            limits: HttpCaptureLimits | None = None,
            at: datetime | None = None,
            evidence_id: EvidenceId | None = None,
        ) -> HttpCaptureResult:
            result = super().capture(request, limits=limits, at=at, evidence_id=evidence_id)
            assert result.evidence is not None
            row = self._session.get(EvidencePayloadRecord, result.evidence.metadata.evidence_id)
            assert row is not None
            row.raw_content = b"{}"
            row.raw_size = 2
            self._session.flush()
            return result

    monkeypatch.setattr(
        "vuln_proof_claw.assessment.service.HttpCaptureCoordinator",
        CorruptingCoordinator,
    )
    database_path = tmp_path / "invalid-capture.db"
    async with assessment_client(database_path, FakeAssessmentTransport()) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": "https://api.example.test/v1"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "invalid-capture"},
        )
        audit = await client.get(f"/api/v1/engagements/{engagement_id}/audit-events")

    assert created.status_code == 409
    assert created.json()["detail"] == "capture_validation_failed"
    event_types = {item["event_type"] for item in audit.json()["items"]}
    assert "assessment.validation_failed" in event_types
    assert "assessment.completed" not in event_types
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(FindingRecord)) == 0
    finally:
        engine.dispose()


async def test_assessment_creates_evidence_findings_report_and_audit_idempotently(  # noqa: PLR0915
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
        history = await client.get("/api/v1/assessments", headers=OPERATOR_HEADERS)
        project_history = await client.get(
            "/api/v1/assessments",
            params={"project_id": history.json()["items"][0]["project_id"], "limit": 1},
            headers=OPERATOR_HEADERS,
        )
        next_page = await client.get(
            "/api/v1/assessments",
            params={"limit": 1, "offset": 1},
            headers=OPERATOR_HEADERS,
        )
        empty_history = await client.get(
            "/api/v1/assessments",
            params={"project_id": "00000000-0000-7000-8000-000000000099"},
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
        report_md = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.md",
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
    assert history.status_code == 200
    assert history.json()["total"] == 1
    assert history.json()["items"][0] == {
        "action_id": created.json()["action_id"],
        "engagement_id": engagement_id,
        "project_id": project_history.json()["items"][0]["project_id"],
        "target": "https://api.example.test:443/v1",
        "state": "succeeded",
        "created_at": history.json()["items"][0]["created_at"],
        "completed_at": history.json()["items"][0]["completed_at"],
        "evidence_count": 1,
        "findings_count": 8,
        "error_code": None,
        "report_url": f"/api/v1/engagements/{engagement_id}/report",
        "markdown_report_url": f"/api/v1/engagements/{engagement_id}/report.md",
        "bundle_report_url": f"/api/v1/engagements/{engagement_id}/report.bundle.zip",
    }
    assert project_history.json()["total"] == 1
    assert next_page.json() == {"schema_version": "v1", "items": [], "total": 1}
    assert empty_history.json() == {"schema_version": "v1", "items": [], "total": 0}
    assert conflict.status_code == 409
    assert len(transport.calls) == 1
    assert report.json()["counts"] == {"actions": 1, "evidence": 1, "findings": 8}
    steps = report.json()["steps"]
    assert len(steps) == 1
    assert steps[0]["index"] == 1
    assert steps[0]["state"] == "succeeded"
    assert steps[0]["evidence_id"] == created.json()["evidence_ids"][0]
    assert steps[0]["evidence_digest"] is not None
    assert steps[0]["finding_count"] == 8
    assert "## Execution steps" in report_md.text
    assert steps[0]["evidence_digest"] in report_md.text
    assert dashboard.json()["execution_available"] is True
    event_types = [item["event_type"] for item in audit.json()["items"]]
    assert event_types[:3] == [
        "assessment.discovery_completed",
        "assessment.completed",
        "assessment.created",
    ]


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


async def test_safe_preset_crawls_same_origin_links_and_aggregates_report(tmp_path: Path) -> None:
    transport = LinkedAssessmentTransport()
    async with assessment_client(tmp_path / "crawl.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={"target": "https://api.example.test/v1", "preset": "safe"},
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "crawl-safe"},
        )
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report",
            headers=OPERATOR_HEADERS,
        )
        html_report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report.html",
            headers=OPERATOR_HEADERS,
        )
        history = await client.get("/api/v1/assessments", headers=OPERATOR_HEADERS)

    assert created.status_code == 201
    assert created.json()["pages_scanned"] == 4
    assert created.json()["crawl_truncated"] is False
    assert len(created.json()["evidence_ids"]) == 4
    assert len(transport.calls) == 4
    assert report.json()["discovery"]["pages_scanned"] == 4
    assert report.json()["discovery"]["scanned_targets"] == [
        "https://api.example.test:443/v1",
        "https://api.example.test:443/v1/one",
        "https://api.example.test:443/v1/two",
        "https://api.example.test:443/v1/three",
    ]
    assert history.json()["items"][0]["evidence_count"] == 4
    assert html_report.status_code == 200
    assert "Content-Security-Policy" in html_report.headers
    assert "Pages scanned" in html_report.text


async def test_active_safe_mode_inventories_and_probes_openapi_reads(tmp_path: Path) -> None:
    transport = OpenApiAssessmentTransport()
    async with assessment_client(tmp_path / "active-openapi.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={
                "target": "https://api.example.test/v1/openapi.json",
                "preset": "safe",
                "mode": "active-safe",
            },
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "active-openapi"},
        )
        report = await client.get(
            f"/api/v1/engagements/{engagement_id}/report",
            headers=OPERATOR_HEADERS,
        )
        fetched = await client.get(
            f"/api/v1/engagements/{engagement_id}/assessments/{created.json()['action_id']}",
            headers=OPERATOR_HEADERS,
        )
        audit = await client.get(
            f"/api/v1/engagements/{engagement_id}/audit-events",
            headers=OPERATOR_HEADERS,
        )

    assert created.status_code == 201
    assert created.json()["pages_scanned"] == 1
    assert created.json()["active_probes_run"] == 1
    assert created.json()["active_probe_truncated"] is False
    assert fetched.json()["pages_scanned"] == 1
    assert fetched.json()["active_probes_run"] == 1
    assert len(transport.calls) == 2
    assert transport.calls[1][0].method == "GET"
    assert transport.calls[1][0].target == "https://api.example.test:443/v1/profile"
    inventory = report.json()["api_inventory"]
    assert inventory["documents_found"] == 1
    assert inventory["operations_total"] == 2
    assert inventory["read_operations"] == 1
    assert inventory["write_operations"] == 1
    assert inventory["active_probes_run"] == 1
    assert report.json()["execution_available"] is True
    assert any(
        finding["vulnerability_class"] == "CWE-306"
        for finding in report.json()["findings"]
    )
    assert "assessment.active_api_completed" in {
        event["event_type"] for event in audit.json()["items"]
    }


async def test_error_page_openapi_is_not_used_for_active_probes_or_inventory(
    tmp_path: Path,
) -> None:
    class ErrorOpenApiTransport(OpenApiAssessmentTransport):
        def send(
            self, request: HttpCaptureRequest, limits: HttpCaptureLimits
        ) -> HttpCaptureResponse:
            return replace(super().send(request, limits), status_code=503)

    transport = ErrorOpenApiTransport()
    async with assessment_client(tmp_path / "error-openapi.db", transport) as client:
        client.headers.update(OPERATOR_HEADERS)
        engagement_id = await _create_engagement(client)
        created = await client.post(
            f"/api/v1/engagements/{engagement_id}/assessments",
            json={
                "target": "https://api.example.test/v1/openapi.json",
                "preset": "safe",
                "mode": "active-safe",
            },
            headers={**OPERATOR_HEADERS, "Idempotency-Key": "error-openapi"},
        )
        report = await client.get(f"/api/v1/engagements/{engagement_id}/report")

    assert created.status_code == 201
    assert created.json()["findings_count"] == 0
    assert created.json()["active_probes_run"] == 0
    assert len(transport.calls) == 1
    assert report.json()["api_inventory"]["documents_found"] == 0


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
        history = await client.get("/api/v1/assessments", headers=OPERATOR_HEADERS)

    assert response.status_code == 201
    assert response.json()["state"] == "failed"
    assert response.json()["error_code"] == "test_transport_failed"
    assert response.json()["evidence_ids"] == []
    assert replay.status_code == 200
    assert replay.json()["error_code"] == "test_transport_failed"
    assert fetched.json()["error_code"] == "test_transport_failed"
    assert history.json()["items"][0]["error_code"] == "test_transport_failed"
    assert history.json()["items"][0]["evidence_count"] == 0
    assert history.json()["items"][0]["findings_count"] == 0
    assert len(transport.calls) == 1
    assert actions.json()["items"][0]["state"] == "failed"
