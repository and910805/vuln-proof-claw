"""Tests for the strict v1 worker protocol and disabled manager."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import (
    ActionId,
    ApprovalId,
    EngagementId,
    EvidenceId,
)
from vuln_proof_claw.execution.http_contract import http_parameter_digest
from vuln_proof_claw.execution.manager import (
    DisabledWorkerManager,
    WorkerExecutionUnavailableError,
)
from vuln_proof_claw.execution.protocol import (
    MAXIMUM_INLINE_CAPTURE_BODY_BYTES,
    WorkerHttpAction,
    WorkerHttpCapture,
    WorkerLimits,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
    WorkerScope,
)

NOW = datetime(2026, 7, 31, 10, 0, tzinfo=UTC)
DIGEST = "a" * 64


def worker_scope() -> WorkerScope:
    return WorkerScope(
        allowed_hostnames=("EXAMPLE.test.",),
        allowed_cidrs=(),
        allowed_ports=(443,),
        allowed_schemes=("https",),
        allowed_paths=("/api",),
        denied_hostnames=("blocked.example.test",),
        denied_cidrs=("192.0.2.128/25",),
        denied_paths=("/api/admin",),
    )


def worker_limits() -> WorkerLimits:
    return WorkerLimits(
        timeout_seconds=300,
        memory_megabytes=512,
        cpu_count=1.0,
        process_limit=128,
    )


def request(*, risk_level: RiskLevel = RiskLevel.L2) -> WorkerRequest:
    return WorkerRequest(
        request_id="request-1",
        engagement_id=EngagementId("00000000-0000-7000-8000-000000000001"),
        action_id=ActionId("00000000-0000-7000-8000-000000000002"),
        action_type="file_upload",
        normalized_target="https://example.test:443/api/upload",
        parameter_digest=DIGEST,
        risk_level=risk_level,
        approval_id=(
            ApprovalId("00000000-0000-7000-8000-000000000003")
            if risk_level.requires_approval
            else None
        ),
        idempotency_key="action-1",
        capabilities=(),
        scope=worker_scope(),
        limits=worker_limits(),
    )


def test_request_round_trip_is_strict_and_versioned() -> None:
    original = request()

    restored = WorkerRequest.model_validate_json(original.model_dump_json())

    assert restored == original
    assert restored.protocol_version == "v1"
    assert restored.scope.allowed_hostnames == ("example.test",)
    assert restored.scope.denied_cidrs == ("192.0.2.128/25",)
    assert "provider_api_key" not in original.model_dump()


def test_unknown_top_level_credentials_are_rejected() -> None:
    payload = request().model_dump(mode="json")
    payload["provider_api_key"] = "must-not-cross-worker-boundary"

    with pytest.raises(ValidationError, match="Extra inputs"):
        WorkerRequest.model_validate(payload)


def test_l2_to_l4_requests_require_approval() -> None:
    payload = request().model_dump()
    payload["approval_id"] = None

    with pytest.raises(ValidationError, match="approval_id"):
        WorkerRequest.model_validate(payload)


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("https://EXAMPLE.test/api/upload", "canonical"),
        ("https://outside.test:443/api/upload", "outside"),
        ("https://example.test:443/api/admin", "outside"),
    ],
)
def test_request_target_must_be_canonical_and_inside_worker_scope(
    target: str,
    message: str,
) -> None:
    payload = request().model_dump()
    payload["normalized_target"] = target

    with pytest.raises(ValidationError, match=message):
        WorkerRequest.model_validate(payload)


def public_read_request() -> WorkerRequest:
    target = "https://example.test:443/api/upload"
    action = WorkerHttpAction(
        method="GET",
        headers=(("accept", "text/plain"),),
        maximum_response_bytes=4096,
    )
    return WorkerRequest(
        request_id="public-read-1",
        engagement_id=EngagementId("00000000-0000-7000-8000-000000000001"),
        action_id=ActionId("00000000-0000-7000-8000-000000000002"),
        action_type="public_page_read",
        normalized_target=target,
        parameter_digest=http_parameter_digest(
            method=action.method,
            target=target,
            headers=action.headers,
        ),
        risk_level=RiskLevel.L0,
        idempotency_key="public-read-1",
        capabilities=("http_client",),
        http_action=action,
        scope=worker_scope(),
        limits=WorkerLimits(
            timeout_seconds=30,
            memory_megabytes=128,
            cpu_count=0.5,
            process_limit=32,
        ),
    )


def test_public_read_request_binds_exact_http_action() -> None:
    original = public_read_request()

    restored = WorkerRequest.model_validate_json(original.model_dump_json())

    assert restored == original
    assert restored.http_action is not None
    assert restored.http_action.headers == (("accept", "text/plain"),)
    assert restored.http_action.maximum_response_bytes == 4096


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"parameter_digest": "b" * 64}, "digest"),
        ({"capabilities": ()}, "requires"),
        ({"action_type": "file_upload"}, "only supported"),
        (
            {
                "limits": WorkerLimits(
                    timeout_seconds=61,
                    memory_megabytes=128,
                    cpu_count=0.5,
                    process_limit=32,
                )
            },
            "60 seconds",
        ),
    ],
)
def test_public_read_request_rejects_ambient_or_drifted_authority(
    changes: dict[str, object],
    message: str,
) -> None:
    payload = public_read_request().model_dump()
    payload.update(changes)

    with pytest.raises(ValidationError, match=message):
        WorkerRequest.model_validate(payload)


def test_http_action_rejects_credentials_and_oversized_response_budget() -> None:
    with pytest.raises(ValidationError, match="not allowed"):
        WorkerHttpAction(headers=(("authorization", "Bearer secret"),))
    with pytest.raises(ValidationError, match="less than or equal"):
        WorkerHttpAction(maximum_response_bytes=MAXIMUM_INLINE_CAPTURE_BODY_BYTES + 1)


def test_response_requires_safe_error_code_and_ordered_aware_times() -> None:
    success = WorkerResponse(
        request_id="request-1",
        engagement_id=request().engagement_id,
        action_id=request().action_id,
        status=WorkerResultStatus.SUCCEEDED,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        evidence_ids=(EvidenceId("00000000-0000-7000-8000-000000000004"),),
        exit_code=0,
    )
    assert success.protocol_version == "v1"

    with pytest.raises(ValidationError, match="evidence_id"):
        WorkerResponse(
            request_id="request-1",
            engagement_id=request().engagement_id,
            action_id=request().action_id,
            status=WorkerResultStatus.SUCCEEDED,
            started_at=NOW,
            completed_at=NOW,
        )

    with pytest.raises(ValidationError, match="error_code"):
        WorkerResponse(
            request_id="request-1",
            engagement_id=request().engagement_id,
            action_id=request().action_id,
            status=WorkerResultStatus.FAILED,
            started_at=NOW,
            completed_at=NOW,
        )

    with pytest.raises(ValidationError, match="earlier"):
        WorkerResponse(
            request_id="request-1",
            engagement_id=request().engagement_id,
            action_id=request().action_id,
            status=WorkerResultStatus.FAILED,
            started_at=NOW,
            completed_at=NOW - timedelta(seconds=1),
            error_code="worker_failed",
        )


def http_capture(**changes: object) -> WorkerHttpCapture:
    body = b"hello"
    values: dict[str, object] = {
        "method": "GET",
        "request_target": "https://example.test:443/api/upload",
        "request_headers": (("accept", "text/plain"),),
        "status_code": 200,
        "final_target": "https://example.test:443/api/upload",
        "response_headers": (("content-type", "text/plain"),),
        "body_base64": base64.b64encode(body).decode(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "captured_at": NOW,
        "duration_ms": 12,
    }
    values.update(changes)
    return WorkerHttpCapture(**values)


def test_success_can_carry_one_bounded_http_capture_before_persistence() -> None:
    capture = http_capture()

    response = WorkerResponse(
        request_id="request-1",
        engagement_id=request().engagement_id,
        action_id=request().action_id,
        status=WorkerResultStatus.SUCCEEDED,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        http_captures=(capture,),
        exit_code=0,
    )

    restored = WorkerResponse.model_validate_json(response.model_dump_json())
    assert restored.http_captures == (capture,)
    assert restored.evidence_ids == ()
    assert "hello" not in repr(restored)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"body_base64": "not-base64"}, "base64"),
        ({"body_sha256": "b" * 64}, "digest"),
        ({"final_target": "https://example.test:443/elsewhere"}, "redirected"),
        ({"request_headers": (("authorization", "secret"),)}, "not allowed"),
        ({"method": "HEAD"}, "HEAD"),
    ],
)
def test_http_capture_rejects_untrusted_content(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        http_capture(**changes)


def test_http_capture_rejects_body_over_decoded_limit() -> None:
    body = b"x" * (MAXIMUM_INLINE_CAPTURE_BODY_BYTES + 1)

    with pytest.raises(ValidationError, match="decoded byte limit"):
        http_capture(
            body_base64=base64.b64encode(body).decode(),
            body_sha256=hashlib.sha256(body).hexdigest(),
        )


def test_response_rejects_capture_outside_window_or_mixed_with_evidence_ids() -> None:
    capture = http_capture(captured_at=NOW - timedelta(seconds=1))

    with pytest.raises(ValidationError, match="outside"):
        WorkerResponse(
            request_id="request-1",
            engagement_id=request().engagement_id,
            action_id=request().action_id,
            status=WorkerResultStatus.SUCCEEDED,
            started_at=NOW,
            completed_at=NOW,
            http_captures=(capture,),
        )

    with pytest.raises(ValidationError, match="must not mix"):
        WorkerResponse(
            request_id="request-1",
            engagement_id=request().engagement_id,
            action_id=request().action_id,
            status=WorkerResultStatus.SUCCEEDED,
            started_at=NOW,
            completed_at=NOW,
            evidence_ids=(EvidenceId("00000000-0000-7000-8000-000000000004"),),
            http_captures=(http_capture(),),
        )

async def test_disabled_manager_fails_closed() -> None:
    manager = DisabledWorkerManager()

    with pytest.raises(WorkerExecutionUnavailableError, match="not configured"):
        await manager.submit(request())

    with pytest.raises(WorkerExecutionUnavailableError, match="not configured"):
        await manager.start("missing")

    assert await manager.status("missing") is None
    assert await manager.collect("missing") is None
