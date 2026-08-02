"""Fail-closed passive HTTP executor for the restricted Worker boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import BinaryIO, Protocol, TextIO

from pydantic import ValidationError

from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.execution.http_capture import (
    CaptureTransportError,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureResponse,
)
from vuln_proof_claw.execution.http_contract import http_parameter_digest
from vuln_proof_claw.execution.pinned_http import PinnedHttpTransport
from vuln_proof_claw.execution.protocol import (
    WorkerHttpCapture,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
)
from vuln_proof_claw.policy.scope import EngagementScope

MAXIMUM_REQUEST_BYTES = 1_048_576
WORKER_FAILURE_EXIT_CODE = 2
_SUPPORTED_ACTION_TYPE = "public_page_read"
_SAFE_TRANSPORT_ERRORS = frozenset(
    {
        "dns_resolution_empty",
        "dns_resolution_failed",
        "dns_resolution_invalid",
        "capture_duration_exceeded",
        "head_response_body_rejected",
        "invalid_content_length",
        "network_transport_failed",
        "resolved_address_denied",
        "resolved_address_not_public",
        "response_body_too_large",
        "transport_scope_denied",
    }
)


class WorkerHttpTransport(Protocol):
    """Narrow injectable boundary used by the Worker executor tests."""

    def send(
        self,
        request: HttpCaptureRequest,
        limits: HttpCaptureLimits,
    ) -> HttpCaptureResponse: ...


WorkerTransportFactory = Callable[[EngagementScope], WorkerHttpTransport]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_transport(scope: EngagementScope) -> WorkerHttpTransport:
    return PinnedHttpTransport(scope)


def evaluate_request(
    payload: bytes,
    *,
    clock: Callable[[], datetime] = _utc_now,
    transport_factory: WorkerTransportFactory = _default_transport,
) -> WorkerResponse:
    """Validate and execute one exact passive HTTP Worker request."""
    if not payload or len(payload) > MAXIMUM_REQUEST_BYTES:
        raise ValueError("worker_request_invalid")
    try:
        request = WorkerRequest.model_validate_json(payload)
    except (UnicodeDecodeError, ValidationError, ValueError) as error:
        raise ValueError("worker_request_invalid") from error

    started_at = clock()
    if request.action_type != _SUPPORTED_ACTION_TYPE or request.http_action is None:
        return _failure_response(
            request,
            started_at=started_at,
            completed_at=clock(),
            status=WorkerResultStatus.POLICY_DENIED,
            error_code="worker_action_not_supported",
        )
    action = request.http_action
    expected_digest = http_parameter_digest(
        method=action.method,
        target=request.normalized_target,
        headers=action.headers,
    )
    if expected_digest != request.parameter_digest or "http_client" not in request.capabilities:
        return _failure_response(
            request,
            started_at=started_at,
            completed_at=clock(),
            status=WorkerResultStatus.POLICY_DENIED,
            error_code="worker_http_binding_invalid",
        )

    capture_request = HttpCaptureRequest(
        action_id=request.action_id,
        method=action.method,
        target=request.normalized_target,
        headers=action.headers,
    )
    limits = HttpCaptureLimits(
        timeout_seconds=request.limits.timeout_seconds,
        max_response_bytes=action.maximum_response_bytes,
    )
    try:
        response = transport_factory(request.scope.as_engagement_scope()).send(
            capture_request,
            limits,
        )
        if action.method == "HEAD" and response.body:
            raise CaptureTransportError("head_response_body_rejected")
        if response.duration_ms > request.limits.timeout_seconds * 1000:
            raise CaptureTransportError("capture_duration_exceeded")
        completed_at = max(started_at, clock())
        capture = WorkerHttpCapture(
            method=action.method,
            request_target=capture_request.target,
            request_headers=capture_request.headers,
            status_code=response.status_code,
            final_target=response.final_target,
            response_headers=response.headers,
            body_base64=base64.b64encode(response.body).decode("ascii"),
            body_sha256=hashlib.sha256(response.body).hexdigest(),
            captured_at=completed_at,
            duration_ms=response.duration_ms,
        )
    except CaptureTransportError as error:
        safe_code = str(error)
        if safe_code not in _SAFE_TRANSPORT_ERRORS:
            safe_code = "worker_http_transport_failed"
        return _failure_response(
            request,
            started_at=started_at,
            completed_at=clock(),
            status=WorkerResultStatus.FAILED,
            error_code=safe_code,
        )
    except DomainValidationError:
        return _failure_response(
            request,
            started_at=started_at,
            completed_at=clock(),
            status=WorkerResultStatus.POLICY_DENIED,
            error_code="worker_http_policy_denied",
        )
    except Exception:  # noqa: BLE001 - untrusted transport details never cross stdout
        return _failure_response(
            request,
            started_at=started_at,
            completed_at=clock(),
            status=WorkerResultStatus.WORKER_ERROR,
            error_code="worker_http_execution_failed",
        )

    return WorkerResponse(
        request_id=request.request_id,
        engagement_id=request.engagement_id,
        action_id=request.action_id,
        status=WorkerResultStatus.SUCCEEDED,
        started_at=started_at,
        completed_at=completed_at,
        http_captures=(capture,),
        exit_code=0,
    )


def _failure_response(
    request: WorkerRequest,
    *,
    started_at: datetime,
    completed_at: datetime,
    status: WorkerResultStatus,
    error_code: str,
) -> WorkerResponse:
    return WorkerResponse(
        request_id=request.request_id,
        engagement_id=request.engagement_id,
        action_id=request.action_id,
        status=status,
        started_at=started_at,
        completed_at=max(started_at, completed_at),
        exit_code=WORKER_FAILURE_EXIT_CODE,
        error_code=error_code,
    )


def _safe_failure(error_code: str) -> str:
    return json.dumps(
        {
            "component": "worker",
            "state": "rejected",
            "error_code": error_code,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def run(
    input_stream: BinaryIO,
    output_stream: TextIO,
    *,
    clock: Callable[[], datetime] = _utc_now,
    transport_factory: WorkerTransportFactory = _default_transport,
) -> int:
    """Consume exactly one bounded stdin message and emit exactly one JSON result."""
    payload = input_stream.read(MAXIMUM_REQUEST_BYTES + 1)
    try:
        response = evaluate_request(
            payload,
            clock=clock,
            transport_factory=transport_factory,
        )
    except ValueError:
        output_stream.write(_safe_failure("worker_request_invalid") + "\n")
        output_stream.flush()
        return WORKER_FAILURE_EXIT_CODE

    output_stream.write(response.model_dump_json() + "\n")
    output_stream.flush()
    return response.exit_code or 0


def main() -> None:
    """Run the Worker protocol over stdin/stdout and return a stable exit status."""
    raise SystemExit(run(sys.stdin.buffer, sys.stdout))


if __name__ == "__main__":
    main()
