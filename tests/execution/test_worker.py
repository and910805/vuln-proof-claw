"""Tests for the fail-closed passive HTTP Worker process boundary."""

from __future__ import annotations

import io
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Literal

import pytest

from vuln_proof_claw.domain.enums import RiskLevel
from vuln_proof_claw.domain.identifiers import ActionId, EngagementId
from vuln_proof_claw.execution.http_capture import (
    CaptureTransportError,
    HttpCaptureLimits,
    HttpCaptureRequest,
    HttpCaptureResponse,
)
from vuln_proof_claw.execution.http_contract import http_parameter_digest
from vuln_proof_claw.execution.protocol import (
    WorkerHttpAction,
    WorkerLimits,
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
    WorkerScope,
)
from vuln_proof_claw.execution.worker import (
    MAXIMUM_REQUEST_BYTES,
    WORKER_FAILURE_EXIT_CODE,
    evaluate_request,
    run,
)
from vuln_proof_claw.policy.scope import EngagementScope

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)


class FakeTransport:
    def __init__(
        self,
        response: HttpCaptureResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response or HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test:443/public",
            headers=(("content-type", "text/plain"),),
            body=b"hello",
            duration_ms=12,
        )
        self.error = error
        self.request: HttpCaptureRequest | None = None
        self.limits: HttpCaptureLimits | None = None

    def send(
        self,
        request: HttpCaptureRequest,
        limits: HttpCaptureLimits,
    ) -> HttpCaptureResponse:
        self.request = request
        self.limits = limits
        if self.error is not None:
            raise self.error
        return self.response


def request(*, method: Literal["GET", "HEAD"] = "GET") -> WorkerRequest:
    target = "https://example.test:443/public"
    headers = (("accept", "text/plain"),)
    action = WorkerHttpAction(
        method=method,
        headers=headers,
        maximum_response_bytes=4096,
    )
    return WorkerRequest(
        request_id="worker-e2e-1",
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
        idempotency_key="worker-e2e-1",
        capabilities=("http_client",),
        http_action=action,
        scope=WorkerScope(
            allowed_hostnames=("example.test",),
            allowed_ports=(443,),
            allowed_schemes=("https",),
            allowed_paths=("/public",),
        ),
        limits=WorkerLimits(
            timeout_seconds=30,
            memory_megabytes=128,
            cpu_count=0.5,
            process_limit=32,
        ),
    )


def unsupported_request() -> WorkerRequest:
    return WorkerRequest(
        request_id="worker-unsupported-1",
        engagement_id=EngagementId("00000000-0000-7000-8000-000000000001"),
        action_id=ActionId("00000000-0000-7000-8000-000000000002"),
        action_type="passive_http_probe",
        normalized_target="https://example.test:443/",
        parameter_digest="a" * 64,
        risk_level=RiskLevel.L1,
        idempotency_key="worker-unsupported-1",
        scope=WorkerScope(
            allowed_hostnames=("example.test",),
            allowed_ports=(443,),
            allowed_schemes=("https",),
        ),
        limits=WorkerLimits(
            timeout_seconds=30,
            memory_megabytes=128,
            cpu_count=0.5,
            process_limit=32,
        ),
    )


def test_valid_request_executes_exact_bounded_action_and_emits_capture() -> None:
    original = request()
    transport = FakeTransport()
    scopes: list[EngagementScope] = []

    def factory(scope: EngagementScope) -> FakeTransport:
        scopes.append(scope)
        return transport

    response = evaluate_request(
        original.model_dump_json().encode(),
        clock=lambda: NOW,
        transport_factory=factory,
    )

    assert response.status is WorkerResultStatus.SUCCEEDED
    assert response.exit_code == 0
    assert len(response.http_captures) == 1
    assert response.http_captures[0].decoded_body() == b"hello"
    assert response.evidence_ids == ()
    assert transport.request is not None
    assert transport.request.method == "GET"
    assert transport.request.target == original.normalized_target
    assert transport.request.headers == (("accept", "text/plain"),)
    assert transport.limits == HttpCaptureLimits(timeout_seconds=30, max_response_bytes=4096)
    assert scopes[0].allowed_hostnames == frozenset({"example.test"})


def test_run_emits_one_strict_success_response() -> None:
    output = io.StringIO()

    exit_code = run(
        io.BytesIO(request().model_dump_json().encode()),
        output,
        clock=lambda: NOW,
        transport_factory=lambda _scope: FakeTransport(),
    )

    assert exit_code == 0
    assert output.getvalue().count("\n") == 1
    response = WorkerResponse.model_validate_json(output.getvalue())
    assert response.request_id == "worker-e2e-1"
    assert response.status is WorkerResultStatus.SUCCEEDED


def test_unsupported_action_is_denied_without_constructing_transport() -> None:
    calls = 0

    def factory(_scope: EngagementScope) -> FakeTransport:
        nonlocal calls
        calls += 1
        return FakeTransport()

    response = evaluate_request(
        unsupported_request().model_dump_json().encode(),
        clock=lambda: NOW,
        transport_factory=factory,
    )

    assert response.status is WorkerResultStatus.POLICY_DENIED
    assert response.error_code == "worker_action_not_supported"
    assert response.exit_code == WORKER_FAILURE_EXIT_CODE
    assert calls == 0


@pytest.mark.parametrize(
    ("error", "status", "error_code"),
    [
        (
            CaptureTransportError("dns_resolution_failed"),
            WorkerResultStatus.FAILED,
            "dns_resolution_failed",
        ),
        (
            CaptureTransportError("private transport detail"),
            WorkerResultStatus.FAILED,
            "worker_http_transport_failed",
        ),
        (
            RuntimeError("private runtime detail"),
            WorkerResultStatus.WORKER_ERROR,
            "worker_http_execution_failed",
        ),
    ],
)
def test_transport_failures_return_only_stable_safe_codes(
    error: Exception,
    status: WorkerResultStatus,
    error_code: str,
) -> None:
    response = evaluate_request(
        request().model_dump_json().encode(),
        clock=lambda: NOW,
        transport_factory=lambda _scope: FakeTransport(error=error),
    )

    assert response.status is status
    assert response.error_code == error_code
    assert "private" not in response.model_dump_json()


def test_head_body_and_excessive_duration_fail_closed() -> None:
    head_response = evaluate_request(
        request(method="HEAD").model_dump_json().encode(),
        clock=lambda: NOW,
        transport_factory=lambda _scope: FakeTransport(),
    )
    slow_response = evaluate_request(
        request().model_dump_json().encode(),
        clock=lambda: NOW,
        transport_factory=lambda _scope: FakeTransport(
            HttpCaptureResponse(
                status_code=200,
                final_target="https://example.test:443/public",
                headers=(),
                body=b"",
                duration_ms=30_001,
            )
        ),
    )

    assert head_response.error_code == "head_response_body_rejected"
    assert slow_response.error_code == "capture_duration_exceeded"


def test_default_executor_connects_only_to_explicitly_scoped_loopback() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"worker local response")

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}/health"
        action = WorkerHttpAction(maximum_response_bytes=128)
        worker_request = WorkerRequest(
            request_id="worker-local-1",
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
            idempotency_key="worker-local-1",
            capabilities=("http_client",),
            http_action=action,
            scope=WorkerScope(
                allowed_cidrs=("127.0.0.1/32",),
                allowed_ports=(server.server_port,),
                allowed_schemes=("http",),
                allowed_paths=("/health",),
            ),
            limits=WorkerLimits(
                timeout_seconds=5,
                memory_megabytes=128,
                cpu_count=0.5,
                process_limit=32,
            ),
        )

        response = evaluate_request(worker_request.model_dump_json().encode())

        assert response.status is WorkerResultStatus.SUCCEEDED
        assert response.http_captures[0].decoded_body() == b"worker local response"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b'{"request_id":"secret-target.example"}',
        b"x" * (MAXIMUM_REQUEST_BYTES + 1),
    ],
    ids=("empty", "malformed", "invalid-schema", "oversized"),
)
def test_invalid_or_oversized_input_is_not_reflected(payload: bytes) -> None:
    output = io.StringIO()

    exit_code = run(io.BytesIO(payload), output, clock=lambda: NOW)

    assert exit_code == WORKER_FAILURE_EXIT_CODE
    assert json.loads(output.getvalue()) == {
        "component": "worker",
        "error_code": "worker_request_invalid",
        "state": "rejected",
    }
    assert "secret-target" not in output.getvalue()
