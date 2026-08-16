"""Disposable-worker entry point: one scope-checked, bounded HTTP capture.

The worker runs inside an isolated, egress-restricted container. It reads a
single authorized :class:`WorkerRequest` from the environment, re-evaluates the
engagement scope for the target *inside* the sandbox (defence in depth), performs
one redirect-free ``GET`` with conservative limits, and writes two lines to
standard output: a :class:`CaptureEnvelope` describing exactly what it observed
(so the control plane can persist tamper-evident evidence) followed by a terminal
:class:`WorkerResponse`. It never follows redirects, sends credentials, or
contacts any host outside the scope it was given.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from pydantic import ValidationError

from vuln_proof_claw.domain.identifiers import new_evidence_id
from vuln_proof_claw.execution.capture_envelope import CaptureEnvelope
from vuln_proof_claw.execution.protocol import (
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
)
from vuln_proof_claw.policy.scope import EngagementScope, evaluate_scope

_REQUEST_ENV = "VULN_PROOF_CLAW_WORKER_REQUEST"
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_CAPTURED_HEADERS = 100


class FetchTimeoutError(Exception):
    """Raised when the bounded fetch exceeds its deadline."""


class FetchError(Exception):
    """Raised for any other transport failure inside the sandbox."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    """Bounded outcome of one redirect-free request."""

    status_code: int
    final_url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    duration_ms: int


Fetcher = Callable[[str, float, int], FetchResult]


def _scope_from_request(request: WorkerRequest) -> EngagementScope:
    return EngagementScope.create(
        allowed_hostnames=request.scope.allowed_hostnames,
        allowed_cidrs=request.scope.allowed_cidrs,
        allowed_ports=request.scope.allowed_ports,
        allowed_schemes=request.scope.allowed_schemes,
        allowed_paths=request.scope.allowed_paths,
        denied_hostnames=request.scope.denied_hostnames,
        denied_cidrs=request.scope.denied_cidrs,
        denied_paths=request.scope.denied_paths,
    )


def run_capture(
    request: WorkerRequest,
    fetch: Fetcher,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[CaptureEnvelope, WorkerResponse]:
    """Perform one capture and return the capture envelope plus a terminal response."""
    started_at = now()

    def terminal(
        status: WorkerResultStatus,
        envelope: CaptureEnvelope,
        *,
        error_code: str | None = None,
        evidence_id: str | None = None,
        exit_code: int | None = None,
    ) -> tuple[CaptureEnvelope, WorkerResponse]:
        response = WorkerResponse(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            action_id=request.action_id,
            status=status,
            started_at=started_at,
            completed_at=now(),
            evidence_ids=() if evidence_id is None else (evidence_id,),
            exit_code=exit_code,
            error_code=error_code,
        )
        return envelope, response

    def failure(
        error_code: str,
        status: WorkerResultStatus,
    ) -> tuple[CaptureEnvelope, WorkerResponse]:
        return terminal(
            status,
            CaptureEnvelope(status="failed", error_code=error_code),
            error_code=error_code,
        )

    scope = _scope_from_request(request)
    if not evaluate_scope(request.normalized_target, scope, at=started_at).allowed:
        return failure("scope_denied", WorkerResultStatus.FAILED)

    try:
        result = fetch(
            request.normalized_target,
            request.limits.timeout_seconds,
            _MAX_RESPONSE_BYTES,
        )
    except FetchTimeoutError:
        return failure("worker_timed_out", WorkerResultStatus.TIMED_OUT)
    except FetchError:
        return failure("transport_failure", WorkerResultStatus.FAILED)

    if result.final_url != request.normalized_target:
        return failure("redirect_or_target_change_rejected", WorkerResultStatus.FAILED)
    if len(result.body) > _MAX_RESPONSE_BYTES:
        return failure("response_body_too_large", WorkerResultStatus.FAILED)

    evidence_id = new_evidence_id()
    envelope = CaptureEnvelope(
        status="succeeded",
        status_code=result.status_code,
        final_target=result.final_url,
        headers=result.headers,
        body_base64=base64.b64encode(result.body).decode("ascii"),
        body_sha256=hashlib.sha256(result.body).hexdigest(),
        duration_ms=result.duration_ms,
    )
    return terminal(
        WorkerResultStatus.SUCCEEDED,
        envelope,
        evidence_id=evidence_id,
        exit_code=0,
    )


def _httpx_fetch(target: str, timeout_seconds: float, max_bytes: int) -> FetchResult:
    started = datetime.now(UTC)
    headers = {"user-agent": "vuln-proof-claw-worker/v1"}
    try:
        with (
            httpx.Client(follow_redirects=False, timeout=timeout_seconds) as client,
            client.stream("GET", target, headers=headers) as response,
        ):
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    break
            captured_headers = tuple(
                (name.lower(), value) for name, value in list(response.headers.items())
            )[:_MAX_CAPTURED_HEADERS]
    except httpx.TimeoutException as error:
        raise FetchTimeoutError(str(error)) from error
    except httpx.HTTPError as error:
        raise FetchError(str(error)) from error
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    return FetchResult(
        status_code=response.status_code,
        final_url=str(response.url),
        headers=captured_headers,
        body=bytes(body),
        duration_ms=duration_ms,
    )


def main() -> None:
    """Read the request, perform the capture, and emit the envelope and response."""
    raw_request = os.environ.get(_REQUEST_ENV, "")
    try:
        request = WorkerRequest.model_validate_json(raw_request)
    except ValidationError:
        sys.stdout.write(
            CaptureEnvelope(status="failed", error_code="worker_error").model_dump_json() + "\n"
        )
        sys.stdout.flush()
        raise SystemExit(2) from None

    envelope, response = run_capture(request, _httpx_fetch)
    sys.stdout.write(envelope.model_dump_json() + "\n")
    sys.stdout.write(response.model_dump_json() + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
