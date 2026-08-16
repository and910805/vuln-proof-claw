"""Disposable-worker entry point: one scope-checked, bounded HTTP capture.

The worker runs inside an isolated, egress-restricted container. It reads a
single authorized :class:`WorkerRequest` from the environment, re-evaluates the
engagement scope for the target *inside* the sandbox (defence in depth), performs
one redirect-free ``GET`` with conservative limits, and writes a terminal
:class:`WorkerResponse` as the last line of standard output for the control
plane to parse. It never follows redirects, sends credentials, or contacts any
host outside the scope it was given.
"""

from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from pydantic import ValidationError

from vuln_proof_claw.domain.identifiers import new_evidence_id
from vuln_proof_claw.evidence.canonical import canonical_json
from vuln_proof_claw.execution.protocol import (
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
)
from vuln_proof_claw.policy.scope import EngagementScope, evaluate_scope

_REQUEST_ENV = "VULN_PROOF_CLAW_WORKER_REQUEST"
_MAX_RESPONSE_BYTES = 1024 * 1024
_CAPTURE_SCHEMA = "worker-capture-v1"


class FetchTimeoutError(Exception):
    """Raised when the bounded fetch exceeds its deadline."""


class FetchError(Exception):
    """Raised for any other transport failure inside the sandbox."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    """Bounded outcome of one redirect-free request."""

    status_code: int
    final_url: str
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
) -> tuple[dict[str, object], WorkerResponse]:
    """Perform one capture and return a human summary plus a terminal response."""
    started_at = now()

    def terminal(
        status: WorkerResultStatus,
        *,
        error_code: str | None = None,
        evidence_id: str | None = None,
        exit_code: int | None = None,
        summary: dict[str, object] | None = None,
    ) -> tuple[dict[str, object], WorkerResponse]:
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
        return summary or {"capture_schema": _CAPTURE_SCHEMA, "status": status.value}, response

    scope = _scope_from_request(request)
    if not evaluate_scope(request.normalized_target, scope, at=started_at).allowed:
        return terminal(WorkerResultStatus.FAILED, error_code="scope_denied")

    try:
        result = fetch(
            request.normalized_target,
            request.limits.timeout_seconds,
            _MAX_RESPONSE_BYTES,
        )
    except FetchTimeoutError:
        return terminal(WorkerResultStatus.TIMED_OUT, error_code="worker_timed_out")
    except FetchError:
        return terminal(WorkerResultStatus.FAILED, error_code="transport_failure")

    if result.final_url != request.normalized_target:
        return terminal(WorkerResultStatus.FAILED, error_code="redirect_or_target_change_rejected")
    if len(result.body) > _MAX_RESPONSE_BYTES:
        return terminal(WorkerResultStatus.FAILED, error_code="response_body_too_large")

    evidence_id = new_evidence_id()
    summary = {
        "capture_schema": _CAPTURE_SCHEMA,
        "status": WorkerResultStatus.SUCCEEDED.value,
        "target": request.normalized_target,
        "status_code": result.status_code,
        "body_bytes": len(result.body),
        "body_sha256": hashlib.sha256(result.body).hexdigest(),
        "duration_ms": result.duration_ms,
        "evidence_id": evidence_id,
    }
    return terminal(
        WorkerResultStatus.SUCCEEDED,
        evidence_id=evidence_id,
        exit_code=0,
        summary=summary,
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
    except httpx.TimeoutException as error:
        raise FetchTimeoutError(str(error)) from error
    except httpx.HTTPError as error:
        raise FetchError(str(error)) from error
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    return FetchResult(
        status_code=response.status_code,
        final_url=str(response.url),
        body=bytes(body),
        duration_ms=duration_ms,
    )


def _write_line(payload: dict[str, object] | WorkerResponse) -> None:
    if isinstance(payload, WorkerResponse):
        sys.stdout.write(payload.model_dump_json() + "\n")
    else:
        sys.stdout.write(canonical_json(payload).decode("utf-8") + "\n")
    sys.stdout.flush()


def main() -> None:
    """Read the request, perform the capture, and emit a terminal response."""
    raw_request = os.environ.get(_REQUEST_ENV, "")
    try:
        request = WorkerRequest.model_validate_json(raw_request)
    except ValidationError:
        sys.stdout.write('{"capture_schema":"worker-capture-v1","status":"worker_error"}\n')
        sys.stdout.flush()
        raise SystemExit(2) from None

    summary, response = run_capture(request, _httpx_fetch)
    _write_line(summary)
    _write_line(response)


if __name__ == "__main__":
    main()
