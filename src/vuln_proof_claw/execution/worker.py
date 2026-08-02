"""Fail-closed worker entry point for the restricted-container boundary."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import BinaryIO, TextIO

from pydantic import ValidationError

from vuln_proof_claw.execution.protocol import (
    WorkerRequest,
    WorkerResponse,
    WorkerResultStatus,
)

MAXIMUM_REQUEST_BYTES = 1_048_576
WORKER_DISABLED_EXIT_CODE = 2


def _utc_now() -> datetime:
    return datetime.now(UTC)


def evaluate_request(
    payload: bytes,
    *,
    clock: Callable[[], datetime] = _utc_now,
) -> WorkerResponse:
    """Validate one bounded request and return a request-bound safe refusal.

    Target-facing execution intentionally remains unavailable. Parsing the real
    protocol here lets the container lifecycle be verified without inventing
    evidence or making network requests.
    """
    if not payload or len(payload) > MAXIMUM_REQUEST_BYTES:
        raise ValueError("worker_request_invalid")
    try:
        request = WorkerRequest.model_validate_json(payload)
    except (UnicodeDecodeError, ValidationError, ValueError) as error:
        raise ValueError("worker_request_invalid") from error

    started_at = clock()
    completed_at = clock()
    return WorkerResponse(
        request_id=request.request_id,
        engagement_id=request.engagement_id,
        action_id=request.action_id,
        status=WorkerResultStatus.POLICY_DENIED,
        started_at=started_at,
        completed_at=max(started_at, completed_at),
        exit_code=WORKER_DISABLED_EXIT_CODE,
        error_code="worker_execution_not_implemented",
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
) -> int:
    """Consume exactly one bounded stdin message and emit exactly one JSON result."""
    payload = input_stream.read(MAXIMUM_REQUEST_BYTES + 1)
    try:
        response = evaluate_request(payload, clock=clock)
    except ValueError:
        output_stream.write(_safe_failure("worker_request_invalid") + "\n")
        output_stream.flush()
        return WORKER_DISABLED_EXIT_CODE

    output_stream.write(response.model_dump_json() + "\n")
    output_stream.flush()
    return WORKER_DISABLED_EXIT_CODE


def main() -> None:
    """Run the worker protocol over stdin/stdout and return a stable exit status."""
    raise SystemExit(run(sys.stdin.buffer, sys.stdout))


if __name__ == "__main__":
    main()
