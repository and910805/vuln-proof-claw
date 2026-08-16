"""Worker capture logic tests using an injected fetcher (no network)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.execution.test_protocol import request
from vuln_proof_claw.execution.protocol import WorkerResultStatus
from vuln_proof_claw.execution.worker import (
    FetchError,
    FetchResult,
    FetchTimeoutError,
    run_capture,
)

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def _clock() -> datetime:
    return NOW


def test_successful_capture_reports_evidence_and_summary() -> None:
    worker_request = request()
    body = b"<html>ok</html>"

    def fetch(target: str, timeout: float, max_bytes: int) -> FetchResult:
        assert target == worker_request.normalized_target
        assert timeout == worker_request.limits.timeout_seconds
        assert max_bytes > 0
        return FetchResult(status_code=200, final_url=target, body=body, duration_ms=12)

    summary, response = run_capture(worker_request, fetch, now=_clock)

    assert response.status is WorkerResultStatus.SUCCEEDED
    assert len(response.evidence_ids) == 1
    assert response.exit_code == 0
    assert summary["status_code"] == 200
    assert summary["body_bytes"] == len(body)
    assert summary["evidence_id"] == response.evidence_ids[0]


def test_out_of_scope_target_is_refused_without_fetching() -> None:
    # model_copy bypasses request validation, letting us drive the worker's own
    # defence-in-depth scope recheck with a target the sandbox must reject.
    worker_request = request().model_copy(
        update={"normalized_target": "https://outside.test:443/api/upload"}
    )
    calls: list[str] = []

    def fetch(target: str, timeout: float, max_bytes: int) -> FetchResult:
        calls.append(target)
        raise AssertionError("fetch must not run for an out-of-scope target")

    _summary, response = run_capture(worker_request, fetch, now=_clock)

    assert calls == []
    assert response.status is WorkerResultStatus.FAILED
    assert response.error_code == "scope_denied"


def test_timeout_and_transport_errors_map_to_safe_codes() -> None:
    worker_request = request()

    def timing_out(target: str, timeout: float, max_bytes: int) -> FetchResult:
        raise FetchTimeoutError("deadline")

    def failing(target: str, timeout: float, max_bytes: int) -> FetchResult:
        raise FetchError("connection refused")

    _s1, timed_out = run_capture(worker_request, timing_out, now=_clock)
    _s2, failed = run_capture(worker_request, failing, now=_clock)

    assert timed_out.status is WorkerResultStatus.TIMED_OUT
    assert timed_out.error_code == "worker_timed_out"
    assert failed.status is WorkerResultStatus.FAILED
    assert failed.error_code == "transport_failure"


def test_redirect_or_target_change_is_rejected() -> None:
    worker_request = request()

    def redirecting(target: str, timeout: float, max_bytes: int) -> FetchResult:
        return FetchResult(
            status_code=302,
            final_url="https://example.test:443/api/elsewhere",
            body=b"",
            duration_ms=3,
        )

    _summary, response = run_capture(worker_request, redirecting, now=_clock)

    assert response.status is WorkerResultStatus.FAILED
    assert response.error_code == "redirect_or_target_change_rejected"


def test_oversized_response_is_rejected() -> None:
    worker_request = request()
    oversized = b"x" * (1024 * 1024 + 1)

    def big(target: str, timeout: float, max_bytes: int) -> FetchResult:
        return FetchResult(status_code=200, final_url=target, body=oversized, duration_ms=7)

    _summary, response = run_capture(worker_request, big, now=_clock)

    assert response.status is WorkerResultStatus.FAILED
    assert response.error_code == "response_body_too_large"


def test_completed_at_is_not_earlier_than_started_at() -> None:
    worker_request = request()
    ticks = iter([NOW, NOW + timedelta(seconds=2)])

    def fetch(target: str, timeout: float, max_bytes: int) -> FetchResult:
        return FetchResult(status_code=200, final_url=target, body=b"ok", duration_ms=1)

    _summary, response = run_capture(worker_request, fetch, now=lambda: next(ticks))

    assert response.completed_at >= response.started_at
