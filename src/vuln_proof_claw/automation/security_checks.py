"""Deterministic analyzers for bounded Web/API security comparisons."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

_SUCCESS_MIN = 200
_SUCCESS_MAX = 300
_SERVER_ERROR_MIN = 500
_SERVER_ERROR_MAX = 600


class SecurityCheck(StrEnum):
    CORS = "cors"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"


class CheckOutcome(StrEnum):
    PASS = "pass"  # noqa: S105  # nosec B105
    CANDIDATE = "candidate"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ResponseObservation:
    status_code: int
    headers: Mapping[str, str]
    body_digest: str
    body_size: int


@dataclass(frozen=True, slots=True)
class CheckResult:
    check: SecurityCheck
    outcome: CheckOutcome
    reason: str
    evidence: tuple[str, ...]


def analyze_cors(headers: Mapping[str, str], *, supplied_origin: str) -> CheckResult:
    normalized = {key.lower(): value.strip() for key, value in headers.items()}
    allow_origin = normalized.get("access-control-allow-origin")
    credentials = normalized.get("access-control-allow-credentials", "").lower() == "true"
    vary = {part.strip().lower() for part in normalized.get("vary", "").split(",")}
    if allow_origin == "*" and credentials:
        return CheckResult(
            SecurityCheck.CORS,
            CheckOutcome.CANDIDATE,
            "credentialed_wildcard_origin",
            ("access-control-allow-origin:*", "access-control-allow-credentials:true"),
        )
    if allow_origin == supplied_origin and credentials and "origin" not in vary:
        return CheckResult(
            SecurityCheck.CORS,
            CheckOutcome.CANDIDATE,
            "credentialed_origin_reflection_without_vary",
            (f"access-control-allow-origin:{allow_origin}", "vary:origin_missing"),
        )
    if allow_origin is None:
        return CheckResult(
            SecurityCheck.CORS,
            CheckOutcome.INCONCLUSIVE,
            "cors_headers_absent",
            (),
        )
    return CheckResult(SecurityCheck.CORS, CheckOutcome.PASS, "no_reviewed_cors_issue", ())


def compare_authentication(
    anonymous: ResponseObservation, authenticated: ResponseObservation
) -> CheckResult:
    same_content = anonymous.body_digest == authenticated.body_digest and anonymous.body_size > 0
    anonymous_success = _SUCCESS_MIN <= anonymous.status_code < _SUCCESS_MAX
    authenticated_success = _SUCCESS_MIN <= authenticated.status_code < _SUCCESS_MAX
    if anonymous_success and authenticated_success and same_content:
        return CheckResult(
            SecurityCheck.AUTHENTICATION,
            CheckOutcome.CANDIDATE,
            "anonymous_response_matches_authenticated_response",
            (f"status:{anonymous.status_code}", f"body-digest:{anonymous.body_digest}"),
        )
    if anonymous.status_code in {401, 403} and authenticated_success:
        return CheckResult(
            SecurityCheck.AUTHENTICATION, CheckOutcome.PASS, "authentication_boundary_observed", ()
        )
    return CheckResult(
        SecurityCheck.AUTHENTICATION,
        CheckOutcome.INCONCLUSIVE,
        "responses_do_not_establish_authentication_boundary",
        (),
    )


def compare_authorization(
    lower_privilege: ResponseObservation, higher_privilege: ResponseObservation
) -> CheckResult:
    same_content = lower_privilege.body_digest == higher_privilege.body_digest
    both_success = all(
        _SUCCESS_MIN <= item.status_code < _SUCCESS_MAX
        for item in (lower_privilege, higher_privilege)
    )
    if both_success and same_content and lower_privilege.body_size > 0:
        return CheckResult(
            SecurityCheck.AUTHORIZATION,
            CheckOutcome.CANDIDATE,
            "lower_privilege_response_matches_higher_privilege_response",
            (f"body-digest:{lower_privilege.body_digest}",),
        )
    if lower_privilege.status_code in {401, 403, 404} and (
        _SUCCESS_MIN <= higher_privilege.status_code < _SUCCESS_MAX
    ):
        return CheckResult(
            SecurityCheck.AUTHORIZATION, CheckOutcome.PASS, "authorization_boundary_observed", ()
        )
    return CheckResult(
        SecurityCheck.AUTHORIZATION,
        CheckOutcome.INCONCLUSIVE,
        "responses_do_not_establish_authorization_boundary",
        (),
    )


def compare_input_validation(
    baseline: ResponseObservation, mutated: ResponseObservation
) -> CheckResult:
    server_error = (
        _SERVER_ERROR_MIN <= mutated.status_code < _SERVER_ERROR_MAX
        and baseline.status_code < _SERVER_ERROR_MIN
    )
    if server_error:
        return CheckResult(
            SecurityCheck.INPUT_VALIDATION,
            CheckOutcome.CANDIDATE,
            "benign_mutation_triggered_server_error",
            (f"baseline-status:{baseline.status_code}", f"mutated-status:{mutated.status_code}"),
        )
    if mutated.status_code in {400, 404, 409, 422}:
        return CheckResult(
            SecurityCheck.INPUT_VALIDATION, CheckOutcome.PASS, "mutation_was_rejected", ()
        )
    return CheckResult(
        SecurityCheck.INPUT_VALIDATION,
        CheckOutcome.INCONCLUSIVE,
        "mutation_response_requires_verifier_review",
        (),
    )
