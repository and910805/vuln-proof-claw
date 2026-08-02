from __future__ import annotations

from vuln_proof_claw.automation.security_checks import (
    CheckOutcome,
    ResponseObservation,
    analyze_cors,
    compare_authentication,
    compare_authorization,
    compare_input_validation,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def observation(status: int, digest: str = DIGEST_A) -> ResponseObservation:
    return ResponseObservation(status, {}, digest, 42)


def test_cors_flags_credentialed_wildcard() -> None:
    result = analyze_cors(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        supplied_origin="https://origin.example.test",
    )
    assert result.outcome is CheckOutcome.CANDIDATE
    assert result.reason == "credentialed_wildcard_origin"


def test_authentication_authorization_and_validation_are_differential() -> None:
    authentication_candidate = compare_authentication(observation(200), observation(200))
    assert authentication_candidate.outcome is CheckOutcome.CANDIDATE
    assert compare_authentication(observation(401), observation(200)).outcome is CheckOutcome.PASS
    assert compare_authorization(observation(403), observation(200)).outcome is CheckOutcome.PASS
    assert compare_input_validation(
        observation(200, DIGEST_A), observation(500, DIGEST_B)
    ).outcome is CheckOutcome.CANDIDATE
