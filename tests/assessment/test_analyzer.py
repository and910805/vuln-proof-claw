"""Deterministic passive response analyzer coverage."""

from __future__ import annotations

import pytest

from vuln_proof_claw.assessment.analyzer import analyze_passive_response
from vuln_proof_claw.domain.enums import (
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    VerificationMethod,
)
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.execution.http_capture import HttpCaptureResponse


def analyze(
    headers: tuple[tuple[str, str], ...],
    *,
    target: str = "https://example.test/",
    status_code: int = 200,
) -> tuple[str, ...]:
    findings = analyze_passive_response(
        EngagementId("00000000-0000-7000-8000-000000000001"),
        target,
        EvidenceId("00000000-0000-7000-8000-000000000002"),
        HttpCaptureResponse(
            status_code=status_code,
            final_target=target,
            headers=headers,
            body=b"response",
            duration_ms=1,
        ),
    )
    return tuple(item.title for item in findings)


def analyze_findings(
    headers: tuple[tuple[str, str], ...],
    *,
    target: str = "https://example.test/",
    status_code: int = 200,
) -> tuple[Finding, ...]:
    return analyze_passive_response(
        EngagementId("00000000-0000-7000-8000-000000000001"),
        target,
        EvidenceId("00000000-0000-7000-8000-000000000002"),
        HttpCaptureResponse(
            status_code=status_code,
            final_target=target,
            headers=headers,
            body=b"response",
            duration_ms=1,
        ),
    )


def test_every_finding_carries_a_validated_cwe_and_a_stated_basis() -> None:
    # cwe_id is the field an external consumer keys on and the one the scoring
    # layer counts coverage with, so a finding that only sets vulnerability_class
    # is invisible to both. Finding.__post_init__ validates the format, so a
    # malformed id cannot reach here -- what this pins is that the value is set
    # at all, on every finding, and agrees with the class.
    findings = analyze_findings(
        (
            ("Content-Type", "text/html"),
            ("Server", "nginx/1.24.0"),
            ("Set-Cookie", "sessionid=secret; Path=/"),
        )
    )

    assert findings
    for finding in findings:
        assert finding.cwe_id is not None, finding.title
        assert finding.cwe_id == finding.vulnerability_class, finding.title
        # Each check reads one captured response against a fixed expectation.
        assert finding.verification_method is VerificationMethod.OBSERVED, finding.title


def test_secure_non_html_response_has_no_findings() -> None:
    titles = analyze(
        (
            ("Content-Type", "application/json"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("X-Content-Type-Options", "nosniff"),
            ("Server", "edge"),
        )
    )

    assert titles == ()


def test_html_headers_version_and_sensitive_cookie_are_analyzed_conservatively() -> None:
    titles = analyze(
        (
            ("Content-Type", "text/html"),
            ("Server", "nginx/1.24.0"),
            ("Set-Cookie", "sessionid=secret; Path=/"),
        )
    )

    assert titles == (
        "HTTP Strict Transport Security header is missing",
        "X-Content-Type-Options header is missing",
        "Content Security Policy header is missing",
        "Referrer-Policy header is missing",
        "Server header discloses a software version",
        "Sensitive cookie sessionid is missing Secure",
        "Sensitive cookie sessionid is missing HttpOnly",
        "Sensitive cookie sessionid is missing SameSite",
    )


def test_cookie_name_heuristics_remain_candidates_with_an_observed_basis() -> None:
    findings = analyze_findings(
        (
            ("Content-Type", "text/html"),
            ("Server", "nginx/1.24.0"),
            ("Set-Cookie", "sessionid=secret; Path=/"),
        )
    )

    cookie_findings = [
        finding for finding in findings if finding.title.startswith("Sensitive cookie")
    ]
    direct_findings = [finding for finding in findings if finding not in cookie_findings]
    assert len(cookie_findings) == 3
    assert all(finding.status is FindingStatus.CANDIDATE for finding in cookie_findings)
    assert all(finding.confidence is FindingConfidence.MEDIUM for finding in cookie_findings)
    assert all(
        finding.verification_method is VerificationMethod.OBSERVED for finding in cookie_findings
    )
    assert direct_findings
    assert all(finding.status is FindingStatus.VERIFIED for finding in direct_findings)


@pytest.mark.parametrize("status_code", [301, 302, 404, 500])
def test_redirects_and_error_responses_do_not_claim_missing_headers(
    status_code: int,
) -> None:
    findings = analyze_findings(
        (
            ("Content-Type", "text/html"),
            ("Server", "nginx/1.24.0"),
            ("Set-Cookie", "sessionid=secret; Path=/"),
        ),
        status_code=status_code,
    )

    assert findings == ()


def test_cleartext_and_non_sensitive_cookie_do_not_overclaim_cookie_risk() -> None:
    titles = analyze(
        (
            ("Content-Type", "application/json"),
            ("X-Content-Type-Options", "nosniff"),
            ("Set-Cookie", "theme=dark"),
        ),
        target="http://example.test/",
    )

    assert titles == ("Cleartext HTTP transport is enabled",)


def test_cookie_values_cannot_impersonate_security_attributes() -> None:
    titles = analyze(
        (
            ("Content-Type", "application/json"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("X-Content-Type-Options", "nosniff"),
            ("Set-Cookie", "sessionid=secure-httponly-samesite; Path=/"),
        )
    )

    assert titles == (
        "Sensitive cookie sessionid is missing Secure",
        "Sensitive cookie sessionid is missing HttpOnly",
        "Sensitive cookie sessionid is missing SameSite",
    )


def test_findings_include_priority_guidance_and_are_deduplicated() -> None:
    findings = analyze_passive_response(
        EngagementId("00000000-0000-7000-8000-000000000001"),
        "https://example.test/",
        EvidenceId("00000000-0000-7000-8000-000000000002"),
        HttpCaptureResponse(
            status_code=200,
            final_target="https://example.test/",
            headers=(
                ("Content-Type", "application/json"),
                ("Set-Cookie", "sessionid=one"),
                ("Set-Cookie", "sessionid=two"),
            ),
            body=b"{}",
            duration_ms=1,
        ),
    )

    secure = [item for item in findings if item.title.endswith("missing Secure")]
    assert len(secure) == 1
    assert secure[0].severity is FindingSeverity.HIGH
    assert secure[0].confidence is FindingConfidence.MEDIUM
    assert secure[0].status is FindingStatus.CANDIDATE
    assert "Secure" in secure[0].remediation
