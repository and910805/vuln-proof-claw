"""Deterministic passive response analyzer coverage."""

from __future__ import annotations

from vuln_proof_claw.assessment.analyzer import analyze_passive_response
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.execution.http_capture import HttpCaptureResponse


def analyze(
    headers: tuple[tuple[str, str], ...], *, target: str = "https://example.test/"
) -> tuple[str, ...]:
    findings = analyze_passive_response(
        EngagementId("00000000-0000-7000-8000-000000000001"),
        target,
        EvidenceId("00000000-0000-7000-8000-000000000002"),
        HttpCaptureResponse(
            status_code=200,
            final_target=target,
            headers=headers,
            body=b"response",
            duration_ms=1,
        ),
    )
    return tuple(item.title for item in findings)


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
