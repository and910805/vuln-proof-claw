"""Deterministic, evidence-backed checks for one bounded HTTP response."""

from __future__ import annotations

import re

from vuln_proof_claw.domain.enums import FindingConfidence, FindingSeverity, FindingStatus
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.execution.http_capture import HttpCaptureResponse
from vuln_proof_claw.policy.scope import normalize_target

_VERSION_DISCLOSURE = re.compile(r"[/ ]\d+(?:\.\d+)+")
_SENSITIVE_COOKIE = re.compile(r"(?:auth|jwt|session|sid|token)", re.IGNORECASE)


def analyze_passive_response(
    engagement_id: EngagementId,
    target: str,
    evidence_id: EvidenceId,
    response: HttpCaptureResponse,
) -> tuple[Finding, ...]:
    """Return conservative findings derived only from the captured response."""
    normalized = normalize_target(target)
    headers: dict[str, list[str]] = {}
    for name, value in response.headers:
        headers.setdefault(name.lower(), []).append(value)
    content_type = " ".join(headers.get("content-type", ())).lower()
    is_html = "text/html" in content_type or "application/xhtml+xml" in content_type
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        title: str,
        vulnerability_class: str,
        severity: FindingSeverity,
        remediation: str,
    ) -> None:
        key = (title, vulnerability_class, str(normalized))
        if key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                engagement_id=engagement_id,
                title=title,
                vulnerability_class=vulnerability_class,
                affected_target=str(normalized),
                evidence_ids=(evidence_id,),
                status=FindingStatus.VERIFIED,
                severity=severity,
                confidence=FindingConfidence.HIGH,
                remediation=remediation,
            )
        )

    if normalized.scheme == "http":
        add(
            "Cleartext HTTP transport is enabled",
            "CWE-319",
            FindingSeverity.HIGH,
            "Serve the target only over HTTPS and redirect HTTP requests to HTTPS.",
        )
    if normalized.scheme == "https" and "strict-transport-security" not in headers:
        add(
            "HTTP Strict Transport Security header is missing",
            "CWE-319",
            FindingSeverity.MEDIUM,
            "Add a Strict-Transport-Security header after confirming the site is HTTPS-only.",
        )
    if "x-content-type-options" not in headers:
        add(
            "X-Content-Type-Options header is missing",
            "CWE-693",
            FindingSeverity.LOW,
            "Set X-Content-Type-Options: nosniff on HTTP responses.",
        )
    if is_html and "content-security-policy" not in headers:
        add(
            "Content Security Policy header is missing",
            "CWE-693",
            FindingSeverity.MEDIUM,
            "Deploy a restrictive Content-Security-Policy and refine it in report-only mode first.",
        )
    if is_html and "referrer-policy" not in headers:
        add(
            "Referrer-Policy header is missing",
            "CWE-200",
            FindingSeverity.LOW,
            "Set Referrer-Policy to strict-origin-when-cross-origin or a stricter policy.",
        )

    server = " ".join(headers.get("server", ()))
    if server and _VERSION_DISCLOSURE.search(server):
        add(
            "Server header discloses a software version",
            "CWE-200",
            FindingSeverity.LOW,
            "Remove product version details from the Server header.",
        )

    for cookie in headers.get("set-cookie", ()):
        name, separator, _remainder = cookie.partition("=")
        if not separator or not _SENSITIVE_COOKIE.search(name):
            continue
        attributes = {
            part.strip().partition("=")[0].lower()
            for part in cookie.split(";")[1:]
            if part.strip()
        }
        if normalized.scheme == "https" and "secure" not in attributes:
            add(
                f"Sensitive cookie {name.strip()} is missing Secure",
                "CWE-614",
                FindingSeverity.HIGH,
                "Set the Secure attribute on sensitive cookies served over HTTPS.",
            )
        if "httponly" not in attributes:
            add(
                f"Sensitive cookie {name.strip()} is missing HttpOnly",
                "CWE-1004",
                FindingSeverity.HIGH,
                "Set HttpOnly unless client-side JavaScript must read this cookie.",
            )
        if "samesite" not in attributes:
            add(
                f"Sensitive cookie {name.strip()} is missing SameSite",
                "CWE-1275",
                FindingSeverity.MEDIUM,
                "Set SameSite=Lax or SameSite=Strict unless a reviewed cross-site "
                "flow requires None.",
            )
    return tuple(findings)
