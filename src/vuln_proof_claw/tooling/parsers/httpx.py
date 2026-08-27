"""Findings that can be defended from one httpx JSONL record.

httpx reports what a service *is*, and almost none of that is a vulnerability.
Five things in its output support a claim, and this module emits only those. The
rest -- title, status code, content length, CDN, JARM, response time -- is
inventory, and emitting a finding per inventory field is how a scanner
integration ends up with a report nobody trusts.

Each check reads one captured record against a fixed expectation, so every
finding here is ``OBSERVED``: there is no baseline to hold it against. A claim
that needs a comparison -- that a payload changed the response -- cannot be made
from this output at all, and this parser never pretends otherwise.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any, Final

from vuln_proof_claw.domain.enums import (
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    VerificationMethod,
)
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.policy.scope import NormalizedTarget, normalize_target

# TLS versions with no safe configuration left. httpx spells them without dots.
_OBSOLETE_TLS_VERSIONS: Final = frozenset({"ssl30", "tls10", "tls11"})

# A version is at least two dot-separated numbers after a separator, so "nginx"
# is not a disclosure and both "nginx/1.24.0" and "PHP:8.1" are. One number
# alone is too weak a signal: "Apache/2" tells an attacker nothing they could
# not guess. This deliberately mirrors the passive analyzer's rule, widened for
# the ``name:version`` spelling httpx uses in its technology list.
_VERSION_DISCLOSURE: Final = re.compile(r"[/ :-]\d+(?:\.\d+)+")

_CERTIFICATE_TIME_FORMATS: Final = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
)

# What ``add`` below accepts. Named so the per-family helpers can be typed
# without restating the signature in three places.
_AddFinding = Callable[..., None]


def _looks_like_a_version(value: str) -> bool:
    return _VERSION_DISCLOSURE.search(value) is not None


def _parse_certificate_time(value: str) -> datetime | None:
    for pattern in _CERTIFICATE_TIME_FORMATS:
        try:
            return datetime.strptime(value, pattern).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _records(stdout: str) -> Iterator[dict[str, Any]]:
    """Yield the JSON objects in httpx's output, skipping anything else.

    ``-silent`` suppresses the banner but not every diagnostic, and a truncated
    run leaves a partial final line. A line that is not a JSON object is not an
    error to raise: raising here would discard the records that did parse, which
    is a worse outcome than ignoring noise.
    """
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            document = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        # Both checks are load-bearing: json.loads rejects a diagnostic line,
        # and the type check rejects a line that is valid JSON but not a record
        # -- an array, a bare string, a number. Screening on a "{" prefix first
        # would make this type check unreachable, which is how a defence stops
        # being a defence.
        if isinstance(document, dict):
            yield document


def _describes_the_target(record: dict[str, Any], target: NormalizedTarget) -> bool:
    """Return whether this record is about the target the approval named.

    httpx normally echoes back the target it was given, but ``input``, ``url``
    and ``host`` can all disagree -- ``host`` is the resolved address, and a
    redirect or a server-supplied URL can name somewhere else entirely. A record
    that does not name the approved host is dropped rather than reported: the
    control plane authorised one target, and a finding about another one is
    outside what anybody agreed to.
    """
    for field in ("url", "input"):
        value = record.get(field)
        if not isinstance(value, str) or not value:
            continue
        try:
            observed = normalize_target(value)
        except Exception:  # noqa: BLE001 - any unparseable value fails closed
            return False
        return observed.host == target.host and observed.port == target.port
    return False


def parse_httpx_findings(
    engagement_id: EngagementId,
    target: str,
    evidence_id: EvidenceId,
    stdout: str,
    *,
    at: datetime,
) -> tuple[Finding, ...]:
    """Return the findings one httpx run supports, and nothing else.

    ``at`` is passed in rather than read from the clock so that certificate
    expiry is a deterministic comparison. A parser that reads the wall clock
    produces a different report every day from the same evidence.
    """
    normalized = normalize_target(target)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(
        title: str,
        cwe: str,
        severity: FindingSeverity,
        remediation: str,
        *,
        confidence: FindingConfidence = FindingConfidence.HIGH,
    ) -> None:
        key = (title, cwe)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                engagement_id=engagement_id,
                title=title,
                vulnerability_class=cwe,
                cwe_id=cwe,
                affected_target=str(normalized),
                evidence_ids=(evidence_id,),
                status=FindingStatus.VERIFIED,
                verification_method=VerificationMethod.OBSERVED,
                severity=severity,
                confidence=confidence,
                remediation=remediation,
            )
        )

    for record in _records(stdout):
        if record.get("failed") is True:
            continue
        if not _describes_the_target(record, normalized):
            continue
        _add_transport_findings(record, normalized, add)
        _add_disclosure_findings(record, add)
        _add_tls_findings(record, at, add)

    return tuple(findings)


def _add_transport_findings(
    record: dict[str, Any],
    normalized: NormalizedTarget,
    add: _AddFinding,
) -> None:
    # The record's own ``scheme`` field is deliberately not consulted. Scope
    # binds host and port together, and http/https are different ports, so a
    # record whose scheme disagrees with the approved target has already been
    # dropped as a different target. What remains is the approved scheme, which
    # is the same basis the passive analyzer uses.
    if normalized.scheme == "http":
        add(
            "Cleartext HTTP transport is enabled",
            "CWE-319",
            FindingSeverity.HIGH,
            "Serve the target only over HTTPS and redirect HTTP requests to HTTPS.",
        )


def _add_disclosure_findings(record: dict[str, Any], add: _AddFinding) -> None:
    webserver = record.get("webserver")
    if isinstance(webserver, str) and _looks_like_a_version(webserver):
        add(
            "Server header discloses a software version",
            "CWE-200",
            FindingSeverity.LOW,
            "Remove product version details from the Server header.",
        )

    technologies = record.get("tech")
    if isinstance(technologies, list):
        disclosed = sorted(
            {
                item
                for item in technologies
                if isinstance(item, str) and _looks_like_a_version(item)
            }
        )
        if disclosed:
            add(
                "Response fingerprint discloses component versions",
                "CWE-200",
                FindingSeverity.INFORMATIONAL,
                "Suppress version banners on the components listed in the evidence: "
                + ", ".join(disclosed),
                # Fingerprinting infers the version rather than reading it from a
                # header, so the version itself may be wrong even when the
                # component is right.
                confidence=FindingConfidence.MEDIUM,
            )


def _add_tls_findings(record: dict[str, Any], at: datetime, add: _AddFinding) -> None:
    tls = record.get("tls")
    if not isinstance(tls, dict):
        return

    version = tls.get("tls_version")
    if isinstance(version, str) and version.lower() in _OBSOLETE_TLS_VERSIONS:
        add(
            f"Obsolete TLS version {version} is accepted",
            "CWE-327",
            FindingSeverity.MEDIUM,
            "Disable TLS 1.1 and below and offer TLS 1.2 as the minimum version.",
        )

    not_after = tls.get("not_after")
    if not isinstance(not_after, str):
        return
    expiry = _parse_certificate_time(not_after)
    # Only an already-expired certificate is reported. "Expiring soon" needs a
    # threshold nobody agreed on, and a finding that turns true on a date the
    # evidence does not contain is not something a third party can check.
    if expiry is not None and expiry <= at:
        add(
            "TLS certificate has expired",
            "CWE-298",
            FindingSeverity.HIGH,
            f"Renew the certificate; it expired at {expiry.isoformat()}.",
        )
