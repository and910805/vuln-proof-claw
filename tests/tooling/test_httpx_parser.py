"""What one httpx run is allowed to claim.

The two tests that matter most here are the negative ones. A parser that emits
a finding per output field passes every positive test and still produces a
report nobody trusts, so ``test_a_clean_service_produces_no_findings`` is the
one that pins restraint. And a parser that reports whatever the tool printed
launders an out-of-scope result into an authorised engagement, which is what
``test_a_record_about_another_host_is_dropped_not_reported`` refuses.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from vuln_proof_claw.domain.enums import (
    FindingSeverity,
    FindingStatus,
    VerificationMethod,
)
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.tooling.parsers import parse_httpx_findings

ENGAGEMENT = EngagementId("00000000-0000-7000-8000-000000000001")
EVIDENCE = EvidenceId("00000000-0000-7000-8000-000000000002")
TARGET = "https://api.example.test/v1"
NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def record(**overrides: Any) -> str:
    """One httpx JSONL line for the target, clean unless overridden."""
    document: dict[str, Any] = {
        "input": TARGET,
        "url": TARGET,
        "scheme": "https",
        "host": "203.0.113.10",
        "port": "443",
        "status_code": 200,
        "content_length": 4096,
        "title": "Example API",
        "webserver": "nginx",
        "tech": ["Nginx", "OpenAPI"],
        "failed": False,
        "tls": {"tls_version": "tls13", "not_after": "2027-01-01T00:00:00Z"},
    }
    document.update(overrides)
    return json.dumps(document)


def parse(
    stdout: str, *, at: datetime = NOW, target: str = TARGET
) -> tuple[Finding, ...]:
    return parse_httpx_findings(ENGAGEMENT, target, EVIDENCE, stdout, at=at)


def titles(stdout: str, *, at: datetime = NOW, target: str = TARGET) -> tuple[str, ...]:
    return tuple(finding.title for finding in parse(stdout, at=at, target=target))


def test_a_clean_service_produces_no_findings() -> None:
    # Everything in this record is inventory: a title, a status code, a length,
    # an unversioned server banner, a current certificate on a current TLS
    # version. None of it is a claim about the target, and a parser that turned
    # any of it into a finding would be manufacturing work for a reviewer.
    assert titles(record()) == ()


def test_a_record_about_another_host_is_dropped_not_reported() -> None:
    # httpx echoes a server-supplied URL, so this is reachable in practice. The
    # engagement authorised one target; a finding about another host would be
    # laundered into it with a real evidence id attached.
    elsewhere = record(
        input="https://unrelated.example.net/",
        url="https://unrelated.example.net/",
        scheme="http",
        webserver="Apache/2.4.6",
        tls={"tls_version": "tls10", "not_after": "2020-01-01T00:00:00Z"},
    )

    assert titles(elsewhere) == ()


def test_a_record_on_another_port_of_the_approved_host_is_also_dropped() -> None:
    # Scope binds host *and* port: 8443 is a different target from 443 even
    # though the hostname matches.
    other_port = record(
        input="https://api.example.test:8443/v1",
        url="https://api.example.test:8443/v1",
        webserver="Apache/2.4.6",
    )

    assert titles(other_port) == ()


def test_cleartext_is_reported_when_the_approved_target_is_cleartext() -> None:
    # http is port 80 and https is port 443, so a record whose scheme disagrees
    # with the approved target has already been dropped as a different target.
    # The claim therefore rests on the approved scheme, which means reaching it
    # requires an engagement whose scope is itself a cleartext URL.
    cleartext = "http://api.example.test/v1"
    findings = parse(
        record(input=cleartext, url=cleartext, scheme="http", tls=None),
        target=cleartext,
    )

    assert [finding.title for finding in findings] == [
        "Cleartext HTTP transport is enabled"
    ]
    assert findings[0].severity is FindingSeverity.HIGH
    assert findings[0].cwe_id == "CWE-319"


def test_an_https_target_never_produces_a_cleartext_finding() -> None:
    # The record's scheme field is server-influenced; the approved target is
    # not. Trusting the field would let a response mint a HIGH finding.
    assert titles(record(scheme="http")) == ()


def test_a_versioned_server_banner_is_reported_and_a_bare_one_is_not() -> None:
    assert titles(record(webserver="nginx/1.24.0")) == (
        "Server header discloses a software version",
    )
    # A single number is not a disclosure: "Apache/2" tells an attacker nothing
    # they could not guess.
    assert titles(record(webserver="Apache/2")) == ()
    assert titles(record(webserver="cloudflare")) == ()


def test_versioned_technologies_are_reported_once_and_listed_in_the_remediation() -> None:
    findings = parse(record(tech=["Nginx:1.24.0", "PHP:8.1", "Bootstrap"]))

    assert [finding.title for finding in findings] == [
        "Response fingerprint discloses component versions"
    ]
    # Informational, because fingerprinting infers the version rather than
    # reading it, and the operator needs to know which components to act on.
    assert findings[0].severity is FindingSeverity.INFORMATIONAL
    assert "Nginx:1.24.0" in findings[0].remediation
    assert "PHP:8.1" in findings[0].remediation
    assert "Bootstrap" not in findings[0].remediation


def test_an_obsolete_tls_version_is_reported() -> None:
    findings = parse(record(tls={"tls_version": "tls10", "not_after": "2027-01-01T00:00:00Z"}))

    assert [finding.title for finding in findings] == [
        "Obsolete TLS version tls10 is accepted"
    ]
    assert findings[0].cwe_id == "CWE-327"


def test_an_expired_certificate_is_reported_and_a_valid_one_is_not() -> None:
    expired = record(tls={"tls_version": "tls13", "not_after": "2026-01-01T00:00:00Z"})

    assert titles(expired) == ("TLS certificate has expired",)
    # "Expiring soon" is deliberately not a finding: it needs a threshold nobody
    # agreed on, and it would turn true on a date the evidence does not contain.
    assert titles(record()) == ()


def test_expiry_is_decided_by_the_passed_clock_not_the_wall_clock() -> None:
    # The same evidence must produce the same report tomorrow. A parser reading
    # the wall clock would silently start reporting an expiry it did not before.
    line = record(tls={"tls_version": "tls13", "not_after": "2026-09-01T00:00:00Z"})

    assert titles(line, at=datetime(2026, 8, 27, tzinfo=UTC)) == ()
    assert titles(line, at=datetime(2026, 9, 2, tzinfo=UTC)) == (
        "TLS certificate has expired",
    )


def test_a_failed_probe_claims_nothing() -> None:
    # httpx marks an unreachable target rather than omitting it. A failed probe
    # is not evidence that the service is clean, and it is not a finding either.
    assert titles(record(failed=True, scheme="http", webserver="Apache/2.4.6")) == ()


def test_diagnostics_and_a_truncated_line_do_not_discard_the_records_that_parsed() -> None:
    # -silent suppresses the banner but not every diagnostic, and a killed run
    # leaves a partial final line. Raising here would throw away real results.
    stdout = "\n".join(
        [
            "[WRN] Could not resolve one host",
            "",
            record(webserver="nginx/1.24.0"),
            "   ",
            "{partial",
        ]
    )

    assert titles(stdout) == ("Server header discloses a software version",)


def test_every_finding_states_its_basis_and_carries_a_validated_cwe() -> None:
    stdout = "\n".join(
        [
            record(
                webserver="nginx/1.24.0",
                tech=["PHP:8.1"],
                tls={"tls_version": "tls10", "not_after": "2026-01-01T00:00:00Z"},
            )
        ]
    )

    findings = parse(stdout)

    # Server version, technology version, obsolete TLS, expired certificate.
    assert len(findings) == 4
    for finding in findings:
        assert finding.verification_method is VerificationMethod.OBSERVED, finding.title
        assert finding.cwe_id is not None, finding.title
        assert finding.cwe_id == finding.vulnerability_class, finding.title
        assert finding.evidence_ids == (EVIDENCE,), finding.title
        assert finding.status is FindingStatus.VERIFIED, finding.title
        # A single record cannot support a differential claim, so none of these
        # may carry one -- Finding refuses a verified differential without a
        # control, and there is no control to give it.
        assert finding.control_evidence_ids == (), finding.title


def test_a_record_that_names_no_target_at_all_is_dropped() -> None:
    # Without a url or an input there is nothing to check against the approved
    # target, so the record cannot be attributed and must not be reported.
    document = json.loads(record(webserver="nginx/1.24.0"))
    document.pop("url")
    document.pop("input")

    assert titles(json.dumps(document)) == ()


def test_an_unparseable_url_is_dropped_rather_than_attributed() -> None:
    # normalize_target rejects anything that is not an absolute HTTP(S) URL. The
    # value is server-influenced, so failing closed here is what stops a
    # malformed url being treated as "probably ours".
    for broken in ("not-a-url", "ftp://api.example.test/v1", "https://", "///v1"):
        assert titles(record(url=broken, input=broken)) == (), broken


def test_an_empty_url_falls_through_to_the_input_field() -> None:
    # httpx has shipped records with an empty url. The input field still names
    # the target that was asked for, so the record is usable rather than dropped.
    assert titles(record(url="", webserver="nginx/1.24.0")) == (
        "Server header discloses a software version",
    )


def test_valid_json_that_is_not_a_record_is_not_treated_as_one() -> None:
    # An array, a bare string and a number are all valid JSON. None of them is
    # an httpx record, and reading fields off them would raise inside the parse.
    for not_a_record in (
        '[{"url": "https://api.example.test/v1", "webserver": "nginx/1.24.0"}]',
        '"https://api.example.test/v1"',
        "4096",
        "null",
    ):
        assert titles("\n".join([not_a_record, record()])) == (), not_a_record


def test_a_certificate_time_without_a_zulu_suffix_is_still_understood() -> None:
    # Not every build emits the same spelling. A format this parser cannot read
    # must not silently become "not expired".
    offset = record(tls={"tls_version": "tls13", "not_after": "2026-01-01T00:00:00+00:00"})

    assert titles(offset) == ("TLS certificate has expired",)


def test_an_unreadable_certificate_time_claims_nothing_either_way() -> None:
    # Fail closed on the claim, not on the run: an unparseable date is not
    # evidence of expiry, and it is not evidence of validity.
    for unreadable in ("", "soon", "0000-13-45", 20260101):
        assert titles(record(tls={"tls_version": "tls13", "not_after": unreadable})) == (), (
            unreadable
        )


def test_a_missing_or_malformed_tls_object_claims_nothing() -> None:
    assert titles(record(tls=None)) == ()
    assert titles(record(tls="tls13")) == ()
    assert titles(record(tls={})) == ()


def test_a_malformed_technology_list_claims_nothing() -> None:
    # A non-list, or a list of non-strings, must not become a finding whose
    # remediation text is a stringified object.
    assert titles(record(tech="Nginx:1.24.0")) == ()
    assert titles(record(tech=[{"name": "PHP:8.1"}, 8.1, None])) == ()


def test_a_malformed_server_banner_claims_nothing() -> None:
    assert titles(record(webserver=None)) == ()
    assert titles(record(webserver=1.24)) == ()


def test_the_same_finding_from_two_records_is_emitted_once() -> None:
    stdout = "\n".join([record(webserver="nginx/1.24.0"), record(webserver="nginx/1.24.0")])

    assert titles(stdout) == ("Server header discloses a software version",)
