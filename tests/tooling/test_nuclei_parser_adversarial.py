"""Tests written from confirmed attacks on the nuclei parser.

Every case here comes from an adversarial review that reproduced a defect, so
each one is known to have been red at some point. They are grouped by what the
attack was actually exploiting, because that is the reusable part:

* **Template metadata admitted a claim.** A tag, a CVE id, a CVSS score and a
  ``metadata.verified`` flag are all written by the rule's author with no
  knowledge of this target. Refusing on metadata can only over-suppress, which
  this design permits. *Admitting* on metadata is the failure the parser exists
  to prevent, and one tag string used to do exactly that.
* **A record left the parse without a trace.** The module promises every record
  is either admitted or refused with a reason. Three separate paths broke it: a
  Unicode line separator in a response body, a domain validation error, and the
  dedupe check.
* **A rule was right but nothing protected it.** Several assertions were weaker
  than their own comments claimed -- the port half of the scope check never
  decided a case, the severity separation was tested for one of six forbidden
  fields, and the switch table was its own oracle.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from vuln_proof_claw.domain.enums import FindingConfidence, FindingStatus
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.tooling.parsers import NucleiParseResult, Suppression, parse_nuclei_output
from vuln_proof_claw.tooling.parsers import nuclei as nuclei_parser

ENGAGEMENT = EngagementId("00000000-0000-7000-8000-000000000001")
EVIDENCE = EvidenceId("00000000-0000-7000-8000-000000000002")
TARGET = "https://api.example.test/v1"
APPROVED = "https://api.example.test:443/v1"

INTERACTION = {
    "protocol": "http",
    "unique-id": "c9s1k2q0k1s0oabcdefg",
    "full-id": "c9s1k2q0k1s0oabcdefg.oast.internal.test",
    "raw-request": "GET / HTTP/1.1\r\nHost: c9s1k2q0k1s0oabcdefg.oast.internal.test\r\n\r\n",
    "remote-address": "203.0.113.10",
}


def http_record(**overrides: Any) -> str:
    info: dict[str, Any] = {
        "name": "Blind SSRF",
        "tags": ["ssrf", "oast"],
        "severity": "high",
    }
    info.update(overrides.pop("info", {}))
    document: dict[str, Any] = {
        "template": "http/vulnerabilities/generic/oob-ssrf.yaml",
        "template-id": "oob-ssrf",
        "info": info,
        "type": "http",
        "matched-at": TARGET,
        "response": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nok",
    }
    document.update(overrides)
    return json.dumps(document)


def ssl_record(**overrides: Any) -> str:
    info: dict[str, Any] = {
        "name": "Expired SSL Certificate",
        "tags": ["ssl", "expiry"],
        "severity": "low",
    }
    info.update(overrides.pop("info", {}))
    document: dict[str, Any] = {
        "template": "ssl/expired-ssl.yaml",
        "template-id": "expired-ssl",
        "info": info,
        "type": "ssl",
        "matched-at": "api.example.test:443",
        "response": "-----BEGIN CERTIFICATE-----",
    }
    document.update(overrides)
    return json.dumps(document)


def parse(stdout: str) -> NucleiParseResult:
    return parse_nuclei_output(ENGAGEMENT, TARGET, EVIDENCE, stdout)


# --------------------------------------------------------------------------- #
# Template metadata must not admit a claim
# --------------------------------------------------------------------------- #


def test_the_oast_tag_alone_does_not_assert_that_the_target_called_back() -> None:
    # This was a CRITICAL defect. One tag string used to mint a VERIFIED
    # CRITICAL row titled with a CVE, asserting the target had contacted
    # scanner-controlled infrastructure -- from a record containing no
    # interaction at all. Worse, the default contract passes -no-interactsh, so
    # a run operating no such infrastructure could still produce that claim.
    result = parse(http_record())

    assert result.findings == ()
    assert [s.reason for s in result.suppressed] == [Suppression.EVIDENCE_NOT_IN_RECORD]


def test_the_interaction_object_is_what_admits_an_out_of_band_claim() -> None:
    result = parse(http_record(interaction=INTERACTION))

    assert [f.title for f in result.findings] == ["Blind SSRF"]
    assert result.findings[0].confidence is FindingConfidence.HIGH


def test_an_interaction_with_no_correlating_token_is_not_a_correlated_callback() -> None:
    # Without a unique id there is nothing tying the interaction to this request.
    for stripped in ({}, {"protocol": "http"}, {"protocol": "http", "unique-id": ""}):
        assert parse(http_record(interaction=stripped)).findings == (), stripped
    # A non-object in the field must not be read as one either.
    wrong_shapes: tuple[object, ...] = ("http", 1, [], None)
    for wrong in wrong_shapes:
        assert parse(http_record(interaction=wrong)).findings == (), wrong


def test_a_dns_only_callback_is_worth_less_than_an_http_one() -> None:
    # Resolver prefetch, a security middlebox and an AV sandbox all reproduce a
    # DNS interaction without the target executing anything.
    dns_only = parse(http_record(interaction={**INTERACTION, "protocol": "dns"}))
    assert dns_only.findings[0].confidence is FindingConfidence.MEDIUM

    unknown = parse(http_record(interaction={**INTERACTION, "protocol": "quic"}))
    assert unknown.findings[0].confidence is FindingConfidence.LOW


def test_a_real_callback_outranks_the_metadata_refusals() -> None:
    # A CVE id and a fingerprint tag are the author's declarations. A correlated
    # callback is a fact about the target, so it wins -- but only because it is
    # now grounded in the interaction object rather than in a tag.
    loaded = http_record(
        interaction=INTERACTION,
        info={
            "name": "Log4j RCE",
            "tags": ["cve", "oast", "tech", "detect"],
            "severity": "critical",
            "classification": {"cve-id": ["cve-2021-44228"], "cwe-id": ["cwe-502"]},
        },
    )

    result = parse(loaded)

    assert [f.title for f in result.findings] == ["Log4j RCE"]
    assert result.findings[0].cwe_id == "CWE-502"


def test_a_blind_callback_needs_no_in_band_response() -> None:
    # For a blind callback the interaction is the only evidence. Requiring a
    # response would demand in-band data to admit an out-of-band claim.
    blind = json.loads(http_record(interaction=INTERACTION))
    blind.pop("response")

    assert [f.title for f in parse(json.dumps(blind)).findings] == ["Blind SSRF"]


def test_a_record_with_neither_a_response_nor_an_interaction_claims_nothing() -> None:
    empty = json.loads(ssl_record())
    empty.pop("response")

    assert parse(json.dumps(empty)).suppressed[0].reason is Suppression.NO_CAPTURED_EVIDENCE


@pytest.mark.parametrize(
    ("field", "low", "high"),
    [
        ("cvss-score", 0.0, 10.0),
        ("epss-score", 0.0, 0.99),
        ("epss-percentile", 0.0, 0.99),
    ],
)
def test_a_score_the_author_assigned_cannot_change_confidence(
    field: str, low: object, high: object
) -> None:
    # Only info.severity was pinned before, so five of the six forbidden fields
    # could be wired into confidence with the suite green.
    def confidence_with(value: object) -> FindingConfidence:
        line = ssl_record(info={"classification": {field: value, "cve-id": None}})
        return parse(line).findings[0].confidence

    assert confidence_with(low) is confidence_with(high) is FindingConfidence.HIGH


@pytest.mark.parametrize("verified", [True, False])
def test_metadata_verified_cannot_change_confidence_or_status(verified: bool) -> None:
    # "verified" means the template's author tested the rule against some
    # vulnerable instance. It says nothing about this match.
    result = parse(ssl_record(info={"metadata": {"verified": verified, "max-request": 1}}))

    assert result.findings[0].confidence is FindingConfidence.HIGH
    assert result.findings[0].status is FindingStatus.VERIFIED


@pytest.mark.parametrize("matcher_name", ["word-1", "certificate-expired", ""])
def test_the_matcher_name_cannot_change_confidence(matcher_name: str) -> None:
    # An author-chosen label with no semantics the engine enforces.
    result = parse(ssl_record(**{"matcher-name": matcher_name}))

    assert result.findings[0].confidence is FindingConfidence.HIGH


def test_a_cve_claim_is_refused_on_every_route_that_would_otherwise_admit() -> None:
    # The CVE gate's *position* was unprotected: it was tested only against an
    # http/cves/ template, a family that falls through to EVIDENCE_NOT_IN_RECORD
    # anyway, so the test passed whether the gate fired or not. These two routes
    # would each admit without it.
    on_ssl = ssl_record(
        info={
            "name": "OpenSSL - Padding Oracle (CVE-2016-2107)",
            "tags": ["ssl", "cve"],
            "severity": "medium",
            "classification": {"cve-id": ["cve-2016-2107"], "cwe-id": ["cwe-310"]},
        }
    )
    on_exposure = http_record(
        template="http/exposures/configs/git-config.yaml",
        **{"template-id": "git-config"},
        info={
            "name": "Git config exposed (CVE-2020-0000)",
            "tags": ["config", "exposure"],
            "severity": "medium",
            "classification": {"cve-id": ["cve-2020-0000"], "cwe-id": ["cwe-200"]},
        },
    )

    for line in (on_ssl, on_exposure):
        result = parse(line)
        assert result.findings == ()
        assert [s.reason for s in result.suppressed] == [Suppression.VERSION_INFERENCE]


# --------------------------------------------------------------------------- #
# No record may leave the parse without a trace
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_a_unicode_line_separator_in_a_response_cannot_delete_a_record(
    separator: str,
) -> None:
    # str.splitlines() splits on all of these; str.split("\n") does not. Go's
    # encoding/json writes U+0085 through unescaped, so a target that puts it in
    # a response body used to split one JSONL record into two unparseable
    # fragments -- and the record vanished from the findings AND from the audit.
    # A target deleting its own evidence.
    #
    # ensure_ascii=False is the whole point of this test. Python's default
    # escapes the character to a six-character ASCII sequence containing no
    # separator at all, so a test built on json.dumps' default emits a perfectly
    # clean line. An earlier version of this test did exactly that, looked
    # right, and survived reverting the fix under mutation.
    document = json.loads(ssl_record())
    document["response"] = f"-----BEGIN{separator}CERTIFICATE-----"
    poisoned = json.dumps(document, ensure_ascii=False)
    assert separator in poisoned, "the test payload must contain the raw separator"
    assert len(poisoned.splitlines()) == 2
    assert len(poisoned.split("\n")) == 1

    result = parse(poisoned)

    assert [f.title for f in result.findings] == ["Expired SSL Certificate"], separator
    assert result.suppressed == ()


def test_an_unparseable_line_is_reported_rather_than_swallowed() -> None:
    result = parse("\n".join(['{"template-id": "half', ssl_record()]))

    assert len(result.findings) == 1
    assert [s.reason for s in result.suppressed] == [Suppression.UNPARSEABLE_LINE]


@pytest.mark.parametrize("blank", ["  ", "\t", "\xa0", "　"])
def test_a_blank_template_name_does_not_void_the_whole_run(blank: str) -> None:
    # Finding requires a non-empty title after stripping, while _text treated a
    # whitespace-only value as present. The DomainValidationError propagated out
    # of the call, so no result was returned at all: one malformed template
    # destroyed every other finding in the run and the entire suppression log.
    stdout = "\n".join([ssl_record(info={"name": blank}), ssl_record()])

    result = parse(stdout)

    assert len(result.findings) == 2, blank
    assert result.findings[0].title == "expired-ssl"


@pytest.mark.parametrize("blank", ["  ", "\t", "\xa0"])
def test_a_blank_remediation_does_not_void_the_whole_run(blank: str) -> None:
    # The second record has to be a different claim, or the dedupe check
    # collapses it and the test stops measuring what it is here to measure.
    other = ssl_record(
        **{"template-id": "self-signed-ssl"},
        info={"name": "Self-signed certificate", "tags": ["ssl"], "severity": "low"},
    )
    stdout = "\n".join([ssl_record(info={"remediation": blank}), other])

    result = parse(stdout)

    assert len(result.findings) == 2, blank
    assert "expired-ssl" in result.findings[0].remediation


def test_a_record_the_domain_refuses_costs_only_that_record() -> None:
    # Any other domain validation failure refuses one record with a reason
    # instead of aborting the call.
    stdout = "\n".join(
        [
            ssl_record(info={"classification": {"cwe-id": ["cwe-79"]}}),
            ssl_record(**{"template-id": "other", "matched-at": "api.example.test:443"}),
        ]
    )

    result = parse(stdout)

    assert len(result.findings) == 2
    assert result.suppressed == ()


def test_an_unanticipated_domain_refusal_costs_one_record_not_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fail-closed branch, reached by injection because nothing else reaches it.

    Every known way template metadata could make ``Finding.__post_init__`` raise
    is now handled upstream -- a blank name and a blank remediation fall back, a
    malformed CWE becomes None, the target and the evidence come from the
    approval rather than the record. So this branch is currently unreachable
    from real input, which is exactly why it needs a test: an unreachable
    ``except`` that nobody has exercised is an assumption, not a defence. If the
    domain grows an invariant this parser does not anticipate, one bad record
    must cost that record and not the whole run's findings and audit.
    """
    calls = {"count": 0}

    def refusing_finding(**kwargs: Any) -> Any:
        calls["count"] += 1
        if calls["count"] == 1:
            raise DomainValidationError("an invariant this parser did not expect")
        return Finding(**kwargs)

    monkeypatch.setattr(nuclei_parser, "Finding", refusing_finding)

    survivor = ssl_record(
        **{"template-id": "self-signed-ssl"},
        info={"name": "Self-signed certificate", "tags": ["ssl"], "severity": "low"},
    )
    result = parse("\n".join([ssl_record(), survivor]))

    assert [f.title for f in result.findings] == ["Self-signed certificate"]
    assert [s.reason for s in result.suppressed] == [Suppression.REFUSED_BY_THE_DOMAIN]
    assert "did not expect" in result.suppressed[0].detail


def test_two_exposures_at_two_paths_are_two_findings() -> None:
    # Dedupe collapsed them on title alone, and because affected_target is the
    # approved target rather than the match location, the surviving row recorded
    # neither path -- so the second secret was not merged, it was unrecoverable.
    first = http_record(
        template="http/exposures/tokens/aws-access-key.yaml",
        **{"template-id": "aws-key", "matched-at": "https://api.example.test/v1/config.json"},
        info={"name": "AWS key exposed", "tags": ["exposure"], "severity": "high"},
    )
    second = http_record(
        template="http/exposures/tokens/aws-access-key.yaml",
        **{
            "template-id": "aws-key",
            "matched-at": "https://api.example.test/v1/backup/config.json",
        },
        info={"name": "AWS key exposed", "tags": ["exposure"], "severity": "high"},
    )

    result = parse("\n".join([first, second]))

    assert len(result.findings) == 2
    assert result.suppressed == ()


def test_a_genuine_duplicate_is_collapsed_but_still_logged() -> None:
    result = parse("\n".join([ssl_record(), ssl_record()]))

    assert len(result.findings) == 1
    assert [s.reason for s in result.suppressed] == [Suppression.DUPLICATE_OF_ADMITTED]
    assert result.suppressed[0].located_at == "api.example.test:443"


def test_every_record_is_either_admitted_or_logged() -> None:
    # The module's stated invariant, asserted directly rather than trusted.
    stdout = "\n".join(
        [
            ssl_record(),
            ssl_record(),
            http_record(),
            http_record(**{"matcher-status": False}),
            http_record(**{"matched-at": "https://elsewhere.example.net/"}),
            "not json at all",
            "[1, 2, 3]",
        ]
    )

    result = parse(stdout)

    assert len(result.findings) + len(result.suppressed) == 7


# --------------------------------------------------------------------------- #
# Rules that were right but unprotected
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "other_port",
    ["https://api.example.test:8443/v1", "http://api.example.test:80/v1"],
)
def test_a_url_on_another_port_of_the_approved_host_is_out_of_scope(other_port: str) -> None:
    # The parametrized scope cases were all rejected on the host or on being
    # unparseable, so the port half of the URL branch never decided one -- it
    # could be deleted with the suite green, and a match on 8443 would then ship
    # as a finding against port 443.
    result = parse(http_record(**{"matched-at": other_port}))

    assert result.findings == ()
    assert [s.reason for s in result.suppressed] == [Suppression.OUT_OF_SCOPE]


def test_the_finding_is_attributed_to_the_approved_target_not_to_the_output() -> None:
    # affected_target was asserted nowhere, so it could be sourced from nuclei's
    # stdout instead of the normalized approval -- the one field that would
    # carry a target-influenced value into the report.
    result = parse(ssl_record())

    assert result.findings[0].affected_target == APPROVED
    # The record's own location is a different shape, so this is not a tautology.
    assert json.loads(ssl_record())["matched-at"] == "api.example.test:443"


@pytest.mark.parametrize("cwe", [["cve-2021-41773"], ["capec-66"], ["cwe2021"], ["CWE_79"]])
def test_an_identifier_from_another_taxonomy_is_not_read_as_a_cwe(cwe: list[str]) -> None:
    # Every malformed value previously listed was rejected by the digit or the
    # separator clause, so the prefix check was unasserted -- and without it a
    # CVE id becomes the finding's CWE and its vulnerability class, feeding a
    # confidently wrong label into the report and any ticket routing.
    result = parse(ssl_record(info={"classification": {"cwe-id": cwe}}))

    assert result.findings[0].cwe_id is None, cwe
    assert result.findings[0].vulnerability_class == "expired-ssl"
