"""What a nuclei match is allowed to claim, and what it is refused for.

Most of these tests assert that nothing was emitted. That is the point: across a
corpus of thousands of community templates, the families whose match a third
party cannot check are simultaneously the most numerous and the least
defensible, so they set the perceived error rate of everything the control plane
ships. A parser that admits them passes every positive test and still produces a
report nobody acts on.

The other half of that bargain is the suppression log. Refusing quietly would be
indistinguishable from a broken parser, so every refusal is returned with its
template id, its location and a reason.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from vuln_proof_claw.domain.enums import (
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    VerificationMethod,
)
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.tooling.parsers import (
    NucleiParseResult,
    Suppression,
    parse_nuclei_output,
)

ENGAGEMENT = EngagementId("00000000-0000-7000-8000-000000000001")
EVIDENCE = EvidenceId("00000000-0000-7000-8000-000000000002")
TARGET = "https://api.example.test/v1"


def record(**overrides: Any) -> str:
    """One nuclei JSONL line for the target.

    The default is an ssl record, because that is one of the few families whose
    artifact a third party can re-derive, so it is the natural baseline for
    "admitted" and every suppression test overrides its way out of it.
    """
    info: dict[str, Any] = {
        "name": "Expired SSL Certificate",
        "author": ["pdteam"],
        "tags": ["ssl", "expiry"],
        "severity": "low",
        "remediation": "Renew the certificate.",
    }
    info.update(overrides.pop("info", {}))
    document: dict[str, Any] = {
        "template": "ssl/expired-ssl.yaml",
        "template-id": "expired-ssl",
        "info": info,
        "type": "ssl",
        "matched-at": "api.example.test:443",
        "response": "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
        "timestamp": "2026-08-27T12:00:00.000000000Z",
    }
    document.update(overrides)
    return json.dumps(document)


def parse(stdout: str, *, target: str = TARGET) -> NucleiParseResult:
    return parse_nuclei_output(ENGAGEMENT, target, EVIDENCE, stdout)


def titles(stdout: str, *, target: str = TARGET) -> tuple[str, ...]:
    return tuple(f.title for f in parse(stdout, target=target).findings)


def reasons(stdout: str, *, target: str = TARGET) -> tuple[Suppression, ...]:
    return tuple(s.reason for s in parse(stdout, target=target).suppressed)


# --------------------------------------------------------------------------- #
# What gets admitted
# --------------------------------------------------------------------------- #


def test_an_independently_rederivable_artifact_is_admitted() -> None:
    # A certificate is re-fetchable by anyone with openssl, which is the
    # strongest form of third-party checkability available.
    result = parse(record())

    assert [f.title for f in result.findings] == ["Expired SSL Certificate"]
    assert result.suppressed == ()
    finding = result.findings[0]
    assert finding.status is FindingStatus.VERIFIED
    assert finding.verification_method is VerificationMethod.OBSERVED
    assert finding.confidence is FindingConfidence.HIGH
    assert finding.severity is FindingSeverity.LOW
    assert finding.evidence_ids == (EVIDENCE,)


def test_a_dns_record_assertion_is_admitted_on_the_same_grounds() -> None:
    # Re-derivable with dig.
    dns = record(
        template="dns/dmarc-detect.yaml",
        **{"template-id": "dmarc-detect"},
        type="dns",
        info={"name": "DMARC record missing", "tags": ["dns", "dmarc"], "severity": "info"},
        **{"matched-at": "api.example.test:443"},
    )

    assert titles(dns) == ("DMARC record missing",)


def test_an_out_of_band_interaction_is_admitted_on_the_interaction_itself() -> None:
    # The target reached out to infrastructure the scanner controls, and the
    # record carries the callback: its protocol and the unique token correlating
    # it to this request. The `oast` tag alone does NOT admit this -- see
    # test_nuclei_parser_adversarial.py, where one tag string used to mint a
    # VERIFIED CVE row from a record containing no interaction at all.
    oob = record(
        template="http/vulnerabilities/generic/oob-ssrf.yaml",
        **{"template-id": "oob-ssrf", "matched-at": TARGET},
        type="http",
        info={"name": "Blind SSRF", "tags": ["ssrf", "oast"], "severity": "high"},
        interaction={
            "protocol": "http",
            "unique-id": "c9s1k2q0k1s0oabcdefg",
            "raw-request": "GET / HTTP/1.1\r\n\r\n",
        },
    )

    result = parse(oob)

    assert [f.title for f in result.findings] == ["Blind SSRF"]
    assert result.findings[0].confidence is FindingConfidence.HIGH
    assert result.findings[0].severity is FindingSeverity.HIGH


def test_a_content_specific_exposure_is_admitted_at_medium_confidence() -> None:
    # Retrievability is observed. Whether the retrieved content is sensitive at
    # this target is not, so the confidence is not HIGH.
    exposure = record(
        template="http/exposures/configs/git-config.yaml",
        **{"template-id": "git-config", "matched-at": TARGET},
        type="http",
        info={
            "name": "Git configuration exposed",
            "tags": ["config", "exposure"],
            "severity": "medium",
        },
    )

    result = parse(exposure)

    assert [f.title for f in result.findings] == ["Git configuration exposed"]
    assert result.findings[0].confidence is FindingConfidence.MEDIUM


# --------------------------------------------------------------------------- #
# Admissibility gates
# --------------------------------------------------------------------------- #


def test_a_matcher_miss_is_never_a_finding() -> None:
    # -matcher-status writes a record for a request that did NOT match, so the
    # existence of a line is not a hit. This has to be checked before anything
    # else or the parser manufactures findings out of misses.
    assert titles(record(**{"matcher-status": False})) == ()
    assert reasons(record(**{"matcher-status": False})) == (Suppression.MATCHER_MISS,)


def test_a_record_without_any_captured_evidence_claims_nothing() -> None:
    # OBSERVED means "one captured artifact read against a fixed expectation".
    # A response is one such artifact and a correlated out-of-band interaction
    # is the other; with neither there is nothing to be observed against. A
    # whole run reported this way is the signal that the collector ran with
    # -omit-raw -- loud here, rather than silently yielding zero findings.
    assert reasons(record(response="")) == (Suppression.NO_CAPTURED_EVIDENCE,)
    stripped = json.loads(record())
    stripped.pop("response")
    assert reasons(json.dumps(stripped)) == (Suppression.NO_CAPTURED_EVIDENCE,)


@pytest.mark.parametrize(
    "elsewhere",
    [
        "https://unrelated.example.net/",
        "unrelated.example.net:443",
        "api.example.test:8443",
        "api.example.test",
        "not a location",
        "",
        # Carries a scheme, so it is read as a URL -- and is then unparseable,
        # which has to fail closed rather than raise out of the parse.
        "ftp://api.example.test:443/v1",
        "https://",
        "://api.example.test",
    ],
)
def test_a_match_that_is_not_at_the_approved_target_is_dropped(elsewhere: str) -> None:
    # Scope binds host and port together. A bare hostname with no port cannot be
    # checked against a target bound to one, so it is not attributable either.
    line = record(**{"matched-at": elsewhere})
    line = json.dumps({**json.loads(line), "url": elsewhere, "host": elsewhere})

    assert titles(line) == ()
    assert reasons(line) == (Suppression.OUT_OF_SCOPE,)


def test_a_local_execution_template_is_not_evidence_about_the_target() -> None:
    # A code or javascript template's captured output is a local process's
    # stdout, which may contain nothing derived from the target at all.
    for protocol in ("code", "javascript"):
        line = record(type=protocol, response="exit status 0")
        assert reasons(line) == (Suppression.NO_TARGET_DERIVED_OUTPUT,), protocol


# --------------------------------------------------------------------------- #
# The families that are deliberately silenced
# --------------------------------------------------------------------------- #


def test_a_fingerprint_is_inventory_not_a_finding() -> None:
    for tag in ("tech", "detect", "detection", "panel", "favicon", "waf"):
        line = record(
            type="http",
            **{"matched-at": TARGET},
            template="http/technologies/nginx-version.yaml",
            info={"name": "Nginx version", "tags": [tag], "severity": "info"},
        )
        assert reasons(line) == (Suppression.FINGERPRINT_ONLY,), tag


def test_a_cve_reached_from_a_matched_string_is_refused_not_softened() -> None:
    # This is the largest family in the corpus and the one with no available
    # verification method: the record entails "the target emitted this string",
    # and everything after that is inference over a vendor version range. The
    # wrong answer is to keep the CVE title and mark it CANDIDATE -- a
    # CVE-titled row reads as "we found CVE-X" to every human and every
    # ticketing integration downstream, whatever its status says.
    line = record(
        type="http",
        **{"matched-at": TARGET},
        template="http/cves/2021/CVE-2021-41773.yaml",
        info={
            "name": "Apache HTTP Server 2.4.49 - Path Traversal",
            "tags": ["cve", "cve2021", "apache", "lfi"],
            "severity": "critical",
            "classification": {
                "cve-id": ["cve-2021-41773"],
                "cwe-id": ["cwe-22"],
                "cvss-score": 9.8,
            },
        },
    )

    result = parse(line)

    assert result.findings == ()
    assert [s.reason for s in result.suppressed] == [Suppression.VERSION_INFERENCE]


def test_a_lead_only_template_is_refused_even_though_the_argv_excludes_it() -> None:
    # The argv never passes -fuzz and excludes the tag, so this should be
    # unreachable. Refusing it here as well means a corpus or flag change cannot
    # turn leads into findings without this test going red.
    for tag in ("fuzz", "dast"):
        line = record(type="http", **{"matched-at": TARGET}, info={"tags": [tag]})
        assert reasons(line) == (Suppression.LEAD_ONLY,), tag


def test_an_unroutable_family_is_refused_rather_than_guessed_at() -> None:
    # A status-only matcher and a content-specific one are indistinguishable in
    # the output, so a family the parser cannot place does not get the benefit
    # of the doubt.
    line = record(
        type="http",
        **{"matched-at": TARGET},
        template="http/misconfiguration/something.yaml",
        info={"name": "Something", "tags": ["misconfig"], "severity": "medium"},
    )

    assert reasons(line) == (Suppression.EVIDENCE_NOT_IN_RECORD,)


def test_two_hundred_lines_may_legitimately_produce_no_findings() -> None:
    # A domain model that refuses undefendable claims has to be allowed to
    # output nothing, otherwise the refusal is decorative. What it may not do is
    # lose the decision -- every refusal is in the log with a reason.
    noisy = "\n".join(
        record(
            type="http",
            **{"matched-at": TARGET, "template-id": f"exposed-panel-{index}"},
            template="http/exposed-panels/panel.yaml",
            info={"name": f"Panel {index}", "tags": ["panel"], "severity": "high"},
        )
        for index in range(200)
    )

    result = parse(noisy)

    assert result.findings == ()
    assert len(result.suppressed) == 200
    assert {s.reason for s in result.suppressed} == {Suppression.FINGERPRINT_ONLY}
    # The queue is reviewable: a human can override one template id.
    assert result.suppressed[7].template_id == "exposed-panel-7"


# --------------------------------------------------------------------------- #
# Rule metadata must not reach the claim
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info", ""])
def test_severity_cannot_change_confidence_or_status(severity: str) -> None:
    # nuclei's severity is the vulnerability class's CVSS-aligned impact,
    # assigned at authoring time with no knowledge of this target. Confidence is
    # a property of this record's evidence. Wiring one to the other is the
    # specific bug that makes a "critical" version-banner guess look like a
    # proven compromise, so there must be no code path between them.
    result = parse(record(info={"severity": severity}))

    assert len(result.findings) == 1
    assert result.findings[0].confidence is FindingConfidence.HIGH
    assert result.findings[0].status is FindingStatus.VERIFIED


def test_severity_cannot_promote_a_refused_record() -> None:
    line = record(
        type="http",
        **{"matched-at": TARGET},
        template="http/technologies/x.yaml",
        info={"tags": ["tech"], "severity": "critical"},
    )

    assert parse(line).findings == ()


def test_an_unrecognised_severity_does_not_abort_the_parse() -> None:
    result = parse(record(info={"severity": "apocalyptic"}))

    assert len(result.findings) == 1
    assert result.findings[0].severity is FindingSeverity.INFORMATIONAL


# --------------------------------------------------------------------------- #
# The CWE conversion, which is the one place a bad value aborts everything
# --------------------------------------------------------------------------- #


def test_a_lowercase_cwe_array_becomes_the_identifier_the_domain_requires() -> None:
    # nuclei emits ["cwe-798"]; the domain requires "CWE-798" and raises on
    # anything else. Getting this wrong would abort the whole parse rather than
    # drop one attribute.
    line = record(info={"classification": {"cwe-id": ["cwe-798"], "cve-id": None}})

    finding = parse(line).findings[0]
    assert finding.cwe_id == "CWE-798"
    assert finding.vulnerability_class == "CWE-798"


@pytest.mark.parametrize(
    "cwe",
    [
        None,
        [],
        ["not-a-cwe"],
        ["cwe-"],
        ["cwe-abc"],
        ["cwe-1234567"],
        [123],
        "cwe-798",
        {"id": "cwe-798"},
    ],
)
def test_a_cwe_the_domain_would_reject_is_dropped_not_raised(cwe: object) -> None:
    # Finding.__post_init__ raises on a malformed cwe_id, so passing one through
    # would take the whole run's findings with it.
    line = record(info={"classification": {"cwe-id": cwe}})

    result = parse(line)

    assert len(result.findings) == 1
    assert result.findings[0].cwe_id is None
    # Something still has to identify what was checked.
    assert result.findings[0].vulnerability_class == "expired-ssl"


def test_the_first_usable_cwe_is_taken_when_several_are_listed() -> None:
    line = record(info={"classification": {"cwe-id": ["nonsense", "cwe-79", "cwe-89"]}})

    assert parse(line).findings[0].cwe_id == "CWE-79"


# --------------------------------------------------------------------------- #
# Output robustness
# --------------------------------------------------------------------------- #


def test_diagnostics_and_a_truncated_line_do_not_discard_the_records_that_parsed() -> None:
    stdout = "\n".join(
        [
            "[INF] Templates loaded for current scan: 12",
            "",
            record(),
            "   ",
            '{"template-id": "half',
        ]
    )

    assert titles(stdout) == ("Expired SSL Certificate",)


def test_valid_json_that_is_not_a_record_is_logged_rather_than_read() -> None:
    stdout = "\n".join(['["expired-ssl"]', "42", "null", record()])

    result = parse(stdout)

    assert [f.title for f in result.findings] == ["Expired SSL Certificate"]
    assert [s.reason for s in result.suppressed] == [Suppression.NOT_A_RECORD] * 3


@pytest.mark.parametrize("broken", [None, "info", [], 7])
def test_a_missing_or_null_info_block_does_not_change_what_was_observed(
    broken: object,
) -> None:
    # info is metadata about the rule. Losing it costs the name and the severity
    # but not the evidence topology, so an ssl record is still admitted -- with
    # the template id as its title and no severity claimed.
    line = json.dumps({**json.loads(record()), "info": broken})

    result = parse(line)

    assert [f.title for f in result.findings] == ["expired-ssl"], broken
    assert result.findings[0].severity is FindingSeverity.INFORMATIONAL


@pytest.mark.parametrize("broken", [None, "info", [], 7])
def test_a_missing_info_block_cannot_route_an_http_record_into_admission(
    broken: object,
) -> None:
    # Without tags or a family there is nothing to route on, and the parser does
    # not give an unroutable record the benefit of the doubt.
    line = json.dumps(
        {
            **json.loads(record()),
            "info": broken,
            "type": "http",
            "matched-at": TARGET,
            "template": "",
        }
    )

    assert reasons(line) == (Suppression.EVIDENCE_NOT_IN_RECORD,), broken


def test_a_null_tag_list_is_the_common_case_not_an_edge_case() -> None:
    # info.tags is declared an array but marshals as JSON null in real output,
    # because its Go type is a struct whose omitempty is a no-op.
    line = record(info={"tags": None})

    assert titles(line) == ("Expired SSL Certificate",)


def test_the_same_finding_from_two_records_is_emitted_once() -> None:
    assert titles("\n".join([record(), record()])) == ("Expired SSL Certificate",)


def test_a_record_with_no_name_falls_back_to_the_template_id() -> None:
    line = record(info={"name": "", "tags": ["ssl"], "severity": "low"})

    assert titles(line) == ("expired-ssl",)
