"""Admit a nuclei match only when the record itself entails the claim.

nuclei's JSONL carries exactly one field that is evidence about the target: the
captured request/response pair. Everything else -- ``info.severity``,
``classification.cve-id``, ``cvss-score``, ``epss-score``, ``matcher-name``,
``metadata.verified`` -- is metadata about the *rule*, written by the template
author with no knowledge of this target. A mapper that grades records on rule
metadata grades the author's confidence, not the target's state, and that
conflation is the specific bug that makes a "critical" version-banner guess
look like a proven compromise.

So this parser does not soften a broad claim into a candidate. It either admits
a record whose evidence entails the claim, or it suppresses the record and says
why. There is no middle tier carrying a CVE title with a disclaimer attached,
because a CVE-titled row reads as "we found CVE-X" to every human and every
ticketing integration downstream, whatever its status field says.

That means a scan producing two hundred JSONL lines can legitimately yield zero
findings. A domain model that refuses undefendable claims has to be allowed to
output nothing, otherwise the refusal is decorative. What it may not do is
discard the decision: every suppressed record is returned with its template id,
its location and a reason, so the set is reviewable as a re-test queue and a
human can override a specific template.

Two claims this parser will never make:

* **DIFFERENTIAL.** nuclei expresses a control comparison natively, through
  multi-request templates with ``req-condition``, but the JSONL flattens the
  exchange into single ``request``/``response`` strings. Recovering "which of
  these pairs omitted the payload" from concatenated text is guesswork, and a
  differential claim without a produced control is exactly what the domain
  refuses. Findings from here are ``OBSERVED`` or they are suppressed.
* **Anything about a matcher's shape.** A status-only matcher and a
  content-specific one are indistinguishable in the output -- ``matcher-name``
  is an author-chosen label with no semantics the engine enforces. Admission is
  therefore decided by protocol type, template family and tags, which are the
  signals the record actually carries.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
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

_MAX_CWE_DIGITS: Final = 5

# nuclei's lowercase severity strings. An unset severity marshals as "" rather
# than "undefined", so the empty string has to be a key here.
_SEVERITIES: Final = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFORMATIONAL,
    "": FindingSeverity.INFORMATIONAL,
}

# Protocol types whose captured artifact any third party can re-derive with
# openssl or dig, which is the strongest form of independent checkability there
# is. The claim stays at the artifact level: an expired certificate is observed;
# "this name is takeoverable" would be an inference on top of it.
_REDERIVABLE_TYPES: Final = frozenset({"dns", "ssl"})

# Protocol types whose captured output is a local process's stdout. It may
# contain nothing derived from the target at all, so it is not evidence about
# the target regardless of what the template claims.
_LOCAL_EXECUTION_TYPES: Final = frozenset({"code", "javascript"})

# Tags that say the template matched a fingerprint rather than a condition.
_FINGERPRINT_TAGS: Final = frozenset({"detect", "detection", "favicon", "panel", "tech", "waf"})

# Tags that say the engine itself treats the result as a lead.
_LEAD_TAGS: Final = frozenset({"dast", "fuzz"})

# The tag for out-of-band confirmation. A record carrying it exists only when an
# interactsh server was named in the contract, and it means the target itself
# reached out to infrastructure the scanner controls -- which nothing in normal
# operation forges.
_OUT_OF_BAND_TAG: Final = "oast"

# Template families whose matcher is the sensitive artifact's own bytes rather
# than a status code, so the response is the claim.
_CONTENT_EXPOSURE_PREFIXES: Final = ("http/exposures/",)


class Admission(StrEnum):
    """Why a record was admitted as a finding."""

    REDERIVABLE_ARTIFACT = "rederivable_artifact"
    OUT_OF_BAND_INTERACTION = "out_of_band_interaction"
    CONTENT_EXPOSURE = "content_exposure"


class Suppression(StrEnum):
    """Why a record did not become a finding.

    Every value names a property of the *record*, never a judgement about the
    vulnerability. "We could not tell from this output" is the honest reason and
    the one a reviewer can act on.
    """

    NOT_A_RECORD = "not_a_record"
    MATCHER_MISS = "matcher_miss"
    OUT_OF_SCOPE = "out_of_scope"
    NO_CAPTURED_RESPONSE = "no_captured_response"
    NO_TARGET_DERIVED_OUTPUT = "no_target_derived_output"
    LEAD_ONLY = "lead_only"
    FINGERPRINT_ONLY = "fingerprint_only"
    VERSION_INFERENCE = "version_inference"
    EVIDENCE_NOT_IN_RECORD = "evidence_not_in_record"


@dataclass(frozen=True, slots=True)
class SuppressedRecord:
    """One record the parser declined to turn into a claim."""

    template_id: str
    reason: Suppression
    located_at: str
    detail: str


@dataclass(frozen=True, slots=True)
class NucleiParseResult:
    """Findings, plus every decision not to make one.

    ``suppressed`` is not a debug aid. It is the re-test queue and the audit of
    what the parser refused, which is what makes aggressive suppression
    reviewable instead of merely quiet.
    """

    findings: tuple[Finding, ...]
    suppressed: tuple[SuppressedRecord, ...]


def _records(stdout: str) -> Iterator[tuple[str, Any]]:
    """Yield each JSON document in the output, with the line it came from."""
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            yield stripped, json.loads(stripped)
        except json.JSONDecodeError:
            # A diagnostic line, or a partial final line from a killed run.
            # Raising would discard the records that did parse.
            continue


def _text(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    return value if isinstance(value, str) else ""


def _string_list(value: Any) -> tuple[str, ...]:
    """Return the strings in a nuclei list field.

    Several of these are declared as arrays but marshal as JSON ``null`` in
    real output -- ``info.tags``, ``info.author``, ``classification.cve-id`` and
    ``classification.cwe-id`` all do, because their Go types are structs whose
    ``omitempty`` is a no-op. So ``null`` is the common case, not the edge one.
    """
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _info(record: dict[str, Any]) -> dict[str, Any]:
    info = record.get("info")
    return info if isinstance(info, dict) else {}


def _classification(record: dict[str, Any]) -> dict[str, Any]:
    classification = _info(record).get("classification")
    return classification if isinstance(classification, dict) else {}


def _cwe_id(record: dict[str, Any]) -> str | None:
    """Return the first CWE as the domain spells it, or None.

    nuclei emits ``["cwe-798"]`` -- an array, lowercased by its own
    normalisation, and frequently ``null``. The domain requires ``CWE-798``.
    Getting this wrong is not a missing field: ``Finding.__post_init__`` raises
    on a malformed ``cwe_id``, so a bad value would abort the whole parse rather
    than drop one attribute. Anything unrecognised therefore returns None here.
    """
    for value in _string_list(_classification(record).get("cwe-id")):
        prefix, separator, number = value.partition("-")
        if (
            prefix.lower() == "cwe"
            and separator
            and number.isdigit()
            and 1 <= len(number) <= _MAX_CWE_DIGITS
        ):
            return f"CWE-{number}"
    return None


def _tags(record: dict[str, Any]) -> frozenset[str]:
    return frozenset(tag.lower() for tag in _string_list(_info(record).get("tags")))


def _claims_a_cve(record: dict[str, Any]) -> bool:
    return bool(_string_list(_classification(record).get("cve-id")))


def _template_path(record: dict[str, Any]) -> str:
    """Return the template's path within the corpus, which is its family.

    Only present when the template resolved relative to the templates directory,
    which is the normal case for a pinned corpus. Absent for a template loaded
    by absolute path -- and a record with no family cannot be routed, so it
    falls through to the default suppression rather than to an admission.
    """
    return _text(record, "template")


def _located_at(record: dict[str, Any]) -> str:
    """Return where the match happened, preferring the most specific field.

    ``host`` is unreliable -- in real http scans it is frequently absent
    entirely, because http and ssl templates fill it from a derived field that
    is often empty. ``matched-at`` is the locator that is actually populated,
    and for ssl and network templates it is ``host:port`` rather than a URL.
    """
    for key in ("matched-at", "url", "host"):
        value = _text(record, key)
        if value:
            return value
    return ""


def _describes_the_target(located_at: str, target: NormalizedTarget) -> bool:
    """Return whether the location names the approved host and port.

    Fails closed on anything unparseable. ``matched-at`` arrives in two shapes:
    an absolute URL for http templates, and a bare ``host:port`` for ssl and
    network ones, so both have to be understood without treating a bare
    authority as a URL.
    """
    if not located_at:
        return False
    if "://" in located_at:
        try:
            observed = normalize_target(located_at)
        except Exception:  # noqa: BLE001 - any unparseable value fails closed
            return False
        return observed.host == target.host and observed.port == target.port
    host, separator, port = located_at.rpartition(":")
    if not separator or not port.isdigit():
        # A bare hostname with no port cannot be checked against a target that
        # is bound to one, so it is not attributable.
        return False
    return host.strip("[]") == target.host and int(port) == target.port


def _classify(  # noqa: PLR0911 - one return per admission and refusal, on purpose
    record: dict[str, Any],
) -> tuple[Admission, FindingConfidence] | Suppression:
    """Decide a record's fate from what the record actually carries.

    Deliberately reads no severity, no CVSS, no EPSS and no ``metadata.verified``.
    Those describe the rule's author's view of the vulnerability class; none of
    them is a fact about this target, and letting any of them influence
    admission or confidence is how a scanner starts over-claiming.
    """
    protocol = _text(record, "type")
    tags = _tags(record)

    if protocol in _LOCAL_EXECUTION_TYPES:
        return Suppression.NO_TARGET_DERIVED_OUTPUT
    if tags & _LEAD_TAGS:
        return Suppression.LEAD_ONLY

    if _OUT_OF_BAND_TAG in tags:
        # The target contacted infrastructure the scanner controls. This is the
        # one class where a single record demonstrates the issue rather than
        # merely observing a condition consistent with it.
        #
        # MEDIUM rather than HIGH, and the reason is a limit of the output: an
        # HTTP or SMTP interaction is materially stronger evidence than a
        # DNS-only one, which resolver prefetch, a security middlebox or a
        # sandbox can also produce -- and the JSONL does not expose the
        # interaction protocol as its own field. Claiming HIGH without being
        # able to tell them apart would be over-claiming on the weaker case, so
        # this errs downward and a reviewer promotes it from the evidence.
        return (Admission.OUT_OF_BAND_INTERACTION, FindingConfidence.MEDIUM)

    if tags & _FINGERPRINT_TAGS:
        return Suppression.FINGERPRINT_ONLY
    if _claims_a_cve(record):
        # A CVE claim reached from a matched string is an inference over a vendor
        # version range, and that inference fails in well-documented ways --
        # distro backports that fix the bug without changing the version, a
        # rewritten or proxied banner, a vulnerable module that is not enabled.
        # The record entails "the target emitted this string" and nothing more,
        # and the verification enum has no slot for the rest.
        return Suppression.VERSION_INFERENCE

    if protocol in _REDERIVABLE_TYPES:
        return (Admission.REDERIVABLE_ARTIFACT, FindingConfidence.HIGH)
    template_path = _template_path(record)
    if template_path.startswith(_CONTENT_EXPOSURE_PREFIXES):
        # Retrievability is observed. Whether the retrieved content is sensitive
        # at this target is not, which is why the confidence is not HIGH.
        return (Admission.CONTENT_EXPOSURE, FindingConfidence.MEDIUM)
    return Suppression.EVIDENCE_NOT_IN_RECORD


def parse_nuclei_output(
    engagement_id: EngagementId,
    target: str,
    evidence_id: EvidenceId,
    stdout: str,
) -> NucleiParseResult:
    """Turn one nuclei run's JSONL into admitted findings and reasoned refusals."""
    normalized = normalize_target(target)
    findings: list[Finding] = []
    suppressed: list[SuppressedRecord] = []
    seen: set[tuple[str, str]] = set()

    def refuse(record: dict[str, Any], reason: Suppression, detail: str) -> None:
        suppressed.append(
            SuppressedRecord(
                template_id=_text(record, "template-id") or "<unknown>",
                reason=reason,
                located_at=_located_at(record),
                detail=detail,
            )
        )

    for line, document in _records(stdout):
        if not isinstance(document, dict):
            suppressed.append(
                SuppressedRecord(
                    template_id="<unknown>",
                    reason=Suppression.NOT_A_RECORD,
                    located_at="",
                    detail=f"valid JSON but not an object: {line[:80]}",
                )
            )
            continue

        # -matcher-status writes a record for a request that did NOT match. The
        # existence of a line is therefore not a hit, and this has to be checked
        # before anything else or the parser manufactures findings out of misses.
        if document.get("matcher-status") is False:
            refuse(document, Suppression.MATCHER_MISS, "matcher-status reported a miss")
            continue

        located_at = _located_at(document)
        if not _describes_the_target(located_at, normalized):
            refuse(
                document,
                Suppression.OUT_OF_SCOPE,
                f"match located at {located_at or '<nowhere>'}, not at {normalized}",
            )
            continue

        if not _text(document, "response"):
            # OBSERVED means "one captured response read against a fixed
            # expectation". With no captured response there is nothing to be
            # observed against, so no finding is constructible at any status --
            # and a whole run reported this way is the signal that the collector
            # ran with -omit-raw, which is loud here rather than silent.
            refuse(document, Suppression.NO_CAPTURED_RESPONSE, "record carries no response")
            continue

        outcome = _classify(document)
        if isinstance(outcome, Suppression):
            refuse(document, outcome, f"template family {_template_path(document) or '<unknown>'}")
            continue

        admission, confidence = outcome
        template_id = _text(document, "template-id") or "<unknown>"
        cwe = _cwe_id(document)
        title = _text(_info(document), "name") or template_id
        key = (title, cwe or template_id)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                engagement_id=engagement_id,
                title=title,
                vulnerability_class=cwe or template_id,
                cwe_id=cwe,
                affected_target=str(normalized),
                evidence_ids=(evidence_id,),
                status=FindingStatus.VERIFIED,
                # Never DIFFERENTIAL: see the module docstring. The JSONL cannot
                # be shown to contain a control, and a claimed control that
                # cannot be produced is what the domain refuses.
                verification_method=VerificationMethod.OBSERVED,
                # Severity is read here and nowhere else, and it never reaches
                # confidence. nuclei's severity is the vulnerability class's
                # CVSS-aligned impact, assigned at authoring time; confidence is
                # a property of this record's evidence. Wiring one to the other
                # is the over-claiming bug this parser exists to avoid.
                severity=_SEVERITIES.get(
                    _text(_info(document), "severity").lower(), FindingSeverity.INFORMATIONAL
                ),
                confidence=confidence,
                remediation=(
                    _text(_info(document), "remediation")
                    or f"Review the captured response for {template_id} ({admission.value})."
                ),
            )
        )

    return NucleiParseResult(findings=tuple(findings), suppressed=tuple(suppressed))
