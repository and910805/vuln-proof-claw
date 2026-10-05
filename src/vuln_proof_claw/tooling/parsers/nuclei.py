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
from vuln_proof_claw.domain.errors import DomainValidationError
from vuln_proof_claw.domain.identifiers import EngagementId, EvidenceId
from vuln_proof_claw.domain.models import Finding
from vuln_proof_claw.policy.scope import NormalizedTarget, normalize_target

_MAX_CWE_DIGITS: Final = 5

# Sentinel for a line that is not JSON at all. Distinct from None, because None
# is a legitimate JSON document that also is not a record.
_UNPARSEABLE: Final = object()

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

# How much an out-of-band callback is worth, by the protocol the target used to
# make it. A DNS-only interaction is reproducible by resolver prefetch, a
# security middlebox or an AV sandbox, none of which is the target executing the
# payload. HTTP, SMTP and LDAP callbacks are not reproducible that way. An
# unrecognised protocol falls to LOW rather than being trusted.
_INTERACTION_CONFIDENCE: Final = {
    "http": FindingConfidence.HIGH,
    "https": FindingConfidence.HIGH,
    "smtp": FindingConfidence.HIGH,
    "smtps": FindingConfidence.HIGH,
    "ldap": FindingConfidence.HIGH,
    "dns": FindingConfidence.MEDIUM,
}

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

    UNPARSEABLE_LINE = "unparseable_line"
    NOT_A_RECORD = "not_a_record"
    MATCHER_MISS = "matcher_miss"
    OUT_OF_SCOPE = "out_of_scope"
    NO_CAPTURED_EVIDENCE = "no_captured_evidence"
    NO_TARGET_DERIVED_OUTPUT = "no_target_derived_output"
    LEAD_ONLY = "lead_only"
    FINGERPRINT_ONLY = "fingerprint_only"
    VERSION_INFERENCE = "version_inference"
    EVIDENCE_NOT_IN_RECORD = "evidence_not_in_record"
    DUPLICATE_OF_ADMITTED = "duplicate_of_admitted"
    REFUSED_BY_THE_DOMAIN = "refused_by_the_domain"


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


def _lines(stdout: str) -> Iterator[str]:
    """Split the output on newlines only, and on nothing else.

    ``str.splitlines()`` also splits on U+0085, U+000B, U+001C-U+001E, U+2028
    and U+2029. Go's ``encoding/json`` escapes everything below 0x20 and the two
    U+202x separators, but writes U+0085 through unescaped -- so a target that
    puts that one byte in a response body splits one JSONL record into two
    fragments, neither of which parses. The record then disappears from the
    findings *and* from the audit, which is a target deleting its own evidence.
    """
    for line in stdout.split("\n"):
        stripped = line.strip()
        if stripped:
            yield stripped


def _records(stdout: str) -> Iterator[tuple[str, Any]]:
    """Yield each line's parsed JSON, or the sentinel for a line that is not JSON.

    A line that fails to parse is yielded rather than dropped: raising would
    discard the records that did parse, and swallowing it silently would break
    the promise that every record's fate is reported.
    """
    for line in _lines(stdout):
        try:
            yield line, json.loads(line)
        except json.JSONDecodeError:
            yield line, _UNPARSEABLE


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


def _interaction(record: dict[str, Any]) -> dict[str, Any] | None:
    """Return the out-of-band interaction the record carries, or None.

    nuclei's ``ResultEvent`` holds the full interactsh interaction in its own
    field -- ``interaction``, an ``omitempty`` pointer -- with the protocol, the
    per-request unique token and the raw exchange nested inside. That object is
    the out-of-band evidence, and because it is omitted when absent, its absence
    is unambiguous and free to check.

    The ``oast`` tag is not a substitute for it. A tag is the template author's
    declaration that the rule *uses* out-of-band detection, and a template whose
    ``matchers-condition`` is ``or`` can match on its in-band branch and emit no
    interaction at all. Worse, the default contract passes ``-no-interactsh``,
    so in the default configuration the only shape an oast-tagged record can
    take is one with no interaction -- which is exactly the shape that must not
    be admitted as "the target called us back".
    """
    interaction = record.get("interaction")
    if not isinstance(interaction, dict) or not interaction:
        return None
    # A correlated callback names the token it was correlated against. Without
    # one there is nothing tying the interaction to this request.
    for key in ("unique-id", "unique_id", "full-id", "full_id"):
        if _text(interaction, key):
            return interaction
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

    interaction = _interaction(record)
    if interaction is not None:
        # The target contacted infrastructure the scanner controls, and the
        # record carries the interaction itself: its protocol, the unique token
        # that correlates it to this request, and the raw exchange. This is the
        # one class where a single record demonstrates the issue rather than
        # observing a condition consistent with it, so it outranks the metadata
        # refusals below -- a real callback is a fact about the target, and a
        # tag or a CVE id is not.
        #
        # Confidence follows the interaction's own protocol. A DNS-only callback
        # is reproducible by resolver prefetch, a security middlebox or a
        # sandbox; an HTTP or SMTP one is not.
        return (
            Admission.OUT_OF_BAND_INTERACTION,
            _INTERACTION_CONFIDENCE.get(
                _text(interaction, "protocol").lower(), FindingConfidence.LOW
            ),
        )

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
    seen: set[tuple[str, str, str]] = set()

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
        if document is _UNPARSEABLE or not isinstance(document, dict):
            # A diagnostic line, a partial final line from a killed run, or
            # valid JSON that is not a record. Logged rather than dropped: a
            # line vanishing from both the findings and the audit is how a
            # target deletes its own evidence.
            suppressed.append(
                SuppressedRecord(
                    template_id="<unknown>",
                    reason=(
                        Suppression.UNPARSEABLE_LINE
                        if document is _UNPARSEABLE
                        else Suppression.NOT_A_RECORD
                    ),
                    located_at="",
                    detail=f"{line[:80]}",
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

        if not _text(document, "response") and _interaction(document) is None:
            # OBSERVED means "one captured artifact read against a fixed
            # expectation". A response is one such artifact; a correlated
            # out-of-band interaction is the other, and for a blind callback the
            # interaction is the *only* evidence -- requiring a response there
            # would demand in-band data to admit an out-of-band claim. With
            # neither, nothing is constructible at any status, and a whole run
            # reported this way is the signal that the collector ran with
            # -omit-raw, which is loud here rather than silent.
            refuse(
                document,
                Suppression.NO_CAPTURED_EVIDENCE,
                "record carries neither a response nor an interaction",
            )
            continue

        outcome = _classify(document)
        if isinstance(outcome, Suppression):
            refuse(document, outcome, f"template family {_template_path(document) or '<unknown>'}")
            continue

        admission, confidence = outcome
        template_id = _text(document, "template-id") or "<unknown>"
        cwe = _cwe_id(document)
        title = _text(_info(document), "name").strip() or template_id
        # The location is part of the key. Two exposures of different secrets at
        # two different paths are two findings, and collapsing them on title
        # alone destroyed the second one -- with affected_target overwritten by
        # the approved target, neither location survived in the row that lived.
        key = (title, cwe or template_id, located_at)
        if key in seen:
            refuse(
                document,
                Suppression.DUPLICATE_OF_ADMITTED,
                f"same claim already admitted for {located_at}",
            )
            continue
        seen.add(key)
        try:
            findings.append(
                Finding(
                    engagement_id=engagement_id,
                    title=title,
                    vulnerability_class=cwe or template_id,
                    cwe_id=cwe,
                    affected_target=str(normalized),
                    evidence_ids=(evidence_id,),
                    status=FindingStatus.VERIFIED,
                    # Never DIFFERENTIAL: see the module docstring. The JSONL
                    # cannot be shown to contain a control, and a claimed control
                    # that cannot be produced is what the domain refuses.
                    verification_method=VerificationMethod.OBSERVED,
                    # Severity is read here and nowhere else, and it never
                    # reaches confidence. nuclei's severity is the vulnerability
                    # class's CVSS-aligned impact, assigned at authoring time;
                    # confidence is a property of this record's evidence. Wiring
                    # one to the other is the over-claiming bug this parser
                    # exists to avoid.
                    severity=_SEVERITIES.get(
                        _text(_info(document), "severity").lower(),
                        FindingSeverity.INFORMATIONAL,
                    ),
                    confidence=confidence,
                    remediation=(
                        _text(_info(document), "remediation").strip()
                        or f"Review the captured evidence for {template_id} ({admission.value})."
                    ),
                )
            )
        except DomainValidationError as error:
            # Template metadata reaches Finding's own validators, and one
            # malformed field used to abort the whole call: no result at all, so
            # every other finding in the run and the entire suppression log were
            # destroyed by one bad template. The blank-after-strip cases are
            # handled above; this refuses the single record for anything else.
            refuse(document, Suppression.REFUSED_BY_THE_DOMAIN, str(error))

    return NucleiParseResult(findings=tuple(findings), suppressed=tuple(suppressed))
