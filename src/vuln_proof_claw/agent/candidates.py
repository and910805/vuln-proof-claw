"""Turn oracle verdicts and recovered endpoints into persisted research objects.

This is the rung of the evidence ladder between "something was observed" and "someone
should look at this":

* a recovered endpoint becomes an :class:`Endpoint` in the knowledge base;
* a triggered verdict becomes a :class:`Candidate`;
* a candidate the planner accepts becomes a :class:`Lead`.

Nothing here produces a finding. A candidate asserts that a rule fired, not that a
vulnerability exists, and the wording of every record keeps that distinction visible so
a later reader cannot mistake one for the other.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.agent.differential import OracleRule, OracleVerdict
from vuln_proof_claw.agent.endpoints import EndpointClassification, EndpointRisk
from vuln_proof_claw.agent.leads import dedupe_key
from vuln_proof_claw.domain.autonomous import Asset, Candidate, Endpoint, Lead
from vuln_proof_claw.domain.enums import AssetKind, CandidateSource, LeadStatus
from vuln_proof_claw.domain.identifiers import AssetId, EngagementId, MissionId
from vuln_proof_claw.persistence.autonomous_repositories import (
    AssetRepository,
    CandidateRepository,
    EndpointRepository,
    LeadRepository,
)
from vuln_proof_claw.policy.scope import normalize_target

#: How confident a rule's own shape makes a candidate before any human looks at it.
#: These are properties of the rule, not judgements about a particular target: a rule
#: that compares two authenticated identities has no benign reading, while one that
#: observes a single response has several.
_RULE_CONFIDENCE: dict[OracleRule, float] = {
    OracleRule.HORIZONTAL_PRIVILEGE: 0.8,
    OracleRule.VERTICAL_PRIVILEGE: 0.75,
    OracleRule.MISSING_AUTHENTICATION: 0.65,
    OracleRule.UNAUTHENTICATED_ACCESS: 0.6,
    OracleRule.DENIAL_INCONSISTENCY: 0.3,
}

_RULE_CATEGORY: dict[OracleRule, str] = {
    OracleRule.HORIZONTAL_PRIVILEGE: "不安全之物件參照",
    OracleRule.VERTICAL_PRIVILEGE: "權限提升",
    OracleRule.MISSING_AUTHENTICATION: "缺乏身分鑑別",
    OracleRule.UNAUTHENTICATED_ACCESS: "不當存取控制",
    OracleRule.DENIAL_INCONSISTENCY: "敏感資訊洩露",
}

_MAXIMUM_PRIORITY = 100
_PRIORITY_SCALE = 100


@dataclass(frozen=True, slots=True)
class RecordedCandidates:
    """What one cycle's verdicts added to the knowledge base."""

    created: tuple[Candidate, ...] = ()
    duplicates: int = 0

    @property
    def total(self) -> int:
        return len(self.created)


def verdict_digest(verdict: OracleVerdict) -> str:
    """Return the key that makes the same observation idempotent across cycles.

    The reason is excluded deliberately: it contains byte counts and digests that shift
    between runs, and a candidate should not be recreated every cycle because a
    response grew by a byte.
    """
    material = f"{verdict.rule.value}\x1f{verdict.target}".encode()
    return hashlib.sha256(material).hexdigest()


def record_verdicts(
    session: Session,
    engagement_id: EngagementId,
    verdicts: Sequence[OracleVerdict],
    *,
    tool_name: str = "differential-oracle",
    at: datetime,
) -> RecordedCandidates:
    """Persist triggered verdicts as candidates, skipping ones already seen."""
    repository = CandidateRepository(session)
    created: list[Candidate] = []
    duplicates = 0

    for verdict in verdicts:
        if not verdict.triggered:
            continue
        digest = verdict_digest(verdict)
        if repository.find_by_digest(engagement_id, digest) is not None:
            duplicates += 1
            continue
        candidate = Candidate(
            engagement_id=engagement_id,
            source=CandidateSource.DIFFERENTIAL,
            tool_name=tool_name,
            title=f"{_RULE_CATEGORY.get(verdict.rule, verdict.rule.value)}：{verdict.target}",
            category=_RULE_CATEGORY.get(verdict.rule, verdict.rule.value),
            target=verdict.target,
            raw_digest=digest,
            severity_hint=verdict.rule.value,
            created_at=at,
        )
        repository.add(candidate)
        created.append(candidate)

    return RecordedCandidates(created=tuple(created), duplicates=duplicates)


def promote_candidate(
    session: Session,
    candidate: Candidate,
    *,
    mission_id: MissionId,
    verdict: OracleVerdict,
    at: datetime,
) -> Lead | None:
    """Turn a candidate into a lead the controller can schedule.

    Returns None when a lead for the same hypothesis already exists, so a target that
    keeps failing the same check does not accumulate duplicate work.
    """
    hypothesis = (
        f"規則 {verdict.rule.value} 於 {verdict.target} 觸發：{verdict.reason}。"
        "此為機器判定之候選，尚未經研究員驗證。"
    )
    key = dedupe_key(
        category=candidate.category, target=candidate.target, hypothesis=verdict.rule.value
    )
    repository = LeadRepository(session)
    if repository.find_by_dedupe_key(mission_id, key) is not None:
        return None

    confidence = _RULE_CONFIDENCE.get(verdict.rule, 0.5)
    lead = Lead(
        engagement_id=candidate.engagement_id,
        mission_id=mission_id,
        title=candidate.title,
        hypothesis=hypothesis,
        category=candidate.category,
        confidence=confidence,
        priority=min(_MAXIMUM_PRIORITY, int(confidence * _PRIORITY_SCALE)),
        status=LeadStatus.NEW,
        origin=("differential-oracle", verdict.rule.value),
        dedupe_key=key,
        next_action=candidate.target,
        created_at=at,
        updated_at=at,
    )
    repository.add(lead)
    CandidateRepository(session).attach_lead(candidate.id, lead.id)
    return lead


def record_endpoints(  # noqa: PLR0913 - each argument names a distinct fact
    session: Session,
    engagement_id: EngagementId,
    base_url: str,
    classifications: Sequence[EndpointClassification],
    *,
    source: str = "jsdiscovery",
    at: datetime,
) -> tuple[int, int]:
    """Persist recovered endpoints against their asset.

    Returns the count stored and the count held back. Destructive endpoints are stored
    too: they are the most interesting part of a target's surface, and an operator
    should see them listed even though the agent will never call them.
    """
    host = normalize_target(base_url).host
    asset = AssetRepository(session).observe(
        Asset(
            engagement_id=engagement_id,
            kind=AssetKind.API,
            identifier=host,
            first_seen_at=at,
            last_seen_at=at,
        )
    )
    repository = EndpointRepository(session)
    stored = 0
    held = 0
    for item in classifications:
        repository.observe(
            Endpoint(
                engagement_id=engagement_id,
                asset_id=AssetId(asset.entity.id),
                method=item.method,
                path=item.path,
                source=f"{source}:{item.risk.value}",
                first_seen_at=at,
                last_seen_at=at,
            )
        )
        stored += 1
        held += int(item.risk is EndpointRisk.DESTRUCTIVE)
    return (stored, held)


__all__ = [
    "RecordedCandidates",
    "promote_candidate",
    "record_endpoints",
    "record_verdicts",
    "verdict_digest",
]
