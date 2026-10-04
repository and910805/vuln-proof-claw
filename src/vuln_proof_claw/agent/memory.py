"""Persistent research memory.

The Planner must consult this before proposing any action. Every answer is derived
from stored rows, never from a model's recollection, so that a restarted process
recalls exactly what the previous one knew.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.domain.autonomous import ChangeEvent, Lead, Observation
from vuln_proof_claw.domain.enums import LeadStatus
from vuln_proof_claw.domain.identifiers import EngagementId, MissionId
from vuln_proof_claw.persistence.autonomous_repositories import (
    AssetRepository,
    ChangeEventRepository,
    EndpointRepository,
    LeadRepository,
    ObservationRepository,
)

_RECALL_LIMIT = 25

_FAILED_STATUSES = (LeadStatus.REJECTED, LeadStatus.STALE)


@dataclass(frozen=True, slots=True)
class MemoryRecall:
    """What the agent already knows about one hypothesis.

    This is the structured answer to the five questions the Planner must resolve before
    proposing work: what was tried, what failed, what is new, what changed, and whether
    a retry is justified.
    """

    lead: Lead
    attempt_count: int
    failure_count: int
    prior_failures: tuple[Lead, ...]
    new_observations: tuple[Observation, ...]
    recent_changes: tuple[ChangeEvent, ...]

    @property
    def has_new_evidence(self) -> bool:
        """Return whether anything new arrived since the lead was last attempted."""
        return bool(self.new_observations or self.recent_changes)

    @property
    def retry_justified(self) -> bool:
        """Return whether a previously failed lead has grounds to be retried."""
        return self.failure_count == 0 or self.has_new_evidence


@dataclass(frozen=True, slots=True)
class SurfaceCounts:
    """Current size of the known attack surface."""

    assets: int
    endpoints: int


class ResearchMemory:
    """Query the knowledge base on behalf of the Planner and the controller."""

    def __init__(self, session: Session, engagement_id: EngagementId) -> None:
        self._engagement_id = engagement_id
        self._assets = AssetRepository(session)
        self._endpoints = EndpointRepository(session)
        self._observations = ObservationRepository(session)
        self._changes = ChangeEventRepository(session)
        self._leads = LeadRepository(session)

    def recall(self, lead: Lead) -> MemoryRecall:
        """Return everything known about a lead, including grounds for a retry."""
        since = lead.last_attempt_at or lead.created_at
        return MemoryRecall(
            lead=lead,
            attempt_count=lead.attempt_count,
            failure_count=lead.failure_count,
            prior_failures=self.failed_hypotheses(lead.mission_id),
            new_observations=self._observations.list_since(
                self._engagement_id, since=since, limit=_RECALL_LIMIT
            ),
            recent_changes=self._changes.list_since(
                self._engagement_id, since=since, limit=_RECALL_LIMIT
            ),
        )

    def has_new_evidence_since(self, lead: Lead) -> bool:
        """Return whether new evidence arrived since the lead was last attempted.

        This is the authoritative input to the "do not retry without new evidence"
        rule, and it is deliberately not something the agent can assert for itself.
        """
        if lead.last_attempt_at is None:
            return True
        return bool(
            self._observations.list_since(self._engagement_id, since=lead.last_attempt_at, limit=1)
            or self._changes.list_since(self._engagement_id, since=lead.last_attempt_at, limit=1)
        )

    def failed_hypotheses(self, mission_id: MissionId) -> tuple[Lead, ...]:
        """Return hypotheses already ruled out, so they are not proposed again."""
        return tuple(
            stored.entity
            for stored in self._leads.list_by_status(
                mission_id, _FAILED_STATUSES, limit=_RECALL_LIMIT
            )
        )

    def observations_for(self, subject: str) -> tuple[Observation, ...]:
        """Return what has previously been recorded about one subject."""
        return self._observations.list_for_subject(
            self._engagement_id, subject, limit=_RECALL_LIMIT
        )

    def changes_since(self, since: datetime) -> tuple[ChangeEvent, ...]:
        """Return attack-surface changes detected after a point in time."""
        return self._changes.list_since(self._engagement_id, since=since, limit=_RECALL_LIMIT)

    def surface_counts(self) -> SurfaceCounts:
        """Return the current inventory size for status reporting."""
        return SurfaceCounts(
            assets=self._assets.count(self._engagement_id),
            endpoints=self._endpoints.count(self._engagement_id),
        )


__all__ = ["MemoryRecall", "ResearchMemory", "SurfaceCounts"]
