"""Repositories for persistent autonomous mission state and research memory."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from vuln_proof_claw.domain.autonomous import (
    AgentCycle,
    Asset,
    Candidate,
    ChangeEvent,
    Endpoint,
    Lead,
    Mission,
    MissionBudget,
    MissionCadence,
    MissionRun,
    Observation,
    SurfaceSnapshot,
)
from vuln_proof_claw.domain.enums import (
    AssetKind,
    CandidateSource,
    ChangeKind,
    CycleState,
    LeadStatus,
    MissionRunState,
    MissionState,
    ObservationKind,
    RiskLevel,
)
from vuln_proof_claw.domain.identifiers import (
    AgentCycleId,
    AssetId,
    CandidateId,
    ChangeEventId,
    EndpointId,
    EngagementId,
    EvidenceId,
    FindingId,
    LeadId,
    MissionId,
    MissionRunId,
    ObservationId,
    SurfaceSnapshotId,
    new_identifier,
)
from vuln_proof_claw.persistence.models import (
    AgentCycleRecord,
    AssetRecord,
    BudgetLedgerRecord,
    CandidateRecord,
    ChangeEventRecord,
    EndpointRecord,
    LeadRecord,
    MissionRecord,
    MissionRunRecord,
    ObservationRecord,
    SurfaceSnapshotRecord,
)
from vuln_proof_claw.persistence.repositories import (
    ConcurrentUpdateError,
    Stored,
    _utc,
)

_DEFAULT_LIMIT = 100


class MissionRepository:
    """Persist autonomous campaign configuration and state."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, mission: Mission) -> None:
        self._session.add(
            MissionRecord(
                id=mission.id,
                engagement_id=mission.engagement_id,
                name=mission.name,
                state=mission.state.value,
                maximum_autonomous_risk=mission.maximum_autonomous_risk.value,
                kill_switch_engaged=mission.kill_switch_engaged,
                cadence=asdict(mission.cadence),
                budget=asdict(mission.budget),
                expires_at=mission.expires_at,
                created_at=mission.created_at,
                updated_at=mission.updated_at,
            )
        )
        self._session.flush()

    def get(self, mission_id: MissionId) -> Stored[Mission] | None:
        row = self._session.get(MissionRecord, mission_id)
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def find_by_name(self, engagement_id: EngagementId, name: str) -> Stored[Mission] | None:
        row = self._session.scalar(
            select(MissionRecord).where(
                MissionRecord.engagement_id == engagement_id,
                MissionRecord.name == name,
            )
        )
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def list_by_state(
        self,
        state: MissionState,
        *,
        limit: int = _DEFAULT_LIMIT,
    ) -> tuple[Stored[Mission], ...]:
        rows = self._session.scalars(
            select(MissionRecord)
            .where(MissionRecord.state == state.value)
            .order_by(MissionRecord.updated_at.asc(), MissionRecord.id.asc())
            .limit(limit)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    def save(self, mission: Mission, *, expected_version: int) -> Stored[Mission]:
        row = self._session.scalar(
            select(MissionRecord).where(
                MissionRecord.id == mission.id,
                MissionRecord.version == expected_version,
            )
        )
        if row is None:
            raise ConcurrentUpdateError
        row.state = mission.state.value
        row.kill_switch_engaged = mission.kill_switch_engaged
        row.cadence = asdict(mission.cadence)
        row.budget = asdict(mission.budget)
        row.expires_at = mission.expires_at
        row.updated_at = mission.updated_at
        self._session.flush()
        return Stored(self._domain_from_record(row), row.version)

    @staticmethod
    def _domain_from_record(row: MissionRecord) -> Mission:
        return Mission(
            id=MissionId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            name=row.name,
            state=MissionState(row.state),
            maximum_autonomous_risk=RiskLevel(row.maximum_autonomous_risk),
            kill_switch_engaged=row.kill_switch_engaged,
            cadence=MissionCadence(**row.cadence),
            budget=MissionBudget(**row.budget),
            expires_at=_utc(row.expires_at) if row.expires_at else None,
            created_at=_utc(row.created_at),
            updated_at=_utc(row.updated_at),
        )


class MissionRunRepository:
    """Persist crash-recoverable mission execution spans."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, run: MissionRun) -> None:
        self._session.add(
            MissionRunRecord(
                id=run.id,
                engagement_id=run.engagement_id,
                mission_id=run.mission_id,
                state=run.state.value,
                cycle_index=run.cycle_index,
                worker_identity=run.worker_identity,
                error_code=run.error_code,
                started_at=run.started_at,
                heartbeat_at=run.heartbeat_at,
                ended_at=run.ended_at,
            )
        )
        self._session.flush()

    def get(self, run_id: MissionRunId) -> Stored[MissionRun] | None:
        row = self._session.get(MissionRunRecord, run_id)
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def list_running(self, *, limit: int = _DEFAULT_LIMIT) -> tuple[Stored[MissionRun], ...]:
        rows = self._session.scalars(
            select(MissionRunRecord)
            .where(MissionRunRecord.state == MissionRunState.RUNNING.value)
            .order_by(MissionRunRecord.heartbeat_at.asc(), MissionRunRecord.id.asc())
            .limit(limit)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    def save(self, run: MissionRun, *, expected_version: int) -> Stored[MissionRun]:
        row = self._session.scalar(
            select(MissionRunRecord).where(
                MissionRunRecord.id == run.id,
                MissionRunRecord.version == expected_version,
            )
        )
        if row is None:
            raise ConcurrentUpdateError
        row.state = run.state.value
        row.cycle_index = run.cycle_index
        row.error_code = run.error_code
        row.heartbeat_at = run.heartbeat_at
        row.ended_at = run.ended_at
        self._session.flush()
        return Stored(self._domain_from_record(row), row.version)

    @staticmethod
    def _domain_from_record(row: MissionRunRecord) -> MissionRun:
        return MissionRun(
            id=MissionRunId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            mission_id=MissionId(row.mission_id),
            state=MissionRunState(row.state),
            cycle_index=row.cycle_index,
            worker_identity=row.worker_identity,
            error_code=row.error_code,
            started_at=_utc(row.started_at),
            heartbeat_at=_utc(row.heartbeat_at),
            ended_at=_utc(row.ended_at) if row.ended_at else None,
        )


class AgentCycleRepository:
    """Persist one observe, plan, act, and verify iteration."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, cycle: AgentCycle) -> None:
        self._session.add(
            AgentCycleRecord(
                id=cycle.id,
                engagement_id=cycle.engagement_id,
                mission_run_id=cycle.mission_run_id,
                index=cycle.index,
                state=cycle.state.value,
                leads_considered=cycle.leads_considered,
                actions_proposed=cycle.actions_proposed,
                actions_executed=cycle.actions_executed,
                candidates_created=cycle.candidates_created,
                findings_created=cycle.findings_created,
                error_code=cycle.error_code,
                started_at=cycle.started_at,
                ended_at=cycle.ended_at,
            )
        )
        self._session.flush()

    def get(self, cycle_id: AgentCycleId) -> Stored[AgentCycle] | None:
        row = self._session.get(AgentCycleRecord, cycle_id)
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def list_for_run(
        self,
        run_id: MissionRunId,
        *,
        limit: int = _DEFAULT_LIMIT,
    ) -> tuple[Stored[AgentCycle], ...]:
        rows = self._session.scalars(
            select(AgentCycleRecord)
            .where(AgentCycleRecord.mission_run_id == run_id)
            .order_by(AgentCycleRecord.index.desc())
            .limit(limit)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    def save(self, cycle: AgentCycle, *, expected_version: int) -> Stored[AgentCycle]:
        row = self._session.scalar(
            select(AgentCycleRecord).where(
                AgentCycleRecord.id == cycle.id,
                AgentCycleRecord.version == expected_version,
            )
        )
        if row is None:
            raise ConcurrentUpdateError
        row.state = cycle.state.value
        row.leads_considered = cycle.leads_considered
        row.actions_proposed = cycle.actions_proposed
        row.actions_executed = cycle.actions_executed
        row.candidates_created = cycle.candidates_created
        row.findings_created = cycle.findings_created
        row.error_code = cycle.error_code
        row.ended_at = cycle.ended_at
        self._session.flush()
        return Stored(self._domain_from_record(row), row.version)

    @staticmethod
    def _domain_from_record(row: AgentCycleRecord) -> AgentCycle:
        return AgentCycle(
            id=AgentCycleId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            mission_run_id=MissionRunId(row.mission_run_id),
            index=row.index,
            state=CycleState(row.state),
            leads_considered=row.leads_considered,
            actions_proposed=row.actions_proposed,
            actions_executed=row.actions_executed,
            candidates_created=row.candidates_created,
            findings_created=row.findings_created,
            error_code=row.error_code,
            started_at=_utc(row.started_at),
            ended_at=_utc(row.ended_at) if row.ended_at else None,
        )


class LeadRepository:
    """Persist research hypotheses and their investigation history."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, lead: Lead) -> None:
        self._session.add(
            LeadRecord(
                id=lead.id,
                engagement_id=lead.engagement_id,
                mission_id=lead.mission_id,
                asset_id=lead.asset_id,
                endpoint_id=lead.endpoint_id,
                title=lead.title,
                hypothesis=lead.hypothesis,
                category=lead.category,
                confidence=lead.confidence,
                priority=lead.priority,
                status=lead.status.value,
                origin=list(lead.origin),
                evidence_ids=list(lead.evidence_ids),
                related_findings=list(lead.related_findings),
                attempt_count=lead.attempt_count,
                failure_count=lead.failure_count,
                last_attempt_at=lead.last_attempt_at,
                next_attempt_at=lead.next_attempt_at,
                last_reasoning_summary=lead.last_reasoning_summary,
                next_action=lead.next_action,
                blocked_reason=lead.blocked_reason,
                dedupe_key=lead.dedupe_key,
                created_at=lead.created_at,
                updated_at=lead.updated_at,
            )
        )
        self._session.flush()

    def get(self, lead_id: LeadId) -> Stored[Lead] | None:
        row = self._session.get(LeadRecord, lead_id)
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def find_by_dedupe_key(self, mission_id: MissionId, dedupe_key: str) -> Stored[Lead] | None:
        row = self._session.scalar(
            select(LeadRecord).where(
                LeadRecord.mission_id == mission_id,
                LeadRecord.dedupe_key == dedupe_key,
            )
        )
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def list_by_status(
        self,
        mission_id: MissionId,
        statuses: tuple[LeadStatus, ...],
        *,
        limit: int = _DEFAULT_LIMIT,
    ) -> tuple[Stored[Lead], ...]:
        rows = self._session.scalars(
            self._status_query(mission_id, statuses)
            .order_by(LeadRecord.priority.desc(), LeadRecord.created_at.asc())
            .limit(limit)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    def list_due(
        self,
        mission_id: MissionId,
        statuses: tuple[LeadStatus, ...],
        *,
        at: datetime,
        limit: int = _DEFAULT_LIMIT,
    ) -> tuple[Stored[Lead], ...]:
        """Return schedulable leads whose cooldown has elapsed, highest priority first."""
        rows = self._session.scalars(
            self._status_query(mission_id, statuses)
            .where(
                (LeadRecord.next_attempt_at.is_(None)) | (LeadRecord.next_attempt_at <= at),
            )
            .order_by(LeadRecord.priority.desc(), LeadRecord.created_at.asc())
            .limit(limit)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    def count_by_status(self, mission_id: MissionId) -> dict[LeadStatus, int]:
        rows = self._session.execute(
            select(LeadRecord.status, func.count())
            .where(LeadRecord.mission_id == mission_id)
            .group_by(LeadRecord.status)
        )
        return {LeadStatus(status): total for status, total in rows}

    def save(self, lead: Lead, *, expected_version: int) -> Stored[Lead]:
        row = self._session.scalar(
            select(LeadRecord).where(
                LeadRecord.id == lead.id,
                LeadRecord.version == expected_version,
            )
        )
        if row is None:
            raise ConcurrentUpdateError
        row.asset_id = lead.asset_id
        row.endpoint_id = lead.endpoint_id
        row.title = lead.title
        row.hypothesis = lead.hypothesis
        row.category = lead.category
        row.confidence = lead.confidence
        row.priority = lead.priority
        row.status = lead.status.value
        row.origin = list(lead.origin)
        row.evidence_ids = list(lead.evidence_ids)
        row.related_findings = list(lead.related_findings)
        row.attempt_count = lead.attempt_count
        row.failure_count = lead.failure_count
        row.last_attempt_at = lead.last_attempt_at
        row.next_attempt_at = lead.next_attempt_at
        row.last_reasoning_summary = lead.last_reasoning_summary
        row.next_action = lead.next_action
        row.blocked_reason = lead.blocked_reason
        row.updated_at = lead.updated_at
        self._session.flush()
        return Stored(self._domain_from_record(row), row.version)

    @staticmethod
    def _status_query(
        mission_id: MissionId,
        statuses: tuple[LeadStatus, ...],
    ) -> Select[tuple[LeadRecord]]:
        return select(LeadRecord).where(
            LeadRecord.mission_id == mission_id,
            LeadRecord.status.in_([status.value for status in statuses]),
        )

    @staticmethod
    def _domain_from_record(row: LeadRecord) -> Lead:
        return Lead(
            id=LeadId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            mission_id=MissionId(row.mission_id),
            asset_id=AssetId(row.asset_id) if row.asset_id else None,
            endpoint_id=EndpointId(row.endpoint_id) if row.endpoint_id else None,
            title=row.title,
            hypothesis=row.hypothesis,
            category=row.category,
            confidence=row.confidence,
            priority=row.priority,
            status=LeadStatus(row.status),
            origin=tuple(row.origin),
            evidence_ids=tuple(EvidenceId(item) for item in row.evidence_ids),
            related_findings=tuple(FindingId(item) for item in row.related_findings),
            attempt_count=row.attempt_count,
            failure_count=row.failure_count,
            last_attempt_at=_utc(row.last_attempt_at) if row.last_attempt_at else None,
            next_attempt_at=_utc(row.next_attempt_at) if row.next_attempt_at else None,
            last_reasoning_summary=row.last_reasoning_summary,
            next_action=row.next_action,
            blocked_reason=row.blocked_reason,
            dedupe_key=row.dedupe_key,
            created_at=_utc(row.created_at),
            updated_at=_utc(row.updated_at),
        )


class AssetRepository:
    """Persist the discovered asset inventory."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def observe(self, asset: Asset) -> Stored[Asset]:
        """Insert a new asset or extend the last-seen time of a known one."""
        row = self._session.scalar(
            select(AssetRecord).where(
                AssetRecord.engagement_id == asset.engagement_id,
                AssetRecord.kind == asset.kind.value,
                AssetRecord.identifier == asset.identifier,
            )
        )
        if row is None:
            self._session.add(
                AssetRecord(
                    id=asset.id,
                    engagement_id=asset.engagement_id,
                    kind=asset.kind.value,
                    identifier=asset.identifier,
                    technologies=list(asset.technologies),
                    in_scope=asset.in_scope,
                    first_seen_at=asset.first_seen_at,
                    last_seen_at=asset.last_seen_at,
                )
            )
            self._session.flush()
            return Stored(asset, 1)
        if asset.last_seen_at > _utc(row.last_seen_at):
            row.last_seen_at = asset.last_seen_at
        if asset.technologies:
            row.technologies = sorted(set(row.technologies) | set(asset.technologies))
        row.in_scope = asset.in_scope
        self._session.flush()
        return Stored(self._domain_from_record(row), row.version)

    def get(self, asset_id: AssetId) -> Stored[Asset] | None:
        row = self._session.get(AssetRecord, asset_id)
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def list_for_engagement(
        self,
        engagement_id: EngagementId,
        *,
        limit: int = _DEFAULT_LIMIT,
        offset: int = 0,
    ) -> tuple[Stored[Asset], ...]:
        rows = self._session.scalars(
            select(AssetRecord)
            .where(AssetRecord.engagement_id == engagement_id)
            .order_by(AssetRecord.identifier.asc())
            .limit(limit)
            .offset(offset)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    def count(self, engagement_id: EngagementId) -> int:
        total = self._session.scalar(
            select(func.count()).where(AssetRecord.engagement_id == engagement_id)
        )
        return int(total or 0)

    @staticmethod
    def _domain_from_record(row: AssetRecord) -> Asset:
        return Asset(
            id=AssetId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            kind=AssetKind(row.kind),
            identifier=row.identifier,
            technologies=tuple(row.technologies),
            in_scope=row.in_scope,
            first_seen_at=_utc(row.first_seen_at),
            last_seen_at=_utc(row.last_seen_at),
        )


class EndpointRepository:
    """Persist the discovered request surface."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def observe(self, endpoint: Endpoint) -> Stored[Endpoint]:
        """Insert a new endpoint or merge newly observed parameters into a known one."""
        row = self._session.scalar(
            select(EndpointRecord).where(
                EndpointRecord.asset_id == endpoint.asset_id,
                EndpointRecord.method == endpoint.method,
                EndpointRecord.path == endpoint.path,
            )
        )
        if row is None:
            self._session.add(
                EndpointRecord(
                    id=endpoint.id,
                    engagement_id=endpoint.engagement_id,
                    asset_id=endpoint.asset_id,
                    method=endpoint.method,
                    path=endpoint.path,
                    parameters=list(endpoint.parameters),
                    requires_authentication=endpoint.requires_authentication,
                    source=endpoint.source,
                    first_seen_at=endpoint.first_seen_at,
                    last_seen_at=endpoint.last_seen_at,
                )
            )
            self._session.flush()
            return Stored(endpoint, 1)
        if endpoint.last_seen_at > _utc(row.last_seen_at):
            row.last_seen_at = endpoint.last_seen_at
        if endpoint.parameters:
            row.parameters = sorted(set(row.parameters) | set(endpoint.parameters))
        if endpoint.requires_authentication is not None:
            row.requires_authentication = endpoint.requires_authentication
        self._session.flush()
        return Stored(self._domain_from_record(row), row.version)

    def get(self, endpoint_id: EndpointId) -> Stored[Endpoint] | None:
        row = self._session.get(EndpointRecord, endpoint_id)
        if row is None:
            return None
        return Stored(self._domain_from_record(row), row.version)

    def list_for_engagement(
        self,
        engagement_id: EngagementId,
        *,
        limit: int = _DEFAULT_LIMIT,
        offset: int = 0,
    ) -> tuple[Stored[Endpoint], ...]:
        rows = self._session.scalars(
            select(EndpointRecord)
            .where(EndpointRecord.engagement_id == engagement_id)
            .order_by(EndpointRecord.path.asc(), EndpointRecord.method.asc())
            .limit(limit)
            .offset(offset)
        )
        return tuple(Stored(self._domain_from_record(row), row.version) for row in rows)

    def count(self, engagement_id: EngagementId) -> int:
        total = self._session.scalar(
            select(func.count()).where(EndpointRecord.engagement_id == engagement_id)
        )
        return int(total or 0)

    @staticmethod
    def _domain_from_record(row: EndpointRecord) -> Endpoint:
        return Endpoint(
            id=EndpointId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            asset_id=AssetId(row.asset_id),
            method=row.method,
            path=row.path,
            parameters=tuple(row.parameters),
            requires_authentication=row.requires_authentication,
            source=row.source,
            first_seen_at=_utc(row.first_seen_at),
            last_seen_at=_utc(row.last_seen_at),
        )


class ObservationRepository:
    """Persist immutable recorded phenomena."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, observation: Observation) -> None:
        self._session.add(
            ObservationRecord(
                id=observation.id,
                engagement_id=observation.engagement_id,
                kind=observation.kind.value,
                subject=observation.subject,
                digest=observation.digest,
                summary=observation.summary,
                evidence_id=observation.evidence_id,
                asset_id=observation.asset_id,
                observed_at=observation.observed_at,
            )
        )
        self._session.flush()

    def list_since(
        self,
        engagement_id: EngagementId,
        *,
        since: datetime,
        limit: int = _DEFAULT_LIMIT,
    ) -> tuple[Observation, ...]:
        rows = self._session.scalars(
            select(ObservationRecord)
            .where(
                ObservationRecord.engagement_id == engagement_id,
                ObservationRecord.observed_at > since,
            )
            .order_by(ObservationRecord.observed_at.desc())
            .limit(limit)
        )
        return tuple(self._domain_from_record(row) for row in rows)

    def list_for_subject(
        self,
        engagement_id: EngagementId,
        subject: str,
        *,
        limit: int = _DEFAULT_LIMIT,
    ) -> tuple[Observation, ...]:
        rows = self._session.scalars(
            select(ObservationRecord)
            .where(
                ObservationRecord.engagement_id == engagement_id,
                ObservationRecord.subject == subject,
            )
            .order_by(ObservationRecord.observed_at.desc())
            .limit(limit)
        )
        return tuple(self._domain_from_record(row) for row in rows)

    @staticmethod
    def _domain_from_record(row: ObservationRecord) -> Observation:
        return Observation(
            id=ObservationId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            kind=ObservationKind(row.kind),
            subject=row.subject,
            digest=row.digest,
            summary=row.summary,
            evidence_id=EvidenceId(row.evidence_id) if row.evidence_id else None,
            asset_id=AssetId(row.asset_id) if row.asset_id else None,
            observed_at=_utc(row.observed_at),
        )


class CandidateRepository:
    """Persist scanner and heuristic signals awaiting triage."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, candidate: Candidate) -> None:
        self._session.add(
            CandidateRecord(
                id=candidate.id,
                engagement_id=candidate.engagement_id,
                source=candidate.source.value,
                tool_name=candidate.tool_name,
                title=candidate.title,
                category=candidate.category,
                target=candidate.target,
                raw_digest=candidate.raw_digest,
                severity_hint=candidate.severity_hint,
                lead_id=candidate.lead_id,
                created_at=candidate.created_at,
            )
        )
        self._session.flush()

    def find_by_digest(
        self,
        engagement_id: EngagementId,
        raw_digest: str,
    ) -> Candidate | None:
        row = self._session.scalar(
            select(CandidateRecord).where(
                CandidateRecord.engagement_id == engagement_id,
                CandidateRecord.raw_digest == raw_digest,
            )
        )
        return None if row is None else self._domain_from_record(row)

    def list_untriaged(
        self,
        engagement_id: EngagementId,
        *,
        limit: int = _DEFAULT_LIMIT,
    ) -> tuple[Candidate, ...]:
        rows = self._session.scalars(
            select(CandidateRecord)
            .where(
                CandidateRecord.engagement_id == engagement_id,
                CandidateRecord.lead_id.is_(None),
            )
            .order_by(CandidateRecord.created_at.asc())
            .limit(limit)
        )
        return tuple(self._domain_from_record(row) for row in rows)

    def attach_lead(self, candidate_id: CandidateId, lead_id: LeadId) -> None:
        row = self._session.get(CandidateRecord, candidate_id)
        if row is None:
            raise ConcurrentUpdateError
        row.lead_id = lead_id
        self._session.flush()

    @staticmethod
    def _domain_from_record(row: CandidateRecord) -> Candidate:
        return Candidate(
            id=CandidateId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            source=CandidateSource(row.source),
            tool_name=row.tool_name,
            title=row.title,
            category=row.category,
            target=row.target,
            raw_digest=row.raw_digest,
            severity_hint=row.severity_hint,
            lead_id=LeadId(row.lead_id) if row.lead_id else None,
            created_at=_utc(row.created_at),
        )


class SurfaceSnapshotRepository:
    """Persist attack-surface digests used for change detection."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, snapshot: SurfaceSnapshot) -> None:
        self._session.add(
            SurfaceSnapshotRecord(
                id=snapshot.id,
                engagement_id=snapshot.engagement_id,
                digest=snapshot.digest,
                asset_count=snapshot.asset_count,
                endpoint_count=snapshot.endpoint_count,
                captured_at=snapshot.captured_at,
            )
        )
        self._session.flush()

    def latest(self, engagement_id: EngagementId) -> SurfaceSnapshot | None:
        row = self._session.scalar(
            select(SurfaceSnapshotRecord)
            .where(SurfaceSnapshotRecord.engagement_id == engagement_id)
            .order_by(
                SurfaceSnapshotRecord.captured_at.desc(),
                SurfaceSnapshotRecord.id.desc(),
            )
            .limit(1)
        )
        return None if row is None else self._domain_from_record(row)

    @staticmethod
    def _domain_from_record(row: SurfaceSnapshotRecord) -> SurfaceSnapshot:
        return SurfaceSnapshot(
            id=SurfaceSnapshotId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            digest=row.digest,
            asset_count=row.asset_count,
            endpoint_count=row.endpoint_count,
            captured_at=_utc(row.captured_at),
        )


class ChangeEventRepository:
    """Persist typed attack-surface differences."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, event: ChangeEvent) -> None:
        self._session.add(
            ChangeEventRecord(
                id=event.id,
                engagement_id=event.engagement_id,
                snapshot_id=event.snapshot_id,
                kind=event.kind.value,
                subject=event.subject,
                previous_digest=event.previous_digest,
                current_digest=event.current_digest,
                detected_at=event.detected_at,
            )
        )
        self._session.flush()

    def list_since(
        self,
        engagement_id: EngagementId,
        *,
        since: datetime,
        limit: int = _DEFAULT_LIMIT,
    ) -> tuple[ChangeEvent, ...]:
        rows = self._session.scalars(
            select(ChangeEventRecord)
            .where(
                ChangeEventRecord.engagement_id == engagement_id,
                ChangeEventRecord.detected_at > since,
            )
            .order_by(ChangeEventRecord.detected_at.desc())
            .limit(limit)
        )
        return tuple(self._domain_from_record(row) for row in rows)

    def exists_for_subject_since(
        self,
        engagement_id: EngagementId,
        subject: str,
        *,
        since: datetime,
    ) -> bool:
        row = self._session.scalar(
            select(ChangeEventRecord.id)
            .where(
                ChangeEventRecord.engagement_id == engagement_id,
                ChangeEventRecord.subject == subject,
                ChangeEventRecord.detected_at > since,
            )
            .limit(1)
        )
        return row is not None

    @staticmethod
    def _domain_from_record(row: ChangeEventRecord) -> ChangeEvent:
        return ChangeEvent(
            id=ChangeEventId(row.id),
            engagement_id=EngagementId(row.engagement_id),
            snapshot_id=SurfaceSnapshotId(row.snapshot_id),
            kind=ChangeKind(row.kind),
            subject=row.subject,
            previous_digest=row.previous_digest,
            current_digest=row.current_digest,
            detected_at=_utc(row.detected_at),
        )


@dataclass(frozen=True, slots=True)
class BudgetWindow:
    """The composite key identifying one budget accounting window."""

    kind: str
    start: datetime
    scope_key: str = ""


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    """Consumption recorded against one budget window."""

    requests: int = 0
    tokens: int = 0


class BudgetLedgerRepository:
    """Persist deterministic request and token counters per mission window."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def usage(self, mission_id: MissionId, window: BudgetWindow) -> BudgetUsage:
        """Return the consumption already recorded in one window."""
        row = self._session.scalar(self._window_query(mission_id, window))
        if row is None:
            return BudgetUsage()
        return BudgetUsage(requests=row.request_count, tokens=row.token_count)

    def consume(
        self,
        mission_id: MissionId,
        window: BudgetWindow,
        usage: BudgetUsage,
    ) -> BudgetUsage:
        """Add usage to one window and return the resulting totals."""
        if usage.requests < 0 or usage.tokens < 0:
            msg = "budget consumption must not be negative"
            raise ValueError(msg)
        row = self._session.scalar(self._window_query(mission_id, window))
        if row is None:
            row = BudgetLedgerRecord(
                id=new_identifier(),
                mission_id=mission_id,
                window_kind=window.kind,
                scope_key=window.scope_key,
                window_start=window.start,
                request_count=usage.requests,
                token_count=usage.tokens,
            )
            self._session.add(row)
        else:
            row.request_count += usage.requests
            row.token_count += usage.tokens
        self._session.flush()
        return BudgetUsage(requests=row.request_count, tokens=row.token_count)

    @staticmethod
    def _window_query(
        mission_id: MissionId,
        window: BudgetWindow,
    ) -> Select[tuple[BudgetLedgerRecord]]:
        return select(BudgetLedgerRecord).where(
            BudgetLedgerRecord.mission_id == mission_id,
            BudgetLedgerRecord.window_kind == window.kind,
            BudgetLedgerRecord.scope_key == window.scope_key,
            BudgetLedgerRecord.window_start == window.start,
        )


__all__ = [
    "AgentCycleRepository",
    "AssetRepository",
    "BudgetLedgerRepository",
    "BudgetUsage",
    "BudgetWindow",
    "CandidateRepository",
    "ChangeEventRepository",
    "EndpointRepository",
    "LeadRepository",
    "MissionRepository",
    "MissionRunRepository",
    "ObservationRepository",
    "SurfaceSnapshotRepository",
]
