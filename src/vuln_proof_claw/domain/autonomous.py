"""Domain value objects for persistent autonomous research missions.

These objects carry the state that must survive process crashes and host reboots.
They are deliberately framework-independent and validate their own invariants so
that an invalid mission, cycle, or lead cannot be constructed anywhere in the system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

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
from vuln_proof_claw.domain.errors import DomainValidationError
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
    new_agent_cycle_id,
    new_asset_id,
    new_candidate_id,
    new_change_event_id,
    new_endpoint_id,
    new_lead_id,
    new_mission_id,
    new_mission_run_id,
    new_observation_id,
    new_surface_snapshot_id,
)
from vuln_proof_claw.domain.models import (
    _require_aware,
    _require_sha256,
    _require_text,
    utc_now,
)

MAXIMUM_AUTONOMOUS_RISK: RiskLevel = RiskLevel.L1
"""Hard ceiling for unattended execution.

Nothing above L1 may ever run without an explicit human approval record. This is a
system constant, not a configurable value: a mission cannot raise it.
"""

_MINIMUM_CADENCE_SECONDS = 30
_MAXIMUM_CADENCE_SECONDS = 2_592_000
_MAXIMUM_PRIORITY = 100


def _require_range(value: int, field_name: str, *, minimum: int, maximum: int) -> None:
    if not minimum <= value <= maximum:
        raise DomainValidationError(f"{field_name} must be between {minimum} and {maximum}")


def _require_non_negative(value: int, field_name: str) -> None:
    if value < 0:
        raise DomainValidationError(f"{field_name} must not be negative")


def _require_positive(value: int, field_name: str) -> None:
    if value < 1:
        raise DomainValidationError(f"{field_name} must be at least one")


def _require_cadence(value: int, field_name: str) -> None:
    _require_range(
        value,
        field_name,
        minimum=_MINIMUM_CADENCE_SECONDS,
        maximum=_MAXIMUM_CADENCE_SECONDS,
    )


@dataclass(frozen=True, slots=True)
class MissionCadence:
    """Operator-controlled scheduling intervals.

    Cadence is never hardcoded in the controller; every interval is supplied by the
    engagement configuration so that programs with different rate expectations can be
    served by the same code.
    """

    cycle_interval_seconds: int = 300
    http_inventory_seconds: int = 2_700
    subdomain_refresh_seconds: int = 21_600
    deep_recon_seconds: int = 86_400
    lead_retry_cooldown_seconds: int = 3_600
    stale_lead_after_seconds: int = 604_800

    def __post_init__(self) -> None:
        _require_cadence(self.cycle_interval_seconds, "cycle_interval_seconds")
        _require_cadence(self.http_inventory_seconds, "http_inventory_seconds")
        _require_cadence(self.subdomain_refresh_seconds, "subdomain_refresh_seconds")
        _require_cadence(self.deep_recon_seconds, "deep_recon_seconds")
        _require_cadence(self.lead_retry_cooldown_seconds, "lead_retry_cooldown_seconds")
        _require_cadence(self.stale_lead_after_seconds, "stale_lead_after_seconds")


@dataclass(frozen=True, slots=True)
class MissionBudget:
    """Deterministic ceilings applied before any action is proposed."""

    requests_per_minute_per_domain: int = 10
    requests_per_hour: int = 1_000
    requests_per_day: int = 10_000
    total_requests: int = 100_000
    llm_tokens_per_day: int = 1_000_000
    llm_tokens_per_lead: int = 50_000
    maximum_concurrent_actions: int = 2
    maximum_lead_attempts: int = 5

    def __post_init__(self) -> None:
        _require_positive(
            self.requests_per_minute_per_domain, "requests_per_minute_per_domain"
        )
        _require_positive(self.requests_per_hour, "requests_per_hour")
        _require_positive(self.requests_per_day, "requests_per_day")
        _require_positive(self.total_requests, "total_requests")
        _require_non_negative(self.llm_tokens_per_day, "llm_tokens_per_day")
        _require_non_negative(self.llm_tokens_per_lead, "llm_tokens_per_lead")
        _require_range(
            self.maximum_concurrent_actions, "maximum_concurrent_actions", minimum=1, maximum=64
        )
        _require_range(
            self.maximum_lead_attempts, "maximum_lead_attempts", minimum=1, maximum=100
        )
        if self.requests_per_hour > self.requests_per_day:
            raise DomainValidationError("requests_per_hour must not exceed requests_per_day")
        if self.requests_per_day > self.total_requests:
            raise DomainValidationError("requests_per_day must not exceed total_requests")


@dataclass(frozen=True, slots=True)
class Mission:
    """A long-running autonomous research campaign bound to one engagement."""

    engagement_id: EngagementId
    name: str
    cadence: MissionCadence = field(default_factory=MissionCadence)
    budget: MissionBudget = field(default_factory=MissionBudget)
    maximum_autonomous_risk: RiskLevel = MAXIMUM_AUTONOMOUS_RISK
    state: MissionState = MissionState.PENDING
    kill_switch_engaged: bool = False
    expires_at: datetime | None = None
    id: MissionId = field(default_factory=new_mission_id)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.name, "name")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise DomainValidationError("updated_at must not be earlier than created_at")
        if self.expires_at is not None:
            _require_aware(self.expires_at, "expires_at")
            if self.expires_at <= self.created_at:
                raise DomainValidationError("expires_at must be later than created_at")
        if self.maximum_autonomous_risk not in {RiskLevel.L0, RiskLevel.L1}:
            raise DomainValidationError(
                "autonomous execution is capped at L1; higher risk requires human approval"
            )

    def permits_cycle(self, *, at: datetime) -> bool:
        """Return whether the controller may begin a new cycle right now."""
        _require_aware(at, "at")
        if self.kill_switch_engaged or not self.state.schedulable:
            return False
        return self.expires_at is None or at < self.expires_at


@dataclass(frozen=True, slots=True)
class MissionRun:
    """One continuous execution span of a mission, recoverable after a crash."""

    engagement_id: EngagementId
    mission_id: MissionId
    state: MissionRunState = MissionRunState.RUNNING
    cycle_index: int = 0
    worker_identity: str = "controller"
    error_code: str | None = None
    id: MissionRunId = field(default_factory=new_mission_run_id)
    started_at: datetime = field(default_factory=utc_now)
    heartbeat_at: datetime = field(default_factory=utc_now)
    ended_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.worker_identity, "worker_identity")
        _require_aware(self.started_at, "started_at")
        _require_aware(self.heartbeat_at, "heartbeat_at")
        _require_non_negative(self.cycle_index, "cycle_index")
        if self.heartbeat_at < self.started_at:
            raise DomainValidationError("heartbeat_at must not be earlier than started_at")
        if self.ended_at is not None:
            _require_aware(self.ended_at, "ended_at")
            if self.ended_at < self.started_at:
                raise DomainValidationError("ended_at must not be earlier than started_at")
        if self.ended_at is None and self.state.terminal:
            raise DomainValidationError("a terminal mission run requires ended_at")
        if self.error_code is not None:
            _require_text(self.error_code, "error_code")

    def is_stale(self, *, at: datetime, timeout_seconds: int) -> bool:
        """Return whether the run's heartbeat is older than the watchdog threshold."""
        _require_aware(at, "at")
        _require_positive(timeout_seconds, "timeout_seconds")
        if self.state is not MissionRunState.RUNNING:
            return False
        return (at - self.heartbeat_at).total_seconds() > timeout_seconds


@dataclass(frozen=True, slots=True)
class AgentCycle:
    """One observe, plan, act, and verify iteration within a mission run."""

    engagement_id: EngagementId
    mission_run_id: MissionRunId
    index: int
    state: CycleState = CycleState.RUNNING
    leads_considered: int = 0
    actions_proposed: int = 0
    actions_executed: int = 0
    candidates_created: int = 0
    findings_created: int = 0
    error_code: str | None = None
    id: AgentCycleId = field(default_factory=new_agent_cycle_id)
    started_at: datetime = field(default_factory=utc_now)
    ended_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_non_negative(self.index, "index")
        _require_non_negative(self.leads_considered, "leads_considered")
        _require_non_negative(self.actions_proposed, "actions_proposed")
        _require_non_negative(self.actions_executed, "actions_executed")
        _require_non_negative(self.candidates_created, "candidates_created")
        _require_non_negative(self.findings_created, "findings_created")
        _require_aware(self.started_at, "started_at")
        if self.actions_executed > self.actions_proposed:
            raise DomainValidationError("actions_executed must not exceed actions_proposed")
        if self.ended_at is not None:
            _require_aware(self.ended_at, "ended_at")
            if self.ended_at < self.started_at:
                raise DomainValidationError("ended_at must not be earlier than started_at")
        if self.ended_at is None and self.state.terminal:
            raise DomainValidationError("a terminal cycle requires ended_at")
        if self.error_code is not None:
            _require_text(self.error_code, "error_code")


@dataclass(frozen=True, slots=True)
class Lead:
    """A testable research hypothesis.

    A lead is not a finding. It records what the agent believes may be true, what it
    has already tried, and what it proposes to do next. Only the Verifier may promote
    a lead into a finding, and only with supporting evidence.
    """

    engagement_id: EngagementId
    mission_id: MissionId
    title: str
    hypothesis: str
    category: str
    asset_id: AssetId | None = None
    endpoint_id: EndpointId | None = None
    confidence: float = 0.5
    priority: int = 50
    status: LeadStatus = LeadStatus.NEW
    origin: tuple[str, ...] = ()
    evidence_ids: tuple[EvidenceId, ...] = ()
    related_findings: tuple[FindingId, ...] = ()
    attempt_count: int = 0
    failure_count: int = 0
    last_attempt_at: datetime | None = None
    next_attempt_at: datetime | None = None
    last_reasoning_summary: str | None = None
    next_action: str | None = None
    blocked_reason: str | None = None
    dedupe_key: str | None = None
    id: LeadId = field(default_factory=new_lead_id)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.title, "title")
        _require_text(self.hypothesis, "hypothesis")
        _require_text(self.category, "category")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise DomainValidationError("updated_at must not be earlier than created_at")
        if not 0.0 <= self.confidence <= 1.0:
            raise DomainValidationError("confidence must be between 0.0 and 1.0")
        _require_range(self.priority, "priority", minimum=0, maximum=_MAXIMUM_PRIORITY)
        _require_non_negative(self.attempt_count, "attempt_count")
        _require_non_negative(self.failure_count, "failure_count")
        if self.failure_count > self.attempt_count:
            raise DomainValidationError("failure_count must not exceed attempt_count")
        for label, moment in (
            ("last_attempt_at", self.last_attempt_at),
            ("next_attempt_at", self.next_attempt_at),
        ):
            if moment is not None:
                _require_aware(moment, label)
        if self.last_attempt_at is None and self.attempt_count:
            raise DomainValidationError("an attempted lead requires last_attempt_at")
        if self.status is LeadStatus.VERIFIED and not self.evidence_ids:
            raise DomainValidationError("a verified lead requires at least one evidence record")
        if self.status is LeadStatus.NEEDS_APPROVAL and not self.blocked_reason:
            raise DomainValidationError("a lead awaiting approval requires blocked_reason")
        for label, text in (
            ("last_reasoning_summary", self.last_reasoning_summary),
            ("next_action", self.next_action),
            ("blocked_reason", self.blocked_reason),
            ("dedupe_key", self.dedupe_key),
        ):
            if text is not None:
                _require_text(text, label)
        for item in self.origin:
            _require_text(item, "origin")


@dataclass(frozen=True, slots=True)
class Asset:
    """A discovered host, address, service, or application within scope."""

    engagement_id: EngagementId
    kind: AssetKind
    identifier: str
    technologies: tuple[str, ...] = ()
    in_scope: bool = True
    id: AssetId = field(default_factory=new_asset_id)
    first_seen_at: datetime = field(default_factory=utc_now)
    last_seen_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.identifier, "identifier")
        _require_aware(self.first_seen_at, "first_seen_at")
        _require_aware(self.last_seen_at, "last_seen_at")
        if self.last_seen_at < self.first_seen_at:
            raise DomainValidationError("last_seen_at must not be earlier than first_seen_at")
        for item in self.technologies:
            _require_text(item, "technologies")


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A discovered request surface belonging to an asset."""

    engagement_id: EngagementId
    asset_id: AssetId
    method: str
    path: str
    parameters: tuple[str, ...] = ()
    requires_authentication: bool | None = None
    source: str = "discovery"
    id: EndpointId = field(default_factory=new_endpoint_id)
    first_seen_at: datetime = field(default_factory=utc_now)
    last_seen_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.method, "method")
        _require_text(self.path, "path")
        _require_text(self.source, "source")
        _require_aware(self.first_seen_at, "first_seen_at")
        _require_aware(self.last_seen_at, "last_seen_at")
        if self.last_seen_at < self.first_seen_at:
            raise DomainValidationError("last_seen_at must not be earlier than first_seen_at")
        if self.method != self.method.upper():
            raise DomainValidationError("method must be uppercase")
        if not self.path.startswith("/"):
            raise DomainValidationError("path must be absolute")
        for item in self.parameters:
            _require_text(item, "parameters")


@dataclass(frozen=True, slots=True)
class Observation:
    """An immutable recorded phenomenon, optionally backed by stored evidence."""

    engagement_id: EngagementId
    kind: ObservationKind
    subject: str
    digest: str
    summary: str
    evidence_id: EvidenceId | None = None
    asset_id: AssetId | None = None
    id: ObservationId = field(default_factory=new_observation_id)
    observed_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.subject, "subject")
        _require_text(self.summary, "summary")
        _require_sha256(self.digest, "digest")
        _require_aware(self.observed_at, "observed_at")


@dataclass(frozen=True, slots=True)
class Candidate:
    """A scanner or heuristic signal awaiting Planner triage.

    Scanner output never becomes a finding directly. It becomes a candidate, which the
    Planner may promote to a lead, which the Verifier may promote to a finding.
    """

    engagement_id: EngagementId
    source: CandidateSource
    tool_name: str
    title: str
    category: str
    target: str
    raw_digest: str
    severity_hint: str | None = None
    lead_id: LeadId | None = None
    id: CandidateId = field(default_factory=new_candidate_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.tool_name, "tool_name")
        _require_text(self.title, "title")
        _require_text(self.category, "category")
        _require_text(self.target, "target")
        _require_sha256(self.raw_digest, "raw_digest")
        _require_aware(self.created_at, "created_at")
        if self.severity_hint is not None:
            _require_text(self.severity_hint, "severity_hint")


@dataclass(frozen=True, slots=True)
class SurfaceSnapshot:
    """A content digest of the known attack surface at one point in time."""

    engagement_id: EngagementId
    digest: str
    asset_count: int
    endpoint_count: int
    id: SurfaceSnapshotId = field(default_factory=new_surface_snapshot_id)
    captured_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_sha256(self.digest, "digest")
        _require_non_negative(self.asset_count, "asset_count")
        _require_non_negative(self.endpoint_count, "endpoint_count")
        _require_aware(self.captured_at, "captured_at")


@dataclass(frozen=True, slots=True)
class ChangeEvent:
    """A typed difference between two attack-surface snapshots.

    Change events are the only mechanism that may reawaken a stale or rejected lead,
    which is how the system avoids retrying a failed hypothesis without new evidence.
    """

    engagement_id: EngagementId
    kind: ChangeKind
    subject: str
    snapshot_id: SurfaceSnapshotId
    previous_digest: str | None = None
    current_digest: str | None = None
    id: ChangeEventId = field(default_factory=new_change_event_id)
    detected_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.subject, "subject")
        _require_aware(self.detected_at, "detected_at")
        for label, digest in (
            ("previous_digest", self.previous_digest),
            ("current_digest", self.current_digest),
        ):
            if digest is not None:
                _require_sha256(digest, label)
        if self.previous_digest is None and self.current_digest is None:
            raise DomainValidationError("a change event requires at least one digest")
