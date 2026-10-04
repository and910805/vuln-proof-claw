"""Mission management for the command line.

These helpers are side-effect free except where stated, return stable ``v1`` documents,
and never print, so the CLI layer stays a thin presentation shell.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from vuln_proof_claw.agent.memory import ResearchMemory
from vuln_proof_claw.config.engagement import (
    EngagementDefinition,
    load_engagement_definition,
)
from vuln_proof_claw.domain.autonomous import Mission
from vuln_proof_claw.domain.enums import MissionState
from vuln_proof_claw.domain.identifiers import EngagementId, MissionId, ProjectId
from vuln_proof_claw.domain.models import Engagement, Project
from vuln_proof_claw.persistence.autonomous_repositories import (
    LeadRepository,
    MissionRepository,
    MissionRunRepository,
)
from vuln_proof_claw.persistence.repositories import (
    EngagementRepository,
    ProjectRepository,
    ScopeRepository,
)
from vuln_proof_claw.policy.scope import EngagementScope


@dataclass(frozen=True, slots=True)
class ScopeSummary:
    """The normalized scope an engagement definition resolves to."""

    allowed_hostnames: tuple[str, ...]
    allowed_wildcards: tuple[str, ...]
    allowed_cidrs: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    allowed_schemes: tuple[str, ...]
    denied_hostnames: tuple[str, ...]
    denied_wildcards: tuple[str, ...]
    denied_cidrs: tuple[str, ...]

    @classmethod
    def from_scope(cls, scope: EngagementScope) -> ScopeSummary:
        return cls(
            allowed_hostnames=tuple(sorted(scope.allowed_hostnames)),
            allowed_wildcards=tuple(sorted(scope.allowed_wildcards)),
            allowed_cidrs=tuple(str(item) for item in scope.allowed_networks),
            allowed_ports=tuple(sorted(scope.allowed_ports)),
            allowed_schemes=tuple(sorted(scope.allowed_schemes)),
            denied_hostnames=tuple(sorted(scope.denied_hostnames)),
            denied_wildcards=tuple(sorted(scope.denied_wildcards)),
            denied_cidrs=tuple(str(item) for item in scope.denied_networks),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed_hostnames": list(self.allowed_hostnames),
            "allowed_wildcards": list(self.allowed_wildcards),
            "allowed_cidrs": list(self.allowed_cidrs),
            "allowed_ports": list(self.allowed_ports),
            "allowed_schemes": list(self.allowed_schemes),
            "denied_hostnames": list(self.denied_hostnames),
            "denied_wildcards": list(self.denied_wildcards),
            "denied_cidrs": list(self.denied_cidrs),
        }


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """The result of checking an engagement definition."""

    valid: bool
    name: str
    program_name: str
    scope: ScopeSummary | None
    maximum_risk: str
    maximum_autonomous_risk: str
    auto_execute_l1: bool
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "v1",
            "valid": self.valid,
            "name": self.name,
            "program_name": self.program_name,
            "scope": self.scope.as_dict() if self.scope else None,
            "maximum_risk": self.maximum_risk,
            "maximum_autonomous_risk": self.maximum_autonomous_risk,
            "auto_execute_l1": self.auto_execute_l1,
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class CreationReport:
    """Identifiers produced when an engagement definition is registered."""

    created: bool
    project_id: str
    engagement_id: str
    mission_id: str
    mission_name: str
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "v1",
            "created": self.created,
            "project_id": self.project_id,
            "engagement_id": self.engagement_id,
            "mission_id": self.mission_id,
            "mission_name": self.mission_name,
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class StatusReport:
    """A point-in-time view of one mission for operators."""

    mission_id: str
    mission_name: str
    state: str
    kill_switch_engaged: bool
    active_run_id: str | None
    cycle_index: int
    lead_counts: dict[str, int]
    assets: int
    endpoints: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "v1",
            "mission_id": self.mission_id,
            "mission_name": self.mission_name,
            "state": self.state,
            "kill_switch_engaged": self.kill_switch_engaged,
            "active_run_id": self.active_run_id,
            "cycle_index": self.cycle_index,
            "lead_counts": dict(sorted(self.lead_counts.items())),
            "assets": self.assets,
            "endpoints": self.endpoints,
        }


def validate_definition(path: Path) -> ValidationReport:
    """Parse an engagement definition and report its normalized authorization."""
    try:
        definition = load_engagement_definition(path)
        scope = definition.as_engagement_scope()
    except Exception as error:  # noqa: BLE001 - surfaced as a structured report
        return ValidationReport(
            valid=False,
            name="",
            program_name="",
            scope=None,
            maximum_risk="",
            maximum_autonomous_risk="",
            auto_execute_l1=False,
            errors=(str(error),),
        )
    return ValidationReport(
        valid=True,
        name=definition.name,
        program_name=definition.program.program_name,
        scope=ScopeSummary.from_scope(scope),
        maximum_risk=definition.risk_policy.maximum_risk.value,
        maximum_autonomous_risk=definition.risk_policy.maximum_autonomous_risk.value,
        auto_execute_l1=definition.risk_policy.auto_execute_l1,
    )


def create_from_definition(
    session: Session,
    definition: EngagementDefinition,
    *,
    at: datetime | None = None,
) -> CreationReport:
    """Register a project, engagement, scope, and mission from a definition.

    The caller owns the transaction. Re-registering an existing mission name for the
    same engagement is refused rather than silently widening an existing authorization.
    """
    moment = at or datetime.now(UTC)
    project = Project(name=definition.project, created_at=moment)
    ProjectRepository(session).add(project)

    engagement = Engagement(
        project_id=ProjectId(project.id),
        name=definition.name,
        starts_at=definition.starts_at,
        ends_at=definition.ends_at,
        maximum_risk=definition.risk_policy.maximum_risk,
        auto_execute_l1=definition.risk_policy.auto_execute_l1,
        created_at=moment,
    )
    EngagementRepository(session).add(engagement)
    engagement_id = EngagementId(engagement.id)
    ScopeRepository(session).add(engagement_id, definition.as_engagement_scope())

    missions = MissionRepository(session)
    if missions.find_by_name(engagement_id, definition.name) is not None:
        return CreationReport(
            created=False,
            project_id=project.id,
            engagement_id=engagement_id,
            mission_id="",
            mission_name=definition.name,
            errors=("mission_already_exists",),
        )

    mission = Mission(
        engagement_id=engagement_id,
        name=definition.name,
        cadence=definition.as_cadence(),
        budget=definition.as_budget(),
        maximum_autonomous_risk=definition.risk_policy.maximum_autonomous_risk,
        state=MissionState.PENDING,
        expires_at=definition.ends_at,
        created_at=moment,
        updated_at=moment,
    )
    missions.add(mission)
    return CreationReport(
        created=True,
        project_id=project.id,
        engagement_id=engagement_id,
        mission_id=mission.id,
        mission_name=mission.name,
    )


def mission_status(session: Session, mission_id: MissionId) -> StatusReport | None:
    """Return the current operator-facing status of one mission."""
    stored = MissionRepository(session).get(mission_id)
    if stored is None:
        return None
    mission = stored.entity

    active_run = next(
        (
            item.entity
            for item in MissionRunRepository(session).list_running()
            if item.entity.mission_id == mission_id
        ),
        None,
    )
    counts = LeadRepository(session).count_by_status(mission_id)
    surface = ResearchMemory(session, mission.engagement_id).surface_counts()
    return StatusReport(
        mission_id=mission.id,
        mission_name=mission.name,
        state=mission.state.value,
        kill_switch_engaged=mission.kill_switch_engaged,
        active_run_id=active_run.id if active_run else None,
        cycle_index=active_run.cycle_index if active_run else 0,
        lead_counts={status.value: total for status, total in counts.items()},
        assets=surface.assets,
        endpoints=surface.endpoints,
    )


def set_mission_state(
    session: Session,
    mission_id: MissionId,
    *,
    state: MissionState | None = None,
    kill_switch_engaged: bool | None = None,
    at: datetime | None = None,
) -> Mission | None:
    """Pause, resume, stop, or engage the kill switch for a mission."""
    stored = MissionRepository(session).get(mission_id)
    if stored is None:
        return None
    moment = at or datetime.now(UTC)
    updated = replace(
        stored.entity,
        state=state if state is not None else stored.entity.state,
        kill_switch_engaged=(
            kill_switch_engaged
            if kill_switch_engaged is not None
            else stored.entity.kill_switch_engaged
        ),
        updated_at=moment,
    )
    return MissionRepository(session).save(updated, expected_version=stored.version).entity


__all__ = [
    "CreationReport",
    "ScopeSummary",
    "StatusReport",
    "ValidationReport",
    "create_from_definition",
    "mission_status",
    "set_mission_state",
    "validate_definition",
]
