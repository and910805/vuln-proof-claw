"""Shared fixtures for database-backed autonomous agent tests."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from vuln_proof_claw.domain.autonomous import (
    Asset,
    Endpoint,
    Lead,
    Mission,
    MissionBudget,
    MissionCadence,
)
from vuln_proof_claw.domain.enums import AssetKind, MissionState, RiskLevel
from vuln_proof_claw.domain.identifiers import EngagementId, MissionId, ProjectId
from vuln_proof_claw.domain.models import Engagement, Project
from vuln_proof_claw.persistence.autonomous_repositories import (
    AssetRepository,
    EndpointRepository,
    LeadRepository,
    MissionRepository,
)
from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.repositories import (
    EngagementRepository,
    ProjectRepository,
    ScopeRepository,
)
from vuln_proof_claw.persistence.session import create_session_factory
from vuln_proof_claw.policy.scope import EngagementScope

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
TARGET_HOST = "api.example.com"
TARGET_URL = f"https://{TARGET_HOST}:443/orders"


def build_engine(database_path: Path) -> Generator[Engine, None, None]:
    """Yield a SQLite engine with foreign keys enforced."""
    engine = create_engine(f"sqlite:///{database_path}", pool_pre_ping=False)

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(engine)


def seed_engagement(
    session: Session,
    *,
    auto_execute_l1: bool = True,
    allowed_hostnames: tuple[str, ...] = (TARGET_HOST,),
    allowed_wildcards: tuple[str, ...] = (),
) -> EngagementId:
    """Create a project, engagement, and authorized scope."""
    project = Project(name="Example Program", created_at=NOW)
    ProjectRepository(session).add(project)
    engagement = Engagement(
        project_id=ProjectId(project.id),
        name="example-program",
        starts_at=NOW - timedelta(days=1),
        ends_at=NOW + timedelta(days=30),
        maximum_risk=RiskLevel.L1,
        auto_execute_l1=auto_execute_l1,
        created_at=NOW,
    )
    EngagementRepository(session).add(engagement)
    ScopeRepository(session).add(
        EngagementId(engagement.id),
        EngagementScope.create(
            allowed_hostnames=allowed_hostnames,
            allowed_wildcards=allowed_wildcards,
            allowed_ports=(443,),
            allowed_schemes=("https",),
            allowed_paths=("/",),
            valid_from=NOW - timedelta(days=1),
            valid_until=NOW + timedelta(days=30),
        ),
    )
    return EngagementId(engagement.id)


def seed_mission(  # noqa: PLR0913 - explicit fields keep test setup readable
    session: Session,
    engagement_id: EngagementId,
    *,
    state: MissionState = MissionState.RUNNING,
    cadence: MissionCadence | None = None,
    budget: MissionBudget | None = None,
    kill_switch_engaged: bool = False,
    expires_at: datetime | None = None,
    created_at: datetime = NOW,
) -> Mission:
    """Create a mission bound to an engagement."""
    mission = Mission(
        engagement_id=engagement_id,
        name="continuous-research",
        state=state,
        cadence=cadence or MissionCadence(),
        budget=budget or MissionBudget(),
        kill_switch_engaged=kill_switch_engaged,
        expires_at=expires_at,
        created_at=created_at,
        updated_at=created_at,
    )
    MissionRepository(session).add(mission)
    return mission


def seed_lead(
    session: Session,
    engagement_id: EngagementId,
    mission_id: MissionId,
    *,
    next_action: str | None = TARGET_URL,
    **overrides: object,
) -> Lead:
    """Create a lead pointing at an in-scope target."""
    defaults: dict[str, object] = {
        "engagement_id": engagement_id,
        "mission_id": mission_id,
        "title": "Possible horizontal authorization weakness",
        "hypothesis": "Object ownership may not be enforced consistently",
        "category": "authorization",
        "next_action": next_action,
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(overrides)
    lead = Lead(**defaults)  # type: ignore[arg-type]
    LeadRepository(session).add(lead)
    return lead


def seed_surface(
    session: Session,
    engagement_id: EngagementId,
    *,
    at: datetime = NOW,
    path: str = "/orders",
) -> tuple[Asset, Endpoint]:
    """Create one asset and one endpoint in the knowledge base."""
    asset = Asset(
        engagement_id=engagement_id,
        kind=AssetKind.HOSTNAME,
        identifier=TARGET_HOST,
        first_seen_at=at,
        last_seen_at=at,
    )
    stored_asset = AssetRepository(session).observe(asset)
    endpoint = Endpoint(
        engagement_id=engagement_id,
        asset_id=stored_asset.entity.id,
        method="GET",
        path=path,
        first_seen_at=at,
        last_seen_at=at,
    )
    stored_endpoint = EndpointRepository(session).observe(endpoint)
    return (stored_asset.entity, stored_endpoint.entity)
