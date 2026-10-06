"""Tests for mission command-line helpers."""

from __future__ import annotations

from collections.abc import Generator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine
from typer.testing import CliRunner

from tests.agent.support import (
    NOW,
    build_engine,
    seed_engagement,
    seed_mission,
    session_factory,
)
from vuln_proof_claw.cli.app import app
from vuln_proof_claw.cli.mission import (
    create_from_definition,
    mission_status,
    set_mission_state,
    validate_definition,
)
from vuln_proof_claw.config.engagement import load_engagement_definition
from vuln_proof_claw.domain.enums import MissionState
from vuln_proof_claw.domain.identifiers import MissionId
from vuln_proof_claw.persistence.autonomous_repositories import MissionRepository

runner = CliRunner()
EXAMPLE = Path("examples/engagement.yaml")


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "cli_mission.db")


def test_validate_reports_the_resolved_scope() -> None:
    report = validate_definition(EXAMPLE)

    assert report.valid
    assert report.scope is not None
    assert report.scope.allowed_wildcards == ("*.example.com",)
    assert report.scope.denied_wildcards == ("*.thirdparty.example",)
    assert report.as_dict()["schema_version"] == "v1"


def test_validate_reports_errors_without_raising(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("name: [unclosed\n", encoding="utf-8")

    report = validate_definition(broken)

    assert not report.valid
    assert report.errors


def test_validate_command_emits_json() -> None:
    result = runner.invoke(app, ["mission", "validate", str(EXAMPLE), "--json"])

    assert result.exit_code == 0
    assert '"valid":true' in result.output


def test_validate_command_fails_for_an_invalid_definition(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("just a string\n", encoding="utf-8")

    result = runner.invoke(app, ["mission", "validate", str(broken)])

    assert result.exit_code == 1


def test_creating_from_a_definition_registers_scope_and_mission(engine: Engine) -> None:
    definition = load_engagement_definition(EXAMPLE)
    factory = session_factory(engine)
    with factory.begin() as session:
        report = create_from_definition(session, definition)

    assert report.created
    assert report.mission_id
    assert report.mission_name == definition.name

    with factory.begin() as session:
        status = mission_status(session, MissionId(report.mission_id))

    assert status is not None
    assert status.state == MissionState.PENDING.value
    assert status.active_run_id is None


def test_a_created_mission_inherits_the_definition_budget(engine: Engine) -> None:
    definition = load_engagement_definition(EXAMPLE)
    factory = session_factory(engine)
    with factory.begin() as session:
        report = create_from_definition(session, definition)

    with factory.begin() as session:
        stored = MissionRepository(session).get(MissionId(report.mission_id))

    assert stored is not None
    assert stored.entity.budget.requests_per_minute_per_domain == 5
    assert stored.entity.cadence.cycle_interval_seconds == 300


def test_status_reports_lead_counts_and_surface_size(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)

        status = mission_status(session, MissionId(mission.id))

    assert status is not None
    assert status.lead_counts == {}
    assert status.assets == 0
    assert status.as_dict()["mission_name"] == mission.name


def test_status_for_an_unknown_mission_is_none(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        assert mission_status(session, MissionId("00000000-0000-7000-8000-000000000000")) is None


def test_pause_resume_and_kill_switch_transitions(engine: Engine) -> None:
    factory = session_factory(engine)
    later = NOW + timedelta(minutes=1)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        mission_id = MissionId(mission.id)

        paused = set_mission_state(session, mission_id, state=MissionState.PAUSED, at=later)
        assert paused is not None
        assert not paused.permits_cycle(at=later)

    with factory.begin() as session:
        resumed = set_mission_state(session, mission_id, state=MissionState.RUNNING, at=later)
        assert resumed is not None
        assert resumed.permits_cycle(at=later)

    with factory.begin() as session:
        killed = set_mission_state(session, mission_id, kill_switch_engaged=True, at=later)

    assert killed is not None
    assert killed.kill_switch_engaged
    assert not killed.permits_cycle(at=later)
