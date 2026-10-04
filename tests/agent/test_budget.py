"""Tests for deterministic request and token budgets."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from tests.agent.support import NOW, build_engine, seed_engagement, seed_mission, session_factory
from vuln_proof_claw.agent.budget import BudgetGate, BudgetWindowKind, window_start
from vuln_proof_claw.domain.autonomous import MissionBudget
from vuln_proof_claw.domain.errors import DomainValidationError

HOST = "api.example.com"
OTHER_HOST = "www.example.com"
NAIVE = datetime(2026, 10, 4, 12, 0)


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "budget.db")


def test_window_start_floors_each_accounting_period() -> None:
    moment = datetime(2026, 10, 4, 13, 47, 31, 500, tzinfo=UTC)

    assert window_start(BudgetWindowKind.MINUTE, moment) == moment.replace(
        second=0, microsecond=0
    )
    assert window_start(BudgetWindowKind.HOUR, moment) == moment.replace(
        minute=0, second=0, microsecond=0
    )
    assert window_start(BudgetWindowKind.DAY, moment) == moment.replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    assert window_start(BudgetWindowKind.TOTAL, moment) == datetime(1970, 1, 1, tzinfo=UTC)


def test_window_start_rejects_naive_timestamps() -> None:
    with pytest.raises(DomainValidationError):
        window_start(BudgetWindowKind.HOUR, NAIVE)


def test_per_domain_rate_limit_is_enforced_independently(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            budget=MissionBudget(requests_per_minute_per_domain=2),
        )
        gate = BudgetGate(session, mission)

        gate.record_request(host=HOST, at=NOW)
        gate.record_request(host=HOST, at=NOW)

        exhausted = gate.permits_request(host=HOST, at=NOW)
        other = gate.permits_request(host=OTHER_HOST, at=NOW)
        next_minute = gate.permits_request(host=HOST, at=NOW + timedelta(minutes=1))

    assert not exhausted
    assert exhausted.reason == "domain_rate_limit_reached"
    assert other
    assert next_minute


def test_hourly_daily_and_total_ceilings_are_each_enforced(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            budget=MissionBudget(
                requests_per_minute_per_domain=100,
                requests_per_hour=2,
                requests_per_day=3,
                total_requests=4,
            ),
        )
        gate = BudgetGate(session, mission)

        gate.record_request(host=HOST, at=NOW)
        gate.record_request(host=HOST, at=NOW)
        hourly = gate.permits_request(host=HOST, at=NOW)

        gate.record_request(host=HOST, at=NOW + timedelta(hours=1))
        daily = gate.permits_request(host=HOST, at=NOW + timedelta(hours=2))

        gate.record_request(host=HOST, at=NOW + timedelta(days=1))
        total = gate.permits_request(host=HOST, at=NOW + timedelta(days=2))

    assert hourly.reason == "hourly_request_ceiling_reached"
    assert daily.reason == "daily_request_ceiling_reached"
    assert total.reason == "mission_request_budget_exhausted"


def test_token_budgets_apply_per_day_and_per_lead(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(
            session,
            engagement_id,
            budget=MissionBudget(llm_tokens_per_day=1_000, llm_tokens_per_lead=400),
        )
        gate = BudgetGate(session, mission)

        within = gate.permits_tokens(tokens=300, lead_key="lead-a", at=NOW)
        gate.record_tokens(tokens=300, lead_key="lead-a", at=NOW)

        over_lead = gate.permits_tokens(tokens=300, lead_key="lead-a", at=NOW)
        other_lead = gate.permits_tokens(tokens=300, lead_key="lead-b", at=NOW)

        gate.record_tokens(tokens=300, lead_key="lead-b", at=NOW)
        gate.record_tokens(tokens=300, lead_key="lead-c", at=NOW)
        over_day = gate.permits_tokens(tokens=300, lead_key="lead-d", at=NOW)

    assert within
    assert over_lead.reason == "lead_token_budget_exhausted"
    assert other_lead
    assert over_day.reason == "daily_token_budget_exhausted"


def test_budget_refuses_negative_consumption(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        mission = seed_mission(session, engagement_id)
        gate = BudgetGate(session, mission)

        with pytest.raises(DomainValidationError):
            gate.permits_tokens(tokens=-1, lead_key="lead-a", at=NOW)
