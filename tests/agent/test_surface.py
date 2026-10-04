"""Tests for attack-surface snapshots and change detection."""

from __future__ import annotations

from collections.abc import Generator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from tests.agent.support import (
    NOW,
    build_engine,
    seed_engagement,
    seed_surface,
    session_factory,
)
from vuln_proof_claw.agent.surface import (
    SurfaceTracker,
    asset_subject,
    endpoint_subject,
    subject_digest,
    surface_digest,
)
from vuln_proof_claw.domain.autonomous import Asset, Endpoint
from vuln_proof_claw.domain.enums import AssetKind, ChangeKind
from vuln_proof_claw.domain.identifiers import new_asset_id, new_engagement_id

LATER = NOW + timedelta(hours=1)


@pytest.fixture
def engine(tmp_path: Path) -> Generator[Engine, None, None]:
    yield from build_engine(tmp_path / "surface.db")


def test_surface_digest_is_order_independent_and_deduplicated() -> None:
    first = surface_digest(["b", "a", "c"])
    second = surface_digest(["c", "b", "a", "a"])

    assert first == second
    assert len(first) == 64


def test_subjects_are_stable_and_distinct_per_kind() -> None:
    asset = Asset(
        engagement_id=new_engagement_id(),
        kind=AssetKind.HOSTNAME,
        identifier="api.example.com",
        first_seen_at=NOW,
        last_seen_at=NOW,
    )
    endpoint = Endpoint(
        engagement_id=asset.engagement_id,
        asset_id=new_asset_id(),
        method="GET",
        path="/orders",
        first_seen_at=NOW,
        last_seen_at=NOW,
    )

    assert asset_subject(asset) == "asset:hostname:api.example.com"
    assert endpoint_subject(endpoint) == "endpoint:GET:/orders"
    assert len(subject_digest(asset_subject(asset))) == 64


def test_the_first_capture_is_a_baseline_without_change_events(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        seed_surface(session, engagement_id)

        capture = SurfaceTracker(session, engagement_id).capture(at=NOW)

    assert capture.baseline
    assert capture.changes == ()
    assert capture.snapshot.asset_count == 1
    assert capture.snapshot.endpoint_count == 1


def test_an_unchanged_surface_produces_no_change_events(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        seed_surface(session, engagement_id)
        tracker = SurfaceTracker(session, engagement_id)
        first = tracker.capture(at=NOW)

        second = tracker.capture(at=LATER)

    assert first.snapshot.digest == second.snapshot.digest
    assert second.changes == ()
    assert not second.baseline


def test_a_new_endpoint_produces_an_endpoint_added_event(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        seed_surface(session, engagement_id, at=NOW)
        tracker = SurfaceTracker(session, engagement_id)
        tracker.capture(at=NOW)

        seed_surface(session, engagement_id, at=LATER, path="/invoices")
        capture = tracker.capture(at=LATER)

    assert len(capture.changes) == 1
    assert capture.changes[0].kind is ChangeKind.ENDPOINT_ADDED
    assert capture.changes[0].subject == "endpoint:GET:/invoices"
    assert capture.changes[0].previous_digest is None


def test_re_observing_a_known_endpoint_is_not_a_change(engine: Engine) -> None:
    factory = session_factory(engine)
    with factory.begin() as session:
        engagement_id = seed_engagement(session)
        seed_surface(session, engagement_id, at=NOW)
        tracker = SurfaceTracker(session, engagement_id)
        tracker.capture(at=NOW)

        seed_surface(session, engagement_id, at=LATER)
        capture = tracker.capture(at=LATER)

    assert capture.changes == ()
