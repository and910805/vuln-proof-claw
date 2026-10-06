"""Attack-surface snapshots and change detection.

Change events are the system's definition of "new evidence". They are the only thing
that may reawaken a stale or rejected lead, which is what prevents the agent from
retrying a failed hypothesis on a timer.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from vuln_proof_claw.domain.autonomous import Asset, ChangeEvent, Endpoint, SurfaceSnapshot
from vuln_proof_claw.domain.enums import ChangeKind
from vuln_proof_claw.domain.identifiers import EngagementId
from vuln_proof_claw.persistence.autonomous_repositories import (
    AssetRepository,
    ChangeEventRepository,
    EndpointRepository,
    SurfaceSnapshotRepository,
)

_SUBJECT_SEPARATOR = "\x1f"
_INVENTORY_PAGE_SIZE = 1000


def subject_digest(subject: str) -> str:
    """Return the content digest identifying one surface element."""
    return hashlib.sha256(subject.encode()).hexdigest()


def asset_subject(asset: Asset) -> str:
    """Return the stable subject string for an asset."""
    return f"asset:{asset.kind.value}:{asset.identifier}"


def endpoint_subject(endpoint: Endpoint) -> str:
    """Return the stable subject string for an endpoint."""
    return f"endpoint:{endpoint.method}:{endpoint.path}"


def surface_digest(subjects: Iterable[str]) -> str:
    """Return an order-independent digest of the whole known attack surface."""
    material = _SUBJECT_SEPARATOR.join(sorted(set(subjects))).encode()
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True, slots=True)
class SurfaceCapture:
    """One snapshot and the changes it revealed."""

    snapshot: SurfaceSnapshot
    changes: tuple[ChangeEvent, ...]
    baseline: bool


class SurfaceTracker:
    """Capture attack-surface snapshots and emit typed change events."""

    def __init__(self, session: Session, engagement_id: EngagementId) -> None:
        self._engagement_id = engagement_id
        self._assets = AssetRepository(session)
        self._endpoints = EndpointRepository(session)
        self._snapshots = SurfaceSnapshotRepository(session)
        self._changes = ChangeEventRepository(session)

    def capture(self, *, at: datetime) -> SurfaceCapture:
        """Snapshot the current surface and record what changed since the last one.

        Additions are detected from first-seen timestamps rather than by storing every
        prior subject, so the snapshot stays a constant-size record.
        """
        previous = self._snapshots.latest(self._engagement_id)
        assets = tuple(
            stored.entity
            for stored in self._assets.list_for_engagement(
                self._engagement_id, limit=_INVENTORY_PAGE_SIZE
            )
        )
        endpoints = tuple(
            stored.entity
            for stored in self._endpoints.list_for_engagement(
                self._engagement_id, limit=_INVENTORY_PAGE_SIZE
            )
        )

        subjects = [asset_subject(asset) for asset in assets]
        subjects.extend(endpoint_subject(endpoint) for endpoint in endpoints)

        snapshot = SurfaceSnapshot(
            engagement_id=self._engagement_id,
            digest=surface_digest(subjects),
            asset_count=len(assets),
            endpoint_count=len(endpoints),
            captured_at=at,
        )
        self._snapshots.add(snapshot)

        if previous is None:
            return SurfaceCapture(snapshot=snapshot, changes=(), baseline=True)
        if previous.digest == snapshot.digest:
            return SurfaceCapture(snapshot=snapshot, changes=(), baseline=False)

        changes = tuple(
            self._record_change(kind, subject, snapshot=snapshot, at=at)
            for kind, subject in self._additions(
                assets, endpoints, since=previous.captured_at
            )
        )
        return SurfaceCapture(snapshot=snapshot, changes=changes, baseline=False)

    def _additions(
        self,
        assets: tuple[Asset, ...],
        endpoints: tuple[Endpoint, ...],
        *,
        since: datetime,
    ) -> tuple[tuple[ChangeKind, str], ...]:
        added: list[tuple[ChangeKind, str]] = [
            (ChangeKind.ASSET_ADDED, asset_subject(asset))
            for asset in assets
            if asset.first_seen_at > since
        ]
        added.extend(
            (ChangeKind.ENDPOINT_ADDED, endpoint_subject(endpoint))
            for endpoint in endpoints
            if endpoint.first_seen_at > since
        )
        return tuple(added)

    def _record_change(
        self,
        kind: ChangeKind,
        subject: str,
        *,
        snapshot: SurfaceSnapshot,
        at: datetime,
    ) -> ChangeEvent:
        event = ChangeEvent(
            engagement_id=self._engagement_id,
            kind=kind,
            subject=subject,
            snapshot_id=snapshot.id,
            current_digest=subject_digest(subject),
            detected_at=at,
        )
        self._changes.add(event)
        return event


__all__ = [
    "SurfaceCapture",
    "SurfaceTracker",
    "asset_subject",
    "endpoint_subject",
    "subject_digest",
    "surface_digest",
]
