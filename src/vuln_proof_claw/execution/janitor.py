"""Reclaim leaked disposable-Worker runtime resources that have no live owner.

Runtime references are never persisted, so a restarted control plane cannot
reattach the disposable Workers it previously created. Restart reconciliation
fails those durable registry rows closed, but the underlying runtime resources
remain allocated. This janitor closes that gap: it enumerates the runtime
resources the platform still owns and destroys every one that no live in-process
manager is protecting.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.orm import Session

from vuln_proof_claw.audit import record_system_audit_event

_SYSTEM_ACTOR = "system:orphan-janitor"


class OrphanJanitorError(Exception):
    """Safe failure raised when an orphan sweep cannot enumerate owned resources."""


class ReapableRuntime(Protocol):
    """Privileged runtime adapter that can list and destroy platform-owned Workers."""

    @property
    def identity(self) -> str:
        """Return the immutable runtime identity included in audit records."""

    async def list_owned(self) -> tuple[str, ...]:
        """Return every runtime reference tagged as owned by this platform."""

    async def destroy(self, runtime_reference: str) -> None:
        """Idempotently destroy one runtime reference and its per-Worker resources."""


@dataclass(frozen=True, slots=True)
class OrphanSweepReport:
    """Safe, reference-free summary of a single reclamation sweep."""

    scanned: int
    protected: int
    reclaimed: int
    failed: int

    @property
    def orphaned(self) -> int:
        """Return how many owned references were not protected by a live owner."""
        return self.reclaimed + self.failed


def _utc_now() -> datetime:
    return datetime.now(UTC)


class OrphanRuntimeJanitor:
    """Destroy runtime resources the platform owns but no live manager is tracking."""

    def __init__(
        self,
        session: Session,
        runtime: ReapableRuntime,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._session = session
        self._runtime = runtime
        self._clock = clock

    async def sweep(
        self,
        *,
        protected_references: Iterable[str] = (),
        at: datetime | None = None,
    ) -> OrphanSweepReport:
        """Reclaim every owned runtime reference outside the protected live set.

        ``protected_references`` is the set of references a concurrently running
        manager still owns; a fresh control plane after a restart owns none, so
        every enumerated reference is treated as an orphan. Enumeration failures
        fail the sweep closed; individual destroy failures are counted and the
        remaining orphans are still attempted.
        """
        timestamp = at or self._clock()
        protected = frozenset(protected_references)
        try:
            owned = await self._runtime.list_owned()
        except Exception as error:
            raise OrphanJanitorError("orphan_enumeration_failed") from error

        # Preserve first-seen order while removing duplicate references.
        orphans = [
            reference
            for reference in dict.fromkeys(owned)
            if reference not in protected
        ]
        reclaimed = 0
        failed = 0
        for reference in orphans:
            try:
                await self._runtime.destroy(reference)
            except Exception:  # noqa: BLE001 - best-effort cleanup mirrors manager teardown
                failed += 1
            else:
                reclaimed += 1

        report = OrphanSweepReport(
            scanned=len(owned),
            protected=len(protected),
            reclaimed=reclaimed,
            failed=failed,
        )
        if report.orphaned:
            self._audit(report, at=timestamp)
        return report

    def _audit(self, report: OrphanSweepReport, *, at: datetime) -> None:
        record_system_audit_event(
            self._session,
            "worker.orphans_reclaimed",
            _SYSTEM_ACTOR,
            {
                "runtime_identity": self._runtime.identity,
                "scanned": report.scanned,
                "protected": report.protected,
                "reclaimed": report.reclaimed,
                "failed": report.failed,
            },
            at=at,
        )
