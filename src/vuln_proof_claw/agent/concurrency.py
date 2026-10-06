"""Hold one engagement to one running agent, across processes.

An engagement declares ``maximum_concurrent_actions``. Nothing enforced it, because
each target has its own database and therefore its own ledger: four agents launched
against four targets of one engagement each believed itself well inside the hourly
budget, while between them they sent 178 requests in an hour authorized for 100. No
ledger was wrong. There was simply no place where the total existed.

Splitting state per target is right -- separate budgets, no two processes writing one
SQLite file -- so the total has to be defended somewhere above the database. This is
that place: a lock file named for the engagement, held for the life of the run.

It is advisory and deliberately simple. It stops the honest mistake of starting a
second agent, which is the mistake that actually happened; it is not a defence against
someone who means to run two.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType


class ConcurrencyError(RuntimeError):
    """Another agent is already running against this engagement."""


@dataclass(frozen=True, slots=True)
class LockHolder:
    """Who holds the lock, as recorded when they took it."""

    pid: int
    mission_id: str
    started_at: str

    def describe(self) -> str:
        return f"pid {self.pid}, mission {self.mission_id}, since {self.started_at}"


def lock_directory() -> Path:
    """Return where locks live: one place every process on this machine agrees on."""
    return Path(tempfile.gettempdir()) / "vuln-proof-claw-locks"


def _running(pid: int) -> bool:
    """Return whether a process is still alive.

    A lock whose holder has died is not a lock, and an agent that crashes must not
    leave an engagement unrunnable until somebody deletes a file they do not know about.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Alive, and owned by someone else.
        return True
    except OSError:
        return False
    return True


@dataclass
class EngagementLock:
    """An advisory, cross-process lock on one engagement."""

    engagement_id: str
    mission_id: str
    directory: Path | None = None
    _path: Path | None = None

    @property
    def path(self) -> Path:
        base = self.directory or lock_directory()
        safe = "".join(
            character if character.isalnum() else "-" for character in self.engagement_id
        )
        return base / f"{safe}.lock"

    def acquire(self, *, at: datetime | None = None) -> None:
        """Take the lock, or say who has it.

        Created with O_EXCL so two processes racing here cannot both succeed.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {
                "pid": os.getpid(),
                "mission_id": self.mission_id,
                "started_at": (at or datetime.now(UTC)).isoformat(),
            }
        )
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            holder = self.holder()
            if holder is not None and _running(holder.pid):
                raise ConcurrencyError(
                    f"another agent is already running for this engagement: {holder.describe()}"
                ) from None
            # The holder is gone. Reclaim rather than leaving the engagement blocked by
            # a file nobody knows to delete.
            self.path.unlink(missing_ok=True)
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
        self._path = self.path

    def holder(self) -> LockHolder | None:
        """Return who the lock file says holds it, or None when it cannot be read."""
        try:
            recorded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        try:
            return LockHolder(
                pid=int(recorded["pid"]),
                mission_id=str(recorded["mission_id"]),
                started_at=str(recorded["started_at"]),
            )
        except (KeyError, TypeError, ValueError):
            return None

    def release(self) -> None:
        """Give the lock up. Only ever removes a lock this instance took."""
        if self._path is not None:
            self._path.unlink(missing_ok=True)
            self._path = None

    def __enter__(self) -> EngagementLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


__all__ = ["ConcurrencyError", "EngagementLock", "LockHolder", "lock_directory"]
