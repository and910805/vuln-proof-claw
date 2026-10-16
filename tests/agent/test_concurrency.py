"""Tests for holding one engagement to one running agent.

The case this exists for: four agents, four targets, one engagement. Each had its own
database and so its own ledger, each believed itself inside an hourly budget of 100,
and between them they sent 178 requests in that hour. Every ledger was correct. The
total simply had nowhere to live.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vuln_proof_claw.agent.concurrency import ConcurrencyError, EngagementLock

NOW = datetime(2026, 10, 6, 3, 0, tzinfo=UTC)


def lock(directory: Path, *, mission: str = "mission-a") -> EngagementLock:
    return EngagementLock(
        engagement_id="01a10f3e-8e6d-7cb4-b2c9-b115d78bd909",
        mission_id=mission,
        directory=directory,
    )


def test_one_agent_takes_the_lock(tmp_path: Path) -> None:
    held = lock(tmp_path)
    held.acquire(at=NOW)

    assert held.path.exists()
    held.release()
    assert not held.path.exists()


def test_a_second_agent_is_refused_and_told_who_has_it(tmp_path: Path) -> None:
    first = lock(tmp_path, mission="mission-a")
    first.acquire(at=NOW)

    with pytest.raises(ConcurrencyError) as raised:
        lock(tmp_path, mission="mission-b").acquire(at=NOW)

    message = str(raised.value)
    assert "mission-a" in message
    assert str(os.getpid()) in message


def test_two_engagements_do_not_block_each_other(tmp_path: Path) -> None:
    """The limit is per engagement. Two separate authorizations are two separate
    permissions, and one must not silently consume the other's."""
    EngagementLock("engagement-one", "m1", directory=tmp_path).acquire(at=NOW)
    EngagementLock("engagement-two", "m2", directory=tmp_path).acquire(at=NOW)


def test_a_dead_holder_does_not_block_the_engagement_forever(tmp_path: Path) -> None:
    """An agent that crashes must not leave the engagement unrunnable until somebody
    deletes a file they do not know exists."""
    stale = lock(tmp_path).path
    stale.parent.mkdir(parents=True, exist_ok=True)
    # A pid that cannot be running: pid 0 is never a user process.
    stale.write_text(
        json.dumps({"pid": 0, "mission_id": "gone", "started_at": NOW.isoformat()}),
        encoding="utf-8",
    )

    lock(tmp_path, mission="mission-b").acquire(at=NOW)

    assert lock(tmp_path).holder() is not None
    holder = lock(tmp_path).holder()
    assert holder is not None
    assert holder.mission_id == "mission-b"


def test_an_unreadable_lock_is_reclaimed_rather_than_trusted(tmp_path: Path) -> None:
    """A truncated file says nothing about whether anyone is running. Refusing on it
    would block the engagement on a file nobody can explain."""
    stale = lock(tmp_path).path
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text("{not json", encoding="utf-8")

    lock(tmp_path, mission="mission-b").acquire(at=NOW)

    holder = lock(tmp_path).holder()
    assert holder is not None
    assert holder.mission_id == "mission-b"


def test_release_only_removes_a_lock_this_instance_took(tmp_path: Path) -> None:
    """Releasing a lock somebody else holds would be worse than never locking."""
    first = lock(tmp_path, mission="mission-a")
    first.acquire(at=NOW)

    never_acquired = lock(tmp_path, mission="mission-b")
    never_acquired.release()

    assert first.path.exists()


def test_the_lock_is_released_when_the_block_ends(tmp_path: Path) -> None:
    with lock(tmp_path) as held:
        path = held.path
        assert path.exists()

    assert not path.exists()


def test_the_lock_is_released_even_when_the_run_fails(tmp_path: Path) -> None:
    """A crash must not leave the next run refused."""
    held = lock(tmp_path)
    with pytest.raises(RuntimeError), held:
        raise RuntimeError("cycle failed")

    assert not held.path.exists()


def test_one_authorization_written_as_two_files_is_still_one_slot(tmp_path: Path) -> None:
    """A real engagement was two files -- an internal target list and a public one --
    and an agent on each ran happily side by side, because the lock was keyed on the
    file rather than on the authorization. The hourly budget belongs to the activity."""
    EngagementLock("nics-024", "mission-vpn", directory=tmp_path).acquire(at=NOW)

    with pytest.raises(ConcurrencyError, match="mission-vpn"):
        EngagementLock("nics-024", "mission-public", directory=tmp_path).acquire(at=NOW)


def test_a_key_with_path_characters_cannot_escape_the_lock_directory(
    tmp_path: Path,
) -> None:
    """The key reaches this from a command line, so it must not be able to name a file
    anywhere else."""
    held = EngagementLock("../../etc/passwd", "m1", directory=tmp_path)
    held.acquire(at=NOW)

    assert held.path.parent == tmp_path
    assert held.path.exists()
