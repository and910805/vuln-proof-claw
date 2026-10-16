"""Tests for noticing that a database predates the code reading it."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, text

from vuln_proof_claw.persistence.base import Base
from vuln_proof_claw.persistence.schema_check import inspect_schema, repair_schema


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    built = create_engine(f"sqlite:///{tmp_path / 'state.db'}")
    Base.metadata.create_all(built)
    return built


def test_a_database_the_models_made_is_current(engine: Engine) -> None:
    assert inspect_schema(engine).current is True


def test_a_dropped_column_is_reported_with_its_table(engine: Engine) -> None:
    """SQLite cannot add a column back, so an operator needs to know which one."""
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE tasks DROP COLUMN sequence"))

    drift = inspect_schema(engine)

    assert drift.current is False
    assert ("tasks", "sequence") in drift.missing_columns
    assert "tasks.sequence" in drift.describe()


def test_a_dropped_table_is_reported(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE tasks"))

    drift = inspect_schema(engine)

    assert "tasks" in drift.missing_tables
    assert "missing table" in drift.describe()
    # Its columns are not listed again; the table covers them.
    assert all(table != "tasks" for table, _ in drift.missing_columns)


def test_a_column_the_database_has_and_the_models_do_not_is_not_drift(
    engine: Engine,
) -> None:
    """A release only ever adds. An extra column is someone else's business."""
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE tasks ADD COLUMN leftover TEXT"))

    assert inspect_schema(engine).current is True


def test_an_empty_database_reports_every_table(tmp_path: Path) -> None:
    """Not an error case: this is what a path typo looks like, and saying 'missing
    table x45' is more use than one failed insert half an hour later."""
    drift = inspect_schema(create_engine(f"sqlite:///{tmp_path / 'empty.db'}"))

    assert drift.current is False
    assert len(drift.missing_tables) == len(Base.metadata.tables)


def test_repair_adds_a_missing_column_with_its_default(engine: Engine) -> None:
    """The case that stopped a run: a column added by a release, absent from a file
    the previous release wrote."""
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE tasks DROP COLUMN sequence"))

    tables, columns, refused = repair_schema(engine)

    assert tables == ()
    assert ("tasks", "sequence") in columns
    assert refused == ()
    assert inspect_schema(engine).current is True


def test_repair_recreates_a_missing_table(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE tasks"))

    tables, _, refused = repair_schema(engine)

    assert "tasks" in tables
    assert refused == ()
    assert inspect_schema(engine).current is True


def test_repair_does_not_touch_rows(engine: Engine) -> None:
    """A database holding evidence records what was sent to somebody else's system.
    Bringing its schema forward must not be able to change what it says."""
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO tasks (id, flow_id, title, created_at, sequence, state, "
                "attempts) VALUES ('t1', 'f1', 'keep me', '2026-10-06', 3, 'planned', 0)"
            )
        )
        connection.execute(text("ALTER TABLE tasks DROP COLUMN state"))

    repair_schema(engine)

    with engine.begin() as connection:
        row = connection.execute(text("SELECT title, sequence FROM tasks")).one()

    assert row.title == "keep me"
    assert row.sequence == 3


def test_repair_on_a_current_database_changes_nothing(engine: Engine) -> None:
    assert repair_schema(engine) == ((), (), ())
