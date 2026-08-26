"""Tests for the initial Alembic migration."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

EXPECTED_TABLES = {
    "actions",
    "alembic_version",
    "approvals",
    "approval_presets",
    "artifacts",
    "audit_events",
    "engagements",
    "engagement_scopes",
    "evidence",
    "evidence_payloads",
    "finding_evidence",
    "findings",
    "flows",
    "projects",
    "report_exports",
    "tasks",
    "usage_samples",
    "worker_executions",
}


def alembic_config(database_url: str) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def test_upgrade_from_empty_database_and_downgrade(tmp_path: Path) -> None:
    database_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{database_path}"
    config = alembic_config(database_url)

    command.upgrade(config, "head")
    command.check(config)

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            inspector = inspect(connection)
            assert set(inspector.get_table_names()) == EXPECTED_TABLES
            assert {"ix_actions_engagement_state", "ix_actions_task_created"} <= {
                index["name"] for index in inspector.get_indexes("actions")
            }
            assert {"ix_evidence_action_captured"} <= {
                index["name"] for index in inspector.get_indexes("evidence")
            }
            assert {"ix_worker_executions_engagement_state"} <= {
                index["name"] for index in inspector.get_indexes("worker_executions")
            }
            assert {"ix_report_exports_engagement_created"} <= {
                index["name"] for index in inspector.get_indexes("report_exports")
            }
            assert {"severity", "confidence", "remediation"} <= {
                column["name"] for column in inspector.get_columns("findings")
            }

        command.downgrade(config, "base")
        with engine.connect() as connection:
            assert set(inspect(connection).get_table_names()) == {"alembic_version"}
    finally:
        engine.dispose()


def test_postgresql_migration_can_render_offline_sql(capsys: pytest.CaptureFixture[str]) -> None:
    config = alembic_config("postgresql+psycopg://user:password@localhost/database")

    command.upgrade(config, "head", sql=True)

    output = capsys.readouterr().out
    assert "CREATE TABLE projects" in output
    assert "CREATE TABLE actions" in output
    assert "CREATE TABLE engagement_scopes" in output
    assert "CREATE TABLE evidence_payloads" in output
    assert "CREATE TABLE worker_executions" in output
    assert "CREATE TABLE report_exports" in output
    assert "ALTER TABLE findings ADD COLUMN severity" in output
    assert "CREATE INDEX ix_evidence_action_captured" in output


def test_live_postgresql_upgrade_when_test_database_is_configured() -> None:
    database_url = os.getenv("VULN_PROOF_CLAW_TEST_POSTGRES_URL")
    if database_url is None:
        pytest.skip("VULN_PROOF_CLAW_TEST_POSTGRES_URL is not configured")
    if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        pytest.fail("VULN_PROOF_CLAW_TEST_POSTGRES_URL must use PostgreSQL")

    config = alembic_config(database_url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
    engine.dispose()
