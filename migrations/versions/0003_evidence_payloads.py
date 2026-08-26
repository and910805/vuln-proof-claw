"""Persist raw evidence and canonical chain material.

Revision ID: 0003_evidence_payloads
Revises: 0002_engagement_scopes
Create Date: 2026-08-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_evidence_payloads"
down_revision: str | None = "0002_engagement_scopes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_payloads",
        sa.Column("evidence_id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("chain_index", sa.Integer(), nullable=False),
        sa.Column("canonical_metadata", sa.LargeBinary(), nullable=False),
        sa.Column("raw_content", sa.LargeBinary(), nullable=False),
        sa.Column("raw_size", sa.Integer(), nullable=False),
        sa.CheckConstraint("raw_size >= 0", name="raw_size"),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.id"],
            name="fk_evidence_payloads_engagement_id_engagements",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_evidence_payloads_evidence_id_evidence",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_evidence_payloads"),
        sa.UniqueConstraint(
            "engagement_id",
            "chain_index",
            name="uq_evidence_payloads_engagement_id_chain_index",
        ),
    )
    op.create_index(
        "ix_evidence_payloads_engagement_id",
        "evidence_payloads",
        ["engagement_id"],
    )
    op.create_index(
        "ix_evidence_payloads_engagement_chain",
        "evidence_payloads",
        ["engagement_id", "chain_index"],
    )


def downgrade() -> None:
    op.drop_table("evidence_payloads")
