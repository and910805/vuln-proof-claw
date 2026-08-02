"""Add severity, confidence, and remediation to findings.

Revision ID: 0006_finding_guidance
Revises: 0005_report_exports
Create Date: 2026-08-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_finding_guidance"
down_revision: str | None = "0005_report_exports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("severity", sa.String(length=32), server_default="informational", nullable=False),
    )
    op.add_column(
        "findings",
        sa.Column("confidence", sa.String(length=32), server_default="medium", nullable=False),
    )
    op.add_column(
        "findings",
        sa.Column(
            "remediation",
            sa.Text(),
            server_default="Review the evidence and apply the relevant security control.",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "remediation")
    op.drop_column("findings", "confidence")
    op.drop_column("findings", "severity")
