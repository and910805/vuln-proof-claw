"""Allow immutable SARIF report exports.

Revision ID: 0007_sarif_exports
Revises: 0006_finding_guidance
Create Date: 2026-08-02
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007_sarif_exports"
down_revision: str | None = "0006_finding_guidance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("report_exports") as batch:
        batch.drop_constraint("format", type_="check")
        batch.create_check_constraint(
            "format",
            "format IN ('json', 'markdown', 'sarif')",
        )


def downgrade() -> None:
    with op.batch_alter_table("report_exports") as batch:
        batch.drop_constraint("format", type_="check")
        batch.create_check_constraint(
            "format",
            "format IN ('json', 'markdown')",
        )
