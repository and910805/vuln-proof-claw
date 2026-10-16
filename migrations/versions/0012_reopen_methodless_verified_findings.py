"""Reopen legacy verified findings that never stated a verification method.

Revision ID: 0012_reopen_methodless_verified_findings
Revises: 0012_merge_missions_and_usage
Create Date: 2026-10-16
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0012_reopen_methodless_verified_findings"
down_revision: str | None = "0012_merge_missions_and_usage"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # There is no defensible way to infer how an old methodless claim was
    # established. Preserve its evidence and reopen it for a fresh review.
    op.execute(
        "UPDATE findings SET status = 'needs_manual_review' "
        "WHERE status = 'verified' AND verification_method IS NULL"
    )


def downgrade() -> None:
    # The old status cannot be reconstructed without falsely promoting rows
    # that were already in manual review before this migration.
    pass
