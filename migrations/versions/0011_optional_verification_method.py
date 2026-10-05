"""Let a finding record that no verification method was stated.

``verification_method`` used to default to ``observed`` at the column level, so
a finding that never said what its claim rested on was stored as though it had
said "observed". "Not stated" is now a value in its own right, which is what
lets the domain refuse a HIGH or CRITICAL finding that never made the claim.

Constraint names are bare tokens on purpose: the metadata naming convention
adds the ``ck_<table>_`` prefix, so passing a prefixed name here would produce
a doubly prefixed constraint that drifts from the models.

Revision ID: 0011_optional_verification_method
Revises: 0010_plan_progress_and_usage
Create Date: 2026-08-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_optional_verification_method"
down_revision: str | None = "0010_plan_progress_and_usage"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.alter_column(
            "verification_method",
            existing_type=sa.String(length=32),
            existing_nullable=False,
            existing_server_default="observed",
            nullable=True,
            server_default=None,
        )


def downgrade() -> None:
    # Rows that recorded "no method stated" have to be given one back before the
    # column can refuse NULL again.
    op.execute(
        "UPDATE findings SET verification_method = 'observed' "
        "WHERE verification_method IS NULL"
    )
    with op.batch_alter_table("findings") as batch:
        batch.alter_column(
            "verification_method",
            existing_type=sa.String(length=32),
            existing_nullable=True,
            nullable=False,
            server_default="observed",
        )
