"""Carry the request query string alongside the normalized action target.

The normalized target stays query-free because that is what scope evaluates and what an
approval binds a host and path to. The query is stored separately and folded into the
parameter digest, so it cannot widen authorization but also cannot be swapped silently.

Existing rows default to an empty query, which produces exactly the digest they already
hold, so every stored action and issued approval remains valid.

Revision ID: 0011_action_query
Revises: 0010_autonomous_missions
Create Date: 2026-10-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_action_query"
down_revision: str | None = "0010_autonomous_missions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "actions",
        sa.Column("query", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("actions", "query")
