"""Join the two schema lines that grew in parallel from 0009.

One line added the autonomous mission tables and the action query column; the other
added plan progress, usage samples, and a finding's stated verification method. They
touch different tables, so neither needs changing — what was missing was a single point
they both lead to, without which a database cannot be told which head to upgrade to.

This revision adds no schema of its own. It exists so that `alembic upgrade head` has
one answer again.

Revision ID: 0012_merge_missions_and_usage
Revises: 0011_action_query, 0011_optional_verification_method
Create Date: 2026-10-05
"""

from collections.abc import Sequence

revision: str = "0012_merge_missions_and_usage"
down_revision: tuple[str, ...] = (
    "0011_action_query",
    "0011_optional_verification_method",
)
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Nothing to do: both parents already applied their own changes."""


def downgrade() -> None:
    """Nothing to undo; downgrading past here follows each parent separately."""
