"""Record whether a person closed a lead, so the agent cannot reopen it.

When a target's attack surface changes, the controller returns every stale and
rejected lead to the queue. For a lead the agent itself ruled out that is right:
its answer was about a surface that no longer exists.

It is wrong for a lead a person closed. Twelve hand-triaged leads, each with a
written reason, were requeued by a surface change; the agent then spent budget
re-asking them and the operator saw them again as work to do. "This is
jquery.min.js, it is a static file" does not stop being true because the
application was redeployed.

Existing rows default to false. That is the safe direction: every lead closed
before this column existed was closed by the agent or by a person whose verdict
we cannot now distinguish, and treating an unknown as "the agent's" means the
worst case is one unnecessary reopening rather than a human conclusion silently
made permanent.

Revision ID: 0013_lead_closed_by_researcher
Revises: 0012_merge_missions_and_usage
Create Date: 2026-10-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_lead_closed_by_researcher"
down_revision: str | None = "0012_merge_missions_and_usage"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "leads",
        sa.Column(
            "closed_by_researcher",
            sa.Boolean(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("leads", "closed_by_researcher")
