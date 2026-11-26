"""Multi-agent orchestration (D6): consolidated assessment stored on the investigation.

Revision ID: c4e9a2d7f310
Revises: b8d2f4a6c913
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "c4e9a2d7f310"
down_revision = "b8d2f4a6c913"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("investigations", sa.Column("multi_agent", _JSON, nullable=True))
    op.add_column("investigations", sa.Column("multi_agent_fingerprint", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("investigations", "multi_agent_fingerprint")
    op.drop_column("investigations", "multi_agent")
