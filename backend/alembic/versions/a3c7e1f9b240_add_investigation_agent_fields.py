"""add case artifacts and investigation agent fields

Revision ID: a3c7e1f9b240
Revises: e5a9c2d7f310
Create Date: 2026-11-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a3c7e1f9b240'
down_revision: Union[str, Sequence[str], None] = 'e5a9c2d7f310'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cases', sa.Column('artifacts', _JSON, nullable=True))
    op.add_column('investigations', sa.Column('report', _JSON, nullable=True))
    op.add_column('investigations', sa.Column('evidence', _JSON, nullable=True))
    op.add_column('investigations', sa.Column('tool_trace', _JSON, nullable=True))
    op.add_column('investigations', sa.Column('input_fingerprint', sa.String(), nullable=True))
    op.add_column('investigations', sa.Column('engine', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('investigations', 'engine')
    op.drop_column('investigations', 'input_fingerprint')
    op.drop_column('investigations', 'tool_trace')
    op.drop_column('investigations', 'evidence')
    op.drop_column('investigations', 'report')
    op.drop_column('cases', 'artifacts')
