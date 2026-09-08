"""add actor_threat_levels table (early-warning sensor Stage 1)

Revision ID: f18c6a3e9b57
Revises: e7b3f5a1c284
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision: str = 'f18c6a3e9b57'
down_revision: Union[str, Sequence[str], None] = 'e7b3f5a1c284'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql')


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'actor_threat_levels',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('actor', sa.String(), nullable=False),
        sa.Column('current_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('recent_signals', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('score_history', _JSON_TYPE, nullable=False, server_default='{}'),
        sa.Column('last_updated', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('account_id', 'actor', name='uq_actor_threat_levels_account_actor'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('actor_threat_levels')
