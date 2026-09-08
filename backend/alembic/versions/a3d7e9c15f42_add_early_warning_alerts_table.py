"""add early_warning_alerts table (early-warning sensor Stage 2)

Revision ID: a3d7e9c15f42
Revises: f18c6a3e9b57
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision: str = 'a3d7e9c15f42'
down_revision: Union[str, Sequence[str], None] = 'f18c6a3e9b57'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql')


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'early_warning_alerts',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('actor', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, server_default='active'),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('signal_timeline', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('recommended_actions', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('acknowledged_by', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('early_warning_alerts')
