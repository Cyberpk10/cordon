"""add suspicious_pattern_score column to actor_baselines (detection max-out Stage D)

Revision ID: e7b3f5a1c284
Revises: d4a8e2f6c910
Create Date: 2026-09-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'e7b3f5a1c284'
down_revision: Union[str, Sequence[str], None] = 'd4a8e2f6c910'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'actor_baselines',
        sa.Column('suspicious_pattern_score', sa.Float(), nullable=False, server_default='0.0'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('actor_baselines', 'suspicious_pattern_score')
