"""add resource-sensitivity + anti-poisoning ramp columns to actor_baselines (detection
max-out Stage B)

Revision ID: d4a8e2f6c910
Revises: c3f7a1d9e824
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision: str = 'd4a8e2f6c910'
down_revision: Union[str, Sequence[str], None] = 'c3f7a1d9e824'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql')


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'actor_baselines',
        sa.Column('sensitive_classes_seen', _JSON_TYPE, nullable=False, server_default='[]'),
    )
    op.add_column(
        'actor_baselines',
        sa.Column('daily_sensitive_count', _JSON_TYPE, nullable=False, server_default='{}'),
    )
    op.add_column(
        'actor_baselines',
        sa.Column('long_term_daily_volume', _JSON_TYPE, nullable=False, server_default='{}'),
    )
    op.add_column(
        'actor_baselines',
        sa.Column('long_term_daily_sensitive_count', _JSON_TYPE, nullable=False, server_default='{}'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('actor_baselines', 'long_term_daily_sensitive_count')
    op.drop_column('actor_baselines', 'long_term_daily_volume')
    op.drop_column('actor_baselines', 'daily_sensitive_count')
    op.drop_column('actor_baselines', 'sensitive_classes_seen')
