"""add related_actors to incidents (Stage 1 detection hardening — cross-actor correlation)

Revision ID: 8f2a4c6e1b09
Revises: 4d99f129660a
Create Date: 2026-08-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision: str = '8f2a4c6e1b09'
down_revision: Union[str, Sequence[str], None] = '4d99f129660a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Nullable, unused (None) for every existing single-actor incident — populated only for
    # a merged coordinated-campaign or cross-actor-spray incident (Stage 1 hardening).
    op.add_column(
        'incidents',
        sa.Column(
            'related_actors',
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('incidents', 'related_actors')
