"""add sender_ip_info to cases

Revision ID: c3e1a7f05b92
Revises: 204b587f6598
Create Date: 2026-11-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c3e1a7f05b92'
down_revision: Union[str, Sequence[str], None] = '204b587f6598'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql')


def upgrade() -> None:
    """Upgrade schema."""
    # Nullable, no default: pre-existing cases simply have no sender-IP panel (their raw
    # email may already be purged, so it can't be backfilled honestly).
    op.add_column('cases', sa.Column('sender_ip_info', _JSON_TYPE, nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cases', 'sender_ip_info')
