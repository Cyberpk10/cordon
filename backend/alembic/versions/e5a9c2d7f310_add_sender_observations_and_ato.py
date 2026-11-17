"""add sender_observations table and account-takeover columns on cases

Revision ID: e5a9c2d7f310
Revises: d8f2b6a41c37
Create Date: 2026-11-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e5a9c2d7f310'
down_revision: Union[str, Sequence[str], None] = 'd8f2b6a41c37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'sender_observations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('from_addr', sa.String(), nullable=False),
        sa.Column('from_domain', sa.String(), nullable=False),
        sa.Column('content_hash', sa.String(), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('message_hour_utc', sa.Integer(), nullable=True),
        sa.Column('sending_ip', sa.String(), nullable=True),
        sa.Column('sending_country', sa.String(), nullable=True),
        sa.Column('country_source', sa.String(), nullable=True),
        sa.Column('sending_provider', sa.String(), nullable=True),
        sa.Column('reply_to_domain', sa.String(), nullable=True),
        sa.Column('return_path_domain', sa.String(), nullable=True),
        sa.Column('auth_pass', sa.Boolean(), nullable=False),
        sa.Column('verdict', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('account_id', 'content_hash', name='uq_sender_observations_account_hash'),
    )
    op.create_index(
        'ix_sender_observations_account_from', 'sender_observations', ['account_id', 'from_addr'],
        unique=False,
    )
    op.add_column('cases', sa.Column('account_takeover', _JSON, nullable=True))
    op.add_column('cases', sa.Column('sender_baseline', _JSON, nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cases', 'sender_baseline')
    op.drop_column('cases', 'account_takeover')
    op.drop_index('ix_sender_observations_account_from', table_name='sender_observations')
    op.drop_table('sender_observations')
