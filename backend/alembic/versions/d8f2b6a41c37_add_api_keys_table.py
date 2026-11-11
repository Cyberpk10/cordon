"""add api_keys table

Revision ID: d8f2b6a41c37
Revises: c3e1a7f05b92
Create Date: 2026-11-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'd8f2b6a41c37'
down_revision: Union[str, Sequence[str], None] = 'c3e1a7f05b92'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'api_keys',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('prefix', sa.String(), nullable=False),
        sa.Column('key_hash', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash'),
    )
    op.create_index(op.f('ix_api_keys_account_id'), 'api_keys', ['account_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_api_keys_account_id'), table_name='api_keys')
    op.drop_table('api_keys')
