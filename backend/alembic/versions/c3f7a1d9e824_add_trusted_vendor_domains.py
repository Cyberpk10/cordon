"""add trusted_vendor_domains table + cases account/created_at index (Stage 3a — sender
history + trusted-vendor context)

Revision ID: c3f7a1d9e824
Revises: 8f2a4c6e1b09
Create Date: 2026-08-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'c3f7a1d9e824'
down_revision: Union[str, Sequence[str], None] = '8f2a4c6e1b09'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'trusted_vendor_domains',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('domain', sa.String(), nullable=False),
        sa.Column('label', sa.String(), nullable=True),
        sa.Column('added_by_user_id', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['added_by_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('account_id', 'domain', name='uq_trusted_vendor_domains_account_domain'),
    )
    # Supports app.sender_history.loader's bounded per-account, per-window query over Case
    # rows — the existing ix_cases_account_content_hash index's leftmost column (account_id)
    # doesn't help a created_at range scan.
    op.create_index(
        'ix_cases_account_created_at', 'cases', ['account_id', 'created_at']
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cases_account_created_at', table_name='cases')
    op.drop_table('trusted_vendor_domains')
