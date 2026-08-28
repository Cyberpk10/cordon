"""add phishing simulation tables (M9 Stage 1)

Revision ID: 74fdb9fbea44
Revises: a1c9e3f7b2d4
Create Date: 2026-08-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '74fdb9fbea44'
down_revision: Union[str, Sequence[str], None] = 'a1c9e3f7b2d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'simulation_domains',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('domain', sa.String(), nullable=False),
        sa.Column('verification_token', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('account_id', 'domain', name='uq_simulation_domains_account_domain'),
    )

    op.create_table(
        'simulation_campaigns',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('template_id', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('created_by_user_id', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('authorized_by_user_id', sa.Uuid(), nullable=True),
        sa.Column('authorized_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('dry_run', sa.Boolean(), nullable=False),
        sa.Column('from_address', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['authorized_by_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'simulation_recipients',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('campaign_id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('send_error', sa.Text(), nullable=True),
        sa.Column('mailgun_message_id', sa.String(), nullable=True),
        sa.Column('clicked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('click_count', sa.Integer(), nullable=False),
        sa.Column('submitted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('submit_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['campaign_id'], ['simulation_campaigns.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('campaign_id', 'email', name='uq_simulation_recipients_campaign_email'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_index(
        'ix_simulation_recipients_account_id', 'simulation_recipients', ['account_id']
    )

    op.create_table(
        'simulation_events',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('campaign_id', sa.Uuid(), nullable=False),
        sa.Column('recipient_id', sa.Uuid(), nullable=False),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['campaign_id'], ['simulation_campaigns.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['recipient_id'], ['simulation_recipients.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_simulation_events_recipient_id', 'simulation_events', ['recipient_id']
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_simulation_events_recipient_id', table_name='simulation_events')
    op.drop_table('simulation_events')
    op.drop_index('ix_simulation_recipients_account_id', table_name='simulation_recipients')
    op.drop_table('simulation_recipients')
    op.drop_table('simulation_campaigns')
    op.drop_table('simulation_domains')
