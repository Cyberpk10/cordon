"""graduated autonomy (D5): policy tier/shadow/kill switch, audit fields, lists, campaigns,
notifications, case triage fields

Revision ID: b8d2f4a6c913
Revises: a3c7e1f9b240
Create Date: 2026-11-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b8d2f4a6c913'
down_revision: Union[str, Sequence[str], None] = 'a3c7e1f9b240'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        'case_campaigns',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('account_id', sa.Uuid(), sa.ForeignKey('accounts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('signature', sa.String(), nullable=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('created_by_action_id', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        'cordon_list_entries',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('account_id', sa.Uuid(), sa.ForeignKey('accounts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(), nullable=False),
        sa.Column('list_name', sa.String(), nullable=False),
        sa.Column('value', sa.String(), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('source_action_id', sa.Uuid(), nullable=True),
        sa.Column('added_by', sa.String(), nullable=False),
        sa.Column('reason', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('removed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('removed_by', sa.String(), nullable=True),
    )
    op.create_index('ix_cordon_list_entries_account_active', 'cordon_list_entries', ['account_id', 'active'])
    op.create_table(
        'notifications',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('account_id', sa.Uuid(), sa.ForeignKey('accounts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('case_id', sa.Uuid(), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=True),
        sa.Column('action_id', sa.Uuid(), nullable=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retracted_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_notifications_account_created', 'notifications', ['account_id', 'created_at'])

    op.add_column('cases', sa.Column('status', sa.String(), nullable=False, server_default='new'))
    op.add_column('cases', sa.Column('priority', sa.String(), nullable=True))
    op.add_column('cases', sa.Column('engine_tags', _JSON, nullable=False, server_default='[]'))
    op.add_column('cases', sa.Column(
        'campaign_id', sa.Uuid(), sa.ForeignKey('case_campaigns.id', ondelete='SET NULL'), nullable=True
    ))

    # Every existing account starts in shadow mode at the conservative L1 ceiling.
    op.add_column('autonomy_policies', sa.Column('tier', sa.String(), nullable=False, server_default='L1'))
    op.add_column('autonomy_policies', sa.Column('shadow_mode', sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column('autonomy_policies', sa.Column('kill_switch', sa.Boolean(), nullable=False, server_default=sa.false()))

    for name, type_ in [
        ('engine', sa.String()), ('tier', sa.String()), ('rule_id', sa.String()),
        ('mode', sa.String()), ('within_tier', sa.Boolean()), ('undo', _JSON),
        ('actor', sa.String()), ('decided_by', sa.String()),
        ('decided_at', sa.DateTime(timezone=True)), ('reversed_by', sa.String()),
        ('reversed_at', sa.DateTime(timezone=True)),
    ]:
        op.add_column('autonomy_actions', sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    for name in ['reversed_at', 'reversed_by', 'decided_at', 'decided_by', 'actor', 'undo',
                 'within_tier', 'mode', 'rule_id', 'tier', 'engine']:
        op.drop_column('autonomy_actions', name)
    for name in ['kill_switch', 'shadow_mode', 'tier']:
        op.drop_column('autonomy_policies', name)
    for name in ['campaign_id', 'engine_tags', 'priority', 'status']:
        op.drop_column('cases', name)
    op.drop_index('ix_notifications_account_created', 'notifications')
    op.drop_table('notifications')
    op.drop_index('ix_cordon_list_entries_account_active', 'cordon_list_entries')
    op.drop_table('cordon_list_entries')
    op.drop_table('case_campaigns')
