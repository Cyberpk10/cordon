"""add simulation reporting columns and training recommendations table (M9 Stage 2)

Revision ID: 4d99f129660a
Revises: 74fdb9fbea44
Create Date: 2026-08-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '4d99f129660a'
down_revision: Union[str, Sequence[str], None] = '74fdb9fbea44'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('simulation_recipients', sa.Column('department', sa.String(), nullable=True))
    op.add_column(
        'simulation_recipients', sa.Column('reported_at', sa.DateTime(timezone=True), nullable=True)
    )
    # server_default so this NOT NULL column can be added to a table that may already have
    # rows — same pattern as f4a2c9d18e6b's 'channel' column.
    op.add_column(
        'simulation_recipients',
        sa.Column('report_count', sa.Integer(), nullable=False, server_default='0'),
    )
    op.alter_column('simulation_recipients', 'report_count', server_default=None)

    op.create_table(
        'simulation_training_recommendations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('recipient', sa.String(), nullable=False),
        sa.Column('template_id', sa.String(), nullable=False),
        sa.Column('template_name', sa.String(), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.Column('first_flagged_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'account_id', 'recipient', name='uq_simulation_training_recommendations_account_recipient'
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('simulation_training_recommendations')
    op.drop_column('simulation_recipients', 'report_count')
    op.drop_column('simulation_recipients', 'reported_at')
    op.drop_column('simulation_recipients', 'department')
