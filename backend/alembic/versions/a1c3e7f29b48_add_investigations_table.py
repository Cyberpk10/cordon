"""add investigations table (agentic investigation layer, M10 Stage 1)

Revision ID: a1c3e7f29b48
Revises: 7ebe29741f5a
Create Date: 2026-10-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision: str = 'a1c3e7f29b48'
down_revision: Union[str, Sequence[str], None] = '7ebe29741f5a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON_TYPE = sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql')


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'investigations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('case_id', sa.Uuid(), nullable=True),
        sa.Column('incident_id', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('trigger', sa.String(), nullable=False),
        sa.Column('actor', sa.String(), nullable=True),
        sa.Column('verdict', sa.String(), nullable=False),
        sa.Column('score', sa.Integer(), nullable=False),
        sa.Column('sender_intelligence', _JSON_TYPE, nullable=False, server_default='{}'),
        sa.Column('related_cases', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('related_incidents', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('threat_intel_hits', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('threat_level', _JSON_TYPE, nullable=True),
        sa.Column('ueba_findings', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('timeline', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('scope', _JSON_TYPE, nullable=False, server_default='{}'),
        sa.Column('recommended_steps', _JSON_TYPE, nullable=False, server_default='[]'),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('summary_model', sa.String(), nullable=True),
        sa.Column('summary_evidence_strength', sa.String(), nullable=True),
        sa.CheckConstraint('(case_id IS NOT NULL) != (incident_id IS NOT NULL)', name='ck_investigations_exactly_one_parent'),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', name='uq_investigations_case_id'),
        sa.UniqueConstraint('incident_id', name='uq_investigations_incident_id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('investigations')
