"""add security_compliance_reports table

Revision ID: 204b587f6598
Revises: e250334a679b
Create Date: 2026-10-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '204b587f6598'
down_revision: Union[str, Sequence[str], None] = 'e250334a679b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'security_compliance_reports',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('emails_analyzed', sa.Integer(), nullable=False),
        sa.Column('threats_detected', sa.Integer(), nullable=False),
        sa.Column('threats_contained', sa.Integer(), nullable=False),
        sa.Column('exposure_avoided_usd', sa.Float(), nullable=False),
        sa.Column('executive_summary', sa.Text(), nullable=False),
        sa.Column('executive_summary_source', sa.String(), nullable=False),
        sa.Column('pdf_path', sa.String(), nullable=False),
        sa.Column('json_path', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('security_compliance_reports')
