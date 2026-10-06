"""add llm intent signal columns to cases

Revision ID: 7ebe29741f5a
Revises: a3d7e9c15f42
Create Date: 2026-10-06 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '7ebe29741f5a'
down_revision: Union[str, Sequence[str], None] = 'a3d7e9c15f42'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Nullable, mirroring analyst_narrative/analyst_model — populated only when
    # ENABLE_LLM_REASONING was on and the model's response passed strict schema validation
    # (app.reasoning.llm_analyst). llm_intent_risk is the actual number of points (0 to
    # app.scoring.risk_engine.LLM_INTENT_MAX_CONTRIBUTION_POINTS) folded into `score`, not a
    # raw/unclamped model output.
    op.add_column('cases', sa.Column('llm_intent_category', sa.String(), nullable=True))
    op.add_column('cases', sa.Column('llm_intent_risk', sa.Integer(), nullable=True))
    op.add_column('cases', sa.Column('llm_intent_confidence', sa.String(), nullable=True))
    op.add_column(
        'cases',
        sa.Column(
            'llm_intent_reasons',
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql'),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cases', 'llm_intent_reasons')
    op.drop_column('cases', 'llm_intent_confidence')
    op.drop_column('cases', 'llm_intent_risk')
    op.drop_column('cases', 'llm_intent_category')
