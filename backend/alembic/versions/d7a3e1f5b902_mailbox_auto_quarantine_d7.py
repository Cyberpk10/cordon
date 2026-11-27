"""D7 live auto-quarantine: policy, directives/audit rows, calibration runs, rule feedback.

Revision ID: d7a3e1f5b902
Revises: c4e9a2d7f310
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "d7a3e1f5b902"
down_revision = "c4e9a2d7f310"
branch_labels = None
depends_on = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
_TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "mailbox_remediation_policies",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("account_id", sa.Uuid(), sa.ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("owner_user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("mailbox_address", sa.String(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("score_floor", sa.Integer(), nullable=False, server_default="95"),
        sa.Column("max_moves_per_hour", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("notify_email", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("calibrated_at", _TS, nullable=True),
        sa.Column("calibrated_floor", sa.Integer(), nullable=True),
        sa.Column("halted_at", _TS, nullable=True),
        sa.Column("halt_reason", sa.String(), nullable=True),
        sa.Column("updated_at", _TS, nullable=False),
    )
    op.create_table(
        "mailbox_actions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("account_id", sa.Uuid(), sa.ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", sa.Uuid(), sa.ForeignKey("cases.id", ondelete="SET NULL"), nullable=True),
        sa.Column("parent_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("mailbox_address", sa.String(), nullable=False),
        sa.Column("gmail_message_id", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column("gate", _JSON, nullable=True),
        sa.Column("issued_at", _TS, nullable=False),
        sa.Column("expires_at", _TS, nullable=False),
        sa.Column("claimed_at", _TS, nullable=True),
        sa.Column("executed_at", _TS, nullable=True),
        sa.Column("undone_at", _TS, nullable=True),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("undo_source", sa.String(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
    )
    op.create_index("ix_mailbox_actions_account_issued", "mailbox_actions", ["account_id", "issued_at"])
    op.create_table(
        "d7_calibration_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("account_id", sa.Uuid(), sa.ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("score_floor", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("rows", _JSON, nullable=False),
        sa.Column("started_at", _TS, nullable=False),
        sa.Column("completed_at", _TS, nullable=True),
    )
    op.create_table(
        "rule_feedback",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("account_id", sa.Uuid(), sa.ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", sa.Uuid(), sa.ForeignKey("cases.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action_id", sa.Uuid(), nullable=True),
        sa.Column("indicator_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("created_at", _TS, nullable=False),
    )
    op.create_index("ix_rule_feedback_account_indicator", "rule_feedback", ["account_id", "indicator_id"])


def downgrade() -> None:
    op.drop_index("ix_rule_feedback_account_indicator", table_name="rule_feedback")
    op.drop_table("rule_feedback")
    op.drop_table("d7_calibration_runs")
    op.drop_index("ix_mailbox_actions_account_issued", table_name="mailbox_actions")
    op.drop_table("mailbox_actions")
    op.drop_table("mailbox_remediation_policies")
