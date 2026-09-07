"""baseline: alerts table as it exists today

Revision ID: 95bddea6b154
Revises:
Create Date: 2026-09-07 04:12:00.000000

No migrations existed before this repo adopted Alembic -- every
deployment so far got its schema from api/main.py's startup-time
Base.metadata.create_all(), which only ever adds new tables and can't
express a column/constraint change. This migration reproduces that
already-live schema exactly, so:

- A brand-new database: `alembic upgrade head` creates it from here.
- An existing deployment (schema already created by create_all()):
  run `alembic stamp 95bddea6b154` once to mark it as already at this
  revision without re-running the DDL, then `alembic upgrade head` for
  everything after it.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '95bddea6b154'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("alert_id", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("threat_class", sa.String(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("destination_ip", sa.String(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("trace_id", sa.String(), nullable=True),
        sa.Column("flow_id", sa.String(), nullable=True),
        sa.Column("span_id", sa.String(), nullable=True),
        sa.Column("mitre_tactic", sa.String(), nullable=True),
        sa.Column("mitre_technique", sa.String(), nullable=True),
        sa.Column("model_name", sa.String(), nullable=True),
        sa.Column("model_version", sa.String(), nullable=True),
        sa.Column("schema_version", sa.String(), nullable=True),
    )
    op.create_index("ix_alerts_alert_id", "alerts", ["alert_id"], unique=True)
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index("ix_alerts_threat_class", "alerts", ["threat_class"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_trace_id", "alerts", ["trace_id"])
    op.create_index("ix_alerts_flow_id", "alerts", ["flow_id"])


def downgrade() -> None:
    op.drop_table("alerts")
