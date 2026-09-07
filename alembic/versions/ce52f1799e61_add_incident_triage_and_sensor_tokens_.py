"""add incident_triage and sensor_tokens tables

Revision ID: ce52f1799e61
Revises: 74fd85b501da
Create Date: 2026-09-07 06:00:00.000000

Two more pieces of the multi-tenant foundation:

- incident_triage replaces shared/triage_store.py's local SQLite table.
  Keyed on (tenant_id, incident_id) together, not incident_id alone --
  incident_id is a client-synthesized "INC-<source_ip>" string, and two
  different tenants' networks can both see traffic from the same IP.
- sensor_tokens is the new ingestion credential: one per tenant's on-prem
  collector, looked up by SHA-256 hash (never the cleartext token).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ce52f1799e61'
down_revision: Union[str, Sequence[str], None] = '74fd85b501da'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incident_triage",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("tenant_id", "incident_id", name="uq_incident_triage_tenant_incident"),
    )
    op.create_index("ix_incident_triage_tenant_id", "incident_triage", ["tenant_id"])
    op.create_index("ix_incident_triage_incident_id", "incident_triage", ["incident_id"])

    op.create_table(
        "sensor_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sensor_tokens_tenant_id", "sensor_tokens", ["tenant_id"])
    op.create_index("ix_sensor_tokens_token_hash", "sensor_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_sensor_tokens_token_hash", table_name="sensor_tokens")
    op.drop_index("ix_sensor_tokens_tenant_id", table_name="sensor_tokens")
    op.drop_table("sensor_tokens")

    op.drop_index("ix_incident_triage_incident_id", table_name="incident_triage")
    op.drop_index("ix_incident_triage_tenant_id", table_name="incident_triage")
    op.drop_table("incident_triage")
