"""add tenants and users, tenant_id on alerts

Revision ID: 74fd85b501da
Revises: 95bddea6b154
Create Date: 2026-09-07 04:12:21.972614

Foundation for the multi-tenant pivot: a tenants/users table (there was
no identity table of any kind before this -- every credential in the
system was a single shared secret), and a tenant_id column on alerts.

tenant_id is nullable here on purpose: api/kafka_sink.py (the only
writer of alerts) doesn't know about tenants yet -- that lands in the
ingestion-isolation phase, which also tightens this column to NOT NULL
once every writer is guaranteed to supply a real tenant_id. Existing
rows are backfilled onto a seeded "default" tenant so nothing is
orphaned in the meantime.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '74fd85b501da'
down_revision: Union[str, Sequence[str], None] = '95bddea6b154'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DEFAULT_TENANT_SLUG = "default"


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # batch_alter_table: on Postgres this is a plain ALTER TABLE ADD COLUMN;
    # SQLite (used by the test suite) can't ALTER a table to add a foreign
    # key constraint directly, so batch mode's copy-and-move strategy is
    # what makes this migration portable across both.
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.add_column(
            sa.Column(
                "tenant_id",
                sa.Integer(),
                sa.ForeignKey("tenants.id", name="fk_alerts_tenant_id"),
                nullable=True,
            )
        )
        batch_op.create_index("ix_alerts_tenant_id", ["tenant_id"])

    # Seed one bootstrap tenant so a fresh environment has somewhere to
    # attach a first admin user and any pre-existing alert rows.
    tenants_table = sa.table(
        "tenants",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String),
        sa.column("slug", sa.String),
    )
    op.bulk_insert(tenants_table, [{"name": "Default Tenant", "slug": _DEFAULT_TENANT_SLUG}])

    connection = op.get_bind()
    default_tenant_id = connection.execute(
        sa.text("SELECT id FROM tenants WHERE slug = :slug"), {"slug": _DEFAULT_TENANT_SLUG}
    ).scalar()
    connection.execute(
        sa.text("UPDATE alerts SET tenant_id = :tenant_id WHERE tenant_id IS NULL"),
        {"tenant_id": default_tenant_id},
    )


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_index("ix_alerts_tenant_id")
        batch_op.drop_column("tenant_id")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_tenant_id", table_name="users")
    op.drop_table("users")
    op.drop_index("ix_tenants_slug", table_name="tenants")
    op.drop_table("tenants")
