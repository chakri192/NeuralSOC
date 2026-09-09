"""composite (tenant_id, alert_id) constraint, tighten tenant_id not null

Revision ID: 28d9095cde3b
Revises: ce52f1799e61
Create Date: 2026-09-09 16:10:05.541977

Defense-in-depth for a real bug found and fixed at the application layer
(api/routes/ingest.py's bulk_upsert_alerts): alerts.alert_id carried only
a *global* unique constraint, so a query that decided whether an
incoming alert "already existed" by matching alert_id alone -- as the
ingest endpoint's upsert logic did before that fix -- could treat one
tenant's row as an update target for another tenant's write, silently
reassigning it. The application-layer fix (scoping the lookup to the
caller's own tenant_id) is correct and sufficient on its own; this
migration makes the same mistake structurally unrepresentable at the
schema layer too, the same way IncidentTriage's (tenant_id, incident_id)
composite key already does.

tenant_id is tightened to NOT NULL in the same migration: every writer
of this table now goes through api/routes/ingest.py's bulk_upsert_alerts,
which always stamps a real tenant_id before writing (the sensor token
IS the tenant), so no code path can create a NULL-tenant_id row anymore.
The earlier migration (74fd85b501da) already backfilled every
pre-existing NULL onto a seeded "Default Tenant"; the UPDATE below
handles the narrow window between that backfill and this migration
landing, if any alerts were written through some other path in between.
A NULL tenant_id would also defeat the composite UNIQUE constraint
outright on databases (Postgres included) where NULL is never considered
equal to NULL for uniqueness purposes -- tightening this first is what
makes the new constraint below actually enforce anything.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '28d9095cde3b'
down_revision: Union[str, Sequence[str], None] = 'ce52f1799e61'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DEFAULT_TENANT_SLUG = "default"


def upgrade() -> None:
    connection = op.get_bind()

    # Same backfill target the tenant_id column's own introducing
    # migration (74fd85b501da) used -- reuse it rather than seed a
    # second "default" tenant if this ever runs against a database where
    # some other process inserted a NULL-tenant_id row after that
    # migration but before this one.
    default_tenant_id = connection.execute(
        sa.text("SELECT id FROM tenants WHERE slug = :slug"), {"slug": _DEFAULT_TENANT_SLUG}
    ).scalar()
    if default_tenant_id is None:
        tenants_table = sa.table(
            "tenants",
            sa.column("id", sa.Integer),
            sa.column("name", sa.String),
            sa.column("slug", sa.String),
        )
        op.bulk_insert(tenants_table, [{"name": "Default Tenant", "slug": _DEFAULT_TENANT_SLUG}])
        default_tenant_id = connection.execute(
            sa.text("SELECT id FROM tenants WHERE slug = :slug"), {"slug": _DEFAULT_TENANT_SLUG}
        ).scalar()

    connection.execute(
        sa.text("UPDATE alerts SET tenant_id = :tenant_id WHERE tenant_id IS NULL"),
        {"tenant_id": default_tenant_id},
    )

    # batch_alter_table: SQLite (the test suite) can't drop/add a unique
    # constraint or alter a column's nullability in place -- batch mode's
    # copy-and-move strategy is what makes this migration portable to
    # both SQLite and Postgres, matching every prior migration's own
    # pattern for this table.
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_index("ix_alerts_alert_id")
        batch_op.alter_column("tenant_id", existing_type=sa.Integer(), nullable=False)
        batch_op.create_unique_constraint("uq_alerts_tenant_alert_id", ["tenant_id", "alert_id"])
        # alert_id is still looked up on its own (api/routes/alerts.py's
        # GET /alerts/{alert_id}, scoped by tenant_id via a separate
        # filter) -- a plain, non-unique index keeps that lookup indexed
        # now that the unique constraint above no longer implies one by
        # itself.
        batch_op.create_index("ix_alerts_alert_id", ["alert_id"])


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch_op:
        batch_op.drop_index("ix_alerts_alert_id")
        batch_op.drop_constraint("uq_alerts_tenant_alert_id", type_="unique")
        batch_op.alter_column("tenant_id", existing_type=sa.Integer(), nullable=True)
        batch_op.create_index("ix_alerts_alert_id", ["alert_id"], unique=True)
