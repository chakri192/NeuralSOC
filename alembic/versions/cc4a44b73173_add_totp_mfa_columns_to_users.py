"""add totp mfa columns to users

Revision ID: cc4a44b73173
Revises: 531d123cd6d9
Create Date: 2026-09-09 16:26:17.064143

Phase 6 ops hardening: optional TOTP MFA for admin accounts. See
api/models.py's User.totp_secret/mfa_enabled comment and
api/routes/auth.py's mfa_* endpoints.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cc4a44b73173'
down_revision: Union[str, Sequence[str], None] = '531d123cd6d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("totp_secret", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("mfa_enabled")
        batch_op.drop_column("totp_secret")
