"""oauth sso support

Revision ID: 0004_oauth_sso
Revises: 0003_blocked_ips
Create Date: 2026-10-08

Adds OAuth2 and OIDC provider tracking columns to ``users``.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_oauth_sso"
down_revision: str | None = "0003_blocked_ips"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch:
        batch.alter_column("hashed_password", nullable=True)
        batch.add_column(sa.Column("oauth_provider", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("oauth_sub", sa.String(length=128), nullable=True))
        batch.add_column(
            sa.Column("oauth_linked", sa.Boolean(), server_default="0", nullable=False)
        )
        batch.create_index(
            batch.f("ix_users_oauth_provider"), ["oauth_provider"], unique=False
        )
        batch.create_index(batch.f("ix_users_oauth_sub"), ["oauth_sub"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch:
        batch.drop_index(batch.f("ix_users_oauth_sub"))
        batch.drop_index(batch.f("ix_users_oauth_provider"))
        batch.drop_column("oauth_linked")
        batch.drop_column("oauth_sub")
        batch.drop_column("oauth_provider")
        batch.alter_column("hashed_password", nullable=False)
