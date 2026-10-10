"""blocked_ips table

Revision ID: 0003_blocked_ips
Revises: 0002_resource_content
Create Date: 2026-10-08

Adds the ``blocked_ips`` table for network-level IP blocking and WAF auto-bans.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_blocked_ips"
down_revision: str | None = "0002_resource_content"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "blocked_ips",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("reason", sa.String(length=200), nullable=True),
        sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_blocked_ips")),
    )
    with op.batch_alter_table("blocked_ips", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_blocked_ips_ip_address"), ["ip_address"], unique=True
        )
        batch_op.create_index(
            batch_op.f("ix_blocked_ips_blocked_until"), ["blocked_until"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_blocked_ips_created_at"), ["created_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("blocked_ips", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_blocked_ips_created_at"))
        batch_op.drop_index(batch_op.f("ix_blocked_ips_blocked_until"))
        batch_op.drop_index(batch_op.f("ix_blocked_ips_ip_address"))
    op.drop_table("blocked_ips")
