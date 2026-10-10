"""resource upstream url

Revision ID: 0006_resource_upstream
Revises: 0005_edr_subsystem
Create Date: 2026-10-08

Adds ``upstream_url`` to ``resources`` table for PEP reverse proxy forwarding.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_resource_upstream"
down_revision: str | None = "0005_edr_subsystem"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("resources", schema=None) as batch_op:
        batch_op.add_column(sa.Column("upstream_url", sa.String(length=512), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("resources", schema=None) as batch_op:
        batch_op.drop_column("upstream_url")
