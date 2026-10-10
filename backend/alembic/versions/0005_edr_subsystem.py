"""edr subsystem

Revision ID: 0005_edr_subsystem
Revises: 0004_oauth_sso
Create Date: 2026-10-08

Creates ``edr_agents`` and ``edr_events`` tables for endpoint telemetry and active response.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_edr_subsystem"
down_revision: str | None = "0004_oauth_sso"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "edr_agents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=128), nullable=False),
        sa.Column("os_type", sa.String(length=32), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("is_isolated", sa.Boolean(), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_edr_agents")),
    )
    with op.batch_alter_table("edr_agents", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_edr_agents_agent_id"), ["agent_id"], unique=True
        )
        batch_op.create_index(
            batch_op.f("ix_edr_agents_device_id"), ["device_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_edr_agents_status"), ["status"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_edr_agents_created_at"), ["created_at"], unique=False
        )

    op.create_table(
        "edr_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_edr_events")),
    )
    with op.batch_alter_table("edr_events", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_edr_events_agent_id"), ["agent_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_edr_events_event_type"), ["event_type"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_edr_events_severity"), ["severity"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_edr_events_timestamp"), ["timestamp"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_edr_events_created_at"), ["created_at"], unique=False
        )


def downgrade() -> None:
    op.drop_table("edr_events")
    op.drop_table("edr_agents")
