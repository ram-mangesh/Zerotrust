"""device ecdsa biometrics

Revision ID: 0007_device_ecdsa_biometrics
Revises: 0006_resource_upstream
Create Date: 2026-10-08

Adds WebCrypto ECDSA P-256 public key and biometric tracking columns to ``devices`` and ``sessions``.
"""
from __future__ import annotations

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_device_ecdsa_biometrics"
down_revision: str | None = "0006_resource_upstream"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ecdsa_pubkey", sa.String(length=128), nullable=True))
        batch_op.create_index(batch_op.f("ix_devices_ecdsa_pubkey"), ["ecdsa_pubkey"], unique=False)

    with op.batch_alter_table("sessions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ecdsa_pubkey", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("avg_wpm", sa.Float(), server_default="0.0", nullable=False))
        batch_op.add_column(sa.Column("avg_mouse_velocity", sa.Float(), server_default="0.0", nullable=False))
        batch_op.create_index(batch_op.f("ix_sessions_ecdsa_pubkey"), ["ecdsa_pubkey"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_sessions_ecdsa_pubkey"))
        batch_op.drop_column("avg_mouse_velocity")
        batch_op.drop_column("avg_wpm")
        batch_op.drop_column("ecdsa_pubkey")

    with op.batch_alter_table("devices", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_devices_ecdsa_pubkey"))
        batch_op.drop_column("ecdsa_pubkey")
