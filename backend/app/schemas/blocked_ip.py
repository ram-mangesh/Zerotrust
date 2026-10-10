"""Pydantic schemas for IP blocking management."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class BlockedIPCreate(BaseModel):
    ip_address: str = Field(..., description="IPv4 or IPv6 address to block")
    reason: str = Field(
        default="Manual admin block", description="Reason for the block"
    )
    duration_minutes: int | None = Field(
        default=60, description="Duration in minutes. None or 0 for permanent block."
    )


class BlockedIPOut(BaseModel):
    id: uuid.UUID
    ip_address: str
    reason: str | None
    blocked_until: datetime | None
    permanent: bool
    created_at: datetime
