"""Blocked IP list model for network-level blocking."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import TZDateTime, TimestampMixin, uuid_pk


class BlockedIP(Base, TimestampMixin):
    __tablename__ = "blocked_ips"

    id: Mapped[uuid.UUID] = uuid_pk()
    ip_address: Mapped[str] = mapped_column(
        String(45), unique=True, nullable=False, index=True
    )
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    blocked_until: Mapped[datetime | None] = mapped_column(
        TZDateTime, nullable=True, index=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<BlockedIP {self.ip_address} until={self.blocked_until}>"
