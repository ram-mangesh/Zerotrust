"""EDR Agent and Telemetry Event database models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import JSONColumn, TZDateTime, TimestampMixin, uuid_pk


class EDRAgent(Base, TimestampMixin):
    __tablename__ = "edr_agents"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    hostname: Mapped[str] = mapped_column(String(128), nullable=False)
    os_type: Mapped[str] = mapped_column(String(32), default="Linux", nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), default="", nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="ONLINE", nullable=False, index=True
    )  # ONLINE, OFFLINE, ISOLATED
    is_isolated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    last_heartbeat_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<EDRAgent {self.agent_id} ({self.hostname}) status={self.status}>"


class EDREvent(Base, TimestampMixin):
    __tablename__ = "edr_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(
        String(48), nullable=False, index=True
    )  # PROCESS_CREATION, NETWORK_CONNECTION, AUTH_EVENT, THREAT_DETECTED
    severity: Mapped[str] = mapped_column(
        String(16), default="INFO", nullable=False, index=True
    )  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    source: Mapped[str] = mapped_column(String(64), default="system", nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<EDREvent {self.event_type} agent={self.agent_id} sev={self.severity}>"
