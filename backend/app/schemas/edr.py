"""Pydantic schemas for EDR agent communication and telemetry ingestion."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EDRHeartbeatRequest(BaseModel):
    agent_id: str = Field(..., description="Unique agent identifier")
    hostname: str = Field(..., description="Endpoint machine hostname")
    os_type: str = Field(default="Linux", description="Operating system type: Linux, Windows, Darwin")
    version: str = Field(default="1.0.0", description="Agent daemon version")
    fingerprint: str | None = Field(default=None, description="Linked device hardware fingerprint")


class EDRAgentOut(BaseModel):
    id: uuid.UUID
    agent_id: str
    hostname: str
    os_type: str
    ip_address: str
    status: str
    is_isolated: bool
    version: str
    last_heartbeat_at: datetime
    device_id: uuid.UUID | None = None
    created_at: datetime


class EDREventItem(BaseModel):
    event_type: str = Field(..., description="Event type: PROCESS_CREATION, NETWORK_CONNECTION, AUTH_EVENT, THREAT_DETECTED")
    severity: str = Field(default="INFO", description="Severity: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    source: str = Field(default="system", description="Telemetry source component")
    details: dict[str, Any] = Field(default_factory=dict, description="Event metadata and parameters")
    timestamp: str | None = Field(default=None, description="ISO-8601 timestamp")


class EDREventIngestRequest(BaseModel):
    agent_id: str = Field(..., description="Reporting agent ID")
    events: list[EDREventItem] = Field(..., description="Batch of telemetry events")


class EDREventOut(BaseModel):
    id: uuid.UUID
    agent_id: str
    event_type: str
    severity: str
    source: str
    details: dict[str, Any]
    timestamp: datetime


class EDRIsolateRequest(BaseModel):
    reason: str = Field(default="Security containment", description="Reason for isolating endpoint")
