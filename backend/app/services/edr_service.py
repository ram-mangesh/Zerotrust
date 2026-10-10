"""EDR Agent and Endpoint Telemetry Service.

Handles:
  - Agent registration & heartbeats
  - Bulk OS telemetry event ingestion (process, auth, network, file events)
  - Threat detection correlation -> ZTNA Alert generation
  - Active response: Host Isolation and quarantine
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.base import as_aware, utcnow
from app.models.device import Device
from app.models.edr import EDRAgent, EDREvent
from app.models.enums import AlertSeverity, AlertStatus, DeviceStatus, SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class EDRService:
    @classmethod
    def record_heartbeat(
        cls,
        db: Session,
        *,
        agent_id: str,
        hostname: str,
        os_type: str,
        ip_address: str,
        version: str = "1.0.0",
        fingerprint: str | None = None,
    ) -> EDRAgent:
        """Register or update an EDR agent heartbeat."""
        now = utcnow()
        agent = db.execute(
            select(EDRAgent).where(EDRAgent.agent_id == agent_id)
        ).scalar_one_or_none()

        device = None
        if fingerprint:
            device = db.execute(
                select(Device).where(Device.fingerprint == fingerprint)
            ).scalar_one_or_none()

        if agent:
            agent.hostname = hostname
            agent.os_type = os_type
            agent.ip_address = ip_address
            agent.version = version
            agent.last_heartbeat_at = now
            if not agent.is_isolated:
                agent.status = "ONLINE"
            if device and not agent.device_id:
                agent.device_id = device.id
        else:
            agent = EDRAgent(
                agent_id=agent_id,
                hostname=hostname,
                os_type=os_type,
                ip_address=ip_address,
                version=version,
                status="ONLINE",
                is_isolated=False,
                last_heartbeat_at=now,
                device_id=device.id if device else None,
            )
            db.add(agent)

        db.flush()
        return agent

    @classmethod
    def ingest_events(
        cls,
        db: Session,
        *,
        agent_id: str,
        events: list[dict[str, Any]],
        ip_address: str = "",
    ) -> dict[str, Any]:
        """Ingest endpoint telemetry events and correlate security threats."""
        now = utcnow()
        saved_count = 0
        critical_threats = 0

        # Ensure agent exists or record activity
        agent = db.execute(
            select(EDRAgent).where(EDRAgent.agent_id == agent_id)
        ).scalar_one_or_none()

        for item in events:
            event_type = str(item.get("event_type") or "SYSTEM_EVENT")
            severity = str(item.get("severity") or "INFO").upper()
            source = str(item.get("source") or "agent_collector")
            details = item.get("details") or item.get("data") or {}

            raw_ts = item.get("timestamp")
            if raw_ts:
                try:
                    ts = as_aware(datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00")))
                except Exception:
                    ts = now
            else:
                ts = now

            event_row = EDREvent(
                agent_id=agent_id,
                event_type=event_type,
                severity=severity,
                source=source,
                details=details,
                timestamp=ts or now,
            )
            db.add(event_row)
            saved_count += 1

            # High or critical threat detection trigger
            if severity in ("HIGH", "CRITICAL") or event_type in (
                "THREAT_DETECTED",
                "MALWARE_EXECUTION",
                "PRIVILEGE_ESCALATION",
            ):
                critical_threats += 1
                logger.warning(
                    "EDR THREAT ALERT | agent=%s type=%s sev=%s",
                    agent_id,
                    event_type,
                    severity,
                )

                # Generate Security Alert in ZTNA
                alert = Alert(
                    severity=(
                        AlertSeverity.CRITICAL
                        if severity == "CRITICAL"
                        else AlertSeverity.HIGH
                    ),
                    status=AlertStatus.OPEN,
                    category=f"edr_{event_type.lower()}",
                    title=f"EDR Threat on {agent.hostname if agent else agent_id}: {event_type}",
                    description=(
                        f"Endpoint Detection & Response detected high-risk activity on "
                        f"{agent.hostname if agent else agent_id} ({ip_address}): {details.get('summary', str(details)[:150])}"
                    ),
                    trust_score=25.0 if severity == "CRITICAL" else 45.0,
                    evidence={
                        "agent_id": agent_id,
                        "hostname": agent.hostname if agent else "unknown",
                        "event_type": event_type,
                        "severity": severity,
                        "details": details,
                        "ip_address": ip_address,
                    },
                )
                db.add(alert)

                # Degrade attached device trust
                if agent and agent.device_id:
                    dev = db.get(Device, agent.device_id)
                    if dev and severity == "CRITICAL":
                        dev.status = DeviceStatus.REVOKED

        db.flush()
        return {
            "ingested": saved_count,
            "threats_detected": critical_threats,
            "status": "success",
        }

    @classmethod
    def isolate_agent(
        cls,
        db: Session,
        *,
        agent_id: str,
        reason: str,
        actor: User,
        ip_address: str = "",
    ) -> EDRAgent:
        """Active response: Isolate host from the network and revoke active sessions."""
        agent = db.execute(
            select(EDRAgent).where(EDRAgent.agent_id == agent_id)
        ).scalar_one_or_none()

        if not agent:
            raise ValueError(f"EDR Agent '{agent_id}' not found")

        agent.status = "ISOLATED"
        agent.is_isolated = True

        # Revoke device sessions if linked
        if agent.device_id:
            dev = db.get(Device, agent.device_id)
            if dev:
                dev.status = DeviceStatus.REVOKED
            sessions = db.scalars(
                select(UserSession).where(
                    UserSession.device_id == agent.device_id,
                    UserSession.status == SessionStatus.ACTIVE,
                )
            ).all()
            for s in sessions:
                s.status = SessionStatus.REVOKED
                s.revoked_reason = f"Endpoint isolated by EDR active response: {reason}"
                s.ended_at = utcnow()

        AuditService.record(
            db,
            action="EDR_ENDPOINT_ISOLATED",
            actor_id=actor.id,
            actor_label=actor.username,
            resource_type="endpoint",
            resource_id=agent_id,
            ip_address=ip_address,
            payload={"agent_id": agent_id, "hostname": agent.hostname, "reason": reason},
        )
        db.flush()
        return agent

    @classmethod
    def unisolate_agent(
        cls,
        db: Session,
        *,
        agent_id: str,
        actor: User,
        ip_address: str = "",
    ) -> EDRAgent:
        """Restore an isolated host back to normal status."""
        agent = db.execute(
            select(EDRAgent).where(EDRAgent.agent_id == agent_id)
        ).scalar_one_or_none()

        if not agent:
            raise ValueError(f"EDR Agent '{agent_id}' not found")

        agent.status = "ONLINE"
        agent.is_isolated = False

        if agent.device_id:
            dev = db.get(Device, agent.device_id)
            if dev:
                dev.status = DeviceStatus.APPROVED

        AuditService.record(
            db,
            action="EDR_ENDPOINT_RESTORED",
            actor_id=actor.id,
            actor_label=actor.username,
            resource_type="endpoint",
            resource_id=agent_id,
            ip_address=ip_address,
            payload={"agent_id": agent_id, "hostname": agent.hostname},
        )
        db.flush()
        return agent
