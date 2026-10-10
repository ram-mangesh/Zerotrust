"""Tests for Endpoint Detection & Response (EDR) agent, telemetry ingestion, and containment."""

from __future__ import annotations

import os
import tempfile
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.agent_daemon import EDRAgentDaemon
from agent.offline_queue import OfflineQueue
from app.models.alert import Alert
from app.models.base import utcnow
from app.models.device import Device
from app.models.edr import EDRAgent, EDREvent
from app.models.enums import DeviceStatus, SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.services.edr_service import EDRService
from tests.conftest import auth_headers, sign_in


def test_edr_heartbeat_registers_agent(client: TestClient, db: Session):
    """POST /api/edr/heartbeat should register a new agent and update last_heartbeat_at."""
    resp = client.post(
        "/api/edr/heartbeat",
        json={
            "agent_id": "test-agent-001",
            "hostname": "workstation-alice",
            "os_type": "Linux",
            "version": "1.2.0",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "test-agent-001"
    assert data["status"] == "ONLINE"
    assert data["is_isolated"] is False

    agent = db.execute(
        select(EDRAgent).where(EDRAgent.agent_id == "test-agent-001")
    ).scalar_one()
    assert agent.hostname == "workstation-alice"


def test_edr_telemetry_ingestion_normal(client: TestClient, db: Session):
    """POST /api/edr/events should store telemetry events in the database."""
    resp = client.post(
        "/api/edr/events",
        json={
            "agent_id": "test-agent-001",
            "events": [
                {
                    "event_type": "PROCESS_CREATION",
                    "severity": "INFO",
                    "source": "sysmon",
                    "details": {"pid": 1234, "cmd": "python script.py"},
                },
                {
                    "event_type": "NETWORK_CONNECTION",
                    "severity": "LOW",
                    "source": "network_monitor",
                    "details": {"dest_ip": "1.1.1.1", "dest_port": 443},
                },
            ],
        },
    )
    assert resp.status_code == 200
    assert resp.json().get("ingested") == 2

    events = db.execute(
        select(EDREvent).where(EDREvent.agent_id == "test-agent-001")
    ).scalars().all()
    assert len(events) >= 2


def test_edr_critical_threat_generates_alert(client: TestClient, db: Session):
    """Critical or threat events should generate an Alert in ZTNA."""
    resp = client.post(
        "/api/edr/events",
        json={
            "agent_id": "test-agent-001",
            "events": [
                {
                    "event_type": "THREAT_DETECTED",
                    "severity": "CRITICAL",
                    "source": "edr_scanner",
                    "details": {"summary": "Reverse shell payload detected", "pid": 9999},
                }
            ],
        },
    )
    assert resp.status_code == 200
    assert resp.json().get("threats_detected") == 1

    alert = db.execute(
        select(Alert).where(Alert.category == "edr_threat_detected")
    ).scalar_one()
    assert alert.severity.value == "CRITICAL"
    assert "Reverse shell" in alert.description


def test_edr_list_agents_and_events(client: TestClient, db: Session, admin: User):
    """Admins should be able to query agents and telemetry events."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    # 1. Register an agent
    client.post(
        "/api/edr/heartbeat",
        json={
            "agent_id": "test-agent-list",
            "hostname": "laptop-bob",
            "os_type": "Darwin",
        },
    )

    # 2. List agents
    resp = client.get("/api/edr/agents", headers=headers)
    assert resp.status_code == 200
    agents = [a["agent_id"] for a in resp.json()]
    assert "test-agent-list" in agents

    # 3. Query events
    events_resp = client.get("/api/edr/events", headers=headers)
    assert events_resp.status_code == 200


def test_edr_endpoint_isolation_and_restoration(client: TestClient, db: Session, admin: User, user: User):
    """Isolating an agent revokes sessions and marks device revoked; unisolate restores it."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    # Link a device and active session
    now = utcnow()
    device = Device(
        user_id=user.id,
        fingerprint="fp_for_isolation_test",
        label="Alice Laptop",
        status=DeviceStatus.APPROVED,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(device)
    db.flush()

    session = UserSession(
        user_id=user.id,
        device_id=device.id,
        status=SessionStatus.ACTIVE,
        started_at=now,
        last_seen_at=now,
        expires_at=now,
    )
    db.add(session)
    db.flush()

    agent = EDRAgent(
        agent_id="agent-isolation-test",
        hostname="alice-mac",
        os_type="Darwin",
        status="ONLINE",
        is_isolated=False,
        last_heartbeat_at=now,
        device_id=device.id,
    )
    db.add(agent)
    db.commit()

    # 1. Isolate agent
    iso_resp = client.post(
        "/api/edr/agents/agent-isolation-test/isolate",
        json={"reason": "Compromised by malware"},
        headers=headers,
    )
    assert iso_resp.status_code == 200
    assert iso_resp.json()["status"] == "ISOLATED"
    assert iso_resp.json()["is_isolated"] is True

    db.refresh(session)
    db.refresh(device)
    assert session.status == SessionStatus.REVOKED
    assert device.status == DeviceStatus.REVOKED

    # 2. Unisolate agent
    uniso_resp = client.post(
        "/api/edr/agents/agent-isolation-test/unisolate",
        headers=headers,
    )
    assert uniso_resp.status_code == 200
    assert uniso_resp.json()["status"] == "ONLINE"
    assert uniso_resp.json()["is_isolated"] is False

    db.refresh(device)
    assert device.status == DeviceStatus.APPROVED


def test_offline_queue():
    """OfflineQueue should buffer events in SQLite and pop them in batches."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = os.path.join(tmpdir, "test_queue.db")
        q = OfflineQueue(db_path=db_file, max_size=100)

        assert q.queue_depth() == 0

        # Enqueue 3 events
        q.enqueue(event_type="PROCESS_CREATION", severity="INFO", source="test", details={"pid": 101})
        q.enqueue(event_type="NETWORK_CONNECTION", severity="LOW", source="test", details={"port": 80})
        q.enqueue(event_type="AUTH_EVENT", severity="HIGH", source="test", details={"user": "root"})

        assert q.queue_depth() == 3

        # Pop batch
        batch = q.pop_batch(limit=2)
        assert len(batch) == 2
        assert batch[0]["event_type"] == "PROCESS_CREATION"
        assert q.queue_depth() == 1

        # Pop remaining
        rest = q.pop_batch(limit=10)
        assert len(rest) == 1
        assert q.queue_depth() == 0


def test_edr_agent_daemon_cycle(client: TestClient):
    """EDRAgentDaemon should execute one collection, heartbeat, and transmission cycle."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = os.path.join(tmpdir, "test_daemon.db")
        daemon = EDRAgentDaemon(
            gateway_url="http://testserver",
            agent_id="test-daemon-agent",
            db_path=db_file,
        )

        daemon.collect_and_queue()
        assert daemon.queue.queue_depth() >= 1
