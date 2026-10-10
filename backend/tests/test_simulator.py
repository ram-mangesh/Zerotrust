"""Tests for Interactive Attack Simulator API and multi-vector scenarios."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.user import User
from tests.conftest import auth_headers, sign_in


def test_simulator_list_scenarios(client: TestClient):
    """GET /api/simulator/scenarios should return all 5 attack scenarios."""
    resp = client.get("/api/simulator/scenarios")
    assert resp.status_code == 200
    scenarios = resp.json()
    assert len(scenarios) == 5
    ids = [s["id"] for s in scenarios]
    assert "normal" in ids
    assert "country_change" in ids
    assert "rapid_export" in ids
    assert "stolen_token" in ids
    assert "full_attack" in ids


def test_scenario_normal_activity(client: TestClient, admin: User):
    """Scenario 'normal' should evaluate in LOW risk band (85-100)."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post("/api/simulator/run/normal", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "normal"
    assert data["final_score"] >= 80.0
    assert data["risk_level"] == "LOW"
    assert data["action"] == "ALLOW"


def test_scenario_country_change_impossible_travel(client: TestClient, db: Session, admin: User):
    """Scenario 'country_change' triggers impossible travel override and critical alert."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post("/api/simulator/run/country_change", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "country_change"
    assert data["final_score"] <= 35.0
    assert data["risk_level"] == "CRITICAL"
    assert len(data["alerts_generated"]) >= 1


def test_scenario_rapid_export_mass_enumeration(client: TestClient, db: Session, admin: User):
    """Scenario 'rapid_export' triggers mass enumeration alert and score drop."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post("/api/simulator/run/rapid_export", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "rapid_export"
    assert data["final_score"] <= 55.0
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert len(data["alerts_generated"]) >= 1


def test_scenario_stolen_token_session_hijack(client: TestClient, db: Session, admin: User):
    """Scenario 'stolen_token' terminates session with CRITICAL risk."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post("/api/simulator/run/stolen_token", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "stolen_token"
    assert data["risk_level"] == "CRITICAL"
    assert data["action"] == "REVOKE_SESSION"


def test_scenario_full_attack_progressive_escalation(client: TestClient, db: Session, admin: User):
    """Scenario 'full_attack' runs all 5 progressive stages resulting in session termination."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post("/api/simulator/run/full_attack", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "full_attack"
    assert len(data["timeline"]) == 5
    assert data["final_score"] <= 25.0
    assert data["risk_level"] == "CRITICAL"
    assert data["action"] == "REVOKE_SESSION"


def test_simulator_reset_endpoint(client: TestClient, admin: User):
    """POST /api/simulator/reset restores session standing back to 95.0 LOW risk."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    # First run an attack to degrade session
    client.post("/api/simulator/run/country_change", headers=headers)

    # Reset
    reset_resp = client.post("/api/simulator/reset", headers=headers)
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "reset"
