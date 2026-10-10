"""Tests for Single Anomaly Scenario Runner, Real Model Inference, SHAP & Audit Verification."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.services.anomaly_runner_service import AnomalyRunnerService
from tests.conftest import auth_headers, sign_in


def test_list_synthetic_scenarios():
    scenarios = AnomalyRunnerService.list_scenarios()
    assert len(scenarios) >= 5
    ids = [s["id"] for s in scenarios]
    assert "baseline_normal" in ids
    assert "geo_velocity_anomaly" in ids
    assert "mass_data_exfiltration" in ids


def test_run_scenario_baseline_normal(db_factory):
    with db_factory() as db:
        res = AnomalyRunnerService.run_scenario(db, scenario_id="baseline_normal")
        assert res["overall_result"] == "PASS"
        assert res["inference"]["anomaly_score"] <= 0.55
        assert res["policy_decision"]["risk_level"] == "LOW"
        assert res["policy_decision"]["action"] == "ALLOW"
        assert res["audit_verification"]["chain_valid"] is True
        assert res["verification_gates"]["gate_1_model_inference"]["passed"] is True
        assert res["verification_gates"]["gate_2_shap_explanation"]["passed"] is True
        assert res["verification_gates"]["gate_3_policy_decision"]["passed"] is True
        assert res["verification_gates"]["gate_4_audit_persistence"]["passed"] is True


def test_run_scenario_impossible_travel(db_factory):
    with db_factory() as db:
        res = AnomalyRunnerService.run_scenario(db, scenario_id="geo_velocity_anomaly")
        assert res["overall_result"] == "PASS"
        assert res["inference"]["anomaly_score"] >= 0.55
        assert res["policy_decision"]["risk_level"] == "CRITICAL"
        assert res["policy_decision"]["action"] == "REVOKE_SESSION"
        assert "impossible_travel" in res["policy_decision"]["overrides_triggered"]
        assert res["audit_verification"]["chain_valid"] is True


def test_api_scenario_runner_endpoints(client: TestClient, admin: User):
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    # 1. GET /api/ai/scenario-runner/scenarios
    resp = client.get("/api/ai/scenario-runner/scenarios", headers=headers)
    assert resp.status_code == 200
    scenarios = resp.json()
    assert len(scenarios) >= 5

    # 2. POST /api/ai/scenario-runner/run (Predefined)
    resp_run = client.post(
        "/api/ai/scenario-runner/run",
        json={"scenario_id": "mass_data_exfiltration"},
        headers=headers,
    )
    assert resp_run.status_code == 200
    data = resp_run.json()
    assert data["overall_result"] == "PASS"
    assert data["scenario"]["id"] == "mass_data_exfiltration"
    assert "inference" in data
    assert "shap_explanation" in data
    assert "policy_decision" in data
    assert "audit_verification" in data
    assert data["audit_verification"]["chain_valid"] is True
    assert len(data["shap_explanation"]["top_anomaly_drivers"]) > 0

    # 3. POST /api/ai/scenario-runner/run (Custom features)
    resp_custom = client.post(
        "/api/ai/scenario-runner/run",
        json={
            "scenario_id": "custom",
            "custom_features": {
                "requests_per_minute": 200.0,
                "is_vpn": 1.0,
                "ip_reputation_score": 90.0,
            },
        },
        headers=headers,
    )
    assert resp_custom.status_code == 200
    custom_data = resp_custom.json()
    assert custom_data["overall_result"] == "PASS"
    assert custom_data["policy_decision"]["risk_level"] in ("HIGH", "CRITICAL")
