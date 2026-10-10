"""Tests for SHAP & Feature-Level Explainability (XAI) for Isolation Forest."""

from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from app.ai import anomaly
from app.ai.scoring import TrustSignals
from app.ai.xai import assess
from app.models.user import User
from tests.conftest import auth_headers, sign_in


@pytest.fixture
def mock_anomaly_model(monkeypatch: pytest.MonkeyPatch):
    """Fixture that installs a fitted IsolationForest model in memory."""
    # Generate random synthetic data for 13 features
    rng = np.random.RandomState(42)
    X = rng.randn(50, len(anomaly.FEATURE_ORDER))
    scaler = StandardScaler().fit(X)
    estimator = IsolationForest(n_estimators=10, random_state=42).fit(scaler.transform(X))

    model = anomaly.LoadedModel(
        estimator=estimator,
        scaler=scaler,
        version="test-model-v1",
        path=anomaly.model_path(),
    )
    monkeypatch.setattr(anomaly, "load_model", lambda name=anomaly.GLOBAL_MODEL_NAME: model)
    return model


def test_explain_anomaly_with_model(mock_anomaly_model):
    """anomaly.explain() should return structured feature attribution and top drivers."""
    features = {
        "travel_velocity_kmh": 1200.0,
        "requests_per_minute": 45.0,
        "failed_auth_count_24h": 5.0,
        "is_vpn": 1.0,
        "is_known_device": 0.0,
    }

    result = anomaly.explain(features)
    assert result is not None
    assert "anomaly_score" in result
    assert "shap_values" in result
    assert len(result["shap_values"]) == len(anomaly.FEATURE_ORDER)
    assert "top_anomaly_drivers" in result
    assert "top_mitigating_signals" in result

    # Check top drivers contain high-impact features
    driver_features = [d["feature"] for d in result["top_anomaly_drivers"]]
    assert any(f in driver_features for f in ("travel_velocity_kmh", "requests_per_minute", "failed_auth_count_24h", "is_known_device"))


def test_explain_mitigating_factors(mock_anomaly_model):
    """Known approved device and clean network should appear with negative contribution (mitigators)."""
    features = {
        "is_known_device": 1.0,
        "is_vpn": 0.0,
        "ip_reputation_score": 0.0,
        "requests_per_minute": 2.0,
    }

    result = anomaly.explain(features)
    assert result is not None
    assert len(result["top_mitigating_signals"]) >= 1
    mitigator_features = [m["feature"] for m in result["top_mitigating_signals"]]
    assert "is_known_device" in mitigator_features


def test_trust_assessment_includes_shap_explanation():
    """TrustAssessment.to_dict() should carry shap_explanation when provided in TrustSignals."""
    shap_data = {
        "anomaly_score": 0.82,
        "top_anomaly_drivers": [{"feature": "travel_velocity_kmh", "impact": "+35.0%"}],
    }
    signals = TrustSignals(anomaly_score=0.82, shap_explanation=shap_data)
    assessment = assess(signals)

    data = assessment.to_dict()
    assert data["anomaly_score"] == 0.82
    assert data["shap_explanation"] == shap_data


def test_api_explain_anomaly_endpoint(client: TestClient, admin: User, mock_anomaly_model):
    """POST /api/ai/explain-anomaly should return feature attribution over the API."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post(
        "/api/ai/explain-anomaly",
        json={
            "features": {
                "travel_velocity_kmh": 850.0,
                "requests_per_minute": 25.0,
                "is_vpn": 1.0,
            }
        },
        headers=headers,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert "anomaly_score" in data
    assert "shap_values" in data
    assert len(data["top_anomaly_drivers"]) >= 1
