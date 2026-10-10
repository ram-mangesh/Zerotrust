"""Tests for LLM Incident Narrator and AI Behavioral Baseline Synthesizer (Groq/Llama-3.3-70B)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.services.llm_service import LLMService
from tests.conftest import auth_headers, sign_in


@pytest.mark.anyio
async def test_synthesize_baseline_fallback():
    """LLMService should return deterministic tailored baselines when offline/no API key."""
    # Finance role
    fin = await LLMService.synthesize_baseline(role="finance_analyst", department="Finance")
    assert fin["expected_hours_start"] == 9
    assert fin["expected_hours_end"] == 18
    assert "payroll-db" in fin["typical_resources"]
    assert "Offline Fallback" in fin["synthesized_by"]

    # Admin role
    adm = await LLMService.synthesize_baseline(role="admin", department="IT")
    assert adm["expected_hours_start"] == 8
    assert adm["expected_hours_end"] == 20
    assert adm["avg_requests_per_minute"] >= 5.0


@pytest.mark.anyio
async def test_synthesize_baseline_with_groq_mock(monkeypatch: pytest.MonkeyPatch):
    """When GROQ_API_KEY is set, LLMService should call Llama-3.3-70B and parse JSON."""
    monkeypatch.setattr("app.core.config.settings.groq_api_key", "mock_groq_key")

    mock_llm_json = json.dumps({
        "expected_hours_start": 7,
        "expected_hours_end": 19,
        "avg_requests_per_minute": 6.5,
        "avg_session_minutes": 55.0,
        "avg_distinct_resources": 5.0,
        "typical_resources": ["source-repo", "internal-wiki"],
        "allowed_countries": ["IN", "SG"],
    })

    with patch("app.services.llm_service.LLMService.call_groq", new=AsyncMock(return_value=mock_llm_json)):
        res = await LLMService.synthesize_baseline(role="lead_developer", department="Engineering")
        assert res["expected_hours_start"] == 7
        assert res["avg_requests_per_minute"] == 6.5
        assert res["synthesized_by"] == "Groq/Llama-3.3-70B"


@pytest.mark.anyio
async def test_narrate_incident_fallback():
    """Incident narration fallback should synthesize an analytical summary."""
    report = await LLMService.narrate_incident(
        username="alice",
        user_id="user-123",
        risk_score=22.0,
        risk_level="CRITICAL",
        action="REVOKE_SESSION",
        overrides=["impossible_travel"],
        threat_details={"origin": "Coimbatore", "destination": "São Paulo"},
    )
    assert "alice" in report
    assert "22.0" in report
    assert "CRITICAL" in report
    assert "impossible travel" in report
    assert "REVOKE_SESSION" in report


@pytest.mark.anyio
async def test_narrate_incident_with_groq_mock(monkeypatch: pytest.MonkeyPatch):
    """Incident narration with Groq Llama-3.3 should return executive summary."""
    monkeypatch.setattr("app.core.config.settings.groq_api_key", "mock_groq_key")

    mock_narrative = (
        "Security Incident: User 'sneha' triggered immediate session revocation at 03:15 UTC. "
        "The primary anomaly was an impossible travel velocity jump from India to Moscow (AS44050) "
        "accompanied by zero mouse movement and an unverified ECDSA public key point. "
        "The gateway terminated all active sessions to protect internal databases."
    )

    with patch("app.services.llm_service.LLMService.call_groq", new=AsyncMock(return_value=mock_narrative)):
        report = await LLMService.narrate_incident(
            username="sneha",
            user_id="user-456",
            risk_score=18.0,
            risk_level="CRITICAL",
            action="REVOKE_SESSION",
            overrides=["session_hijack", "impossible_travel"],
        )
        assert "sneha" in report
        assert "Moscow" in report
        assert "session revocation" in report


def test_api_synthesize_baseline_endpoint(client: TestClient, admin: User):
    """POST /api/ai/synthesize-baseline should generate role baseline via API."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post(
        "/api/ai/synthesize-baseline",
        json={"role": "contractor", "department": "Operations"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "expected_hours_start" in data
    assert "typical_resources" in data


def test_api_narrate_incident_endpoint(client: TestClient, admin: User):
    """POST /api/ai/narrate-incident should return plain-English report."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post(
        "/api/ai/narrate-incident",
        json={
            "username": "bob",
            "risk_score": 28.0,
            "risk_level": "CRITICAL",
            "action": "REVOKE_SESSION",
            "overrides": ["session_hijack"],
        },
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "narrative" in data
    assert "bob" in data["narrative"]
    assert data["risk_score"] == 28.0
