"""Tests for WebCrypto ECDSA P-256 device binding, anti-session-hijacking, and biometrics."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.ecdsa_verify import (
    generate_test_keypair,
    sign_message_p1363,
    verify_ecdsa_signature,
)
from app.models.alert import Alert
from app.models.session import UserSession
from app.models.user import User
from tests.conftest import auth_headers, sign_in


def test_ecdsa_signature_verification():
    """WebCrypto P1363 raw signature should convert to DER and verify correctly."""
    pub_b64, priv_key = generate_test_keypair()
    message = "GET:/api/resources:1728400000000"
    sig_b64 = sign_message_p1363(priv_key, message)

    # Valid
    assert verify_ecdsa_signature(pub_b64, message, sig_b64) is True

    # Tampered message
    assert verify_ecdsa_signature(pub_b64, "GET:/api/other:1728400000000", sig_b64) is False

    # Wrong key
    other_pub_b64, _ = generate_test_keypair()
    assert verify_ecdsa_signature(other_pub_b64, message, sig_b64) is False


def test_device_binding_valid_signed_request(client: TestClient, admin: User):
    """Signed request with valid ECDSA headers should pass and carry X-Device-Bound header."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    pub_b64, priv_key = generate_test_keypair()
    ts = str(int(time.time() * 1000))
    path = "/api/resources"
    sig_b64 = sign_message_p1363(priv_key, f"GET:{path}:{ts}")

    headers.update({
        "X-Device-Signature": sig_b64,
        "X-Device-Timestamp": ts,
        "X-Device-Pubkey": pub_b64,
    })

    resp = client.get(path, headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("X-Device-Bound") == "ECDSA-P256"


def test_device_binding_expired_timestamp_rejected(client: TestClient, admin: User):
    """Request with timestamp outside 30-second window should be rejected (replay attack prevention)."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    pub_b64, priv_key = generate_test_keypair()
    # 45 seconds in the past
    expired_ts = str(int((time.time() - 45) * 1000))
    path = "/api/resources"
    sig_b64 = sign_message_p1363(priv_key, f"GET:{path}:{expired_ts}")

    headers.update({
        "X-Device-Signature": sig_b64,
        "X-Device-Timestamp": expired_ts,
        "X-Device-Pubkey": pub_b64,
    })

    resp = client.get(path, headers=headers)
    assert resp.status_code == 401
    assert resp.json().get("code") == "signature_expired"


def test_device_binding_anti_session_hijack(client: TestClient, db: Session, admin: User):
    """If a stolen token is used with a different device key, access is rejected as session_hijack."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    # Legitimate device registers PubKey A
    legit_pub, legit_priv = generate_test_keypair()
    reg_resp = client.post(
        "/api/signals/register-device-key",
        json={"ecdsa_pubkey": legit_pub},
        headers=headers,
    )
    assert reg_resp.status_code == 200

    # Attacker uses stolen token with Attacker's PubKey B
    attacker_pub, attacker_priv = generate_test_keypair()
    ts = str(int(time.time() * 1000))
    path = "/api/resources"
    attacker_sig = sign_message_p1363(attacker_priv, f"GET:{path}:{ts}")

    hijack_headers = dict(headers)
    hijack_headers.update({
        "X-Device-Signature": attacker_sig,
        "X-Device-Timestamp": ts,
        "X-Device-Pubkey": attacker_pub,
    })

    resp = client.get(path, headers=hijack_headers)
    assert resp.status_code == 401
    assert resp.json().get("code") == "session_hijack"

    # Verify Critical Security Alert logged
    alert = db.execute(
        select(Alert).where(Alert.category == "session_hijack")
    ).scalar_one()
    assert alert.severity.value == "CRITICAL"


def test_biometrics_telemetry_ingestion(client: TestClient, db: Session, admin: User):
    """POST /api/signals should update session keystroke WPM and mouse velocity."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post(
        "/api/signals",
        json={
            "wpm": 65.5,
            "mouse_velocity": 420.0,
            "requests_per_minute": 5.0,
            "data_mb": 1.2,
        },
        headers=headers,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["wpm"] == 65.5
    assert data["mouse_velocity"] == 420.0
    assert data["bot_detected"] is False

    session = db.get(UserSession, admin.sessions[0].id)
    assert session.avg_wpm == 65.5
    assert session.avg_mouse_velocity == 420.0


def test_biometrics_bot_detection(client: TestClient, admin: User):
    """Abnormal keystrokes (>220 WPM) or zero mouse velocity with high RPM triggers bot detection."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    # 1. Pasted script input (250 WPM)
    resp = client.post(
        "/api/signals",
        json={"wpm": 250.0, "mouse_velocity": 100.0, "requests_per_minute": 2.0},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["bot_detected"] is True
    assert resp.json()["risk_indicator"] == "UNNATURAL_TYPING_SPEED"

    # 2. Headless browser automation (0 mouse velocity with high request volume)
    resp2 = client.post(
        "/api/signals",
        json={"wpm": 0.0, "mouse_velocity": 0.0, "requests_per_minute": 30.0},
        headers=headers,
    )
    assert resp2.status_code == 200
    assert resp2.json()["bot_detected"] is True
    assert resp2.json()["risk_indicator"] == "HEADLESS_BROWSER_AUTOMATION"
