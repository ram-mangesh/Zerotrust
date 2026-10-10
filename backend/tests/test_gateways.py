"""Tests for Envoy ext_authz, NGINX auth_request, and Kong gateway plugins."""

from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.session import UserSession
from app.models.enums import SessionStatus, RiskLevel, AccessAction, ScoreTrigger
from app.models.trust_score import TrustScore
from app.core import jwt as jwt_service


def _make_test_session(db: Session, user: User, trust_score: float = 90.0) -> UserSession:
    now = datetime.now(timezone.utc)
    session = UserSession(
        user_id=user.id,
        ip_address="127.0.0.1",
        country="IN",
        city="Bengaluru",
        started_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=8),
        status=SessionStatus.ACTIVE,
        current_trust_score=trust_score,
        mfa_passed=True,
    )
    db.add(session)
    db.flush()

    trust = TrustScore(
        user_id=user.id,
        session_id=session.id,
        score=trust_score,
        risk_level=RiskLevel.LOW if trust_score >= 80 else RiskLevel.MEDIUM,
        action=AccessAction.ALLOW,
        trigger=ScoreTrigger.LOGIN,
        factors=[],
        reason="Initial login baseline",
    )
    db.add(trust)
    db.commit()
    return session


def test_envoy_ext_authz_unauthorized(client: TestClient):
    """Envoy ext_authz returns 401 when no token is present."""
    res = client.get("/api/gateways/envoy/ext_authz")
    assert res.status_code == 401
    assert res.headers.get("X-ZTNA-Decision") == "DENY"


def test_envoy_ext_authz_authorized(client: TestClient, admin: User, db: Session):
    """Envoy ext_authz returns 200 and upstream headers when authenticated."""
    session = _make_test_session(db, admin, trust_score=92.0)

    token, _, _ = jwt_service.create_access_token(
        user_id=admin.id,
        session_id=session.id,
        role=admin.role.name,
    )

    res = client.get(
        "/api/gateways/envoy/ext_authz",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Envoy-Original-Path": "/api/v1/orders",
            "X-Envoy-Original-Method": "GET",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("X-ZTNA-Decision") == "ALLOW"
    assert res.headers.get("X-Forwarded-User") == admin.username
    assert res.headers.get("X-Forwarded-Role") == admin.role.name
    assert res.headers.get("X-ZTNA-Trust-Score") == "92.00"
    assert "X-Gateway-Signature" in res.headers


def test_nginx_auth_request_flow(client: TestClient, user: User, db: Session):
    """NGINX auth_request returns 200 with headers or 401."""
    # Unauth
    res_unauth = client.get("/api/gateways/nginx/auth")
    assert res_unauth.status_code == 401

    # Auth
    session = _make_test_session(db, user, trust_score=88.5)

    token, _, _ = jwt_service.create_access_token(
        user_id=user.id,
        session_id=session.id,
        role=user.role.name,
    )

    res_auth = client.get(
        "/api/gateways/nginx/auth",
        headers={"Authorization": f"Bearer {token}", "X-Original-URI": "/dashboard"},
    )
    assert res_auth.status_code == 200
    assert res_auth.headers.get("X-Forwarded-User") == user.username
    assert res_auth.headers.get("X-ZTNA-Trust-Score") == "88.50"


def test_kong_verify_plugin_flow(client: TestClient, user: User, db: Session):
    """Kong verification endpoint evaluates payload and returns allow decision."""
    # Invalid token
    res_invalid = client.post(
        "/api/gateways/kong/verify",
        json={"token": "invalid.jwt.token", "client_ip": "1.2.3.4", "path": "/api"},
    )
    assert res_invalid.status_code == 401
    assert res_invalid.json()["allow"] is False

    # Valid token
    session = _make_test_session(db, user, trust_score=80.0)

    token, _, _ = jwt_service.create_access_token(
        user_id=user.id,
        session_id=session.id,
        role=user.role.name,
    )

    res_ok = client.post(
        "/api/gateways/kong/verify",
        json={
            "token": token,
            "client_ip": "1.2.3.4",
            "path": "/api/users",
            "min_trust_score": 50.0,
        },
    )
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["allow"] is True
    assert data["headers"]["X-Forwarded-User"] == user.username
