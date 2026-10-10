"""Tests for Drop-In Zero Trust Reverse Proxy Gateway."""

import time
import hmac
import hashlib
import jwt
from fastapi.testclient import TestClient

from app.core.config import settings
from app.dropin.config import DropInProxyConfig, RouteRule
from app.dropin.proxy_server import create_dropin_proxy_app
from app.dropin.html_injector import inject_sdk_into_html
from app.dropin.header_transformer import (
    sanitize_incoming_headers,
    generate_gateway_signature,
    build_upstream_headers,
)


def create_test_token(username="admin", role="admin", trust_score=95.0):
    claims = {
        "sub": "usr-123",
        "user_id": "usr-123",
        "username": username,
        "email": f"{username}@securecorp.local",
        "role": role,
        "trust_score": trust_score,
        "risk_level": "LOW",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(claims, settings.secret_key, algorithm=settings.jwt_algorithm)


def test_html_injector_head():
    raw = b"<html><head><title>App</title></head><body>Content</body></html>"
    injected = inject_sdk_into_html(raw)
    assert b'<script src="/__ztna/ztna-sdk.js" defer></script></head>' in injected


def test_html_injector_body_fallback():
    raw = b"<html><body>Content</body></html>"
    injected = inject_sdk_into_html(raw)
    assert b'<script src="/__ztna/ztna-sdk.js" defer></script></body>' in injected


def test_header_sanitization():
    incoming = {
        "Host": "evil.com",
        "Connection": "keep-alive",
        "X-Forwarded-User": "forged_admin",
        "X-Custom-Header": "valid_value",
    }
    clean = sanitize_incoming_headers(incoming)
    assert "Host" not in clean
    assert "Connection" not in clean
    assert "X-Forwarded-User" not in clean
    assert clean["X-Custom-Header"] == "valid_value"


def test_gateway_signature_verification():
    ts = str(int(time.time()))
    sig = generate_gateway_signature("user1", "admin", 90.0, ts)
    expected_payload = f"user1:admin:90.00:{ts}".encode()
    expected_sig = hmac.new(settings.secret_key.encode(), expected_payload, hashlib.sha256).hexdigest()
    assert sig == expected_sig


def test_dropin_health_endpoint():
    app = create_dropin_proxy_app()
    client = TestClient(app)
    res = client.get("/__ztna/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["gateway"] == "VajraNetra-DropIn-PEP"


def test_dropin_sdk_endpoint():
    app = create_dropin_proxy_app()
    client = TestClient(app)
    res = client.get("/__ztna/ztna-sdk.js")
    assert res.status_code == 200
    assert "application/javascript" in res.headers["content-type"]


def test_dropin_auth_flow():
    app = create_dropin_proxy_app()
    client = TestClient(app)

    # Invalid creds
    res_fail = client.post("/__ztna/auth", json={"username": "fake", "password": "wrong"})
    assert res_fail.status_code == 401

    # Valid creds
    res_ok = client.post("/__ztna/auth", json={"username": "admin", "password": "admin123"})
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["status"] == "authenticated"
    assert "token" in data
    assert "ztna_session" in res_ok.cookies


def test_dropin_unauthenticated_interception():
    app = create_dropin_proxy_app()
    client = TestClient(app)

    # Browser request returns HTML login page
    res_browser = client.get("/dashboard", headers={"Accept": "text/html"})
    assert res_browser.status_code == 200
    assert "VajraNetra Zero Trust Gateway Authentication" in res_browser.text

    # API request returns 401 JSON
    res_api = client.get("/api/data", headers={"Accept": "application/json"})
    assert res_api.status_code == 401
    assert res_api.json()["error"] == "unauthenticated"


def test_dropin_role_and_trust_enforcement():
    app = create_dropin_proxy_app()
    client = TestClient(app)

    # Regular user token trying to access /admin (requires role: admin)
    user_token = create_test_token(username="normaluser", role="user", trust_score=90.0)
    res_user = client.get("/admin/secret", headers={"Authorization": f"Bearer {user_token}"})
    assert res_user.status_code == 403
    assert res_user.json()["error"] == "forbidden"

    # Admin with low trust score trying to access /admin (requires min trust 70.0)
    degraded_token = create_test_token(username="admin", role="admin", trust_score=45.0)
    res_degraded = client.get("/admin/secret", headers={"Authorization": f"Bearer {degraded_token}"})
    assert res_degraded.status_code == 403
    assert res_degraded.json()["error"] == "trust_degraded"
