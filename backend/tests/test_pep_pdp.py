"""Tests for Policy Enforcement Point (PEP) & Policy Decision Point (PDP) architecture."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.request_signing import sign_gateway_request, verify_gateway_signature
from app.models.resource import Resource
from app.models.user import User
from tests.conftest import auth_headers, sign_in


def test_request_signing_and_verification():
    """HMAC-SHA256 request signing and verification should work and reject tampering."""
    secret = "super_secret_gateway_key_123"
    sig, ts = sign_gateway_request("GET", "/api/v1/data", secret)

    # Valid signature
    assert verify_gateway_signature("GET", "/api/v1/data", sig, ts, secret) is True

    # Path tampering
    assert verify_gateway_signature("GET", "/api/v1/other", sig, ts, secret) is False

    # Method tampering
    assert verify_gateway_signature("POST", "/api/v1/data", sig, ts, secret) is False

    # Wrong secret
    assert verify_gateway_signature("GET", "/api/v1/data", sig, ts, "wrong_secret") is False

    # Expired timestamp (older than max_age_seconds)
    old_ts = str(int(ts) - 100)
    old_sig, _ = sign_gateway_request("GET", "/api/v1/data", secret)
    assert verify_gateway_signature("GET", "/api/v1/data", old_sig, old_ts, secret, max_age_seconds=30) is False


def test_pdp_authorize_unauthenticated_request(client: TestClient):
    """PDP /api/pdp/authorize should return DENY for requests with no token."""
    resp = client.post(
        "/api/pdp/authorize",
        json={"method": "GET", "path": "/proxy/source-repo/code"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "DENY"
    assert data["allowed"] is False
    assert data["username"] == "anonymous"


def test_pdp_authorize_allowed_request(client: TestClient, admin: User, catalogue: dict[str, Resource]):
    """PDP should return ALLOW for valid admin requests on registered resources."""
    tokens = sign_in(client, admin)

    resp = client.post(
        "/api/pdp/authorize",
        json={
            "method": "GET",
            "path": "/proxy/public-docs/read",
            "access_token": tokens["access_token"],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"
    assert data["allowed"] is True
    assert data["username"] == admin.username
    assert data["role"] == "admin"


def test_pep_proxy_denies_unauthenticated_request(client: TestClient):
    """PEP ingress route `/proxy/{slug}/*` should reject unauthenticated requests."""
    resp = client.get("/proxy/source-repo/v1/commits")
    assert resp.status_code == 401
    assert resp.headers.get("X-ZTNA-Decision") == "DENY"
    assert resp.json().get("code") == "access_denied"


def test_pep_proxy_allowed_without_upstream(
    client: TestClient, admin: User, catalogue: dict[str, Resource]
):
    """PEP ingress on resource without upstream URL should return 200 authorization confirmation."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.get("/proxy/public-docs/overview", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "authorized"
    assert data["decision"] == "ALLOW"
    assert resp.headers.get("X-ZTNA-Decision") == "ALLOW"


@pytest.mark.anyio
async def test_pep_proxy_forwarding_with_hmac_signing(
    client: TestClient, db: Session, admin: User, catalogue: dict[str, Resource]
):
    """PEP should forward allowed requests with cryptographic HMAC signature to upstream."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    # Configure upstream_url on resource
    res = catalogue["hr-portal"]
    res.upstream_url = "http://internal-hr-service:8080"
    db.commit()

    captured_headers = {}

    async def mock_upstream_request(*args, **kwargs):
        nonlocal captured_headers
        captured_headers = kwargs.get("headers", {})
        import httpx
        return httpx.Response(200, json={"message": "hello from internal upstream hr service"})

    with patch("httpx.AsyncClient.request", new=AsyncMock(side_effect=mock_upstream_request)):
        resp = client.get("/proxy/hr-portal/employees/list?dept=eng", headers=headers)
        assert resp.status_code == 200
        assert resp.json().get("message") == "hello from internal upstream hr service"
        assert resp.headers.get("X-ZTNA-Decision") == "ALLOW"

        # Check injected gateway headers
        assert "X-Gateway-Signature" in captured_headers
        assert "X-Gateway-Timestamp" in captured_headers
        assert captured_headers.get("X-ZTNA-User") == admin.username
        assert captured_headers.get("X-ZTNA-Role") == "admin"
        assert "authorization" not in captured_headers  # Bearer token stripped
