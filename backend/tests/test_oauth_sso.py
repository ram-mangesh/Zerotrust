"""Tests for OAuth2 (Google, GitHub) and Keycloak OIDC Single Sign-On (SSO)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import ContextBundle
from app.models.role import Role
from app.models.session import UserSession
from app.models.user import User
from app.services.auth_service import RequestContext
from app.services.device_service import DeviceContext
from app.services.oauth_service import OAuthService
from tests.conftest import DEVICE_FINGERPRINT


def test_oauth_providers_list(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    """GET /api/auth/oauth/providers should return configured SSO providers."""
    monkeypatch.setattr("app.core.config.settings.google_client_id", "google-id-123")
    monkeypatch.setattr("app.core.config.settings.github_client_id", "github-id-456")
    monkeypatch.setattr("app.core.config.settings.keycloak_issuer_url", "http://keycloak:8080/realms/ztna")
    monkeypatch.setattr("app.core.config.settings.keycloak_client_id", "keycloak-client-789")

    resp = client.get("/api/auth/oauth/providers")
    assert resp.status_code == 200
    providers = resp.json()
    provider_ids = [p["id"] for p in providers]
    assert "google" in provider_ids
    assert "github" in provider_ids
    assert "keycloak" in provider_ids


def test_oauth_get_authorize_urls(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    """GET /api/auth/oauth/{provider}/authorize returns provider redirect URLs."""
    monkeypatch.setattr("app.core.config.settings.google_client_id", "google-test-client")
    monkeypatch.setattr("app.core.config.settings.github_client_id", "github-test-client")
    monkeypatch.setattr("app.core.config.settings.keycloak_issuer_url", "http://keycloak.local/realms/ztna")
    monkeypatch.setattr("app.core.config.settings.keycloak_client_id", "kc-test-client")

    # Google
    resp = client.get("/api/auth/oauth/google/authorize?state=xyz123")
    assert resp.status_code == 200
    assert "accounts.google.com" in resp.json()["authorization_url"]
    assert "google-test-client" in resp.json()["authorization_url"]
    assert "state=xyz123" in resp.json()["authorization_url"]

    # GitHub
    resp = client.get("/api/auth/oauth/github/authorize?state=abc456")
    assert resp.status_code == 200
    assert "github.com/login/oauth/authorize" in resp.json()["authorization_url"]
    assert "github-test-client" in resp.json()["authorization_url"]

    # Keycloak OIDC
    resp = client.get("/api/auth/oauth/keycloak/authorize?state=kc789")
    assert resp.status_code == 200
    assert "keycloak.local/realms/ztna/protocol/openid-connect/auth" in resp.json()["authorization_url"]


def test_oauth_unsupported_provider(client: TestClient):
    """Unsupported provider request should return 400 Bad Request."""
    resp = client.get("/api/auth/oauth/unknown_provider/authorize")
    assert resp.status_code == 400


def test_oauth_auto_provisions_new_user(db: Session, roles: dict[str, Role]):
    """First-time OAuth login should auto-provision a user with role and session."""
    user_info = {
        "provider": "google",
        "sub": "google-sub-998877",
        "email": "new.oauth.user@example.com",
        "name": "New OAuth User",
        "department": "Security",
    }
    context = RequestContext(
        ip_address="198.51.100.10",
        user_agent="Mozilla/5.0",
        device=DeviceContext(fingerprint=DEVICE_FINGERPRINT, user_agent="Mozilla/5.0"),
        bundle=None,
    )

    tokens = OAuthService.authenticate_oauth_user(db, "google", user_info, context)

    assert tokens.access_token is not None
    assert tokens.refresh_token is not None

    user = db.execute(
        select(User).where(User.email == "new.oauth.user@example.com")
    ).scalar_one()

    assert user.oauth_provider == "google"
    assert user.oauth_sub == "google-sub-998877"
    assert user.oauth_linked is True
    assert user.role_id == roles["employee"].id


def test_oauth_links_existing_user(db: Session, user: User):
    """OAuth login with matching email links OAuth credentials to existing user."""
    user_info = {
        "provider": "github",
        "sub": "github-sub-112233",
        "email": user.email,
        "name": user.full_name,
    }
    context = RequestContext(
        ip_address="198.51.100.10",
        user_agent="Mozilla/5.0",
        device=DeviceContext(fingerprint=DEVICE_FINGERPRINT, user_agent="Mozilla/5.0"),
        bundle=None,
    )

    tokens = OAuthService.authenticate_oauth_user(db, "github", user_info, context)
    db.refresh(user)

    assert tokens.access_token is not None
    assert user.oauth_provider == "github"
    assert user.oauth_sub == "github-sub-112233"
    assert user.oauth_linked is True


@pytest.mark.anyio
async def test_oauth_callback_endpoint_flow(client: TestClient, db: Session, roles: dict[str, Role]):
    """GET /api/auth/oauth/{provider}/callback should exchange code and return tokens."""
    mock_user_info = {
        "provider": "google",
        "sub": "mock-google-12345",
        "email": "google.sso.tester@example.com",
        "name": "Google Tester",
    }

    with patch(
        "app.services.oauth_service.OAuthService.exchange_code_for_user_info",
        new=AsyncMock(return_value=mock_user_info),
    ):
        resp = client.get("/api/auth/oauth/google/callback?code=mock_code_123&state=mock_state")
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data.get("username") == "google_sso_tester"


@pytest.mark.anyio
async def test_oauth_token_exchange_spa_endpoint(client: TestClient, db: Session, roles: dict[str, Role]):
    """POST /api/auth/oauth/{provider}/token should exchange code for SPA clients."""
    mock_user_info = {
        "provider": "keycloak",
        "sub": "kc-sub-889900",
        "email": "keycloak.sso@example.com",
        "name": "Keycloak User",
        "department": "Engineering",
    }

    with patch(
        "app.services.oauth_service.OAuthService.exchange_code_for_user_info",
        new=AsyncMock(return_value=mock_user_info),
    ):
        resp = client.post(
            "/api/auth/oauth/keycloak/token",
            json={"code": "kc_auth_code_xyz", "redirect_uri": "http://localhost:5173/auth/callback"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data.get("role") == "employee"
