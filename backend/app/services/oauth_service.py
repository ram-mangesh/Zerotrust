"""OAuth2 and OpenID Connect (OIDC) Single Sign-On (SSO) service.

Handles:
  - Google OAuth 2.0
  - GitHub OAuth 2.0
  - Keycloak / Enterprise OpenID Connect (OIDC)
"""

from __future__ import annotations

import logging
import secrets
import urllib.parse
import uuid
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.external.mfa import generate_secret as generate_totp_secret
from app.models.base import utcnow
from app.models.enums import AccountStatus, SessionStatus
from app.models.role import Role
from app.models.session import UserSession
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.auth_service import AuthError, AuthService, RequestContext
from app.services.device_service import DeviceContext, DeviceService

logger = logging.getLogger(__name__)

# Provider configuration definitions
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


class OAuthService:
    @staticmethod
    def get_enabled_providers() -> list[dict[str, Any]]:
        """List configured OAuth/OIDC providers."""
        providers = []
        if settings.google_client_id:
            providers.append({"id": "google", "name": "Google", "type": "oauth2"})
        if settings.github_client_id:
            providers.append({"id": "github", "name": "GitHub", "type": "oauth2"})
        if settings.keycloak_issuer_url and settings.keycloak_client_id:
            providers.append({"id": "keycloak", "name": "Keycloak OIDC", "type": "oidc"})
        return providers

    @classmethod
    def get_authorization_url(
        cls, provider: str, redirect_uri: str | None = None, state: str | None = None
    ) -> str:
        """Generate the provider-specific OAuth2/OIDC authorization redirect URL."""
        state = state or secrets.token_urlsafe(32)
        base_redirect = (
            redirect_uri
            or f"{settings.oauth_redirect_base_url.rstrip('/')}/api/auth/oauth/{provider}/callback"
        )

        if provider == "google":
            client_id = settings.google_client_id or "mock_google_client_id"
            params = {
                "client_id": client_id,
                "redirect_uri": base_redirect,
                "response_type": "code",
                "scope": "openid email profile",
                "access_type": "online",
                "state": state,
                "prompt": "select_account",
            }
            return f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"

        if provider == "github":
            client_id = settings.github_client_id or "mock_github_client_id"
            params = {
                "client_id": client_id,
                "redirect_uri": base_redirect,
                "scope": "user:email read:user",
                "state": state,
            }
            return f"{GITHUB_AUTH_URL}?{urllib.parse.urlencode(params)}"

        if provider == "keycloak":
            issuer = (settings.keycloak_issuer_url or "http://localhost:8080/realms/ztna").rstrip("/")
            client_id = settings.keycloak_client_id or "mock_keycloak_client_id"
            auth_endpoint = f"{issuer}/protocol/openid-connect/auth"
            params = {
                "client_id": client_id,
                "redirect_uri": base_redirect,
                "response_type": "code",
                "scope": "openid email profile",
                "state": state,
            }
            return f"{auth_endpoint}?{urllib.parse.urlencode(params)}"

        raise AuthError(f"Unsupported OAuth provider: {provider}", "unsupported_provider", 400)

    @classmethod
    async def exchange_code_for_user_info(
        cls, provider: str, code: str, redirect_uri: str | None = None
    ) -> dict[str, Any]:
        """Exchange authorization code with the provider and return normalized user info."""
        base_redirect = (
            redirect_uri
            or f"{settings.oauth_redirect_base_url.rstrip('/')}/api/auth/oauth/{provider}/callback"
        )

        async with httpx.AsyncClient(timeout=10.0) as client:
            if provider == "google":
                token_resp = await client.post(
                    GOOGLE_TOKEN_URL,
                    data={
                        "code": code,
                        "client_id": settings.google_client_id,
                        "client_secret": settings.google_client_secret,
                        "redirect_uri": base_redirect,
                        "grant_type": "authorization_code",
                    },
                )
                if token_resp.status_code != 200:
                    raise AuthError("Failed to exchange Google OAuth code", "oauth_exchange_failed")
                tokens = token_resp.json()
                access_token = tokens.get("access_token")

                userinfo_resp = await client.get(
                    GOOGLE_USERINFO_URL,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if userinfo_resp.status_code != 200:
                    raise AuthError("Failed to fetch Google profile", "oauth_profile_failed")
                profile = userinfo_resp.json()
                return {
                    "provider": "google",
                    "sub": profile.get("sub"),
                    "email": profile.get("email"),
                    "name": profile.get("name") or profile.get("email", "").split("@")[0],
                    "picture": profile.get("picture"),
                }

            if provider == "github":
                token_resp = await client.post(
                    GITHUB_TOKEN_URL,
                    data={
                        "code": code,
                        "client_id": settings.github_client_id,
                        "client_secret": settings.github_client_secret,
                        "redirect_uri": base_redirect,
                    },
                    headers={"Accept": "application/json"},
                )
                if token_resp.status_code != 200:
                    raise AuthError("Failed to exchange GitHub OAuth code", "oauth_exchange_failed")
                tokens = token_resp.json()
                access_token = tokens.get("access_token")
                if not access_token:
                    raise AuthError("GitHub did not return access token", "oauth_exchange_failed")

                userinfo_resp = await client.get(
                    GITHUB_USER_URL,
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                )
                profile = userinfo_resp.json()

                # GitHub primary email might be private, fetch from /user/emails
                email = profile.get("email")
                if not email:
                    emails_resp = await client.get(
                        GITHUB_EMAILS_URL,
                        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                    )
                    if emails_resp.status_code == 200:
                        for em in emails_resp.json():
                            if em.get("primary") and em.get("verified"):
                                email = em.get("email")
                                break

                return {
                    "provider": "github",
                    "sub": str(profile.get("id")),
                    "email": email or f"{profile.get('login')}@users.noreply.github.com",
                    "name": profile.get("name") or profile.get("login"),
                    "picture": profile.get("avatar_url"),
                }

            if provider == "keycloak":
                issuer = (settings.keycloak_issuer_url or "").rstrip("/")
                token_endpoint = f"{issuer}/protocol/openid-connect/token"
                userinfo_endpoint = f"{issuer}/protocol/openid-connect/userinfo"

                token_resp = await client.post(
                    token_endpoint,
                    data={
                        "code": code,
                        "client_id": settings.keycloak_client_id,
                        "client_secret": settings.keycloak_client_secret,
                        "redirect_uri": base_redirect,
                        "grant_type": "authorization_code",
                    },
                )
                if token_resp.status_code != 200:
                    raise AuthError("Failed to exchange Keycloak OIDC code", "oidc_exchange_failed")
                tokens = token_resp.json()
                access_token = tokens.get("access_token")

                userinfo_resp = await client.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                profile = userinfo_resp.json()
                return {
                    "provider": "keycloak",
                    "sub": profile.get("sub"),
                    "email": profile.get("email"),
                    "name": profile.get("name") or profile.get("preferred_username"),
                    "department": profile.get("department"),
                }

        raise AuthError(f"Unsupported provider {provider}", "unsupported_provider", 400)

    @classmethod
    def authenticate_oauth_user(
        cls,
        db: Session,
        provider: str,
        user_info: dict[str, Any],
        context: RequestContext,
    ) -> Any:
        """Find or provision user from OAuth profile and issue active session tokens."""
        sub = str(user_info.get("sub") or "")
        email = str(user_info.get("email") or "").lower().strip()
        name = str(user_info.get("name") or email.split("@")[0]).strip()

        if not sub or not email:
            raise AuthError("OAuth profile missing required sub or email", "oauth_invalid_profile")

        # 1. Check if user already linked with this provider + sub
        user = db.execute(
            select(User).where(User.oauth_provider == provider, User.oauth_sub == sub)
        ).scalar_one_or_none()

        # 2. Check by email and link
        if user is None:
            user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
            if user is not None:
                user.oauth_provider = provider
                user.oauth_sub = sub
                user.oauth_linked = True
                db.flush()

        # 3. Auto-provision new user if not found
        if user is None:
            # Default role: employee
            role = db.execute(select(Role).where(Role.name == "employee")).scalar_one_or_none()
            if role is None:
                role = db.execute(select(Role)).scalars().first()

            username_base = email.split("@")[0].replace(".", "_")[:48]
            candidate_username = username_base
            suffix = 1
            while db.execute(select(User).where(User.username == candidate_username)).scalar_one_or_none() is not None:
                candidate_username = f"{username_base}_{suffix}"
                suffix += 1

            user = User(
                username=candidate_username,
                email=email,
                full_name=name,
                department=user_info.get("department") or "Engineering",
                role_id=role.id,
                account_status=AccountStatus.ACTIVE,
                mfa_enabled=False,
                mfa_secret=generate_totp_secret(),
                oauth_provider=provider,
                oauth_sub=sub,
                oauth_linked=True,
                hashed_password=None,
            )
            db.add(user)
            db.flush()
            logger.info("Auto-provisioned new SSO user: %s (%s)", user.username, provider)

        if user.account_status is AccountStatus.DISABLED:
            raise AuthError("This account is disabled.", "account_disabled", 403)

        if user.is_locked:
            raise AuthError("Account is currently locked.", "account_locked", 423)

        # Register / touch device
        device_ctx = context.device or DeviceContext(
            fingerprint="oauth_sso_browser_fingerprint",
            user_agent=context.user_agent,
        )
        resolution = DeviceService.register_or_touch(db, user, device_ctx)

        # Create session
        network = context.bundle.network if context.bundle else None
        now = utcnow()
        session = UserSession(
            user_id=user.id,
            device_id=resolution.device.id,
            status=SessionStatus.ACTIVE,
            ip_address=context.ip_address,
            country=network.geo.country if network else "",
            city=network.geo.city if network else "",
            latitude=network.geo.latitude if network else None,
            longitude=network.geo.longitude if network else None,
            asn=(network.intel.asn or network.geo.asn) if network else "",
            isp=network.geo.isp if network else "",
            is_vpn=network.intel.is_vpn if network else False,
            is_datacenter=network.intel.is_datacenter if network else False,
            ip_reputation=network.reputation.abuse_confidence if network else 0,
            started_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        )
        db.add(session)
        db.flush()

        AuditService.record(
            db,
            action="OAUTH_LOGIN_SUCCESS",
            actor_id=user.id,
            actor_label=user.username,
            resource_type="session",
            resource_id=str(session.id),
            ip_address=context.ip_address,
            payload={
                "provider": provider,
                "sub": sub,
                "email": email,
                "session_id": str(session.id),
                "device_id": str(resolution.device.id),
            },
        )

        return AuthService._issue_session_tokens(
            db, user, session, context, mfa=f"sso_{provider}"
        )
