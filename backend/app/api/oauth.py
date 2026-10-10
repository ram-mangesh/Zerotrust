"""OAuth2 and OpenID Connect (OIDC) Single Sign-On router."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_request_context
from app.schemas.auth import TokenResponse
from app.services.auth_service import AuthError, RequestContext
from app.services.oauth_service import OAuthService

router = APIRouter(prefix="/api/auth/oauth", tags=["oauth-sso"])


class OAuthTokenExchangeRequest(BaseModel):
    code: str = Field(..., description="Authorization code from the OAuth provider")
    redirect_uri: str | None = Field(
        default=None, description="Redirect URI matching authorization request"
    )
    state: str | None = Field(default=None, description="CSRF state parameter")


class OAuthAuthorizeResponse(BaseModel):
    provider: str
    authorization_url: str


@router.get("/providers", summary="List enabled OAuth/OIDC identity providers")
def list_providers() -> list[dict[str, Any]]:
    """Return all configured and enabled SSO identity providers."""
    return OAuthService.get_enabled_providers()


@router.get(
    "/{provider}/authorize",
    response_model=OAuthAuthorizeResponse,
    summary="Get OAuth authorization URL",
)
def get_authorize_url(
    provider: str,
    redirect_uri: str | None = Query(default=None),
    state: str | None = Query(default=None),
) -> OAuthAuthorizeResponse:
    """Generate authorization URL for client redirection to the provider login page."""
    try:
        url = OAuthService.get_authorization_url(
            provider, redirect_uri=redirect_uri, state=state
        )
        return OAuthAuthorizeResponse(provider=provider, authorization_url=url)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@router.get(
    "/{provider}/callback",
    response_model=TokenResponse,
    summary="OAuth callback handler",
)
async def oauth_callback(
    provider: str,
    code: str = Query(..., description="Authorization code from provider"),
    state: str | None = Query(default=None),
    redirect_uri: str | None = Query(default=None),
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> TokenResponse:
    """Exchange authorization code from redirect callback and establish session."""
    try:
        user_info = await OAuthService.exchange_code_for_user_info(
            provider, code=code, redirect_uri=redirect_uri
        )
        tokens = OAuthService.authenticate_oauth_user(
            db, provider=provider, user_info=user_info, context=context
        )
        db.commit()
        return TokenResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.expires_in,
            session_id=tokens.session_id,
            **tokens.extra,
        )
    except AuthError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authentication failed: {exc}",
        ) from exc


@router.post(
    "/{provider}/token",
    response_model=TokenResponse,
    summary="Direct OAuth token exchange (SPA/Mobile)",
)
async def oauth_token_exchange(
    provider: str,
    payload: OAuthTokenExchangeRequest,
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> TokenResponse:
    """Direct API token exchange for Single Page Apps (SPA) or mobile clients."""
    try:
        user_info = await OAuthService.exchange_code_for_user_info(
            provider, code=payload.code, redirect_uri=payload.redirect_uri
        )
        tokens = OAuthService.authenticate_oauth_user(
            db, provider=provider, user_info=user_info, context=context
        )
        db.commit()
        return TokenResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.expires_in,
            session_id=tokens.session_id,
            **tokens.extra,
        )
    except AuthError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authentication failed: {exc}",
        ) from exc
