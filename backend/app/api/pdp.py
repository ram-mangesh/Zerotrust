"""Policy Decision Point (PDP) internal API endpoint."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import get_context_bundle
from app.core.request_signing import verify_gateway_signature
from app.services.pdp_service import PDPService

router = APIRouter(tags=["pdp-authorization"])


class PDPAuthorizeRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    method: str = Field(default="GET")
    path: str = Field(..., description="Target resource path, e.g. /proxy/payroll-db/data")
    source_ip: str = Field(default="127.0.0.1")
    access_token: str | None = Field(default=None)
    device_fingerprint: str | None = Field(default=None)
    user_agent: str = Field(default="")


class PDPAuthorizeResponse(BaseModel):
    decision: str
    allowed: bool
    reason: str
    matched_policy: str
    trust_score: float
    username: str
    role: str
    resource: str | None = None
    upstream_url: str | None = None
    upstream_path: str | None = None
    action: str = "BLOCK"


@router.post(
    "/api/pdp/authorize",
    response_model=PDPAuthorizeResponse,
    summary="PDP Authorization Evaluation",
)
@router.post(
    "/internal/authorize",
    response_model=PDPAuthorizeResponse,
    summary="Internal PEP Gateway Authorization",
)
def pdp_authorize(
    payload: PDPAuthorizeRequest,
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
    x_gateway_signature: str | None = Header(default=None),
    x_gateway_timestamp: str | None = Header(default=None),
) -> PDPAuthorizeResponse:
    """Evaluate access authorization for an incoming PEP gateway request."""
    # If signed with gateway HMAC key, verify signature
    signing_secret = settings.gateway_signing_key or settings.secret_key
    if x_gateway_signature and x_gateway_timestamp:
        if not verify_gateway_signature(
            payload.method,
            "/internal/authorize",
            x_gateway_signature,
            x_gateway_timestamp,
            signing_secret,
        ) and not verify_gateway_signature(
            payload.method,
            "/api/pdp/authorize",
            x_gateway_signature,
            x_gateway_timestamp,
            signing_secret,
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid gateway HMAC signature",
            )

    result = PDPService.authorize(
        db,
        request_id=payload.request_id,
        method=payload.method,
        path=payload.path,
        source_ip=payload.source_ip,
        access_token=payload.access_token,
        device_fingerprint=payload.device_fingerprint,
        bundle=bundle,
    )
    db.commit()

    return PDPAuthorizeResponse(
        decision=result.decision,
        allowed=result.allowed,
        reason=result.reason,
        matched_policy=result.matched_policy,
        trust_score=result.trust_score,
        username=result.username,
        role=result.role,
        resource=result.resource,
        upstream_url=result.upstream_url,
        upstream_path=result.upstream_path,
        action=result.action,
    )
