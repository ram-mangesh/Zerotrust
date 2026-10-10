"""Gateway external authorization endpoints for Envoy ext_authz, NGINX auth_request, and Kong."""

from __future__ import annotations

import time
import uuid
from typing import Optional, Dict
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.dependencies import get_db
from app.core import jwt as jwt_service
from app.core.request_signing import sign_gateway_request
from app.dropin.header_transformer import generate_gateway_signature, sanitize_incoming_headers
from app.models.user import User
from app.models.session import UserSession
from app.models.alert import Alert
from app.models.enums import AccountStatus, SessionStatus, AlertSeverity, AlertStatus
from app.models.base import utcnow
from app.services.audit_service import AuditService
from app.services.events import Event, publish_sync
from app.core.databroker import get_cached_session, get_cached_user, set_cached_session, set_cached_user
from app.core.jwt_assertion import create_identity_assertion, get_jwks
from app.core.routes_policy import route_policy_engine
from app.services.pdp_service import PDPService

router = APIRouter(prefix="/api/gateways", tags=["Gateway Ext-Authz"])


def _extract_token_from_headers_or_cookies(headers: Dict[str, str], cookie_str: Optional[str] = None) -> Optional[str]:
    """Extract JWT token from Authorization header or ztna_session cookie."""
    auth_header = headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    if cookie_str:
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if pair.startswith("ztna_session="):
                return pair[len("ztna_session="):].strip()
    return None


@router.api_route("/envoy/ext_authz/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@router.api_route("/envoy/ext_authz", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def envoy_ext_authz_http(request: Request, db: Session = Depends(get_db)):
    """Envoy HTTP ext_authz external authorization filter endpoint.
    
    Envoy sends original client request details. This endpoint returns:
    - 200 OK + injects headers (x-forwarded-user, x-ztna-trust-score, x-gateway-signature) on ALLOW
    - 401/403 with denial explanation on DENY.
    """
    raw_headers = {k.lower(): v for k, v in request.headers.items()}
    original_path = raw_headers.get("x-envoy-original-path") or request.path_params.get("path") or request.url.path
    if original_path and not original_path.startswith("/"): original_path = "/" + original_path
    original_method = raw_headers.get("x-envoy-original-method") or request.method
    client_ip = raw_headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host
    cookie_str = raw_headers.get("cookie", "")

    # Check if route allows public unauthenticated access
    matched_route = route_policy_engine.find_matching_route(original_path)
    if matched_route and matched_route.allow_public_unauthenticated:
        return Response(
            status_code=200,
            content="",
            headers={
                "X-ZTNA-Decision": "ALLOW",
                "X-Forwarded-User": "anonymous",
                "X-Forwarded-Role": "public",
                "X-ZTNA-Trust-Score": "100.0",
                "X-ZTNA-Risk-Level": "LOW",
            },
        )

    token = _extract_token_from_headers_or_cookies(raw_headers, cookie_str)
    if not token:
        return Response(
            status_code=401,
            content="Unauthorized: Missing ZTNA session token or credentials",
            headers={
                "WWW-Authenticate": 'Bearer realm="VajraNetra ZTNA"',
                "X-ZTNA-Decision": "DENY",
                "X-ZTNA-Reason": "Missing credentials",
            },
        )

    # Decode and verify token
    try:
        claims = jwt_service.decode_token(token, expected_type="access")
    except Exception:
        return Response(
            status_code=401,
            content="Unauthorized: Invalid or expired ZTNA token",
            headers={"X-ZTNA-Decision": "DENY", "X-ZTNA-Reason": "Token invalid"},
        )

    # ⚡ [DATABROKER ZERO-LATENCY CACHE]
    sub = claims.get("sub")
    sid = claims.get("sid")
    
    # 1. Immediate termination if session is marked revoked in local mesh
    cached_session = get_cached_session(sid)
    if cached_session and cached_session.get("status") == "REVOKED":
        return Response(
            status_code=403,
            content="Forbidden: Session explicitly revoked across mesh",
            headers={"X-ZTNA-Decision": "DENY", "X-ZTNA-Reason": "Session revoked"},
        )

    # 2. Check cached user identity
    cached_user = get_cached_user(sub)
    if cached_user:
        if cached_user.get("status") != "ACTIVE":
            return Response(status_code=403, headers={"X-ZTNA-Decision": "DENY", "X-ZTNA-Reason": "User inactive"})
        username = cached_user.get("username")
        email = cached_user.get("email")
        user_role = cached_user.get("role")
    else:
        # Fallback to DB and update local cache
        user = db.query(User).filter(User.id == uuid.UUID(sub)).first()
        if not user or user.account_status != AccountStatus.ACTIVE:
            return Response(status_code=403, headers={"X-ZTNA-Decision": "DENY", "X-ZTNA-Reason": "User inactive"})
        username = user.username
        email = user.email
        user_role = user.role.name if user.role else "user"
        set_cached_user(sub, {"username": username, "email": email, "role": user_role, "status": user.account_status.name})

    # 3. Check cached session trust score
    if cached_session and "trust_score" in cached_session:
        trust_score = float(cached_session["trust_score"])
    else:
        # Fallback to DB and update local cache
        user_session = db.query(UserSession).filter(UserSession.id == uuid.UUID(sid)).first()
        if user_session and user_session.status != SessionStatus.REVOKED:
            trust_score = float(user_session.current_trust_score)
            set_cached_session(sid, {"status": "ACTIVE", "trust_score": trust_score})
        else:
            set_cached_session(sid, {"status": "REVOKED"})
            return Response(status_code=403, headers={"X-ZTNA-Decision": "DENY", "X-ZTNA-Reason": "Session revoked or expired"})
    risk_level = "LOW" if trust_score >= 80 else ("MEDIUM" if trust_score >= 50 else "HIGH")

    # ⚡ [POMERIUM-STYLE ROUTE MICRO-SEGMENTATION EVALUATION]
    allowed, route_reason = route_policy_engine.evaluate_request(
        path=original_path,
        method=original_method,
        user_email=email,
        user_role=user_role,
        user_groups=[],
        device_approved=True,
        mfa_verified=True,
        trust_score=trust_score,
    )
    
    if not allowed:
        # 1. Record Audit Log for Policy Refusal
        AuditService.record(
            db,
            action="ROUTE_POLICY_VIOLATION",
            actor_id=uuid.UUID(sub) if sub else None,
            actor_label=username,
            resource_type="gateway_route",
            resource_id=original_path,
            ip_address=client_ip,
            payload={
                "path": original_path,
                "method": original_method,
                "user_role": user_role,
                "reason": route_reason,
                "trust_score": trust_score,
            },
        )

        # 2. Raise Security Alert on Dashboard
        alert_sev = AlertSeverity.CRITICAL if ("admin" in original_path or "export" in original_path) else AlertSeverity.HIGH
        alert = Alert(
            user_id=uuid.UUID(sub) if sub else None,
            session_id=uuid.UUID(sid) if sid else None,
            severity=alert_sev,
            status=AlertStatus.OPEN,
            category="policy_violation",
            title=f"Policy Violation: '{username}' ({user_role}) denied access to {original_path}",
            description=f"Zero Trust micro-segmentation block: {route_reason}",
            trust_score=trust_score,
            evidence={"ip": client_ip, "path": original_path, "role": user_role, "reason": route_reason},
        )
        db.add(alert)

        # 3. Update session metrics
        user_session = db.query(UserSession).filter(UserSession.id == uuid.UUID(sid)).first() if sid else None
        if user_session:
            user_session.denied_count += 1
            user_session.request_count += 1
            user_session.last_seen_at = utcnow()

        db.commit()

        # 4. Broadcast live WebSocket event
        publish_sync(Event(
            type="alert.created",
            payload={
                "id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity.value,
                "user": username,
                "path": original_path,
            }
        ))
        if sid:
            publish_sync(Event(
                type="session.score",
                payload={
                    "session_id": sid,
                    "user_id": sub,
                    "score": trust_score,
                    "risk_level": risk_level,
                    "action": "BLOCK",
                    "denied_count": user_session.denied_count if user_session else 1,
                }
            ))

        return Response(
            status_code=403,
            content=f"Forbidden: Micro-segmentation policy denied access - {route_reason}",
            headers={
                "X-ZTNA-Decision": "DENY",
                "X-ZTNA-Reason": route_reason,
                "X-ZTNA-Trust-Score": str(trust_score),
            },
        )

    # Update session activity on ALLOW
    user_session = db.query(UserSession).filter(UserSession.id == uuid.UUID(sid)).first() if sid else None
    if user_session:
        user_session.request_count += 1
        user_session.last_seen_at = utcnow()
        db.commit()
        publish_sync(Event(
            type="session.score",
            payload={
                "session_id": sid,
                "user_id": sub,
                "score": trust_score,
                "risk_level": risk_level,
                "action": "ALLOW",
                "request_count": user_session.request_count,
            }
        ))

    # Signature generation
    ts = str(int(time.time()))
    sig = generate_gateway_signature(username, user_role, trust_score, ts, settings.secret_key)

    # Envoy ext_authz headers returned to be added to upstream request
    envoy_response_headers = {
        "X-ZTNA-Decision": "ALLOW",
        "X-Forwarded-User": username,
        "X-Forwarded-Email": email,
        "X-Forwarded-Role": user_role,
        "X-ZTNA-Trust-Score": f"{trust_score:.2f}",
        "X-ZTNA-Risk-Level": risk_level,
        "X-Gateway-Timestamp": ts,
        "X-Gateway-Signature": sig,
    }

    return Response(
        status_code=200,
        content="",
        headers=envoy_response_headers,
    )


@router.get("/nginx/auth")
async def nginx_auth_request(request: Request, db: Session = Depends(get_db)):
    """NGINX auth_request subrequest verification endpoint."""
    raw_headers = {k.lower(): v for k, v in request.headers.items()}
    original_uri = raw_headers.get("x-original-uri", request.url.path)
    cookie_str = raw_headers.get("cookie", "")

    token = _extract_token_from_headers_or_cookies(raw_headers, cookie_str)
    if not token:
        return Response(status_code=401, headers={"X-ZTNA-Decision": "DENY"})

    try:
        claims = jwt_service.decode_token(token, expected_type="access")
    except Exception:
        return Response(status_code=401, headers={"X-ZTNA-Decision": "DENY"})

    user = db.query(User).filter(User.id == uuid.UUID(claims.get("sub"))).first()
    if not user or user.account_status != AccountStatus.ACTIVE:
        return Response(status_code=403, headers={"X-ZTNA-Decision": "DENY"})

    user_role = user.role.name if user.role else "user"
    user_session = db.query(UserSession).filter(UserSession.id == uuid.UUID(claims.get("sid"))).first()
    trust_score = float(user_session.current_trust_score) if user_session else 85.0

    if trust_score < 30.0:
        return Response(status_code=403, headers={"X-ZTNA-Decision": "DENY"})

    ts = str(int(time.time()))
    sig = generate_gateway_signature(user.username, user_role, trust_score, ts, settings.secret_key)

    return Response(
        status_code=200,
        headers={
            "X-Forwarded-User": user.username,
            "X-Forwarded-Email": user.email,
            "X-Forwarded-Role": user_role,
            "X-ZTNA-Trust-Score": f"{trust_score:.2f}",
            "X-Gateway-Timestamp": ts,
            "X-Gateway-Signature": sig,
        },
    )


class KongVerifyRequest(BaseModel):
    token: Optional[str] = Field(None, description="Bearer token or cookie")
    client_ip: str = Field(default="127.0.0.1")
    path: str = Field(default="/")
    method: str = Field(default="GET")
    min_trust_score: float = Field(default=30.0)


@router.post("/kong/verify")
async def kong_plugin_verify(payload: KongVerifyRequest, db: Session = Depends(get_db)):
    """Kong custom plugin HTTP callback endpoint."""
    if not payload.token:
        return JSONResponse(
            status_code=401,
            content={"allow": False, "reason": "Missing token", "status_code": 401},
        )

    try:
        claims = jwt_service.decode_token(payload.token, expected_type="access")
    except Exception:
        return JSONResponse(
            status_code=401,
            content={"allow": False, "reason": "Invalid token", "status_code": 401},
        )

    user = db.query(User).filter(User.id == uuid.UUID(claims.get("sub"))).first()
    if not user or user.account_status != AccountStatus.ACTIVE:
        return JSONResponse(
            status_code=403,
            content={"allow": False, "reason": "User inactive", "status_code": 403},
        )

    user_role = user.role.name if user.role else "user"
    user_session = db.query(UserSession).filter(UserSession.id == uuid.UUID(claims.get("sid"))).first()
    trust_score = float(user_session.current_trust_score) if user_session else 85.0

    if trust_score < payload.min_trust_score:
        return JSONResponse(
            status_code=403,
            content={
                "allow": False,
                "reason": "Trust score degraded",
                "trust_score": trust_score,
                "status_code": 403,
            },
        )

    ts = str(int(time.time()))
    sig = generate_gateway_signature(user.username, user_role, trust_score, ts, settings.secret_key)

    return JSONResponse(
        status_code=200,
        content={
            "allow": True,
            "headers": {
                "X-Forwarded-User": user.username,
                "X-Forwarded-Email": user.email,
                "X-Forwarded-Role": user_role,
                "X-ZTNA-Trust-Score": f"{trust_score:.2f}",
                "X-Gateway-Timestamp": ts,
                "X-Gateway-Signature": sig,
            },
        },
    )


@router.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """Serve the public JWKS for verifying X-Vajra-Jwt-Assertion tokens."""
    return JSONResponse(content=get_jwks())
