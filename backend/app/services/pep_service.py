"""Policy Enforcement Point (PEP) Reverse Proxy Gateway Service."""

from __future__ import annotations

import logging
import time
import uuid

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.context import ContextBundle
from app.core.request_signing import sign_gateway_request
from app.middleware.context import DEVICE_FINGERPRINT_HEADER, client_ip
from app.services.pdp_service import PDPService

logger = logging.getLogger(__name__)

# Hop-by-hop headers according to RFC 7230 §6.1 must be stripped
HOP_BY_HOP = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
})


def _extract_bearer(request: Request) -> str | None:
    auth_hdr = request.headers.get("Authorization", "")
    if auth_hdr.lower().startswith("bearer "):
        return auth_hdr[7:].strip()
    return None


class PEPService:
    @classmethod
    async def enforce_and_proxy(
        cls,
        request: Request,
        resource_slug: str,
        subpath: str,
        db: Session,
        bundle: ContextBundle,
    ) -> Response:
        """Enforce PDP authorization and asynchronously proxy allowed requests to upstream."""
        started = time.perf_counter()
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
        full_path = f"/proxy/{resource_slug}/{subpath.lstrip('/')}"
        token = _extract_bearer(request)
        fingerprint = request.headers.get(DEVICE_FINGERPRINT_HEADER)
        ip = client_ip(request)

        # 1. Query the Policy Decision Point (PDP)
        decision = PDPService.authorize(
            db,
            request_id=request_id,
            method=request.method,
            path=full_path,
            source_ip=ip,
            access_token=token,
            device_fingerprint=fingerprint,
            bundle=bundle,
        )

        headers = {
            "X-Request-ID": request_id,
            "X-ZTNA-Decision": decision.decision,
            "X-ZTNA-Trust-Score": str(round(decision.trust_score, 1)),
        }
        if decision.matched_policy:
            headers["X-ZTNA-Policy"] = decision.matched_policy

        # 2. Denied requests: return 401/403 refusal
        if not decision.allowed:
            status_code = 401 if decision.username == "anonymous" else 403
            return JSONResponse(
                status_code=status_code,
                content={
                    "detail": "Access denied by Zero Trust policy",
                    "code": "access_denied",
                    "reason": decision.reason,
                    "resource": decision.resource,
                    "trust_score": decision.trust_score,
                    "action": decision.action,
                    "request_id": request_id,
                },
                headers=headers,
            )

        # 3. Allowed request with no upstream configured: return confirmed PEP decision
        if not decision.upstream_url:
            elapsed_ms = (time.perf_counter() - started) * 1000
            headers["X-Response-Time-ms"] = f"{elapsed_ms:.1f}"
            return JSONResponse(
                status_code=200,
                content={
                    "status": "authorized",
                    "message": f"Access to '{decision.resource}' granted by Zero Trust PEP gateway",
                    "decision": decision.decision,
                    "user": decision.username,
                    "role": decision.role,
                    "trust_score": decision.trust_score,
                    "path": full_path,
                },
                headers=headers,
            )

        # 4. Allowed request with upstream service: sign and proxy
        upstream_target = f"{decision.upstream_url.rstrip('/')}{decision.upstream_path or ''}"
        signing_secret = settings.gateway_signing_key or settings.secret_key
        sig, ts = sign_gateway_request(request.method, decision.upstream_path or "/", signing_secret)

        forward_headers = {
            k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP
        }
        forward_headers.update({
            "X-Gateway-Signature": sig,
            "X-Gateway-Timestamp": ts,
            "X-ZTNA-User": decision.username,
            "X-ZTNA-Role": decision.role,
            "X-ZTNA-Trust-Score": str(decision.trust_score),
            "X-Request-ID": request_id,
        })
        forward_headers.pop("authorization", None)

        body_bytes = await request.body()

        try:
            async with httpx.AsyncClient(timeout=settings.upstream_timeout_seconds) as client:
                upstream_resp = await client.request(
                    method=request.method,
                    url=upstream_target,
                    content=body_bytes or None,
                    headers=forward_headers,
                    params=dict(request.query_params),
                )
        except Exception as exc:
            logger.error("PEP upstream %s unreachable: %s", upstream_target, exc)
            return JSONResponse(
                status_code=502,
                content={
                    "detail": "Upstream internal service unavailable",
                    "upstream_url": upstream_target,
                    "request_id": request_id,
                },
                headers=headers,
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        headers["X-Response-Time-ms"] = f"{elapsed_ms:.1f}"

        resp_headers = {
            k: v for k, v in upstream_resp.headers.items() if k.lower() not in HOP_BY_HOP
        }
        resp_headers.update(headers)

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )
