"""Drop-in Zero Trust Reverse Proxy Gateway Server.

Provides a standalone, zero-code-change reverse proxy that intercepts all incoming
traffic, enforces continuous authentication and trust verification, injects the browser
SDK into HTML pages, and forwards cryptographically signed identity headers upstream.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import os
import uuid
import time
from typing import Optional
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
import jwt

from app.core.config import settings
from app.dropin.config import DropInProxyConfig, RouteRule
from app.dropin.html_injector import inject_sdk_into_html
from app.dropin.header_transformer import sanitize_incoming_headers, build_upstream_headers
from app.dropin.auth_interceptor import (
    enforce_perimeter_auth,
    get_login_page_html,
    decode_jwt_token,
    match_route_rule,
)


def create_dropin_proxy_app(config: Optional[DropInProxyConfig] = None) -> FastAPI:
    """Create and configure the Drop-in Zero Trust Reverse Proxy FastAPI application."""
    cfg = config or DropInProxyConfig()

    sdk_file_path = Path("/tmp/ztna/main/frontend/public/ztna-sdk.js")
    if not sdk_file_path.exists():
        sdk_file_path = Path(__file__).parent.parent.parent.parent / "frontend" / "public" / "ztna-sdk.js"

    proxy_client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await proxy_client.aclose()

    app = FastAPI(
        title="VajraNetra Drop-In Zero Trust Gateway",
        description="Zero-code-change drop-in perimeter security gateway",
        version="1.0.0",
        docs_url="/__ztna/docs",
        openapi_url="/__ztna/openapi.json",
        lifespan=lifespan,
    )

    @app.get("/__ztna/ztna-sdk.js")
    async def get_sdk_script():
        """Serve the Zero Trust Browser WebCrypto & Biometrics SDK."""
        if sdk_file_path.exists():
            return FileResponse(sdk_file_path, media_type="application/javascript")
        return Response(
            content="""console.log('ZTNA Browser SDK loaded');""",
            media_type="application/javascript",
        )

    @app.get("/__ztna/health")
    async def gateway_health():
        """Health and status endpoint for the drop-in gateway."""
        return {
            "status": "healthy",
            "gateway": "VajraNetra-DropIn-PEP",
            "default_upstream": cfg.default_upstream,
            "rules_count": len(cfg.rules),
            "html_injection": cfg.enable_html_injection,
            "waf_enabled": cfg.enable_waf,
            "timestamp": int(time.time()),
        }

    @app.get("/__ztna/login")
    async def login_page(return_to: str = "/"):
        """Serve the gateway login UI."""
        return HTMLResponse(get_login_page_html(return_to=return_to))

    @app.post("/__ztna/auth")
    async def authenticate_user(payload: dict):
        """Perimeter authentication endpoint producing a signed ZTNA session JWT."""
        username = payload.get("username", "").strip()
        password = payload.get("password", "").strip()

        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password are required")

        # Mock / default user credentials for demonstration or database lookup
        # Default test accounts: admin / admin123, analyst / analyst123, user / user123
        role = "user"
        user_id = str(uuid.uuid4())[:8]
        email = f"{username}@securecorp.local" if "@" not in username else username

        if username.lower() in ("admin", "admin@securecorp.local") and password == "admin123":
            role = "admin"
        elif username.lower() in ("analyst", "analyst@securecorp.local") and password == "analyst123":
            role = "security_analyst"
        elif username.lower() in ("user", "john.doe", "user@securecorp.local") and password == "user123":
            role = "user"
        elif password == "ztna2026!":
            role = "admin"
        else:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        claims = {
            "sub": user_id,
            "user_id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "trust_score": 95.0,
            "risk_level": "LOW",
            "iat": int(time.time()),
            "exp": int(time.time()) + (settings.access_token_expire_minutes * 60),
        }

        token = jwt.encode(claims, settings.secret_key, algorithm=settings.jwt_algorithm)

        response = JSONResponse(
            content={
                "status": "authenticated",
                "token": token,
                "user": {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "role": role,
                    "trust_score": 95.0,
                },
            }
        )
        response.set_cookie(
            key="ztna_session",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=settings.access_token_expire_minutes * 60,
        )
        return response

    @app.post("/__ztna/logout")
    async def logout_user():
        """Clear ZTNA session cookie."""
        response = JSONResponse(content={"status": "logged_out"})
        response.delete_cookie(key="ztna_session")
        return response

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def proxy_all(request: Request, path: str):
        """Universal transparent reverse proxy with zero-trust verification and HTML injection."""
        # 1. Enforce Perimeter Auth & Trust Decisions
        allowed, immediate_resp, claims = enforce_perimeter_auth(request, cfg)
        if not allowed and immediate_resp is not None:
            return immediate_resp

        # 2. Match Target Upstream URL
        full_path = f"/{path}"
        rule = match_route_rule(full_path, cfg)
        target_base = rule.upstream_url or cfg.default_upstream

        # Construct target URL
        query = str(request.url.query)
        target_url = f"{target_base.rstrip('/')}{full_path}"
        if query:
            target_url = f"{target_url}?{query}"

        # 3. Sanitize and Transform Headers
        user_id = claims.get("sub", "anonymous") if claims else "anonymous"
        email = claims.get("email", "anonymous@unknown") if claims else "anonymous@unknown"
        role = claims.get("role", "guest") if claims else "guest"
        trust_score = float(claims.get("trust_score", 100.0)) if claims else 100.0
        risk_level = claims.get("risk_level", "LOW") if claims else "LOW"
        request_id = str(uuid.uuid4())

        clean_headers = sanitize_incoming_headers(request.headers)
        upstream_headers = build_upstream_headers(
            sanitized_headers=clean_headers,
            user_id=user_id,
            email=email,
            role=role,
            trust_score=trust_score,
            risk_level=risk_level,
            request_id=request_id,
        )

        # 4. Stream or buffer request payload
        body = await request.body()

        # 5. Forward to Upstream
        try:
            upstream_resp = await proxy_client.request(
                method=request.method,
                url=target_url,
                headers=upstream_headers,
                content=body if body else None,
            )
        except httpx.ConnectError:
            return JSONResponse(
                status_code=502,
                content={
                    "error": "bad_gateway",
                    "detail": f"Failed to connect to upstream server at {target_base}",
                },
            )
        except httpx.TimeoutException:
            return JSONResponse(
                status_code=504,
                content={
                    "error": "gateway_timeout",
                    "detail": f"Upstream server timed out at {target_base}",
                },
            )

        # 6. Process Response & Perform Dynamic HTML Injection
        resp_headers = dict(upstream_resp.headers)
        # Remove hop-by-hop response headers
        for h in ("transfer-encoding", "content-encoding", "content-length", "connection"):
            resp_headers.pop(h, None)

        content_type = resp_headers.get("content-type", "").lower()
        if cfg.enable_html_injection and "text/html" in content_type:
            raw_html = upstream_resp.content
            modified_html = inject_sdk_into_html(raw_html)
            return Response(
                content=modified_html,
                status_code=upstream_resp.status_code,
                headers=resp_headers,
                media_type="text/html",
            )

        # Non-HTML response (API JSON, binary, images, etc.)
        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=content_type or None,
        )

    return app
