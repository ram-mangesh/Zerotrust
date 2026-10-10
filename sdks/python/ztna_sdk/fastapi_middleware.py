"""FastAPI & Starlette middleware for VajraNetra ZTNA SDK."""

from __future__ import annotations

from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from .verifier import ZTNAGatewayVerifier, ZTNAMissingHeaderError, ZTNASignatureInvalidError


class ZTNAMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        secret_key: str,
        max_age_seconds: int = 60,
        min_trust_score: float = 0.0,
        enforce: bool = True,
    ):
        super().__init__(app)
        self.verifier = ZTNAGatewayVerifier(
            secret_key=secret_key,
            max_age_seconds=max_age_seconds,
            min_trust_score=min_trust_score,
        )
        self.enforce = enforce

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            ctx = self.verifier.verify_headers(request.headers)
            request.state.ztna = ctx
            request.state.user_id = ctx.user_id
            request.state.user_role = ctx.role
            request.state.trust_score = ctx.trust_score
        except (ZTNAMissingHeaderError, ZTNASignatureInvalidError) as exc:
            if self.enforce:
                return JSONResponse(
                    status_code=403,
                    content={"error": "ztna_verification_failed", "detail": str(exc)},
                )
            request.state.ztna = None

        return await call_next(request)
