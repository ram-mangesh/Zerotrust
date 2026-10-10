"""Header transformer for Zero Trust Drop-in Reverse Proxy.

Strips client-spoofed internal headers and hop-by-hop headers,
then injects validated identity, trust scores, and cryptographic HMAC signatures.
"""

from __future__ import annotations

import hmac
import hashlib
import time
from typing import Mapping, Dict, Tuple
from app.core.config import settings
from app.core.jwt_assertion import create_identity_assertion

HOP_BY_HOP_HEADERS = {
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
}

SPOOFABLE_INTERNAL_HEADERS = {
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-role",
    "x-ztna-trust-score",
    "x-ztna-risk-level",
    "x-gateway-signature",
    "x-gateway-timestamp",
    "x-vajra-jwt-assertion",
}


def sanitize_incoming_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    """Sanitize incoming headers from client, stripping hop-by-hop and internal spoof headers."""
    clean: Dict[str, str] = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in HOP_BY_HOP_HEADERS or k_lower in SPOOFABLE_INTERNAL_HEADERS:
            continue
        clean[k] = v
    return clean


def generate_gateway_signature(
    user_id: str,
    role: str,
    trust_score: float,
    timestamp: str,
    secret_key: str | None = None,
) -> str:
    """Generate HMAC-SHA256 signature asserting authenticated gateway origin."""
    key = (secret_key or settings.secret_key).encode()
    payload = f"{user_id}:{role}:{trust_score:.2f}:{timestamp}".encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def build_upstream_headers(
    sanitized_headers: Mapping[str, str],
    user_id: str,
    email: str,
    role: str,
    trust_score: float,
    risk_level: str,
    request_id: str,
    secret_key: str | None = None,
) -> Dict[str, str]:
    """Inject verified identity, risk posture, and cryptographic origin signature."""
    headers = dict(sanitized_headers)
    ts = str(int(time.time()))
    sig = generate_gateway_signature(user_id, role, trust_score, ts, secret_key)

    headers["X-Forwarded-User"] = user_id
    headers["X-Forwarded-Email"] = email
    headers["X-Forwarded-Role"] = role
    headers["X-ZTNA-Trust-Score"] = f"{trust_score:.2f}"
    headers["X-ZTNA-Risk-Level"] = risk_level
    headers["X-Gateway-Timestamp"] = ts
    headers["X-Gateway-Signature"] = sig
    headers["X-Request-ID"] = request_id
    
    # ⚡ Standardized Pomerium-like Identity Assertion (ES256)
    try:
        headers["X-Vajra-Jwt-Assertion"] = create_identity_assertion(
            user_id=user_id,
            username=user_id,
            email=email,
            role=role,
            groups=[],
            trust_score=trust_score,
            audience="dropin.upstream.local"
        )
    except Exception:
        pass

    return headers
