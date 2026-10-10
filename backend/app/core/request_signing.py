"""Cryptographic HMAC-SHA256 request signing and verification for PEP/PDP gateways."""

from __future__ import annotations

import hashlib
import hmac
import time


def sign_gateway_request(method: str, path: str, secret: str) -> tuple[str, str]:
    """Generate a cryptographic HMAC-SHA256 signature and timestamp for a gateway request."""
    ts = str(int(time.time()))
    clean_path = "/" + path.lstrip("/")
    message = f"{method.upper()}:{clean_path}:{ts}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return signature, ts


def verify_gateway_signature(
    method: str,
    path: str,
    signature: str,
    timestamp: str,
    secret: str,
    max_age_seconds: int = 60,
) -> bool:
    """Verify that an incoming request carries a valid, non-expired gateway HMAC signature."""
    try:
        ts = int(timestamp)
        if abs(int(time.time()) - ts) > max_age_seconds:
            return False

        clean_path = "/" + path.lstrip("/")
        message = f"{method.upper()}:{clean_path}:{timestamp}".encode("utf-8")
        expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False
