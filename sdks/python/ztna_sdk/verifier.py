"""Cryptographic gateway signature verification and context extraction."""

from __future__ import annotations

import hmac
import hashlib
import time
from dataclasses import dataclass
from typing import Mapping, Optional


class ZTNAMissingHeaderError(Exception):
    """Raised when mandatory gateway headers are missing."""
    pass


class ZTNAMisconfigurationError(Exception):
    """Raised when signature secret or configuration is invalid."""
    pass


class ZTNASignatureInvalidError(Exception):
    """Raised when HMAC signature verification fails or timestamp expired."""
    pass


@dataclass
class ZTNAContext:
    user_id: str
    email: str
    role: str
    trust_score: float
    risk_level: str
    timestamp: int
    request_id: Optional[str] = None


class ZTNAGatewayVerifier:
    """Verifies that an incoming HTTP request originated from an authentic VajraNetra ZTNA gateway."""

    def __init__(self, secret_key: str, max_age_seconds: int = 60, min_trust_score: float = 0.0):
        if not secret_key:
            raise ZTNAMisconfigurationError("secret_key must not be empty")
        self.secret_key = secret_key.encode("utf-8")
        self.max_age_seconds = max_age_seconds
        self.min_trust_score = min_trust_score

    def verify_headers(self, headers: Mapping[str, str]) -> ZTNAContext:
        """Verify headers and extract validated ZTNAContext.

        Raises:
            ZTNAMissingHeaderError: If required headers are missing.
            ZTNASignatureInvalidError: If signature is forged or timestamp is out of range.
        """
        # Case-insensitive lookup
        h = {k.lower(): v for k, v in headers.items()}

        user_id = h.get("x-forwarded-user")
        email = h.get("x-forwarded-email", "")
        role = h.get("x-forwarded-role", "guest")
        trust_str = h.get("x-ztna-trust-score")
        risk_level = h.get("x-ztna-risk-level", "LOW")
        sig = h.get("x-gateway-signature")
        ts_str = h.get("x-gateway-timestamp")
        request_id = h.get("x-request-id")

        if not user_id or not sig or not ts_str or not trust_str:
            raise ZTNAMissingHeaderError("Missing required ZTNA gateway headers")

        try:
            ts = int(ts_str)
            trust_score = float(trust_str)
        except ValueError:
            raise ZTNASignatureInvalidError("Malformed timestamp or trust score header")

        # Anti-replay / clock drift check
        if abs(int(time.time()) - ts) > self.max_age_seconds:
            raise ZTNASignatureInvalidError(f"Gateway signature expired (timestamp delta > {self.max_age_seconds}s)")

        # Verify HMAC signature
        payload = f"{user_id}:{role}:{trust_score:.2f}:{ts_str}".encode("utf-8")
        expected_sig = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, sig):
            raise ZTNASignatureInvalidError("Invalid gateway HMAC signature: request forged or modified in transit")

        if trust_score < self.min_trust_score:
            raise ZTNASignatureInvalidError(f"Trust score ({trust_score}) below required threshold ({self.min_trust_score})")

        return ZTNAContext(
            user_id=user_id,
            email=email,
            role=role,
            trust_score=trust_score,
            risk_level=risk_level,
            timestamp=ts,
            request_id=request_id,
        )
