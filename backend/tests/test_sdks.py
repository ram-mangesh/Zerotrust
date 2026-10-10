"""Tests for VajraNetra Zero Trust SDKs."""

import time
import hmac
import hashlib
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

import sys
sys.path.insert(0, "/tmp/ztna/main/sdks/python")

from ztna_sdk.verifier import (
    ZTNAGatewayVerifier,
    ZTNAMissingHeaderError,
    ZTNASignatureInvalidError,
)
from ztna_sdk.fastapi_middleware import ZTNAMiddleware


def _make_headers(secret: str, user="alice", role="admin", trust=95.0, delta_ts=0):
    ts = str(int(time.time()) + delta_ts)
    payload = f"{user}:{role}:{trust:.2f}:{ts}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return {
        "X-Forwarded-User": user,
        "X-Forwarded-Email": f"{user}@example.com",
        "X-Forwarded-Role": role,
        "X-ZTNA-Trust-Score": f"{trust:.2f}",
        "X-ZTNA-Risk-Level": "LOW",
        "X-Gateway-Timestamp": ts,
        "X-Gateway-Signature": sig,
        "X-Request-ID": "req-12345",
    }


def test_python_sdk_verifier_success():
    secret = "super-secret-key-123"
    verifier = ZTNAGatewayVerifier(secret_key=secret)
    headers = _make_headers(secret, user="bob", role="user", trust=82.5)

    ctx = verifier.verify_headers(headers)
    assert ctx.user_id == "bob"
    assert ctx.role == "user"
    assert ctx.trust_score == 82.5
    assert ctx.request_id == "req-12345"


def test_python_sdk_missing_header_fails():
    verifier = ZTNAGatewayVerifier(secret_key="secret")
    with pytest.raises(ZTNAMissingHeaderError):
        verifier.verify_headers({"X-Forwarded-User": "bob"})


def test_python_sdk_forged_sig_fails():
    secret = "correct-secret"
    verifier = ZTNAGatewayVerifier(secret_key=secret)
    headers = _make_headers("wrong-secret", user="bob")
    with pytest.raises(ZTNASignatureInvalidError):
        verifier.verify_headers(headers)


def test_python_sdk_expired_timestamp_fails():
    secret = "correct-secret"
    verifier = ZTNAGatewayVerifier(secret_key=secret, max_age_seconds=30)
    headers = _make_headers(secret, delta_ts=-100)
    with pytest.raises(ZTNASignatureInvalidError):
        verifier.verify_headers(headers)


def test_fastapi_sdk_middleware_integration():
    secret = "integration-secret"

    async def endpoint(request):
        ctx = getattr(request.state, "ztna", None)
        return JSONResponse({"user": ctx.user_id if ctx else None, "role": ctx.role if ctx else None})

    app = Starlette(routes=[Route("/test", endpoint, methods=["GET"])])
    app.add_middleware(ZTNAMiddleware, secret_key=secret, enforce=True)

    client = TestClient(app)

    # 1. Unauthenticated / No headers -> 403
    res_unauth = client.get("/test")
    assert res_unauth.status_code == 403

    # 2. Valid headers -> 200 + context available
    headers = _make_headers(secret, user="carol", role="security_analyst", trust=91.0)
    res_auth = client.get("/test", headers=headers)
    assert res_auth.status_code == 200
    assert res_auth.json() == {"user": "carol", "role": "security_analyst"}
