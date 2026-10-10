"""Flask middleware and decorators for VajraNetra ZTNA SDK."""

from __future__ import annotations

from functools import wraps
from typing import Callable, Optional
from .verifier import ZTNAGatewayVerifier, ZTNAMissingHeaderError, ZTNASignatureInvalidError


def init_flask_ztna(app, secret_key: str, max_age_seconds: int = 60, min_trust_score: float = 0.0):
    """Register ZTNA gateway verifier hook into Flask application."""
    verifier = ZTNAGatewayVerifier(secret_key=secret_key, max_age_seconds=max_age_seconds, min_trust_score=min_trust_score)

    try:
        from flask import request, g, jsonify
    except ImportError:
        raise ImportError("Flask is required to use init_flask_ztna")

    @app.before_request
    def ztna_before_request():
        try:
            ctx = verifier.verify_headers(request.headers)
            g.ztna = ctx
            g.user_id = ctx.user_id
            g.user_role = ctx.role
            g.trust_score = ctx.trust_score
        except (ZTNAMissingHeaderError, ZTNASignatureInvalidError) as exc:
            g.ztna = None


def require_ztna_role(required_role: str):
    """Flask endpoint decorator ensuring minimum role standing."""
    from flask import g, jsonify

    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not getattr(g, "ztna", None) or g.ztna.role != required_role:
                return jsonify({"error": "forbidden", "detail": f"Role '{required_role}' required"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
