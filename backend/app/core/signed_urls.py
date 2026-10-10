"""Cryptographically signed URL generator and verifier for CSRF / redirect protection.

Modeled after Pomerium's signed redirect & sign-out URL state pattern.
Guarantees integrity, expiration checks, and actor identity bound into the signature.
"""

from __future__ import annotations

import hmac
import hashlib
import time
import urllib.parse
from typing import Optional, Dict, Any, Tuple
from app.core.config import settings

def sign_redirect_url(
    base_url: str,
    action: str,
    session_id: str,
    ttl_seconds: int = 300,
    secret_key: Optional[str] = None
) -> str:
    """Generate an HMAC-SHA256 signed redirect / callback URL.
    
    Includes:
    - vajra_action: string identifier (e.g., 'sign_out', 'auth_callback')
    - vajra_sid: session identifier
    - vajra_issued: unix timestamp of creation
    - vajra_expiry: unix timestamp of expiration
    - vajra_signature: hex HMAC-SHA256 digest
    """
    key = (secret_key or settings.secret_key).encode("utf-8")
    now = int(time.time())
    expiry = now + ttl_seconds
    
    params = {
        "vajra_action": action,
        "vajra_sid": session_id,
        "vajra_issued": str(now),
        "vajra_expiry": str(expiry)
    }
    
    # Message format: "action|session_id|issued|expiry"
    msg = f"{action}|{session_id}|{now}|{expiry}".encode("utf-8")
    sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
    params["vajra_signature"] = sig
    
    query = urllib.parse.urlencode(params)
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}{query}"


def verify_signed_url_params(
    params: Dict[str, str],
    expected_action: Optional[str] = None,
    secret_key: Optional[str] = None
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Verify HMAC signature and freshness of URL parameters.
    
    Returns: (is_valid, session_id, error_reason)
    """
    action = params.get("vajra_action")
    sid = params.get("vajra_sid")
    issued_str = params.get("vajra_issued")
    expiry_str = params.get("vajra_expiry")
    sig = params.get("vajra_signature")
    
    if not all([action, sid, issued_str, expiry_str, sig]):
        return False, None, "Missing cryptographic signature parameters."
        
    if expected_action and action != expected_action:
        return False, None, f"Action mismatch. Expected {expected_action}, got {action}."
        
    try:
        expiry = int(expiry_str)
    except ValueError:
        return False, None, "Invalid expiry timestamp format."
        
    now = int(time.time())
    if now > expiry:
        return False, None, "Signed URL has expired."
        
    key = (secret_key or settings.secret_key).encode("utf-8")
    msg = f"{action}|{sid}|{issued_str}|{expiry_str}".encode("utf-8")
    expected_sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(sig, expected_sig):
        return False, None, "Invalid cryptographic HMAC signature."
        
    return True, sid, None
