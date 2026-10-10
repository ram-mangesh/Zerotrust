import json
import time
import uuid
from typing import Dict, Any
from jwcrypto import jwk, jwt

# Singleton key management for Identity Assertions
_KID = "vajranetra-assertion-key-2026"
_JWK_CACHE = None

def get_or_create_assertion_key() -> jwk.JWK:
    """Generate or retrieve a shared EC P-256 key for JWT assertions."""
    global _JWK_CACHE
    if _JWK_CACHE is None:
        # In a real cluster environment, this would be loaded from a secure vault or shared DB.
        # For this deployment, we generate it on startup.
        key = jwk.JWK.generate(kty='EC', crv='P-256', kid=_KID)
        _JWK_CACHE = key
    return _JWK_CACHE

def get_jwks() -> Dict[str, Any]:
    """Return the public JWKS representation for downstream applications to verify tokens."""
    key = get_or_create_assertion_key()
    return {"keys": [key.export_public(as_dict=True)]}

def create_identity_assertion(
    user_id: str,
    username: str,
    email: str,
    role: str,
    groups: list,
    trust_score: float,
    audience: str = "vajranetra.local"
) -> str:
    """Create a standard signed JWT asserting the user's identity (like Pomerium's X-Pomerium-Jwt-Assertion)."""
    key = get_or_create_assertion_key()
    
    now = int(time.time())
    header = {
        "alg": "ES256",
        "kid": _KID,
        "typ": "JWT"
    }
    
    payload = {
        "iss": "vajranetra.local",
        "aud": audience,
        "exp": now + 300, # 5 min validity for assertions
        "iat": now,
        "jti": str(uuid.uuid4()),
        "sub": user_id,
        "user": username,
        "email": email,
        "name": username, 
        "groups": groups,
        "role": role,
        "trust_score": trust_score
    }
    
    token = jwt.JWT(header=header, claims=payload)
    token.make_signed_token(key)
    return token.serialize()
