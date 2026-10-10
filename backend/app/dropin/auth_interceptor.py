"""Authentication and authorization interceptor for Drop-In Zero Trust Proxy."""

from __future__ import annotations

from typing import Optional, Tuple
from fastapi import Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import jwt
from jwt import InvalidTokenError

from app.core.config import settings
from app.dropin.config import DropInProxyConfig, RouteRule


def match_route_rule(path: str, config: DropInProxyConfig) -> RouteRule:
    """Find the most specific route rule matching the path prefix."""
    best_match: Optional[RouteRule] = None
    best_len = -1
    for rule in config.rules:
        if path.startswith(rule.path_prefix) and len(rule.path_prefix) > best_len:
            best_match = rule
            best_len = len(rule.path_prefix)
    return best_match or config.rules[-1]


def extract_token(request: Request) -> Optional[str]:
    """Extract JWT from Authorization header or ztna_session cookie."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return request.cookies.get("ztna_session")


def decode_jwt_token(token: str) -> Optional[dict]:
    """Decode and validate ZTNA JWT token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except InvalidTokenError:
        return None


def get_login_page_html(return_to: str = "/") -> str:
    """Return sleek dark-mode perimeter authentication page for browser navigation."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VajraNetra Zero Trust Gateway Authentication</title>
    <style>
        :root {{
            --bg: #090d16;
            --card: #111827;
            --border: #1f2937;
            --text: #f9fafb;
            --text-dim: #9ca3af;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --danger: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{
            background: var(--bg);
            color: var(--text);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 1.5rem;
        }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2.5rem;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        }}
        .logo {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }}
        .sub {{
            color: var(--text-dim);
            font-size: 0.875rem;
            margin-bottom: 1.5rem;
        }}
        .form-group {{
            margin-bottom: 1.25rem;
        }}
        label {{
            display: block;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 0.375rem;
        }}
        input {{
            width: 100%;
            padding: 0.75rem 1rem;
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 6px;
            color: #fff;
            font-size: 0.95rem;
        }}
        input:focus {{
            outline: none;
            border-color: var(--primary);
        }}
        button {{
            width: 100%;
            padding: 0.75rem;
            background: var(--primary);
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.15s ease;
        }}
        button:hover {{
            background: var(--primary-hover);
        }}
        .badge {{
            display: inline-block;
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            font-size: 0.75rem;
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            margin-bottom: 1rem;
            font-family: monospace;
        }}
        #error-msg {{
            color: var(--danger);
            font-size: 0.875rem;
            margin-top: 1rem;
            display: none;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">ZERO TRUST DROP-IN GATEWAY</div>
        <div class="logo">🛡️ VajraNetra ZTNA</div>
        <p class="sub">Continuous Verification & Adaptive Access Control</p>

        <form id="login-form">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" required autocomplete="username" placeholder="user@securecorp.local">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="••••••••">
            </div>
            <button type="submit" id="submit-btn">Authenticate & Verify</button>
            <p id="error-msg"></p>
        </form>
    </div>

    <script src="/__ztna/ztna-sdk.js"></script>
    <script>
        const form = document.getElementById('login-form');
        const errorMsg = document.getElementById('error-msg');
        const submitBtn = document.getElementById('submit-btn');

        form.addEventListener('submit', async (e) => {{
            e.preventDefault();
            errorMsg.style.display = 'none';
            submitBtn.disabled = true;
            submitBtn.textContent = 'Verifying Device & Identity...';

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {{
                const res = await fetch('/__ztna/auth', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ username, password }})
                }});
                const data = await res.json();
                if (!res.ok) {{
                    throw new Error(data.detail || data.error || 'Authentication failed');
                }}
                // Successfully authenticated, navigate to target
                window.location.href = '{return_to}';
            }} catch (err) {{
                errorMsg.textContent = err.message;
                errorMsg.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.textContent = 'Authenticate & Verify';
            }}
        }});
    </script>
</body>
</html>
"""


def enforce_perimeter_auth(
    request: Request,
    config: DropInProxyConfig,
) -> Tuple[bool, Optional[Response], Optional[dict]]:
    """Enforce zero-trust perimeter auth, returning (allowed, immediate_response, user_claims)."""
    path = request.url.path

    # Allow public endpoints
    if any(path == pub or path.startswith(pub + "/") for pub in config.public_paths):
        return True, None, None

    token = extract_token(request)
    if not token:
        # Check if browser navigation
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return False, HTMLResponse(get_login_page_html(return_to=request.url.path)), None
        return False, JSONResponse(
            status_code=401,
            content={"error": "unauthenticated", "detail": "ZTNA session token missing or expired", "login_url": "/__ztna/login"}
        ), None

    claims = decode_jwt_token(token)
    if not claims:
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return False, HTMLResponse(get_login_page_html(return_to=request.url.path)), None
        return False, JSONResponse(
            status_code=401,
            content={"error": "invalid_token", "detail": "Invalid or expired ZTNA cryptographic token", "login_url": "/__ztna/login"}
        ), None

    # Check route rule policies
    rule = match_route_rule(path, config)
    user_role = claims.get("role", "user")

    if rule.allowed_roles and user_role not in rule.allowed_roles:
        return False, JSONResponse(
            status_code=403,
            content={"error": "forbidden", "detail": f"Role '{user_role}' not authorized for resource '{path}'"}
        ), claims

    # Trust score threshold check if present in claims
    trust_score = float(claims.get("trust_score", 100.0))
    if trust_score < rule.min_trust_score:
        return False, JSONResponse(
            status_code=403,
            content={
                "error": "trust_degraded",
                "detail": f"Access denied: current trust score ({trust_score:.1f}) is below minimum requirement ({rule.min_trust_score:.1f})",
                "current_trust": trust_score,
                "required_trust": rule.min_trust_score,
            }
        ), claims

    return True, None, claims
