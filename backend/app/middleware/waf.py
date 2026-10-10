"""Web Application Firewall (WAF) middleware.

Scans incoming request paths, query parameters, JSON bodies, and HTTP
headers for common attack patterns:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal / LFI
  - Command Injection

On match:
  - Logs a high-priority security Alert to the database
  - Returns HTTP 403 with detailed security headers
  - Automatically records threat frequency to trigger IP auto-blocking
"""

from __future__ import annotations

import logging
import re
from urllib.parse import unquote_plus

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.database import get_session_factory
from app.middleware.context import client_ip
from app.middleware.ip_blocker import auto_block_ip, record_waf_hit
from app.models.alert import Alert
from app.models.enums import AlertSeverity, AlertStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled threat signature regexes
# ---------------------------------------------------------------------------

_SQLI_PATTERNS = [
    r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
    r"delete\s+from|update\s+.*\s+set|exec\s*\(|execute\s*\(|"
    r"--\s|;\s*drop|;\s*delete|;\s*insert|;\s*update|"
    r"or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s+'|'\s*and\s+'|"
    r"benchmark\s*\(|sleep\s*\(|waitfor\s+delay|"
    r"information_schema|pg_sleep|xp_cmdshell)",
]

_XSS_PATTERNS = [
    r"(?i)(<script[\s>]|</script>|javascript\s*:|vbscript\s*:|"
    r"on\w+\s*=\s*[\"']?[^\"'>]*[\"']?\s*(?:>|/>)|"
    r"<\s*iframe|<\s*object|<\s*embed|<\s*svg\s+on|"
    r"document\.(cookie|write|location)|window\.(location|open)|"
    r"eval\s*\(|expression\s*\(|alert\s*\(|prompt\s*\(|confirm\s*\()",
]

_PATH_TRAVERSAL_PATTERNS = [
    r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e\.%2f|"
    r"/etc/passwd|/etc/shadow|/proc/self|\\windows\\system32)",
]

_CMD_INJECTION_PATTERNS = [
    r"(?i)([`|;&$]\s*(ls|cat|rm|mv|cp|chmod|chown|whoami|id|uname|wget|curl|nc|bash|sh|cmd|"
    r"powershell|python|perl|ruby|php)\s*|"
    r"\|\s*\w+|\bping\s+-[nc]\b|\bnslookup\b|\bdig\b|;\s*rm\s+-[rf])",
]

_ALL_PATTERNS: list[tuple[str, list[str]]] = [
    ("sql_injection", _SQLI_PATTERNS),
    ("xss", _XSS_PATTERNS),
    ("path_traversal", _PATH_TRAVERSAL_PATTERNS),
    ("command_injection", _CMD_INJECTION_PATTERNS),
]

_COMPILED: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile("|".join(patterns))) for name, patterns in _ALL_PATTERNS
]

RISK_SCORES: dict[str, float] = {
    "sql_injection": 0.90,
    "xss": 0.80,
    "path_traversal": 0.85,
    "command_injection": 0.95,
}

_EXEMPT_PREFIXES = (
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
    "/ready",
    "/favicon.ico",
)

_HEADERS_ALWAYS_SCANNED = (
    "user-agent",
    "referer",
    "x-forwarded-for",
    "cookie",
)


def _get_db_session(request: Request | None = None) -> Session:
    """Obtain a session from factory, respecting any app dependency overrides."""
    if request is not None and hasattr(request, "app"):
        factory_override = getattr(request.app, "dependency_overrides", {}).get(
            get_session_factory
        )
        if factory_override is not None:
            return factory_override()()
    return get_session_factory()()


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in _EXEMPT_PREFIXES)


def _detect_threat(text: str) -> str | None:
    """Return the threat type name if any pattern matches, else None."""
    for name, pattern in _COMPILED:
        if pattern.search(text):
            return name
    return None


def _log_waf_alert(
    threat_type: str,
    ip: str,
    endpoint: str,
    payload: str,
    risk_score: float,
    request: Request | None = None,
) -> None:
    """Persist an Alert row in the database for the blocked threat."""
    try:
        with _get_db_session(request) as db:
            alert = Alert(
                severity=AlertSeverity.CRITICAL if risk_score >= 0.90 else AlertSeverity.HIGH,
                status=AlertStatus.OPEN,
                category=f"waf_{threat_type}",
                title=f"WAF: {threat_type.replace('_', ' ').title()} Blocked",
                description=(
                    f"Web Application Firewall blocked an incoming {threat_type} "
                    f"payload from IP {ip} targeting {endpoint}."
                ),
                trust_score=round((1.0 - risk_score) * 100, 1),
                evidence={
                    "threat_type": threat_type,
                    "ip_address": ip,
                    "endpoint": endpoint,
                    "payload_sample": payload[:500],
                    "risk_score": risk_score,
                },
            )
            db.add(alert)
            db.commit()
    except Exception as exc:
        logger.warning("WAF: failed to write alert to database: %s", exc)


class WAFMiddleware(BaseHTTPMiddleware):
    """
    Web Application Firewall (WAF) inspects:
      1. URL path + query string
      2. Headers (User-Agent, Referer, X-Forwarded-For, Cookie)
      3. JSON request body
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if _is_exempt(path) or request.method == "OPTIONS":
            return await call_next(request)

        ip = client_ip(request)
        threat = None

        # ── 1. Check URL path + query string ─────────────────────────────────
        full_url = unquote_plus(str(request.url))
        threat = _detect_threat(full_url)

        # ── 2. Check HTTP headers ────────────────────────────────────────────
        if not threat:
            for header_name in _HEADERS_ALWAYS_SCANNED:
                header_value = request.headers.get(header_name, "")
                if header_value:
                    threat = _detect_threat(header_value)
                    if threat:
                        break

        # ── 3. Check JSON body ───────────────────────────────────────────────
        body_text = ""
        content_type = request.headers.get("content-type", "")
        if not threat and content_type.startswith("application/json"):
            try:
                body_bytes = await request.body()
                body_text = body_bytes.decode("utf-8", errors="replace")
                threat = _detect_threat(body_text)
            except Exception as exc:
                logger.warning(
                    "WAF could not inspect request body | ip=%s path=%s | %s",
                    ip,
                    path,
                    exc,
                )

        # ── Threat detected: block request ───────────────────────────────────
        if threat:
            score = RISK_SCORES.get(threat, 0.75)
            payload_sample = (full_url + " " + body_text)[:500]

            logger.warning(
                "WAF BLOCKED | threat=%s ip=%s path=%s score=%.2f",
                threat,
                ip,
                path,
                score,
            )

            # Log alert in DB
            _log_waf_alert(threat, ip, path, payload_sample, score, request=request)

            # Auto-block IPs with repeated attacks
            try:
                if record_waf_hit(ip):
                    auto_block_ip(
                        ip,
                        reason=f"WAF auto-block: {threat} triggered 5+ times in 120s",
                        request=request,
                    )
            except Exception as exc:
                logger.error("WAF auto-block check failed for ip=%s: %s", ip, exc)

            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Request blocked by Web Application Firewall policy.",
                    "code": "waf_blocked",
                    "threat_type": threat,
                    "risk_score": score,
                },
                headers={
                    "X-WAF-Blocked": threat,
                    "X-WAF-Risk-Score": str(score),
                },
            )

        return await call_next(request)
