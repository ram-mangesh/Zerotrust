"""Outermost IP blocklist middleware.

Checks every incoming request against the `blocked_ips` table.
If the source IP is actively blocked, returns 403 immediately —
before WAF, rate limiter, or any route handler runs.

An IP is auto-blocked when:
  - The WAF fires against it more than WAF_BLOCK_THRESHOLD times in
    WAF_BLOCK_WINDOW seconds.
  - An admin manually blocks it via the admin API.

Blocks can be time-limited (default: 1 hour) or permanent (blocked_until=None).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from datetime import timedelta
from threading import Lock

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.database import get_session_factory
from app.middleware.context import client_ip
from app.models.base import as_aware, utcnow
from app.models.blocked_ip import BlockedIP

logger = logging.getLogger(__name__)

# ── Auto-block configuration ─────────────────────────────────────────────────
WAF_BLOCK_THRESHOLD = 5       # WAF hits required in window to auto-block
WAF_BLOCK_WINDOW = 120        # seconds
AUTO_BLOCK_DURATION = 3600    # 1 hour in seconds

# ── In-memory WAF hit counters (fast, avoids DB round-trip per hit) ──────────
_waf_hits: dict[str, deque[float]] = defaultdict(deque)
_waf_lock = Lock()


def _get_db_session(request: Request | None = None) -> Session:
    """Obtain a session from factory, respecting any app dependency overrides."""
    if request is not None and hasattr(request, "app"):
        factory_override = getattr(request.app, "dependency_overrides", {}).get(
            get_session_factory
        )
        if factory_override is not None:
            return factory_override()()
    return get_session_factory()()


def record_waf_hit(ip: str) -> bool:
    """Record a WAF hit for this IP. Returns True if threshold exceeded."""
    now = time.monotonic()
    cutoff = now - WAF_BLOCK_WINDOW
    with _waf_lock:
        dq = _waf_hits[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        return len(dq) >= WAF_BLOCK_THRESHOLD


def clear_waf_hits(ip: str) -> None:
    """Clear recorded WAF hits for this IP."""
    with _waf_lock:
        _waf_hits.pop(ip, None)


def auto_block_ip(
    ip: str,
    reason: str,
    duration_seconds: int = AUTO_BLOCK_DURATION,
    request: Request | None = None,
) -> None:
    """Persist an automatic block for an IP after repeated security violations."""
    if ip in ("127.0.0.1", "::1", "localhost", "testclient"):
        logger.warning("Skipping auto-block for loopback/test IP %s", ip)
        return

    try:
        blocked_until = utcnow() + timedelta(seconds=duration_seconds)
        with _get_db_session(request) as db:
            existing = db.execute(
                select(BlockedIP).where(BlockedIP.ip_address == ip)
            ).scalar_one_or_none()

            if existing:
                existing.blocked_until = blocked_until
                existing.reason = reason
            else:
                db.add(
                    BlockedIP(
                        ip_address=ip,
                        reason=reason,
                        blocked_until=blocked_until,
                    )
                )
            db.commit()
        logger.warning(
            "IP AUTO-BLOCKED | ip=%s reason=%s duration=%ds",
            ip,
            reason,
            duration_seconds,
        )
    except Exception as exc:
        logger.warning("Failed to persist IP block for %s: %s", ip, exc)


EXEMPT_PATHS = frozenset({
    "/health",
    "/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
})


class IPBlockerMiddleware(BaseHTTPMiddleware):
    """
    Outermost middleware — runs before WAF, rate limiter, and all routes.
    Checks the blocked_ips table and returns 403 for blocked IPs.
    Cleans up expired blocks lazily on hit.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        # Allow admin unblock/block endpoints so admins can recover from IP blocks
        if path.startswith("/api/blocked-ips"):
            return await call_next(request)

        ip = client_ip(request)

        try:
            now = utcnow()
            with _get_db_session(request) as db:
                row = db.execute(
                    select(BlockedIP).where(BlockedIP.ip_address == ip)
                ).scalar_one_or_none()

                if row:
                    # Permanent block or active time-limited block
                    if row.blocked_until is None:
                        logger.warning("BLOCKED IP (permanent) | ip=%s path=%s", ip, path)
                        return JSONResponse(
                            status_code=403,
                            content={
                                "detail": "Your IP address has been permanently blocked.",
                                "code": "ip_blocked",
                                "ip_address": ip,
                            },
                            headers={"X-IP-Blocked": "1"},
                        )

                    fu = as_aware(row.blocked_until)
                    if fu and fu >= now:
                        logger.warning("BLOCKED IP | ip=%s until=%s path=%s", ip, fu, path)
                        return JSONResponse(
                            status_code=403,
                            content={
                                "detail": "Your IP address is temporarily blocked.",
                                "code": "ip_blocked",
                                "ip_address": ip,
                                "blocked_until": fu.isoformat(),
                            },
                            headers={"X-IP-Blocked": "1"},
                        )

                    # Block has expired — remove it
                    db.delete(row)
                    db.commit()
        except Exception as exc:
            # Fail open if database is momentarily unavailable so gateway stays accessible
            logger.warning(
                "IPBlocker DB check failed, allowing request (fail-open) | ip=%s path=%s | %s",
                ip,
                path,
                exc,
            )

        return await call_next(request)
