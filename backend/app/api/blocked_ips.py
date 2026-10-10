"""IP Blocklist administration API."""

from __future__ import annotations

import ipaddress
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal,
    get_context_bundle,
    require_permission,
)
from app.middleware.ip_blocker import clear_waf_hits
from app.models.base import as_aware, utcnow
from app.models.blocked_ip import BlockedIP
from app.schemas.blocked_ip import BlockedIPCreate, BlockedIPOut
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/blocked-ips", tags=["blocked-ips"])


def _to_out(blocked: BlockedIP) -> BlockedIPOut:
    fu = as_aware(blocked.blocked_until)
    return BlockedIPOut(
        id=blocked.id,
        ip_address=blocked.ip_address,
        reason=blocked.reason,
        blocked_until=fu,
        permanent=fu is None,
        created_at=as_aware(blocked.created_at) or utcnow(),
    )


@router.get("", response_model=list[BlockedIPOut], summary="List all blocked IPs")
def list_blocked_ips(
    principal: Principal = Depends(require_permission("policies:read")),
    db: Session = Depends(get_db),
) -> list[BlockedIPOut]:
    """List all blocked IP addresses (active blocks and history)."""
    now = utcnow()
    rows = db.execute(select(BlockedIP).order_by(BlockedIP.created_at.desc())).scalars().all()
    out: list[BlockedIPOut] = []
    for r in rows:
        fu = as_aware(r.blocked_until)
        if fu is not None and fu < now:
            # Expired block - prune it
            db.delete(r)
        else:
            out.append(_to_out(r))
    db.commit()
    return out


@router.post(
    "",
    response_model=BlockedIPOut,
    status_code=status.HTTP_201_CREATED,
    summary="Block an IP address",
)
def block_ip(
    payload: BlockedIPCreate,
    principal: Principal = Depends(require_permission("policies:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> BlockedIPOut:
    """Manually add an IP address to the blocklist."""
    raw_ip = payload.ip_address.strip()
    try:
        validated_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{raw_ip}' is not a valid IPv4 or IPv6 address.",
        )

    # Protect against blocking the caller's own current IP address
    if bundle.ip_address == validated_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot block your own current IP address.",
        )

    now = utcnow()
    blocked_until = (
        now + timedelta(minutes=payload.duration_minutes)
        if payload.duration_minutes and payload.duration_minutes > 0
        else None
    )

    existing = db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == validated_ip)
    ).scalar_one_or_none()

    if existing:
        existing.reason = payload.reason
        existing.blocked_until = blocked_until
        row = existing
    else:
        row = BlockedIP(
            ip_address=validated_ip,
            reason=payload.reason,
            blocked_until=blocked_until,
        )
        db.add(row)
    db.commit()
    db.refresh(row)

    AuditService.record(
        db,
        action="IP_BLOCKED",
        actor_id=principal.user.id,
        actor_label=principal.user.username,
        resource_type="network",
        resource_id=validated_ip,
        ip_address=bundle.ip_address,
        payload={
            "ip_address": validated_ip,
            "reason": payload.reason,
            "blocked_until": blocked_until.isoformat() if blocked_until else "PERMANENT",
        },
    )

    return _to_out(row)


@router.delete(
    "/{ip_address:path}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Unblock an IP address",
)
def unblock_ip(
    ip_address: str,
    principal: Principal = Depends(require_permission("policies:write")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> Response:
    """Remove an IP address from the blocklist and reset any rate/WAF counters."""
    raw_ip = ip_address.strip()
    row = db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == raw_ip)
    ).scalar_one_or_none()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{raw_ip}' is not in the blocklist.",
        )

    db.delete(row)
    db.commit()

    clear_waf_hits(raw_ip)

    AuditService.record(
        db,
        action="IP_UNBLOCKED",
        actor_id=principal.user.id,
        actor_label=principal.user.username,
        resource_type="network",
        resource_id=raw_ip,
        ip_address=bundle.ip_address,
        payload={"ip_address": raw_ip},
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
