"""EDR Agent and Telemetry Ingestion API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal,
    get_context_bundle,
    get_request_context,
    require_permission,
)
from app.models.base import as_aware
from app.models.edr import EDRAgent, EDREvent
from app.schemas.edr import (
    EDRAgentOut,
    EDREventIngestRequest,
    EDREventOut,
    EDRHeartbeatRequest,
    EDRIsolateRequest,
)
from app.services.auth_service import RequestContext
from app.services.edr_service import EDRService

router = APIRouter(prefix="/api/edr", tags=["edr-telemetry"])


def _agent_to_out(agent: EDRAgent) -> EDRAgentOut:
    return EDRAgentOut(
        id=agent.id,
        agent_id=agent.agent_id,
        hostname=agent.hostname,
        os_type=agent.os_type,
        ip_address=agent.ip_address,
        status=agent.status,
        is_isolated=agent.is_isolated,
        version=agent.version,
        last_heartbeat_at=as_aware(agent.last_heartbeat_at),
        device_id=agent.device_id,
        created_at=as_aware(agent.created_at),
    )


@router.post("/heartbeat", response_model=EDRAgentOut, summary="Agent heartbeat & registration")
def agent_heartbeat(
    payload: EDRHeartbeatRequest,
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> EDRAgentOut:
    """Register or refresh an endpoint agent heartbeat."""
    agent = EDRService.record_heartbeat(
        db,
        agent_id=payload.agent_id,
        hostname=payload.hostname,
        os_type=payload.os_type,
        ip_address=context.ip_address,
        version=payload.version,
        fingerprint=payload.fingerprint,
    )
    db.commit()
    return _agent_to_out(agent)


@router.post("/events", summary="Ingest batch endpoint telemetry events")
def ingest_telemetry_events(
    payload: EDREventIngestRequest,
    db: Session = Depends(get_db),
    context: RequestContext = Depends(get_request_context),
) -> dict[str, object]:
    """Ingest bulk endpoint telemetry events from an active EDR agent."""
    result = EDRService.ingest_events(
        db,
        agent_id=payload.agent_id,
        events=[e.model_dump() for e in payload.events],
        ip_address=context.ip_address,
    )
    db.commit()
    return result


@router.get("/agents", response_model=list[EDRAgentOut], summary="List all registered EDR agents")
def list_agents(
    principal: Principal = Depends(require_permission("devices:read")),
    db: Session = Depends(get_db),
) -> list[EDRAgentOut]:
    """List all registered endpoint agents and their active standing."""
    rows = db.execute(select(EDRAgent).order_by(EDRAgent.last_heartbeat_at.desc())).scalars().all()
    return [_agent_to_out(r) for r in rows]


@router.get("/events", response_model=list[EDREventOut], summary="Query telemetry events")
def list_events(
    agent_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    principal: Principal = Depends(require_permission("devices:read")),
    db: Session = Depends(get_db),
) -> list[EDREventOut]:
    """Query ingested EDR events by agent or severity level."""
    stmt = select(EDREvent).order_by(EDREvent.timestamp.desc()).limit(limit)
    if agent_id:
        stmt = stmt.where(EDREvent.agent_id == agent_id)
    if severity:
        stmt = stmt.where(EDREvent.severity == severity.upper())

    rows = db.execute(stmt).scalars().all()
    return [
        EDREventOut(
            id=r.id,
            agent_id=r.agent_id,
            event_type=r.event_type,
            severity=r.severity,
            source=r.source,
            details=r.details,
            timestamp=as_aware(r.timestamp),
        )
        for r in rows
    ]


@router.post("/agents/{agent_id}/isolate", response_model=EDRAgentOut, summary="Active response: Isolate endpoint")
def isolate_endpoint(
    agent_id: str,
    payload: EDRIsolateRequest,
    principal: Principal = Depends(require_permission("devices:revoke")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> EDRAgentOut:
    """Isolate an infected endpoint from the corporate network and revoke active sessions."""
    try:
        agent = EDRService.isolate_agent(
            db,
            agent_id=agent_id,
            reason=payload.reason,
            actor=principal.user,
            ip_address=bundle.ip_address,
        )
        db.commit()
        return _agent_to_out(agent)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/agents/{agent_id}/unisolate", response_model=EDRAgentOut, summary="Restore isolated endpoint")
def unisolate_endpoint(
    agent_id: str,
    principal: Principal = Depends(require_permission("devices:revoke")),
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> EDRAgentOut:
    """Restore an isolated endpoint back to active online status."""
    try:
        agent = EDRService.unisolate_agent(
            db,
            agent_id=agent_id,
            actor=principal.user,
            ip_address=bundle.ip_address,
        )
        db.commit()
        return _agent_to_out(agent)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
