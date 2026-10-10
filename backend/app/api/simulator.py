"""Interactive Attack Simulator API router."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import jwt as jwt_service
from app.core.database import get_db
from app.models.enums import SessionStatus
from app.models.session import UserSession
from app.models.user import User
from app.core.databroker import set_cached_session
from app.services.simulator_service import SimulatorService

router = APIRouter(prefix="/api/simulator", tags=["attack-simulator"])
bearer_scheme = HTTPBearer(auto_error=False)


class ScenarioRunRequest(BaseModel):
    user_id: uuid.UUID | None = Field(default=None, description="Optional target user UUID")
    session_id: uuid.UUID | None = Field(default=None, description="Optional target session UUID")


class ResetRequest(BaseModel):
    session_id: uuid.UUID | None = Field(default=None, description="Session ID to restore")


@router.get("/scenarios", summary="List all available attack simulation scenarios")
def list_scenarios() -> list[dict[str, Any]]:
    """Get metadata for all 5 interactive attack simulation scenarios."""
    return SimulatorService.list_scenarios()


@router.post("/run/{scenario_id}", summary="Execute interactive attack simulation")
def run_simulation(
    scenario_id: str,
    request: Request,
    payload: ScenarioRunRequest | None = None,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, Any]:
    """Trigger an interactive attack scenario (Normal, Country Change, Rapid Export, Stolen Token, Full Attack)."""
    user_id = payload.user_id if payload else None
    session_id = payload.session_id if payload else None

    # Try extracting from Bearer token
    if not user_id or not session_id:
        token = credentials.credentials if credentials else request.cookies.get("ztna_session")
        if token:
            try:
                token_payload = jwt_service.decode_token(token, "access")
                if not user_id and "sub" in token_payload:
                    user_id = uuid.UUID(token_payload["sub"])
                if not session_id and "sid" in token_payload:
                    session_id = uuid.UUID(token_payload["sid"])
            except Exception:
                pass

    # If still not found, fallback to latest active session or admin user
    if not session_id:
        active_session = db.scalar(
            select(UserSession).where(UserSession.status == SessionStatus.ACTIVE).order_by(UserSession.started_at.desc()).limit(1)
        )
        if active_session:
            session_id = active_session.id
            user_id = active_session.user_id

    if not user_id:
        admin_user = db.scalar(select(User).where(User.username == "admin"))
        if admin_user:
            user_id = admin_user.id

    if not user_id or not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active user or session found to target for simulation. Log in first.",
        )

    try:
        return SimulatorService.run_scenario(
            db,
            scenario_id=scenario_id,
            user_id=user_id,
            session_id=session_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post("/reset", summary="Reset simulated attack states")
def reset_simulation(
    request: Request,
    payload: ResetRequest | None = None,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, str]:
    """Reset session trust scores and state after running demo attack scenarios."""
    session_id = payload.session_id if payload else None
    if not session_id:
        token = credentials.credentials if credentials else request.cookies.get("ztna_session")
        if token:
            try:
                token_payload = jwt_service.decode_token(token, "access")
                if "sid" in token_payload:
                    session_id = uuid.UUID(token_payload["sid"])
            except Exception:
                pass

    if not session_id:
        active_session = db.scalar(
            select(UserSession).order_by(UserSession.started_at.desc()).limit(1)
        )
        if active_session:
            session_id = active_session.id

    if session_id:
        session = db.get(UserSession, session_id)
        if session:
            session.status = SessionStatus.ACTIVE
            session.current_trust_score = 95.0
            session.current_risk_level = "LOW"
            session.current_action = "ALLOW"
            session.revoked_reason = ""
            session.ended_at = None
            session.request_count = 5
            session.distinct_resource_count = 2
            session.denied_count = 0
            db.commit()
            set_cached_session(str(session_id), {"status": "ACTIVE", "trust_score": 95.0})
            return {
                "status": "reset",
                "session_id": str(session_id),
                "message": "Demo session standing restored to 95.0 (LOW risk)",
            }

    return {"status": "reset", "message": "Simulation reset complete"}
