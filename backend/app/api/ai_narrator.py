"""AI Behavioral Baseline Synthesizer and Incident Narrator API router."""

from __future__ import annotations

from typing import Any, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai import anomaly
from app.core import jwt as jwt_service
from app.core.config import settings
from app.core.database import get_db
from app.core.dependencies import Principal, get_principal, require_permission
from app.services.anomaly_runner_service import AnomalyRunnerService
from app.services.llm_service import LLMService

router = APIRouter(prefix="/api/ai", tags=["ai-llm-narrator"])
bearer_scheme = HTTPBearer(auto_error=False)


class SynthesizeBaselineRequest(BaseModel):
    role: str = Field(default="employee", description="Target role name")
    department: str = Field(default="Engineering", description="Department name")
    permissions: list[str] = Field(default_factory=lambda: ["resources:read"])


class NarrateIncidentRequest(BaseModel):
    user_id: str = Field(default="unknown")
    username: str = Field(default="anonymous")
    risk_score: float = Field(default=25.0, ge=0.0, le=100.0)
    risk_level: str = Field(default="CRITICAL")
    action: str = Field(default="REVOKE_SESSION")
    overrides: list[str] = Field(default_factory=list)
    factors: list[dict[str, Any]] = Field(default_factory=list)
    threat_details: dict[str, Any] = Field(default_factory=dict)


class ExplainAnomalyRequest(BaseModel):
    features: dict[str, float] = Field(..., description="13-D feature map for anomaly explanation")
    user_id: str | None = Field(default=None, description="Optional user ID for per-user model")


class ScenarioRunnerRequest(BaseModel):
    scenario_id: Optional[str] = Field(default="baseline_normal", description="Predefined scenario ID")
    custom_features: Optional[dict[str, float]] = Field(default=None, description="Optional custom 13-D feature values")


@router.post("/synthesize-baseline", summary="AI synthesis of user behavioral baseline")
async def synthesize_baseline(
    payload: SynthesizeBaselineRequest,
    principal: Principal = Depends(require_permission("users:write")),
) -> dict[str, Any]:
    """Ask Llama-3.3-70B (or rule synthesizer) to generate a role/department-aware behavioral baseline."""
    return await LLMService.synthesize_baseline(
        role=payload.role,
        department=payload.department,
        permissions=payload.permissions,
    )


@router.post("/narrate-incident", summary="Generate plain-English incident investigation narrative")
async def narrate_incident(
    payload: NarrateIncidentRequest,
    principal: Principal = Depends(require_permission("alerts:read")),
) -> dict[str, Any]:
    """Generate an analytical, executive plain-English incident report from raw z-scores and security signals."""
    narrative = await LLMService.narrate_incident(
        username=payload.username,
        user_id=payload.user_id,
        risk_score=payload.risk_score,
        risk_level=payload.risk_level,
        action=payload.action,
        factors=payload.factors,
        overrides=payload.overrides,
        threat_details=payload.threat_details,
    )

    return {
        "narrative": narrative,
        "model": settings.llm_model if settings.llm_enabled or settings.llm_api_key or settings.groq_api_key else "deterministic_fallback",
        "username": payload.username,
        "risk_score": payload.risk_score,
    }


@router.post("/explain-anomaly", summary="Feature-level SHAP explainability for Isolation Forest")
def explain_anomaly(
    payload: ExplainAnomalyRequest,
    principal: Principal = Depends(require_permission("alerts:read")),
) -> dict[str, Any]:
    """Calculate feature attribution and SHAP anomaly drivers for Isolation Forest."""
    uid = None
    if payload.user_id:
        try:
            uid = uuid.UUID(payload.user_id)
        except Exception:
            pass

    res = anomaly.explain_for_user(payload.features, uid)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No anomaly model loaded or available for explanation.",
        )
    return res


@router.get("/scenario-runner/scenarios", summary="List all predefined anomaly test scenarios")
def list_synthetic_scenarios() -> list[dict[str, Any]]:
    """List all available normal-versus-anomalous synthetic request scenarios."""
    return AnomalyRunnerService.list_scenarios()


@router.post("/scenario-runner/run", summary="Run full single anomaly scenario, inference, SHAP, and audit verification")
def run_anomaly_scenario(
    request: Request,
    payload: ScenarioRunnerRequest | None = None,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, Any]:
    """Execute real model inference (.pkl), SHAP explanation, policy evaluation, and SHA-256 audit verification."""
    actor_label = "security_analyst"
    actor_id: Optional[uuid.UUID] = None

    token = credentials.credentials if credentials else request.cookies.get("ztna_session")
    if token:
        try:
            token_payload = jwt_service.decode_token(token, "access")
            if "username" in token_payload:
                actor_label = token_payload["username"]
            if "sub" in token_payload:
                actor_id = uuid.UUID(token_payload["sub"])
        except Exception:
            pass

    scen_id = payload.scenario_id if payload else "baseline_normal"
    custom_feat = payload.custom_features if payload else None

    return AnomalyRunnerService.run_scenario(
        db,
        scenario_id=scen_id,
        custom_features=custom_feat,
        actor_label=actor_label,
        actor_id=actor_id,
    )
