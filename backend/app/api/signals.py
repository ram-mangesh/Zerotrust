"""Client biometrics, device key registration, and live telemetry signals API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import Principal, get_principal
from app.models.behavior_profile import BehaviorProfile
from app.models.device import Device
from app.models.session import UserSession
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/signals", tags=["biometrics-signals"])


class BiometricSignalBatch(BaseModel):
    wpm: float = Field(default=0.0, ge=0.0, le=500.0, description="Typing speed in words per minute")
    mouse_velocity: float = Field(
        default=0.0, ge=0.0, le=10000.0, description="Average pointer velocity in pixels per second"
    )
    requests_per_minute: float = Field(default=1.0, ge=0.0)
    data_mb: float = Field(default=0.0, ge=0.0)
    device_fp: str | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RegisterPubkeyRequest(BaseModel):
    ecdsa_pubkey: str = Field(..., description="Base64 encoded uncompressed ECDSA P-256 public key")
    device_fingerprint: str | None = Field(default=None)


class SignalIngestResponse(BaseModel):
    status: str
    wpm: float
    mouse_velocity: float
    bot_detected: bool
    risk_indicator: str


@router.post("", response_model=SignalIngestResponse, summary="Ingest client biometric and telemetry signals")
def ingest_client_signals(
    payload: BiometricSignalBatch,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> SignalIngestResponse:
    """Ingest live keystroke WPM, mouse velocity, and client behavioral telemetry."""
    session = principal.session
    user = principal.user

    # Update session running biometric averages
    if payload.wpm > 0:
        session.avg_wpm = (
            payload.wpm if session.avg_wpm == 0 else round((session.avg_wpm * 0.7 + payload.wpm * 0.3), 1)
        )
    if payload.mouse_velocity > 0:
        session.avg_mouse_velocity = (
            payload.mouse_velocity
            if session.avg_mouse_velocity == 0
            else round((session.avg_mouse_velocity * 0.7 + payload.mouse_velocity * 0.3), 1)
        )

    # Heuristic bot / automation detection
    bot_detected = False
    risk_indicator = "NORMAL"

    # Extreme typing speed (> 220 WPM) indicates scripted clipboard pasting or bot input
    if payload.wpm > 220.0:
        bot_detected = True
        risk_indicator = "UNNATURAL_TYPING_SPEED"
    # Zero mouse velocity with high request volume indicates automated headless browser
    elif payload.mouse_velocity == 0.0 and payload.requests_per_minute > 15.0:
        bot_detected = True
        risk_indicator = "HEADLESS_BROWSER_AUTOMATION"

    # Update user behavior profile
    profile = db.execute(
        select(BehaviorProfile).where(BehaviorProfile.user_id == user.id)
    ).scalar_one_or_none()
    if profile and payload.requests_per_minute > 0:
        profile.avg_requests_per_minute = round(
            profile.avg_requests_per_minute * 0.8 + payload.requests_per_minute * 0.2, 2
        )

    db.commit()

    return SignalIngestResponse(
        status="ok",
        wpm=session.avg_wpm,
        mouse_velocity=session.avg_mouse_velocity,
        bot_detected=bot_detected,
        risk_indicator=risk_indicator,
    )


@router.post("/register-device-key", summary="Bind WebCrypto ECDSA public key to session")
def register_device_pubkey(
    payload: RegisterPubkeyRequest,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Register the browser's hardware-bound ECDSA P-256 public key with the active session."""
    clean_pubkey = payload.ecdsa_pubkey.strip()
    session = principal.session

    session.ecdsa_pubkey = clean_pubkey

    if principal.device:
        principal.device.ecdsa_pubkey = clean_pubkey

    AuditService.record(
        db,
        action="DEVICE_ECDSA_KEY_REGISTERED",
        actor_id=principal.user.id,
        actor_label=principal.user.username,
        resource_type="device",
        resource_id=str(session.device_id) if session.device_id else str(session.id),
        ip_address=session.ip_address,
        payload={"pubkey_prefix": clean_pubkey[:16] + "..."},
    )
    db.commit()

    return {"status": "bound", "algorithm": "ECDSA_P256", "pubkey": clean_pubkey}
