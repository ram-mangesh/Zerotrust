"""Authenticated voice-alert trigger and signed Twilio webhook routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator

from app.core.dependencies import Principal, require_permission
from app.external import voice_alert

router = APIRouter(tags=["voice-alerts"])


class VoiceAlertRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=10000)
    severity: str = Field(default="Critical", min_length=1, max_length=20)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        normalised = value.strip().capitalize()
        if normalised not in {"High", "Critical"}:
            raise ValueError("Severity must be High or Critical")
        return normalised


@router.post("/api/voice-alert", status_code=status.HTTP_202_ACCEPTED)
async def trigger_voice_alert(
    payload: VoiceAlertRequest,
    _: Principal = Depends(require_permission("alerts:write")),
) -> dict[str, str]:
    result = await voice_alert.place_alert_call(payload.count, payload.severity)
    return {"call_sid": result.sid, "status": result.status}


@router.get("/voice/audio/{file_name}")
def voice_audio(file_name: str) -> Response:
    if not file_name.endswith(".mp3"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audio not found.")
    audio = voice_alert.get_audio(file_name[:-4])
    if audio is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audio expired or not found.")
    return Response(audio, media_type="audio/mpeg")


@router.post("/voice/twiml")
async def voice_twiml(request: Request, audio: str = "", msg: str = "") -> Response:
    await voice_alert.validate_twilio_request(request)
    return Response(voice_alert.build_twiml(audio_id=audio, message=msg), media_type="text/xml")


@router.post("/voice/action")
async def voice_action(request: Request) -> Response:
    await voice_alert.validate_twilio_request(request)
    form = await request.form()
    return Response(
        voice_alert.build_action_twiml(form.get("Digits")),
        media_type="text/xml",
    )
