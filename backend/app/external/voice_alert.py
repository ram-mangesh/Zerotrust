"""Twilio outbound calling with ElevenLabs-generated alert audio and Twilio TTS fallback."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from threading import Lock
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request, status
from twilio.base.exceptions import TwilioRestException
from twilio.request_validator import RequestValidator
from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse

import urllib.parse

from app.core.config import settings


@dataclass(frozen=True)
class VoiceCallResult:
    sid: str
    status: str


_audio_files: dict[str, tuple[float, bytes]] = {}
_audio_lock = Lock()


def _require_configuration() -> None:
    required = {
        "TWILIO_ACCOUNT_SID": settings.twilio_account_sid,
        "TWILIO_AUTH_TOKEN": settings.twilio_auth_token,
        "TWILIO_FROM_NUMBER": settings.twilio_from_number,
        "TWILIO_TO_NUMBER": settings.twilio_to_number,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Voice alerts are not configured. Missing in .env: {', '.join(missing)}",
        )


def _remove_expired_audio() -> None:
    now = time.monotonic()
    with _audio_lock:
        expired = [key for key, (expires_at, _) in _audio_files.items() if expires_at <= now]
        for key in expired:
            _audio_files.pop(key, None)


async def create_speech(text: str) -> str | None:
    if not settings.elevenlabs_api_key or not settings.elevenlabs_voice_id:
        return None
    url = f"https://api.elevenlabs.io/v1/text-to-speech/{settings.elevenlabs_voice_id}"
    try:
        async with httpx.AsyncClient(timeout=settings.voice_provider_timeout_seconds) as client:
            response = await client.post(
                url,
                params={"output_format": settings.elevenlabs_output_format},
                headers={
                    "xi-api-key": settings.elevenlabs_api_key or "",
                    "Content-Type": "application/json",
                    "Accept": "audio/mpeg",
                },
                json={
                    "text": text,
                    "model_id": settings.elevenlabs_model_id,
                    "voice_settings": {"stability": 0.5, "similarity_boost": 0.75},
                },
            )
            response.raise_for_status()
    except httpx.HTTPError:
        return None

    _remove_expired_audio()
    audio_id = str(uuid.uuid4())
    expires_at = time.monotonic() + settings.voice_audio_ttl_seconds
    with _audio_lock:
        _audio_files[audio_id] = (expires_at, response.content)
    return audio_id


def get_audio(audio_id: str) -> bytes | None:
    _remove_expired_audio()
    with _audio_lock:
        item = _audio_files.get(audio_id)
    return item[1] if item else None


def build_twiml(audio_id: str = "", message: str = "") -> str:
    base_url = (settings.twilio_public_base_url or "").rstrip("/")
    response = VoiceResponse()
    gather_kwargs = {
        "num_digits": 1,
        "method": "POST",
        "timeout": 8,
    }
    if base_url:
        gather_kwargs["action"] = f"{base_url}/voice/action"

    gather = response.gather(**gather_kwargs)
    if audio_id and get_audio(audio_id) is not None and base_url:
        gather.play(f"{base_url}/voice/audio/{audio_id}.mp3")
    else:
        speech = message or "Critical vulnerabilities have been detected."
        gather.say(speech, voice="Polly.Matthew-Neural", language="en-US")

    response.say("No input was received. Goodbye.", voice="Polly.Matthew-Neural", language="en-US")
    return str(response)


def build_action_twiml(digit: str | None) -> str:
    messages = {
        "1": "Access granted. Alice has been given access to the Payroll Portal.",
        "2": "Access denied. Alice has been blocked from accessing the Payroll Portal.",
        "3": "The accepted risk action was selected.",
        "4": "The reminder action was selected.",
    }
    response = VoiceResponse()
    response.say(messages.get(digit or "", "That option is invalid."), voice="Polly.Matthew-Neural", language="en-US")
    response.hangup()
    return str(response)


async def validate_twilio_request(request: Request) -> None:
    if not settings.twilio_auth_token or not settings.twilio_public_base_url:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Twilio is not configured.")
    signature = request.headers.get("X-Twilio-Signature", "")
    base_url = settings.twilio_public_base_url.rstrip("/")
    url = f"{base_url}{request.url.path}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    form = await request.form()
    params: dict[str, str | list[str]] = {}
    for key, value in form.multi_items():
        text = str(value)
        existing = params.get(key)
        if existing is None:
            params[key] = text
        elif isinstance(existing, list):
            existing.append(text)
        else:
            params[key] = [existing, text]
    if not RequestValidator(settings.twilio_auth_token).validate(url, params, signature):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid Twilio signature.")


async def place_alert_call(count: int = 1, severity: str = "Critical") -> VoiceCallResult:
    _require_configuration()
    message = (
        "In demo app, Alice had clicked the Payroll Portal. "
        "Should I give access to her? "
        "Press 1 to give access, and 2 for deny."
    )
    audio_id = await create_speech(message)
    client = Client(settings.twilio_account_sid, settings.twilio_auth_token)

    try:
        if audio_id and settings.twilio_public_base_url:
            query = urlencode({"audio": audio_id})
            call_url = f"{settings.twilio_public_base_url.rstrip('/')}/voice/twiml?{query}"
        else:
            twiml_direct = build_twiml(message=message)
            call_url = "https://twimlets.com/echo?Twiml=" + urllib.parse.quote(twiml_direct)

        call = await asyncio.to_thread(
            client.calls.create,
            to=settings.twilio_to_number,
            from_=settings.twilio_from_number,
            url=call_url,
        )
    except TwilioRestException as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Twilio call creation failed: {exc.msg}",
        ) from exc
    return VoiceCallResult(sid=call.sid, status=call.status)
