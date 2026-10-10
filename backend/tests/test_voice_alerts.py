"""Twilio and ElevenLabs voice-alert integration."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from twilio.request_validator import RequestValidator

from app.external import voice_alert
from tests.conftest import auth_headers, sign_in


def configure_voice(monkeypatch) -> None:
    monkeypatch.setattr(voice_alert.settings, "twilio_account_sid", "ACtest")
    monkeypatch.setattr(voice_alert.settings, "twilio_auth_token", "test-token")
    monkeypatch.setattr(voice_alert.settings, "twilio_from_number", "+15551234567")
    monkeypatch.setattr(voice_alert.settings, "twilio_to_number", "+15557654321")
    monkeypatch.setattr(voice_alert.settings, "twilio_public_base_url", "https://alerts.example")
    monkeypatch.setattr(voice_alert.settings, "elevenlabs_api_key", "eleven-key")
    monkeypatch.setattr(voice_alert.settings, "elevenlabs_voice_id", "voice-id")


def test_trigger_requires_authentication(client) -> None:
    response = client.post(
        "/api/voice-alert",
        json={"count": 7, "severity": "Critical"},
    )
    assert response.status_code == 401


def test_trigger_places_call_for_authorised_user(client, admin, monkeypatch) -> None:
    tokens = sign_in(client, admin)

    async def fake_place_alert_call(count: int, severity: str) -> voice_alert.VoiceCallResult:
        assert count == 7
        assert severity == "Critical"
        return voice_alert.VoiceCallResult(sid="CA123", status="queued")

    monkeypatch.setattr(voice_alert, "place_alert_call", fake_place_alert_call)
    response = client.post(
        "/api/voice-alert",
        headers=auth_headers(tokens),
        json={"count": 7, "severity": "critical"},
    )
    assert response.status_code == 202
    assert response.json() == {"call_sid": "CA123", "status": "queued"}


def test_audio_is_served_and_expires(client, monkeypatch) -> None:
    monkeypatch.setattr(voice_alert.settings, "voice_audio_ttl_seconds", 900)
    with voice_alert._audio_lock:
        voice_alert._audio_files["audio-id"] = (float("inf"), b"mp3-data")
    response = client.get("/voice/audio/audio-id.mp3")
    assert response.status_code == 200
    assert response.headers["content-type"] == "audio/mpeg"
    assert response.content == b"mp3-data"


def test_twiml_rejects_invalid_signature(client, monkeypatch) -> None:
    configure_voice(monkeypatch)
    response = client.post(
        "/voice/twiml?audio=audio-id",
        headers={"X-Twilio-Signature": "invalid"},
    )
    assert response.status_code == 403


def test_twilio_action_accepts_valid_signature(client, monkeypatch) -> None:
    configure_voice(monkeypatch)
    url = "https://alerts.example/voice/action"
    form = {"Digits": "2"}
    signature = RequestValidator("test-token").compute_signature(url, form)
    response = client.post(
        "/voice/action",
        data=form,
        headers={"X-Twilio-Signature": signature},
    )
    assert response.status_code == 200
    assert "Access denied" in response.text


def test_missing_configuration_is_reported(monkeypatch) -> None:
    monkeypatch.setattr(voice_alert.settings, "twilio_account_sid", None)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(voice_alert.place_alert_call(1, "Critical"))
    assert exc.value.status_code == 503
