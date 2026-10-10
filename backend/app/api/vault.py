"""Zero-Trust Self-Destructing Vault API endpoints and tamper alert receiver."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import (
    APIRouter, Depends, HTTPException, Query, Request, Response, status,
)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import storage
from app.core.config import settings
from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import (
    Principal, get_context_bundle, get_principal,
)
from app.external import voice_alert
from app.models.alert import Alert
from app.models.enums import AlertSeverity, AlertStatus
from app.models.resource import Resource
from app.services.access_service import AccessService
from app.services.audit_service import AuditService
from app.services.vault_service import generate_vault_script

router = APIRouter(prefix="/api/vault", tags=["vault"])
logger = logging.getLogger(__name__)


class TamperAlertPayload(BaseModel):
    event: str = "VAULT_TAMPER_SELF_DESTRUCT"
    filename: str = ""
    resource_id: str = ""
    user_attempted: str = ""
    reason: str = ""
    timestamp: float = 0.0


class ExportVaultRequest(BaseModel):
    password: str = Field(min_length=4, max_length=128)
    max_attempts: int = Field(default=1, ge=1, le=5)


@router.post("/export/{slug}", summary="Export resource as self-destructing protected vault")
def export_vault(
    slug: str,
    payload: ExportVaultRequest,
    principal: Principal = Depends(get_principal),
    bundle: ContextBundle = Depends(get_context_bundle),
    db: Session = Depends(get_db),
) -> Response:
    """Package a protected resource into a self-destructing Python vault container."""
    resource = db.scalar(select(Resource).where(Resource.slug == slug))
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found.")

    is_admin_user = principal.user.role.is_admin or "resources:write" in (principal.user.role.permissions or [])

    if not is_admin_user:
        decision, _ = AccessService.request_access(
            db,
            user=principal.user,
            session=principal.session,
            resource=resource,
            bundle=bundle,
            device=principal.device,
            method="GET",
            path=f"/api/vault/export/{slug}",
        )

        if not decision.granted:
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=decision.reason,
            )

    if resource.has_file and resource.file_path:
        try:
            data = storage.read(resource.file_path)
        except storage.StorageError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, exc.message) from exc
    else:
        # Fallback generated confidential content for resources without raw file
        data = (
            f"=== CONFIDENTIAL ASSET: {resource.name} ===\n"
            f"Classification: {resource.sensitivity.value}\n"
            f"Owner: {resource.owner}\n"
            f"Description: {resource.description}\n"
            f"Trust Floor Required: {resource.min_trust_score}\n"
            f"Generated: Secure Vault Container\n"
        ).encode("utf-8")

    alert_url = ""
    if settings.twilio_public_base_url:
        alert_url = f"{settings.twilio_public_base_url.rstrip('/')}/api/vault/tamper-alert"
    else:
        alert_url = "http://127.0.0.1:8000/api/vault/tamper-alert"

    vault_code = generate_vault_script(
        plaintext=data,
        filename=resource.file_name or f"{resource.slug}.txt",
        password=payload.password,
        max_attempts=payload.max_attempts,
        alert_url=alert_url,
        resource_id=str(resource.id),
    )

    AuditService.record(
        db,
        action="VAULT_CONTAINER_EXPORTED",
        actor_id=principal.user.id,
        actor_label=principal.user.username,
        resource_type="resource",
        resource_id=str(resource.id),
        ip_address=bundle.network.ip_address if bundle else "127.0.0.1",
        payload={
            "filename": resource.file_name,
            "max_attempts": payload.max_attempts,
            "slug": slug,
        },
    )
    db.commit()

    safe_name = f"SecureVault_{resource.slug}.py"
    return Response(
        content=vault_code.encode("utf-8"),
        media_type="text/x-python",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
        },
    )


@router.post("/tamper-alert", summary="Receive stealth vault self-destruct signal")
async def receive_tamper_alert(
    payload: TamperAlertPayload,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Stealth webhook called when a vault self-destructs upon incorrect password entry."""
    client_ip = request.client.host if request.client else "unknown"
    logger.warning(
        "🚨 VAULT SELF-DESTRUCT TRIGGERED! File: %s, User Attempted: %s, Reason: %s",
        payload.filename,
        payload.user_attempted,
        payload.reason,
    )

    alert = Alert(
        severity=AlertSeverity.CRITICAL,
        category="data_exfiltration_prevented",
        title=f"Self-Destruct Triggered: {payload.filename or 'Protected Asset'}",
        description=(
            f"An unauthorized attempt was made to open encrypted container '{payload.filename}'. "
            f"Incorrect credentials were provided by user '{payload.user_attempted or 'unknown'}'. "
            f"The Dead-Man's Switch engaged: local file was securely shredded and deleted."
        ),
        evidence={
            "filename": payload.filename,
            "resource_id": payload.resource_id,
            "user_attempted": payload.user_attempted,
            "reason": payload.reason,
            "source_ip": client_ip,
        },
        status=AlertStatus.OPEN,
    )
    db.add(alert)

    AuditService.record(
        db,
        action="VAULT_SELF_DESTRUCT_EXECUTED",
        actor_label=payload.user_attempted or "unauthorized-intruder",
        resource_type="vault_container",
        resource_id=payload.resource_id or payload.filename,
        ip_address=client_ip,
        payload={
            "filename": payload.filename,
            "user_attempted": payload.user_attempted,
            "reason": payload.reason,
            "action_taken": "PERMANENT_CRYPTOGRAPHIC_SHRED",
        },
    )
    db.commit()

    # Trigger Twilio Voice Alert Call if Twilio is configured
    try:
        await voice_alert.place_alert_call(count=1, severity="Critical")
    except Exception as exc:
        logger.info("Twilio voice alert call skipped or failed: %s", exc)

    return {"status": "alert_recorded", "action": "self_destruct_logged", "alert_id": str(alert.id)}
