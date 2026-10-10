"""Policy Decision Point (PDP) internal authorization service."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.decision import Decision
from app.core import jwt as jwt_service
from app.core.context import ContextBundle
from app.models.device import Device
from app.models.enums import AccessAction, RiskLevel, ScoreTrigger
from app.models.resource import Resource
from app.models.session import UserSession
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.policy_engine import PolicyDecision, PolicyEngine
from app.services.trust_service import TrustService

logger = logging.getLogger(__name__)


@dataclass
class PDPDecisionResult:
    decision: str
    allowed: bool
    reason: str
    matched_policy: str
    trust_score: float
    username: str
    role: str
    resource: str | None = None
    upstream_url: str | None = None
    upstream_path: str | None = None
    action: str = "BLOCK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "allowed": self.allowed,
            "reason": self.reason,
            "matched_policy": self.matched_policy,
            "trust_score": self.trust_score,
            "username": self.username,
            "role": self.role,
            "resource": self.resource,
            "upstream_url": self.upstream_url,
            "upstream_path": self.upstream_path,
            "action": self.action,
        }


class PDPService:
    @staticmethod
    def resolve_resource_and_subpath(
        db: Session, full_path: str
    ) -> tuple[Resource | None, str]:
        """Extract resource slug from path and find matching Resource record.

        Examples:
          /proxy/payroll-db/employees -> (Resource(payroll-db), /employees)
          /api/v1/source-repo/pulls   -> (Resource(source-repo), /pulls)
        """
        clean = full_path.strip("/")
        parts = clean.split("/")

        # Skip leading namespace prefixes like 'proxy' or 'api'
        idx = 0
        if parts and parts[0] in ("proxy", "service", "upstream"):
            idx = 1

        if idx < len(parts):
            slug = parts[idx]
            resource = db.execute(
                select(Resource).where(Resource.slug == slug)
            ).scalar_one_or_none()
            if resource:
                subpath = "/" + "/".join(parts[idx + 1:])
                return resource, subpath

        # Direct slug lookup
        for resource in db.execute(select(Resource)).scalars().all():
            if clean.startswith(resource.slug):
                subpath = clean[len(resource.slug):]
                if not subpath.startswith("/"):
                    subpath = "/" + subpath
                return resource, subpath

        return None, "/" + clean

    @classmethod
    def authorize(
        cls,
        db: Session,
        *,
        request_id: str,
        method: str,
        path: str,
        source_ip: str,
        access_token: str | None = None,
        device_fingerprint: str | None = None,
        bundle: ContextBundle,
    ) -> PDPDecisionResult:
        """Central policy decision point evaluation."""
        user = None
        session = None
        device = None

        if access_token:
            try:
                payload = jwt_service.decode_token(access_token, "access")
                user = db.get(User, uuid.UUID(payload["sub"]))
                session = db.get(UserSession, uuid.UUID(payload["sid"]))
            except Exception as exc:
                logger.debug("PDP token decode failed: %s", exc)

        if not user or not session or session.status.value != "ACTIVE":
            return PDPDecisionResult(
                decision="DENY",
                allowed=False,
                reason="Unauthenticated: valid active bearer token required",
                matched_policy="",
                trust_score=0.0,
                username="anonymous",
                role="anonymous",
                action="BLOCK",
            )

        if device_fingerprint:
            device = db.execute(
                select(Device).where(
                    Device.user_id == user.id,
                    Device.fingerprint == device_fingerprint,
                )
            ).scalar_one_or_none()
        elif session.device_id:
            device = db.get(Device, session.device_id)

        resource, upstream_subpath = cls.resolve_resource_and_subpath(db, path)
        if not resource:
            return PDPDecisionResult(
                decision="DENY",
                allowed=False,
                reason=f"No protected resource configured for path '{path}'",
                matched_policy="",
                trust_score=0.0,
                username=user.username,
                role=user.role.name,
                action="BLOCK",
            )

        # Real-time continuous trust scoring
        trust_eval, _ = TrustService.evaluate(
            db,
            user=user,
            session=session,
            bundle=bundle,
            trigger=ScoreTrigger.ACCESS_REQUEST,
            device=device,
            sensitivity=resource.sensitivity,
            resource_name=resource.name,
        )

        device_known = device is not None and device.status.value == "APPROVED"

        # Three-gate policy evaluation
        policy_decision = PolicyEngine.evaluate(
            db,
            user=user,
            session=session,
            resource=resource,
            score=trust_eval.score,
            risk=trust_eval.risk_level,
            bundle=bundle,
            device_known=device_known,
        )

        decision_str = "ALLOW" if policy_decision.granted else "DENY"

        # Log authorization decision in audit chain
        AuditService.record(
            db,
            action="PDP_AUTHORIZATION",
            actor_id=user.id,
            actor_label=user.username,
            resource_type="resource",
            resource_id=resource.slug,
            ip_address=source_ip,
            payload={
                "request_id": request_id,
                "method": method,
                "path": path,
                "decision": decision_str,
                "action": policy_decision.action.value,
                "trust_score": trust_eval.score,
                "reason": policy_decision.reason,
                "matched_policy": policy_decision.matched_policy,
                "upstream_url": resource.upstream_url,
            },
        )

        return PDPDecisionResult(
            decision=decision_str,
            allowed=policy_decision.granted,
            reason=policy_decision.reason,
            matched_policy=policy_decision.matched_policy,
            trust_score=trust_eval.score,
            username=user.username,
            role=user.role.name,
            resource=resource.slug,
            upstream_url=resource.upstream_url if policy_decision.granted else None,
            upstream_path=upstream_subpath if policy_decision.granted else None,
            action=policy_decision.action.value,
        )
