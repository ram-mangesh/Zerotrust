"""Open Policy Agent (OPA) integration service for RBAC + ABAC evaluation.

Provides a unified interface to evaluate fine-grained access policies using OPA.
Supports:
  - Live HTTP evaluation against a standalone OPA daemon (`settings.opa_url`)
  - Embedded in-process Rego rule engine fallback when OPA server is offline
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import settings
from app.core.context import ContextBundle
from app.models.enums import SENSITIVITY_MIN_TRUST, SENSITIVITY_ORDINAL, Sensitivity
from app.models.resource import Resource
from app.models.session import UserSession
from app.models.user import User

logger = logging.getLogger(__name__)

OPA_DECISION_PATH = "/v1/data/ztp/authz/decision"


class OPAService:
    @staticmethod
    def build_input(
        *,
        user: User,
        session: UserSession,
        resource: Resource,
        action: str,
        score: float,
        bundle: ContextBundle,
        device_known: bool,
    ) -> dict[str, Any]:
        """Build the canonical input document for OPA policy evaluation."""
        return {
            "input": {
                "subject": {
                    "id": str(user.id),
                    "username": user.username,
                    "roles": [user.role.name] if user.role else [],
                    "permissions": user.role.permissions if user.role else [],
                    "attributes": {
                        "department": user.department or "General",
                        "clearance_ordinal": (
                            user.role.max_sensitivity_ordinal if user.role else 0
                        ),
                        "home_country": user.home_country,
                    },
                },
                "resource": resource.slug,
                "resource_name": resource.name,
                "resource_sensitivity": resource.sensitivity.value,
                "action": action,
                "trust_score": float(score),
                "device_trusted": bool(device_known),
                "mfa_verified": bool(session.mfa_passed),
                "is_vpn": bool(bundle.network.intel.is_anonymised),
                "country": bundle.network.geo.country or "UNKNOWN",
            }
        }

    @classmethod
    async def evaluate_http(cls, input_doc: dict[str, Any]) -> dict[str, Any] | None:
        """Query OPA REST API if configured."""
        if not settings.opa_url:
            return None

        url = f"{settings.opa_url.rstrip('/')}{OPA_DECISION_PATH}"
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.post(url, json=input_doc)
                if resp.status_code == 200:
                    data = resp.json()
                    result = data.get("result")
                    if isinstance(result, dict) and "allow" in result:
                        result["engine"] = "OPA_HTTP"
                        return result
        except Exception as exc:
            logger.warning(
                "OPA server at %s unreachable (%s); falling back to in-process evaluator",
                url,
                exc,
            )
        return None

    @classmethod
    def evaluate_in_process(cls, input_doc: dict[str, Any]) -> dict[str, Any]:
        """In-process Python implementation of the OPA Rego rules (fallback)."""
        inp = input_doc.get("input", {})
        subject = inp.get("subject", {})
        roles = subject.get("roles", [])
        permissions = subject.get("permissions", [])
        attrs = subject.get("attributes", {})
        resource_slug = inp.get("resource", "")
        sensitivity_str = inp.get("resource_sensitivity", "PUBLIC")
        action = inp.get("action", "read")
        score = float(inp.get("trust_score", 0.0))
        mfa_verified = bool(inp.get("mfa_verified", False))
        device_trusted = bool(inp.get("device_trusted", False))

        try:
            sens_enum = Sensitivity(sensitivity_str)
        except ValueError:
            sens_enum = Sensitivity.PUBLIC

        reasons: list[str] = []

        # 1. RBAC
        is_admin = "admin" in roles
        rbac_allow = is_admin
        if not rbac_allow:
            if "*" in permissions or "resources:*" in permissions:
                rbac_allow = True
            elif f"resources:{action}" in permissions:
                rbac_allow = True
            elif action == "read" and "resources:read" in permissions:
                rbac_allow = True
            elif action in ("read", "write") and "resources:write" in permissions:
                rbac_allow = True

        if not rbac_allow:
            reasons.append("RBAC permission check failed")

        # 2. ABAC: Clearance & Department
        req_ordinal = SENSITIVITY_ORDINAL.get(sens_enum, 0)
        user_ordinal = int(attrs.get("clearance_ordinal", 0))
        clearance_allow = is_admin or (user_ordinal >= req_ordinal)
        if not clearance_allow:
            reasons.append("Role clearance below resource sensitivity ceiling")

        # Department check for restricted resources
        dept = str(attrs.get("department", "")).lower()
        dept_allow = True
        if resource_slug in ("payroll-db", "finance-reports"):
            if not is_admin and dept not in ("finance", "hr"):
                dept_allow = False
                reasons.append("Department attribute mismatch for restricted resource")

        # 3. Contextual Trust Score
        floor = SENSITIVITY_MIN_TRUST.get(sens_enum, 0)
        trust_score_allow = score >= floor
        if not trust_score_allow:
            reasons.append(
                f"Trust score {score:.0f} below sensitivity floor of {floor}"
            )

        if score < 40:
            reasons.append("Trust score in critical risk band (< 40)")

        # 4. Device & MFA
        device_mfa_allow = True
        if sens_enum != Sensitivity.PUBLIC:
            if not mfa_verified:
                device_mfa_allow = False
                reasons.append("MFA verification required for non-public resources")

        final_allow = (
            rbac_allow
            and clearance_allow
            and dept_allow
            and trust_score_allow
            and device_mfa_allow
            and score >= 40
        )

        if final_allow:
            action_out = "ALLOW" if score >= 80 else "ALLOW_LIMITED"
        elif not mfa_verified and score >= 40:
            action_out = "STEP_UP_MFA"
        else:
            action_out = "BLOCK"

        return {
            "allow": final_allow,
            "action": action_out,
            "reasons": reasons,
            "engine": "OPA_IN_PROCESS",
        }

    @classmethod
    def evaluate_sync(cls, input_doc: dict[str, Any]) -> dict[str, Any]:
        """Synchronously evaluate OPA policy (uses in-process evaluator)."""
        return cls.evaluate_in_process(input_doc)
