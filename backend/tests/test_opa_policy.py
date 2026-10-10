"""Tests for Open Policy Agent (OPA) RBAC + ABAC policy engine."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.context import (
    ContextBundle,
    GeoLocation,
    IPReputation,
    NetworkContext,
    NetworkIntel,
    TemporalContext,
)
from app.models.base import utcnow
from app.models.enums import Sensitivity
from app.models.resource import Resource
from app.models.role import Role
from app.models.session import UserSession
from app.models.user import User
from app.services.opa_service import OPAService
from app.services.policy_engine import PolicyEngine
from tests.conftest import auth_headers, sign_in


def make_test_bundle(country: str = "IN", is_vpn: bool = False) -> ContextBundle:
    now = utcnow()
    return ContextBundle(
        request_id="test-req-id",
        method="GET",
        path="/test",
        user_agent="test-agent",
        network=NetworkContext(
            ip_address="117.192.1.1",
            geo=GeoLocation(
                ip="117.192.1.1",
                country=country,
                city="Coimbatore",
                latitude=11.0,
                longitude=76.9,
                resolved=True,
                provider="test",
            ),
            intel=NetworkIntel(
                asn="AS9829",
                is_vpn=is_vpn,
                is_proxy=is_vpn,
            ),
            reputation=IPReputation(ip="117.192.1.1", provider="test"),
        ),
        temporal=TemporalContext(
            at=now,
            local_time=now,
            hour_of_day=14,
            day_of_week=2,
            is_weekend=False,
            is_business_hours=True,
        ),
    )


def test_opa_admin_allowed_all_resources(db: Session, admin: User, catalogue: dict[str, Resource]):
    """Admin role should pass RBAC + ABAC clearance on any resource."""
    resource = catalogue["payroll-db"]
    session = UserSession(user_id=admin.id, mfa_passed=True)
    bundle = make_test_bundle()

    result = PolicyEngine.evaluate_with_opa(
        user=admin,
        session=session,
        resource=resource,
        action="read",
        score=95.0,
        bundle=bundle,
        device_known=True,
    )

    assert result["allow"] is True
    assert result["action"] == "ALLOW"
    assert "engine" in result


def test_opa_employee_allowed_public_resource(
    db: Session, user: User, catalogue: dict[str, Resource]
):
    """Employee should be allowed to access public resources."""
    resource = catalogue["public-docs"]
    session = UserSession(user_id=user.id, mfa_passed=True)
    bundle = make_test_bundle()

    result = PolicyEngine.evaluate_with_opa(
        user=user,
        session=session,
        resource=resource,
        action="read",
        score=90.0,
        bundle=bundle,
        device_known=True,
    )

    assert result["allow"] is True
    assert result["action"] == "ALLOW"


def test_opa_abac_department_match_allows_payroll(
    db: Session, roles: dict[str, Role], catalogue: dict[str, Resource]
):
    """User in Finance department should clear ABAC department check for payroll."""
    resource = catalogue["payroll-db"]
    finance_user = User(
        username="finance.specialist",
        email="finance@example.com",
        full_name="Finance Specialist",
        department="Finance",
        hashed_password="hash",
        role_id=roles["admin"].id,
    )
    finance_user.role = roles["admin"]
    session = UserSession(user_id=finance_user.id, mfa_passed=True)
    bundle = make_test_bundle()

    result = PolicyEngine.evaluate_with_opa(
        user=finance_user,
        session=session,
        resource=resource,
        action="read",
        score=92.0,
        bundle=bundle,
        device_known=True,
    )

    assert result["allow"] is True


def test_opa_abac_department_mismatch_denies_payroll(
    db: Session, roles: dict[str, Role], catalogue: dict[str, Resource]
):
    """Non-admin user in Engineering department should be denied payroll-db via ABAC."""
    resource = catalogue["payroll-db"]
    # Create a role with high clearance and read permission but non-admin
    role = Role(
        name="senior_engineer",
        description="Senior Eng",
        is_admin=False,
        max_sensitivity_ordinal=3,  # can reach restricted
        permissions=["resources:read"],
    )
    db.add(role)
    db.flush()

    eng_user = User(
        username="eng.lead",
        email="eng@example.com",
        full_name="Eng Lead",
        department="Engineering",
        hashed_password="hash",
        role_id=role.id,
    )
    session = UserSession(user_id=eng_user.id, mfa_passed=True)
    bundle = make_test_bundle()

    result = PolicyEngine.evaluate_with_opa(
        user=eng_user,
        session=session,
        resource=resource,
        action="read",
        score=92.0,
        bundle=bundle,
        device_known=True,
    )

    assert result["allow"] is False
    assert any("Department attribute mismatch" in r for r in result["reasons"])


def test_opa_trust_score_below_floor_denies_access(
    db: Session, admin: User, catalogue: dict[str, Resource]
):
    """Trust score below resource sensitivity floor should be denied."""
    resource = catalogue["payroll-db"]  # requires 90 floor
    session = UserSession(user_id=admin.id, mfa_passed=True)
    bundle = make_test_bundle()

    result = PolicyEngine.evaluate_with_opa(
        user=admin,
        session=session,
        resource=resource,
        action="read",
        score=65.0,  # below 90
        bundle=bundle,
        device_known=True,
    )

    assert result["allow"] is False
    assert any("below sensitivity floor" in r for r in result["reasons"])


def test_opa_missing_mfa_triggers_step_up(
    db: Session, admin: User, catalogue: dict[str, Resource]
):
    """Non-public resource without verified MFA should trigger step-up recommendation."""
    resource = catalogue["hr-portal"]
    session = UserSession(user_id=admin.id, mfa_passed=False)
    bundle = make_test_bundle()

    result = PolicyEngine.evaluate_with_opa(
        user=admin,
        session=session,
        resource=resource,
        action="read",
        score=70.0,
        bundle=bundle,
        device_known=True,
    )

    assert result["allow"] is False
    assert result["action"] == "STEP_UP_MFA"


def test_api_policy_check_endpoint(
    client: TestClient, admin: User, catalogue: dict[str, Resource]
):
    """Continuous verification API endpoint `/api/policies/check` should evaluate and return decision."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post(
        "/api/policies/check",
        json={"resource": "public-docs", "action": "read"},
        headers=headers,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data.get("decision") in ("allow", "deny")
    assert data.get("granted") is True
    assert "trust_score" in data
    assert "reasons" in data
    assert "engine" in data


def test_api_policy_check_resource_not_found(client: TestClient, admin: User):
    """Checking a non-existent resource should return 404."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    resp = client.post(
        "/api/policies/check",
        json={"resource": "non-existent-resource-12345", "action": "read"},
        headers=headers,
    )

    assert resp.status_code == 404
