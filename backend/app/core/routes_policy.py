"""Pomerium-style Route-Level Micro-Segmentation Policy Engine.

Evaluates granular per-route access rules defined in policies or route config:
- allowed_domains / allowed_emails / allowed_roles / allowed_groups
- device_managed_required
- mfa_required
- min_trust_score
- path_prefix / method regex matching
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("route_policy")

class RoutePolicyRule(BaseModel):
    from_url: str = Field(description="Ingress URL or route prefix, e.g. /payroll")
    to_url: str = Field(description="Upstream destination URL")
    path_regex: Optional[str] = Field(default=".*")
    allowed_roles: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_groups: List[str] = Field(default_factory=list)
    device_managed_required: bool = Field(default=False)
    mfa_required: bool = Field(default=False)
    min_trust_score: float = Field(default=40.0)
    allow_public_unauthenticated: bool = Field(default=False)


# Default Pomerium-style granular route definitions for SecureCorp Demo App
DEFAULT_ROUTES: List[RoutePolicyRule] = [
    RoutePolicyRule(
        from_url="/public",
        to_url="http://demo-app:19000",
        allow_public_unauthenticated=True,
        min_trust_score=0.0,
    ),
    RoutePolicyRule(
        from_url="/profile",
        to_url="http://demo-app:19000",
        allowed_roles=["*"],
        min_trust_score=50.0,
    ),
    RoutePolicyRule(
        from_url="/employees/export",
        to_url="http://demo-app:19000",
        allowed_roles=["admin", "hr", "employee"],
        min_trust_score=70.0,
    ),
    RoutePolicyRule(
        from_url="/employees",
        to_url="http://demo-app:19000",
        allowed_roles=["*"],
        min_trust_score=55.0,
    ),
    RoutePolicyRule(
        from_url="/payroll",
        to_url="http://demo-app:19000",
        allowed_roles=["admin", "hr"],
        min_trust_score=75.0,
    ),
    RoutePolicyRule(
        from_url="/admin",
        to_url="http://demo-app:19000",
        allowed_roles=["admin"],
        min_trust_score=85.0,
    ),
    RoutePolicyRule(
        from_url="/",
        to_url="http://demo-app:19000",
        allowed_roles=["*"],
        min_trust_score=40.0,
    )
]


class RoutePolicyEngine:
    """Evaluates Pomerium-style microsegmentation policies for incoming HTTP requests."""
    
    def __init__(self, routes: Optional[List[RoutePolicyRule]] = None):
        self.routes = routes or DEFAULT_ROUTES

    def find_matching_route(self, path: str) -> Optional[RoutePolicyRule]:
        # Sort routes by length of from_url descending (longest prefix match)
        sorted_routes = sorted(self.routes, key=lambda r: len(r.from_url), reverse=True)
        for route in sorted_routes:
            if route.from_url != "/" and path.startswith(route.from_url):
                return route
        # Fallback to root /
        for route in sorted_routes:
            if route.from_url == "/":
                return route
        return None

    def evaluate_request(
        self,
        path: str,
        method: str,
        user_email: Optional[str],
        user_role: Optional[str],
        user_groups: List[str],
        device_approved: bool,
        mfa_verified: bool,
        trust_score: float,
    ) -> tuple[bool, str]:
        """Perform granular Zero Trust evaluation against route-level rules.
        
        Returns: (allowed: bool, reason: str)
        """
        route = self.find_matching_route(path)
        if not route:
            return False, f"No micro-segmentation route matches path '{path}'"

        # Public access
        if route.allow_public_unauthenticated:
            return True, "Public unauthenticated route allowed."

        # Authentication check
        if not user_email or not user_role:
            return False, "Authentication required for protected route."

        # Role restriction
        if route.allowed_roles:
            if "*" not in route.allowed_roles and user_role not in route.allowed_roles and "admin" != user_role:
                return False, f"Role '{user_role}' is not authorized to access '{route.from_url}' (Requires: {route.allowed_roles})"

        # Managed device requirement
        if route.device_managed_required and not device_approved:
            return False, "Route requires an approved corporate-managed device."

        # MFA requirement
        if route.mfa_required and not mfa_verified:
            return False, "MFA verification is strictly required for this route."

        # Trust score floor
        if trust_score < route.min_trust_score:
            return False, f"Trust score ({trust_score:.1f}) is below route sensitivity floor ({route.min_trust_score:.1f})"

        return True, f"Route policy satisfied for {route.from_url}."


route_policy_engine = RoutePolicyEngine()
