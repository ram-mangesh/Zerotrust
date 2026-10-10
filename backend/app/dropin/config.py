"""Configuration and route policy mapping for Drop-In Reverse Proxy."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class RouteRule(BaseModel):
    path_prefix: str = Field(..., description="URL path prefix to match, e.g. /api or /admin")
    upstream_url: Optional[str] = Field(None, description="Specific upstream target for this prefix if multi-target")
    min_trust_score: float = Field(default=30.0, description="Minimum trust score required (0-100)")
    require_mfa: bool = Field(default=False, description="Whether MFA is mandatory")
    allowed_roles: List[str] = Field(default_factory=lambda: ["admin", "security_analyst", "user", "guest"])
    sensitivity: str = Field(default="low", description="Resource sensitivity tier (low, medium, high, critical)")


class DropInProxyConfig(BaseModel):
    default_upstream: str = Field(default="http://localhost:3000", description="Default upstream backend URL")
    listen_host: str = Field(default="0.0.0.0", description="Gateway host interface")
    listen_port: int = Field(default=8080, description="Gateway port")
    enable_html_injection: bool = Field(default=True, description="Auto-inject SDK into HTML")
    enable_waf: bool = Field(default=True, description="Enable Layer 7 WAF filter")
    enable_device_binding: bool = Field(default=True, description="Enforce ECDSA device binding")
    public_paths: List[str] = Field(
        default_factory=lambda: [
            "/favicon.ico",
            "/robots.txt",
            "/__ztna/ztna-sdk.js",
            "/__ztna/login",
            "/__ztna/auth",
            "/__ztna/health",
        ]
    )
    rules: List[RouteRule] = Field(
        default_factory=lambda: [
            RouteRule(path_prefix="/admin", min_trust_score=70.0, require_mfa=True, allowed_roles=["admin"], sensitivity="critical"),
            RouteRule(path_prefix="/api/finance", min_trust_score=60.0, require_mfa=True, allowed_roles=["admin", "security_analyst"], sensitivity="high"),
            RouteRule(path_prefix="/api", min_trust_score=40.0, require_mfa=False, allowed_roles=["admin", "security_analyst", "user"], sensitivity="medium"),
            RouteRule(path_prefix="/", min_trust_score=30.0, require_mfa=False, allowed_roles=["admin", "security_analyst", "user", "guest"], sensitivity="low"),
        ]
    )
