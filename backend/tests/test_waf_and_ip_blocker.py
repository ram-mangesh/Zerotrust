"""Tests for Web Application Firewall (WAF) and IP Blocker middleware."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.middleware.ip_blocker import clear_waf_hits
from app.models.alert import Alert
from app.models.blocked_ip import BlockedIP
from app.models.user import User
from tests.conftest import auth_headers, sign_in


def test_waf_blocks_sqli_query_param(client: TestClient, db: Session):
    """WAF should inspect URL query parameters and block SQL injection."""
    resp = client.get("/api/resources?query=UNION+SELECT+1,2,3,4,5--")
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("code") == "waf_blocked"
    assert data.get("threat_type") == "sql_injection"
    assert resp.headers.get("X-WAF-Blocked") == "sql_injection"
    assert "X-WAF-Risk-Score" in resp.headers


def test_waf_blocks_sqli_json_body(client: TestClient, db: Session):
    """WAF should inspect JSON body payloads for SQL injection."""
    resp = client.post(
        "/api/auth/login",
        json={
            "username": "admin' OR 1=1 --",
            "password": "some_password",
        },
    )
    assert resp.status_code == 403
    assert resp.json().get("threat_type") == "sql_injection"


def test_waf_blocks_xss_payload(client: TestClient, db: Session):
    """WAF should block Cross-Site Scripting (XSS) patterns."""
    resp = client.get("/api/resources?search=<script>alert(document.cookie)</script>")
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("code") == "waf_blocked"
    assert data.get("threat_type") == "xss"


def test_waf_blocks_path_traversal(client: TestClient, db: Session):
    """WAF should block path traversal payloads."""
    resp = client.get("/api/resources/..%2f..%2fetc/passwd")
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("code") == "waf_blocked"
    assert data.get("threat_type") == "path_traversal"


def test_waf_blocks_command_injection(client: TestClient, db: Session):
    """WAF should block OS command injection attempts."""
    resp = client.get("/api/resources?cmd=test.sh;+whoami")
    assert resp.status_code == 403
    data = resp.json()
    assert data.get("code") == "waf_blocked"
    assert data.get("threat_type") == "command_injection"


def test_waf_logs_alert_in_database(client: TestClient, db: Session):
    """WAF blocks should generate an Alert in the database."""
    client.get("/api/resources?q=DROP+TABLE+users--")
    alert = db.query(Alert).filter(Alert.category == "waf_sql_injection").first()
    assert alert is not None
    assert alert.severity.value in ("HIGH", "CRITICAL")
    assert "threat_type" in alert.evidence


def test_clean_request_allowed_by_waf(client: TestClient):
    """Normal legitimate requests should pass through without WAF interference."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "X-WAF-Blocked" not in resp.headers


def test_ip_blocker_blocks_listed_ip(client: TestClient, db: Session):
    """IPBlockerMiddleware should block any IP present in the blocked_ips table."""
    blocked_ip = "198.51.100.42"
    db.add(BlockedIP(ip_address=blocked_ip, reason="Malicious activity"))
    db.commit()

    resp = client.get("/api/resources", headers={"X-Forwarded-For": blocked_ip})
    assert resp.status_code == 403
    assert resp.json().get("code") == "ip_blocked"
    assert resp.headers.get("X-IP-Blocked") == "1"


def test_ip_blocker_exempt_health_routes(client: TestClient, db: Session):
    """Health endpoints should remain reachable even for blocked IPs for monitoring."""
    blocked_ip = "198.51.100.43"
    db.add(BlockedIP(ip_address=blocked_ip, reason="Test block"))
    db.commit()

    resp = client.get("/health", headers={"X-Forwarded-For": blocked_ip})
    assert resp.status_code == 200


def test_blocked_ips_admin_api(
    client: TestClient, db: Session, admin: User
):
    """Admins should be able to list, add, and remove blocked IPs via API."""
    tokens = sign_in(client, admin)
    headers = auth_headers(tokens)

    # 1. Block an IP
    target_ip = "203.0.113.88"
    resp = client.post(
        "/api/blocked-ips",
        json={
            "ip_address": target_ip,
            "reason": "Automated security test",
            "duration_minutes": 120,
        },
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.json().get("ip_address") == target_ip

    # 2. List blocked IPs
    list_resp = client.get("/api/blocked-ips", headers=headers)
    assert list_resp.status_code == 200
    ips = [item["ip_address"] for item in list_resp.json()]
    assert target_ip in ips

    # 3. Verify target IP is blocked on subsequent requests
    blocked_check = client.get(
        "/api/resources", headers={"X-Forwarded-For": target_ip}
    )
    assert blocked_check.status_code == 403
    assert blocked_check.json().get("code") == "ip_blocked"

    # 4. Unblock IP
    del_resp = client.delete(f"/api/blocked-ips/{target_ip}", headers=headers)
    assert del_resp.status_code == 204

    # 5. Verify IP is no longer blocked
    unblocked_check = client.get(
        "/api/resources", headers={"X-Forwarded-For": target_ip}
    )
    assert unblocked_check.status_code != 403 or unblocked_check.json().get("code") != "ip_blocked"
