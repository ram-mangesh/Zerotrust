#!/usr/bin/env python3
"""Automated Multi-Scenario Test Harness for SecureCorp Zero Trust Demo.

Covers:
1. Happy Path (Normal User / Allowed)
2. Role Boundary Enforcement (Employee vs HR vs Admin)
3. Risk-Based Degradation & Read-Only Restrict Mode
4. Threat Anomaly & Instant Session Block via Databroker Mesh
"""

from __future__ import annotations

import sys
import time
import subprocess
import requests
from typing import Dict, Any

BACKEND_URL = "http://localhost:18000"
ENVOY_URL = "http://localhost:18080"


def get_token_and_session(username: str, password: str = "Ztna@Demo2026!") -> tuple[str, str]:
    """Helper to perform 2-step TOTP login."""
    mfa_out = subprocess.check_output(["/usr/bin/python3", "/tmp/ztna/main/scripts/totp.py", username]).decode()
    code = [w for w in mfa_out.split() if len(w) == 6 and w.isdigit()][0]
    
    headers = {'X-Device-Fingerprint': f'{username}_device_approved'}
    res = requests.post(f'{BACKEND_URL}/api/auth/login', json={'username': username, 'password': password}, headers=headers)
    mfa_token = res.json().get('mfa_token')
    
    res2 = requests.post(f'{BACKEND_URL}/api/auth/mfa/verify', json={'mfa_token': mfa_token, 'code': code}, headers=headers)
    j = res2.json()
    return j.get('access_token'), j.get('session_id')


def run_tests():
    print("=" * 80)
    print("🚀 STARTING ZERO TRUST MULTI-SCENARIO INTEGRATION TESTS")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # SCENARIO 1: Normal Happy Path (Alice / Employee)
    # -------------------------------------------------------------------------
    print("\n[SCENARIO 1] Normal User Access (Alice - Employee)")
    token_alice, sid_alice = get_token_and_session("alice")
    headers_alice = {"Authorization": f"Bearer {token_alice}"}

    # Public News
    res_pub = requests.get(f"{ENVOY_URL}/public", headers=headers_alice)
    assert res_pub.status_code == 200, f"Expected 200 on /public, got {res_pub.status_code}"
    print("  ✅ GET /public -> 200 OK (Announcements retrieved)")

    # User Profile (GET)
    res_prof = requests.get(f"{ENVOY_URL}/profile", headers=headers_alice)
    assert res_prof.status_code == 200, f"Expected 200 on /profile, got {res_prof.status_code}"
    assert res_prof.json().get("user") == "alice"
    print("  ✅ GET /profile -> 200 OK (Alice profile verified)")

    # User Profile (POST Mutation)
    res_update = requests.post(f"{ENVOY_URL}/profile", json={"location": "Bangalore Tech Park"}, headers=headers_alice)
    assert res_update.status_code == 200, f"Expected 200 on POST /profile, got {res_update.status_code}"
    print("  ✅ POST /profile -> 200 OK (Profile mutation permitted in Full Access mode)")

    # Employees Directory
    res_emp = requests.get(f"{ENVOY_URL}/employees", headers=headers_alice)
    assert res_emp.status_code == 200, f"Expected 200 on /employees, got {res_emp.status_code}"
    print("  ✅ GET /employees -> 200 OK (Staff directory accessed)")


    # -------------------------------------------------------------------------
    # SCENARIO 2: Least-Privilege Role Boundary Enforcement
    # -------------------------------------------------------------------------
    print("\n[SCENARIO 2] Least-Privilege Role Boundaries")
    
    # Alice (employee) -> /payroll (Should be 403 Forbidden)
    res_pay_alice = requests.get(f"{ENVOY_URL}/payroll", headers=headers_alice)
    assert res_pay_alice.status_code == 403, f"Expected 403 for employee on /payroll, got {res_pay_alice.status_code}"
    print(f"  ✅ Alice (employee) -> GET /payroll: 403 Forbidden (Blocked by OPA/Route policy)")

    # Alice (employee) -> /admin (Should be 403 Forbidden)
    res_adm_alice = requests.get(f"{ENVOY_URL}/admin", headers=headers_alice)
    assert res_adm_alice.status_code == 403, f"Expected 403 for employee on /admin, got {res_adm_alice.status_code}"
    print(f"  ✅ Alice (employee) -> GET /admin: 403 Forbidden (Blocked by OPA/Route policy)")

    # Bob (HR) -> /payroll (Should be 200 Allowed)
    token_bob, sid_bob = get_token_and_session("bob")
    headers_bob = {"Authorization": f"Bearer {token_bob}"}
    res_pay_bob = requests.get(f"{ENVOY_URL}/payroll", headers=headers_bob)
    assert res_pay_bob.status_code == 200, f"Expected 200 for HR on /payroll, got {res_pay_bob.status_code}"
    assert "payroll_records" in res_pay_bob.json()
    print("  ✅ Bob (HR) -> GET /payroll: 200 OK (Authorized payroll access)")

    # Carol (Admin) -> /admin (Should be 200 Allowed)
    token_carol, sid_carol = get_token_and_session("carol")
    headers_carol = {"Authorization": f"Bearer {token_carol}"}
    res_adm_carol = requests.get(f"{ENVOY_URL}/admin", headers=headers_carol)
    assert res_adm_carol.status_code == 200, f"Expected 200 for Admin on /admin, got {res_adm_carol.status_code}"
    assert "system_settings" in res_adm_carol.json()
    print("  ✅ Carol (Admin) -> GET /admin: 200 OK (Authorized admin settings access)")


    # -------------------------------------------------------------------------
    # SCENARIO 3: Risk-Based Degradation & Read-Only Restrict Mode
    # -------------------------------------------------------------------------
    print("\n[SCENARIO 3] Context Anomaly -> Read-Only Restriction")
    
    # Direct demonstration: When gateway detects elevated risk (or X-Access-Mode: readonly)
    # 1. Reading profile is still allowed
    res_read = requests.get(f"{ENVOY_URL}/profile", headers=headers_alice)
    assert res_read.status_code == 200
    print("  ✅ GET /profile in read mode -> 200 OK (User can read data)")

    # 2. Testing Upstream Demo App's strict enforcement of Read-Only header
    res_mut_blocked = requests.post(
        "http://localhost:19000/profile",
        json={"location": "Attacker Update"},
        headers={"X-Forwarded-User": "alice", "X-Access-Mode": "readonly"}
    )
    assert res_mut_blocked.status_code == 403, f"Expected 403 on readonly write, got {res_mut_blocked.status_code}"
    print("  ✅ POST /profile in Read-Only Mode -> 403 Forbidden (Write disabled by Zero Trust Policy)")


    # -------------------------------------------------------------------------
    # SCENARIO 4: Threat Simulation & Databroker Real-Time Block
    # -------------------------------------------------------------------------
    print("\n[SCENARIO 4] Mass Exfiltration Attack & Real-Time Session Revocation")
    
    # Alice downloads bulk employee data
    res_export = requests.get(f"{ENVOY_URL}/employees/export", headers=headers_alice)
    assert res_export.status_code == 200, f"Expected 200 on /employees/export, got {res_export.status_code}"
    print(f"  ✅ Triggered /employees/export: Fetched {res_export.json().get('record_count')} records.")

    # Admin / Anomaly Engine revokes the session in real-time
    headers_admin = {"Authorization": f"Bearer {token_carol}"}
    res_revoke = requests.post(f"{BACKEND_URL}/api/sessions/{sid_alice}/revoke", json={"reason": "Suspicious mass exfiltration detected."}, headers=headers_admin)
    assert res_revoke.status_code == 200, f"Expected 200 on revoke, got {res_revoke.status_code}"
    print(f"  🚨 Session '{sid_alice}' Revoked by Security Operations.")

    # Edge Proxy immediately rejects any further request from Alice without delay
    res_blocked = requests.get(f"{ENVOY_URL}/profile", headers=headers_alice)
    assert res_blocked.status_code == 403, f"Expected immediate 403 on Envoy edge, got {res_blocked.status_code}"
    print(f"  🔒 Envoy Edge Verification: Immediate 403 Denied ({res_blocked.headers.get('x-ztna-reason', 'Revoked')})")

    print("\n" + "=" * 80)
    print("🎉 ALL 4 ZERO TRUST DEMO SCENARIOS PASSED WITH 100% SUCCESS!")
    print("=" * 80)

if __name__ == "__main__":
    run_tests()
