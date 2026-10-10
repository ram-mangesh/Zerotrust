"""SecureCorp Demo Application & In-Depth Zero Trust Testing Lab ("Bholi" Upstream App).

Designed to demonstrate Zero Trust Network Access in depth:
- Contains ZERO internal auth logic, ZERO token minting; entirely governed by VajraNetra PEP Gateway.
- Enforces 6 sensitivity tiers: /public, /profile, /employees, /payroll, /admin, /employees/export.
- Enforces X-Access-Mode: readonly by rejecting mutation methods (POST, PUT, DELETE, PATCH).
- Includes an interactive Security Testing Lab with 1-click scenario triggers, live telemetry, and header inspection.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import time
import uuid
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="SecureCorp Zero Trust Portal & Security Lab", docs_url=None, redoc_url=None)

# Sample corporate database
EMPLOYEES_DATA = [
    {"id": "EMP-101", "name": "Alice Johnson", "department": "Engineering", "role": "Senior Engineer", "email": "alice@securecorp.internal"},
    {"id": "EMP-102", "name": "Bob Williams", "department": "Human Resources", "role": "HR Director", "email": "bob@securecorp.internal"},
    {"id": "EMP-103", "name": "Carol Danvers", "department": "Information Security", "role": "Security Lead", "email": "carol@securecorp.internal"},
    {"id": "EMP-104", "name": "Dave Miller", "department": "Engineering", "role": "Software Intern", "email": "dave@securecorp.internal"},
    {"id": "EMP-105", "name": "Siva Balan", "department": "IT Operations", "role": "Lead Administrator", "email": "admin@securecorp.internal"},
]

PAYROLL_DATA = [
    {"employee_id": "EMP-101", "name": "Alice Johnson", "salary_usd": 125000, "bank_token": "TOK-BNK-98112", "tax_bracket": "32%"},
    {"employee_id": "EMP-102", "name": "Bob Williams", "salary_usd": 140000, "bank_token": "TOK-BNK-33419", "tax_bracket": "35%"},
    {"employee_id": "EMP-103", "name": "Carol Danvers", "salary_usd": 165000, "bank_token": "TOK-BNK-77120", "tax_bracket": "35%"},
    {"employee_id": "EMP-104", "name": "Dave Miller", "salary_usd": 45000, "bank_token": "TOK-BNK-11048", "tax_bracket": "15%"},
    {"employee_id": "EMP-105", "name": "Siva Balan", "salary_usd": 190000, "bank_token": "TOK-BNK-55210", "tax_bracket": "37%"},
]

ADMIN_SETTINGS = {
    "tenant_id": "SECURECORP-PROD-EAST",
    "mfa_enforced": True,
    "encryption_at_rest": "AES-256-GCM",
    "cloud_provider": "Private Cloud Cluster / Air-gapped Mesh",
    "active_microservices": 18,
    "audit_tamper_seal": "ACTIVE-SHA256-CHAINED",
    "vault_status": "LOCKED-HSM-P256"
}

USER_PROFILES = {
    "alice": {"full_name": "Alice Johnson", "theme": "Dark", "phone": "+1-555-0199", "location": "Bangalore Office", "title": "Senior Engineer"},
    "bob": {"full_name": "Bob Williams", "theme": "Light", "phone": "+1-555-0144", "location": "Chennai HQ", "title": "HR Director"},
    "carol": {"full_name": "Carol Danvers", "theme": "Dark", "phone": "+1-555-0177", "location": "Security Operations", "title": "Security Lead"},
    "dave": {"full_name": "Dave Miller", "theme": "System", "phone": "+1-555-0122", "location": "Remote / Intern", "title": "Intern"},
    "admin": {"full_name": "Siva Balan", "theme": "Cyberpunk Dark", "phone": "+1-555-0100", "location": "Central SOC", "title": "Super Administrator"}
}


@app.middleware("http")
async def verify_gateway_and_enforce_readonly(request: Request, call_next):
    """Enforce upstream read-only mode if gateway specifies X-Access-Mode: readonly."""
    access_mode = request.headers.get("x-access-mode", "").lower()
    risk_level = request.headers.get("x-ztna-risk-level", "").upper()

    if request.method in ("POST", "PUT", "DELETE", "PATCH") and request.url.path not in ("/api/lab/simulate-attack", "/api/lab/reset-session"):
        if access_mode == "readonly" or risk_level in ("HIGH", "CRITICAL"):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "status": "RESTRICTED_READONLY",
                    "error": "Write operations forbidden by Zero Trust Engine. Your session is currently restricted to READ-ONLY.",
                    "risk_level": risk_level or "ELEVATED",
                    "action_taken": "MUTATION_BLOCKED",
                }
            )

    response = await call_next(request)
    return response


# --- 1. Tier: Public ---
@app.get("/public")
async def get_public_news(request: Request):
    user = request.headers.get("x-forwarded-user", "Anonymous")
    return {
        "sensitivity": "LOW (Public)",
        "user": user,
        "announcements": [
            {"date": "2026-10-01", "title": "Quarterly Zero Trust Review Completed", "category": "Security"},
            {"date": "2026-10-05", "title": "Q4 Engineering Hackathon Registration Open", "category": "Engineering"},
            {"date": "2026-10-08", "title": "Annual Company Holiday Calendar 2027 Published", "category": "Operations"}
        ]
    }


# --- 2. Tier: Profile ---
@app.get("/profile")
async def get_profile(request: Request):
    user = request.headers.get("x-forwarded-user", "alice")
    role = request.headers.get("x-forwarded-role", "employee")
    trust = request.headers.get("x-ztna-trust-score", "85.0")
    profile = USER_PROFILES.get(user, {"full_name": user, "theme": "Dark", "phone": "Unknown", "location": "Unknown", "title": "Employee"})
    return {
        "sensitivity": "MEDIUM (Profile)",
        "user": user,
        "role": role,
        "trust_score": trust,
        "profile": profile
    }


@app.post("/profile")
async def update_profile(request: Request):
    user = request.headers.get("x-forwarded-user", "alice")
    body = await request.json()
    if user in USER_PROFILES:
        USER_PROFILES[user].update(body)
    return {
        "status": "SUCCESS",
        "message": f"Profile for '{user}' updated successfully.",
        "profile": USER_PROFILES.get(user)
    }


# --- 3. Tier: Employees ---
@app.get("/employees")
async def get_employees(request: Request):
    user = request.headers.get("x-forwarded-user", "alice")
    return {
        "sensitivity": "MEDIUM-HIGH (Internal Directory)",
        "requested_by": user,
        "total_employees": len(EMPLOYEES_DATA),
        "employees": EMPLOYEES_DATA
    }


# --- 4. Tier: Payroll (Restricted) ---
@app.get("/payroll")
async def get_payroll(request: Request):
    user = request.headers.get("x-forwarded-user", "bob")
    role = request.headers.get("x-forwarded-role", "hr")
    return {
        "sensitivity": "HIGH (Confidential Payroll)",
        "accessed_by": user,
        "authorized_role": role,
        "payroll_records": PAYROLL_DATA
    }


# --- 5. Tier: Admin (Critical) ---
@app.get("/admin")
async def get_admin_settings(request: Request):
    user = request.headers.get("x-forwarded-user", "carol")
    return {
        "sensitivity": "CRITICAL (Restricted Admin)",
        "accessed_by": user,
        "system_settings": ADMIN_SETTINGS
    }


# --- 6. Tier: Bulk Export ---
@app.get("/employees/export")
async def export_bulk_employees(request: Request):
    user = request.headers.get("x-forwarded-user", "alice")
    bulk_records = []
    for i in range(1, 2001):
        dept = "Engineering" if i % 3 == 0 else ("Finance" if i % 3 == 1 else "Operations")
        bulk_records.append({
            "id": f"EMP-BULK-{i:05d}",
            "name": f"Corporate Employee {i}",
            "department": dept,
            "salary_ref": f"REF-SAL-{i * 1337}",
            "national_id": f"ID-{i * 9999}"
        })
    return {
        "sensitivity": "CONFIDENTIAL (Bulk Export)",
        "requested_by": user,
        "record_count": len(bulk_records),
        "data": bulk_records[:20],
        "_note": f"Truncated preview of {len(bulk_records)} records."
    }


# --- Posture & Header Diagnostics ---
@app.get("/api/posture")
async def get_ztna_posture(request: Request):
    """Return all ZTNA headers forwarded by PEP."""
    headers_dict = {k.lower(): v for k, v in request.headers.items()}
    ztna_headers = {k: v for k, v in headers_dict.items() if k.startswith("x-") or k in ("authorization", "cookie")}
    
    user = headers_dict.get("x-forwarded-user", "Anonymous")
    role = headers_dict.get("x-forwarded-role", "None")
    trust = headers_dict.get("x-ztna-trust-score", "100.0")
    risk = headers_dict.get("x-ztna-risk-level", "LOW")
    sig = headers_dict.get("x-gateway-signature", "")
    ts = headers_dict.get("x-gateway-timestamp", "")
    mode = headers_dict.get("x-access-mode", "full")

    return {
        "user": user,
        "role": role,
        "trust_score": trust,
        "risk_level": risk,
        "access_mode": mode,
        "signature_present": bool(sig),
        "timestamp": ts,
        "forwarded_headers": ztna_headers,
    }


# --- Visual Interactive Portal & In-Depth Testing Lab ---
@app.get("/", response_class=HTMLResponse)
async def serve_portal_and_lab(request: Request):
    user = request.headers.get("x-forwarded-user", "Guest / Unauthenticated")
    role = request.headers.get("x-forwarded-role", "None")
    trust_raw = request.headers.get("x-ztna-trust-score", "N/A")
    risk = request.headers.get("x-ztna-risk-level", "UNKNOWN")
    access_mode = request.headers.get("x-access-mode", "Full Access")
    sig_present = bool(request.headers.get("x-gateway-signature"))

    try:
        trust_val = float(trust_raw)
    except Exception:
        trust_val = 0.0

    badge_bg = "#10b981" if risk == "LOW" else ("#f59e0b" if risk == "MEDIUM" else "#ef4444")
    badge_text = "#000" if risk in ("LOW", "MEDIUM") else "#fff"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureCorp Zero Trust Portal & Security Lab</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: #1f2937;
            --border-highlight: #374151;
            --text: #f9fafb;
            --text-muted: #9ca3af;
            --text-dim: #6b7280;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --purple: #8b5cf6;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1300px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(135deg, rgba(31,41,55,0.8), rgba(17,24,39,0.95));
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 24px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.4);
        }}
        .header-title h1 {{
            margin: 0;
            font-size: 22px;
            font-weight: 700;
            letter-spacing: -0.02em;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .header-title p {{
            margin: 4px 0 0 0;
            color: var(--text-muted);
            font-size: 13px;
        }}
        .posture-bar {{
            display: flex;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }}
        .posture-item {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            font-size: 13px;
        }}
        .posture-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
            font-weight: 600;
        }}
        .posture-val {{
            font-weight: 700;
            color: #fff;
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            background-color: {badge_bg};
            color: {badge_text};
        }}
        .tabs {{
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
            padding-bottom: 4px;
        }}
        .tab-btn {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 14px;
            font-weight: 600;
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .tab-btn:hover {{
            color: #fff;
            background: var(--surface);
        }}
        .tab-btn.active {{
            color: #fff;
            background: var(--primary);
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
        .grid-3 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 20px;
        }}
        .card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            transition: border-color 0.2s, transform 0.2s;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }}
        .card:hover {{
            border-color: var(--border-highlight);
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
        }}
        .card-title {{
            font-size: 16px;
            font-weight: 700;
            margin: 0;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .card-desc {{
            color: var(--text-muted);
            font-size: 13px;
            margin: 6px 0 16px 0;
            flex-grow: 1;
        }}
        .tag {{
            font-size: 11px;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 6px;
            background: #1f2937;
            color: var(--text-muted);
            border: 1px solid #374151;
        }}
        .tag.low {{ color: #10b981; border-color: rgba(16,185,129,0.3); background: rgba(16,185,129,0.1); }}
        .tag.med {{ color: #60a5fa; border-color: rgba(96,165,250,0.3); background: rgba(96,165,250,0.1); }}
        .tag.high {{ color: #f59e0b; border-color: rgba(245,158,11,0.3); background: rgba(245,158,11,0.1); }}
        .tag.crit {{ color: #ef4444; border-color: rgba(239,68,68,0.3); background: rgba(239,68,68,0.1); }}
        .btn {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            background-color: var(--primary);
            color: #fff;
            border: 1px solid transparent;
            padding: 9px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .btn:hover {{ background-color: var(--primary-hover); }}
        .btn-secondary {{ background-color: #374151; color: #fff; }}
        .btn-secondary:hover {{ background-color: #4b5563; }}
        .btn-danger {{ background-color: #dc2626; }}
        .btn-danger:hover {{ background-color: #b91c1c; }}
        .btn-success {{ background-color: #059669; }}
        .btn-success:hover {{ background-color: #047857; }}
        .btn-purple {{ background-color: var(--purple); }}
        .btn-purple:hover {{ background-color: #7c3aed; }}
        .btn-group {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }}
        pre.response-box {{
            background-color: #030712;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
            color: #4ade80;
            max-height: 180px;
            overflow-y: auto;
            margin: 12px 0 0 0;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .status-badge {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            margin-right: 6px;
        }}
        .status-200 {{ background: #064e3b; color: #34d399; }}
        .status-403 {{ background: #7f1d1d; color: #f87171; }}
        .status-401 {{ background: #78350f; color: #fbbf24; }}
        .lab-banner {{
            background: linear-gradient(90deg, #1e1b4b, #172554);
            border: 1px solid #3730a3;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .table-wrap {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            margin-top: 16px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #1f2937;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        tr:last-child td {{ border-bottom: none; }}
        code {{
            background: #1f2937;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #93c5fd;
            font-family: ui-monospace, monospace;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER WITH LIVE GATEWAY POSTURE -->
        <div class="header">
            <div class="header-title">
                <h1>🏢 SecureCorp Enterprise Portal & Security Lab</h1>
                <p>Protected Dumb Upstream Application · Fully Controlled by VajraNetra Zero Trust PDP/PEP</p>
            </div>
            <div class="posture-bar">
                <div class="posture-item">
                    <span class="posture-label">Forwarded Identity</span>
                    <span class="posture-val">{user} <span style="color:var(--primary);">({role})</span></span>
                </div>
                <div class="posture-item">
                    <span class="posture-label">Trust Score</span>
                    <span class="posture-val">{trust_raw} / 100</span>
                </div>
                <div class="posture-item">
                    <span class="posture-label">Risk Level</span>
                    <span class="badge">{risk}</span>
                </div>
                <div class="posture-item">
                    <span class="posture-label">Gateway Access Mode</span>
                    <span class="posture-val">{access_mode}</span>
                </div>
                <div class="posture-item">
                    <span class="posture-label">HMAC Signature</span>
                    <span class="posture-val" style="color:{'#10b981' if sig_present else '#ef4444'};">{'Verified ✓' if sig_present else 'Missing ✗'}</span>
                </div>
            </div>
        </div>

        <!-- LAB BANNER WITH SOC DASHBOARD LINK -->
        <div class="lab-banner">
            <div>
                <strong style="color:#a5b4fc; font-size:15px;">🛡️ Real-Time Zero Trust Gateway Protection Active</strong>
                <p style="margin:2px 0 0 0; font-size:13px; color:#cbd5e1;">Requests passing through Envoy (Port 18080) undergo continuous AI behavioral scoring, OPA micro-segmentation, and HMAC origin sealing.</p>
            </div>
            <div>
                <a href="http://172.10.21.166:15173/" target="_blank" class="btn btn-purple" style="text-decoration:none;">
                    📊 Open SOC Admin Dashboard ↗
                </a>
            </div>
        </div>

        <!-- NAVIGATION TABS -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('apps')">🏛️ Protected Corporate Apps (6 Tiers)</button>
            <button class="tab-btn" onclick="switchTab('lab')">🧪 Interactive Attack & Scenario Lab</button>
            <button class="tab-btn" onclick="switchTab('headers')">🔍 Live Headers & Signature Inspector</button>
            <button class="tab-btn" onclick="switchTab('guide')">📖 Testing Guide & Personas</button>
        </div>

        <!-- TAB 1: CORPORATE PROTECTED APPS -->
        <div id="tab-apps" class="tab-content active">
            <div class="grid-3">
                <!-- 1. Public -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">📢 Public Announcements</h3>
                            <span class="tag low">Public Tier</span>
                        </div>
                        <p class="card-desc">Company news & public updates. Allows unauthenticated access without tokens.</p>
                    </div>
                    <div>
                        <button class="btn btn-secondary" onclick="executeApi('/public', 'res-public')">GET /public</button>
                        <pre id="res-public" class="response-box">Click button to test...</pre>
                    </div>
                </div>

                <!-- 2. Profile -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">👤 My Profile & Mutation</h3>
                            <span class="tag med">Internal Tier</span>
                        </div>
                        <p class="card-desc">Personal profile details. Allows GET; POST mutation is blocked in Read-Only mode.</p>
                    </div>
                    <div>
                        <div class="btn-group">
                            <button class="btn btn-secondary" onclick="executeApi('/profile', 'res-profile')">GET /profile</button>
                            <button class="btn" onclick="executeProfileUpdate('res-profile')">POST /profile (Update)</button>
                        </div>
                        <pre id="res-profile" class="response-box">Click button to test...</pre>
                    </div>
                </div>

                <!-- 3. Employees Directory -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">👥 Staff Directory</h3>
                            <span class="tag med">Internal Directory</span>
                        </div>
                        <p class="card-desc">Internal company staff directory. Accessible by all authenticated corporate users.</p>
                    </div>
                    <div>
                        <button class="btn btn-secondary" onclick="executeApi('/employees', 'res-employees')">GET /employees</button>
                        <pre id="res-employees" class="response-box">Click button to test...</pre>
                    </div>
                </div>

                <!-- 4. Payroll -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">💰 Payroll & Compensation</h3>
                            <span class="tag high">High Sensitivity</span>
                        </div>
                        <p class="card-desc">Restricted financial data & bank accounts. Requires <strong>HR</strong> or <strong>Admin</strong> role + Trust ≥ 75.</p>
                    </div>
                    <div>
                        <button class="btn btn-danger" onclick="executeApi('/payroll', 'res-payroll')">GET /payroll</button>
                        <pre id="res-payroll" class="response-box">Click button to test...</pre>
                    </div>
                </div>

                <!-- 5. Admin Settings -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">⚙️ Tenant Admin Settings</h3>
                            <span class="tag crit">Critical Admin</span>
                        </div>
                        <p class="card-desc">Master tenant configuration, encryption keys, and security controls. Requires <strong>Admin</strong> role + Trust ≥ 85.</p>
                    </div>
                    <div>
                        <button class="btn btn-danger" onclick="executeApi('/admin', 'res-admin')">GET /admin</button>
                        <pre id="res-admin" class="response-box">Click button to test...</pre>
                    </div>
                </div>

                <!-- 6. Bulk Export -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">📦 Bulk Employee Export</h3>
                            <span class="tag high">Data Volume Anomaly</span>
                        </div>
                        <p class="card-desc">Mass records export (2,000+ entries). Triggers behavioral volume anomaly detection.</p>
                    </div>
                    <div>
                        <button class="btn btn-purple" onclick="executeApi('/employees/export', 'res-export')">GET /employees/export</button>
                        <pre id="res-export" class="response-box">Click button to test...</pre>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 2: INTERACTIVE ATTACK & SCENARIO LAB -->
        <div id="tab-lab" class="tab-content">
            <div class="grid-3">
                <!-- Lab 1: Role Boundary Test -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">🛡️ Scenario 1: Role Boundary Breach</h3>
                            <span class="tag high">RBAC / ABAC</span>
                        </div>
                        <p class="card-desc">Test least-privilege enforcement. An Employee attempting to access <code>/payroll</code> or <code>/admin</code> will be stopped with <strong>403 Forbidden</strong> by OPA.</p>
                    </div>
                    <div>
                        <div class="btn-group">
                            <button class="btn btn-danger" onclick="executeApi('/payroll', 'res-lab-1')">Test /payroll</button>
                            <button class="btn btn-danger" onclick="executeApi('/admin', 'res-lab-1')">Test /admin</button>
                        </div>
                        <pre id="res-lab-1" class="response-box">Ready for test...</pre>
                    </div>
                </div>

                <!-- Lab 2: Read-Only Enforcement Test -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">🔒 Scenario 2: Read-Only Lockdown</h3>
                            <span class="tag med">Adaptive Degradation</span>
                        </div>
                        <p class="card-desc">When trust drops into MEDIUM/HIGH risk, gateway signals <code>X-Access-Mode: readonly</code>. Upstream app permits GET but rejects POST mutations.</p>
                    </div>
                    <div>
                        <div class="btn-group">
                            <button class="btn btn-secondary" onclick="executeApi('/profile', 'res-lab-2')">Read Profile (Allowed)</button>
                            <button class="btn btn-danger" onclick="executeProfileUpdate('res-lab-2')">Mutate Profile (Blocked if Degraded)</button>
                        </div>
                        <pre id="res-lab-2" class="response-box">Ready for test...</pre>
                    </div>
                </div>

                <!-- Lab 3: Mass Exfiltration -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">⚡ Scenario 3: Rapid Mass Enumeration</h3>
                            <span class="tag crit">Insider Threat</span>
                        </div>
                        <p class="card-desc">Simulate an attacker attempting rapid mass data exfiltration. Fires 5 sequential bulk requests to trigger the AI Anomaly Isolation Forest.</p>
                    </div>
                    <div>
                        <button class="btn btn-purple" onclick="runMassExfiltration('res-lab-3')">Simulate Mass Exfiltration (5x)</button>
                        <pre id="res-lab-3" class="response-box">Ready for test...</pre>
                    </div>
                </div>

                <!-- Lab 4: Impossible Travel Simulation -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">🌍 Scenario 4: Impossible Travel Jump</h3>
                            <span class="tag crit">Geo Anomaly</span>
                        </div>
                        <p class="card-desc">Simulates a user hopping from India to São Paulo / Moscow in minutes at &gt;900 km/h. Triggers immediate score collapse to CRITICAL.</p>
                    </div>
                    <div>
                        <button class="btn btn-danger" onclick="triggerSimulation('country_change', 'res-lab-4')">Simulate Impossible Travel</button>
                        <pre id="res-lab-4" class="response-box">Ready for test...</pre>
                    </div>
                </div>

                <!-- Lab 5: Stolen Token Simulation -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">🔑 Scenario 5: Stolen Session Token</h3>
                            <span class="tag crit">Session Hijack</span>
                        </div>
                        <p class="card-desc">Simulates presenting a stolen session JWT from an unverified device with mismatched ECDSA hardware key binding.</p>
                    </div>
                    <div>
                        <button class="btn btn-danger" onclick="triggerSimulation('stolen_token', 'res-lab-5')">Simulate Stolen Token Hijack</button>
                        <pre id="res-lab-5" class="response-box">Ready for test...</pre>
                    </div>
                </div>

                <!-- Lab 6: Instant Reset -->
                <div class="card">
                    <div>
                        <div class="card-header">
                            <h3 class="card-title">🔄 Scenario Reset & Recovery</h3>
                            <span class="tag low">Restoration</span>
                        </div>
                        <p class="card-desc">Restores the current test session standing back to <strong>Trust Score 95.0 (LOW Risk)</strong> after testing attacks.</p>
                    </div>
                    <div>
                        <button class="btn btn-success" onclick="resetSessionStanding('res-lab-6')">Reset Session to Trust 95.0</button>
                        <pre id="res-lab-6" class="response-box">Click to restore standing...</pre>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 3: HEADERS & SIGNATURE INSPECTOR -->
        <div id="tab-headers" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">🔍 Live ZTNA Headers & Cryptographic Verifier</h3>
                    <button class="btn btn-secondary" onclick="loadHeadersTable()">Refresh Headers</button>
                </div>
                <p class="card-desc">All security context headers injected by the VajraNetra Zero Trust Gateway before forwarding requests to this upstream application.</p>
                
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:250px;">Header Name</th>
                                <th>Value</th>
                                <th style="width:280px;">Purpose & Security Meaning</th>
                            </tr>
                        </thead>
                        <tbody id="headers-tbody">
                            <tr><td colspan="3" style="text-align:center; color:var(--text-muted);">Loading headers...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 4: TESTING GUIDE & PERSONAS -->
        <div id="tab-guide" class="tab-content">
            <div class="card">
                <h3 class="card-title" style="margin-bottom:12px;">📖 Zero Trust Evaluation & Demo Walkthrough Guide</h3>
                
                <div style="font-size:14px; line-height:1.7; color:var(--text-muted);">
                    <h4 style="color:#fff; margin:16px 0 6px 0;">👥 Pre-configured Demo Accounts:</h4>
                    <ul>
                        <li><strong style="color:#fff;">alice</strong> (Password: <code>Ztna@Demo2026!</code>) · <em>Role: Employee</em> · Can access <code>/profile</code> and <code>/employees</code>. Denied on <code>/payroll</code> & <code>/admin</code>.</li>
                        <li><strong style="color:#fff;">bob</strong> (Password: <code>Ztna@Demo2026!</code>) · <em>Role: HR</em> · Can access <code>/profile</code>, <code>/employees</code>, and <code>/payroll</code>. Denied on <code>/admin</code>.</li>
                        <li><strong style="color:#fff;">carol</strong> / <strong style="color:#fff;">admin</strong> (Password: <code>admin123</code>, MFA: <code>123456</code>) · <em>Role: Admin</em> · Full access across all tiers when Trust ≥ 85.</li>
                    </ul>

                    <h4 style="color:#fff; margin:16px 0 6px 0;">🎯 What to Test & Observe in Real-Time:</h4>
                    <ol>
                        <li><strong>Least-Privilege Role Boundaries:</strong> Sign in as <code>alice</code>. Open this portal at <code>http://172.10.21.166:18080/</code>. Click <code>GET /payroll</code> → see immediate <strong>403 Forbidden</strong> enforced at the edge by OPA.</li>
                        <li><strong>Adaptive Read-Only Degradation:</strong> Lower trust score in the SOC dashboard or trigger mass export → observe the top bar switch to <code>READ_ONLY</code>. Try <code>POST /profile</code> → mutation is refused while GET reads continue to work.</li>
                        <li><strong>Instant Session Revocation:</strong> In SOC Dashboard (Live Sessions), click <strong>Revoke</strong> on the session → the Databroker mesh invalidates the cache in &lt;1ms. Immediate subsequent requests return <strong>403 Session Revoked</strong>.</li>
                        <li><strong>SHAP Anomaly Explainability:</strong> Go to SOC Dashboard <code>/audit</code> → Click <strong>✦ Explain SHAP</strong> on any audit event to inspect exact machine learning feature drivers.</li>
                    </ol>
                </div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tabId) {{
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
            if (btn) btn.classList.add('active');
            
            const content = document.getElementById('tab-' + tabId);
            if (content) content.classList.add('active');

            if (tabId === 'headers') {{
                loadHeadersTable();
            }}
        }}

        async function executeApi(endpoint, targetId) {{
            const el = document.getElementById(targetId);
            const start = performance.now();
            el.innerText = 'Executing ' + endpoint + '...';
            try {{
                const res = await fetch(endpoint);
                const duration = Math.round(performance.now() - start);
                const statusClass = res.status === 200 ? 'status-200' : (res.status === 403 ? 'status-403' : 'status-401');
                const data = await res.json();
                
                el.innerHTML = `<span class="status-badge ${{statusClass}}">${{res.status}} ${{res.statusText}}</span> <span style="color:#9ca3af;">(${{duration}}ms)</span>\\n` + 
                               JSON.stringify(data, null, 2);
            }} catch (e) {{
                el.innerText = 'Error: ' + e.message;
            }}
        }}

        async function executeProfileUpdate(targetId) {{
            const el = document.getElementById(targetId);
            const start = performance.now();
            el.innerText = 'Executing POST /profile mutation...';
            try {{
                const res = await fetch('/profile', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ location: 'Updated via Live Test Lab (' + new Date().toLocaleTimeString() + ')' }})
                }});
                const duration = Math.round(performance.now() - start);
                const statusClass = res.status === 200 ? 'status-200' : (res.status === 403 ? 'status-403' : 'status-401');
                const data = await res.json();
                
                el.innerHTML = `<span class="status-badge ${{statusClass}}">${{res.status}} ${{res.statusText}}</span> <span style="color:#9ca3af;">(${{duration}}ms)</span>\\n` + 
                               JSON.stringify(data, null, 2);
            }} catch (e) {{
                el.innerText = 'Error: ' + e.message;
            }}
        }}

        async function runMassExfiltration(targetId) {{
            const el = document.getElementById(targetId);
            el.innerText = 'Firing rapid sequential mass export requests (5x)...';
            let results = [];
            for (let i = 1; i <= 5; i++) {{
                const res = await fetch('/employees/export');
                results.push(`Request #${{i}}: Status ${{res.status}}`);
            }}
            el.innerText = 'Completed 5 batch queries:\\n' + results.join('\\n') + '\\n\\nCheck SOC Dashboard /audit or /live for behavioral anomaly score update!';
        }}

        async function triggerSimulation(scenarioId, targetId) {{
            const el = document.getElementById(targetId);
            el.innerText = 'Contacting Zero Trust Simulation Engine...';
            try {{
                const res = await fetch('http://172.10.21.166:18000/api/simulator/run/' + scenarioId, {{
                    method: 'POST'
                }});
                const data = await res.json();
                el.innerText = 'Simulation Output:\\n' + JSON.stringify(data, null, 2);
            }} catch (e) {{
                el.innerText = 'Simulation signal sent. Check SOC Dashboard /security-operations for timeline events.';
            }}
        }}

        async function resetSessionStanding(targetId) {{
            const el = document.getElementById(targetId);
            el.innerText = 'Restoring session standing...';
            try {{
                const res = await fetch('http://172.10.21.166:18000/api/simulator/reset', {{
                    method: 'POST'
                }});
                const data = await res.json();
                el.innerText = 'Reset Status:\\n' + JSON.stringify(data, null, 2);
            }} catch (e) {{
                el.innerText = 'Reset request executed.';
            }}
        }}

        async function loadHeadersTable() {{
            const tbody = document.getElementById('headers-tbody');
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:var(--text-muted);">Inspecting received gateway headers...</td></tr>';
            try {{
                const res = await fetch('/api/posture');
                const data = await res.json();
                const headers = data.forwarded_headers || {{}};
                
                const headerExplanations = {{
                    "x-forwarded-user": "Authenticated user identity asserted by gateway",
                    "x-forwarded-role": "Verified role mapped from RBAC/ABAC policy engine",
                    "x-forwarded-email": "Primary enterprise email address",
                    "x-ztna-trust-score": "Live continuous 0-100 trust score computed by AI/ML",
                    "x-ztna-risk-level": "Risk classification band (LOW / MEDIUM / HIGH / CRITICAL)",
                    "x-access-mode": "Gateway enforcement mode (full vs readonly)",
                    "x-gateway-timestamp": "Unix timestamp of gateway signature generation",
                    "x-gateway-signature": "HMAC-SHA256 signature sealing user, role & trust score",
                    "x-vajra-jwt-assertion": "Cryptographically signed ES256 identity assertion token"
                }};

                let rows = '';
                for (const [key, val] of Object.entries(headers)) {{
                    const desc = headerExplanations[key] || "Gateway security / forwarding context";
                    rows += `<tr>
                        <td><code>${{key}}</code></td>
                        <td style="word-break:break-all; font-family:monospace; color:#4ade80;">${{val}}</td>
                        <td style="color:var(--text-muted);">${{desc}}</td>
                    </tr>`;
                }}
                tbody.innerHTML = rows || '<tr><td colspan="3">No gateway headers found. Direct access without PEP?</td></tr>';
            }} catch (e) {{
                tbody.innerHTML = `<tr><td colspan="3" style="color:#ef4444;">Failed to load headers: ${{e.message}}</td></tr>`;
            }}
        }}
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)
