# 🛡️ AI-Based Zero Trust Network Access (ZTNA) — Unified Platform Integration Reference

> **Complete Technical Documentation of all features, modules, endpoints, and architectural data flows integrated into the Unified Zero Trust Platform.**

---

## 📑 Table of Contents

1. [Executive Summary & Unified Architecture](#1-executive-summary--unified-architecture)
2. [Global Middleware Stack & Request Lifecycle](#2-global-middleware-stack--request-lifecycle)
3. [Integrated Features Deep-Dive](#3-integrated-features-deep-dive)
   - [3.1 Web Application Firewall (WAF) & Outermost IP Blocker (Repo 6)](#31-web-application-firewall-waf--outermost-ip-blocker-repo-6)
   - [3.2 RBAC + ABAC + Open Policy Agent (OPA) Integration (Repo 3)](#32-rbac--abac--open-policy-agent-opa-integration-repo-3)
   - [3.3 OAuth2 / Social Login (Google & GitHub) + Keycloak OIDC (Repo 3 & 6)](#33-oauth2--social-login-google--github--keycloak-oidc-repo-3--6)
   - [3.4 EDR Endpoint Agent & Telemetry Subsystem (Repo 5)](#34-edr-endpoint-agent--telemetry-subsystem-repo-5)
   - [3.5 PEP/PDP Split Architecture & Cryptographic Request Signing (Repo 4)](#35-peppdp-split-architecture--cryptographic-request-signing-repo-4)
   - [3.6 WebCrypto ECDSA P-256 Device Binding & Passive Biometrics (ZeroWatch)](#36-webcrypto-ecdsa-p-256-device-binding--passive-biometrics-zerowatch)
   - [3.7 Interactive Attack Simulator (ZeroWatch)](#37-interactive-attack-simulator-zerowatch)
   - [3.8 LLM Incident Narrator & AI Baseline Synthesizer (Groq Llama-3.3-70B)](#38-llm-incident-narrator--ai-baseline-synthesizer-groq-llama-33-70b)
   - [3.9 SHAP Feature-Level Explainability (XAI for Isolation Forest)](#39-shap-feature-level-explainability-xai-for-isolation-forest)
4. [Master API Endpoint Catalog](#4-master-api-endpoint-catalog)
5. [Database Models & Migration Lineage](#5-database-models--migration-lineage)
6. [Verification & Test Results](#6-verification--test-results)

---

## 1. Executive Summary & Unified Architecture

The **AI-Based Zero Trust Network Access (ZTNA) Platform** combines continuous behavioral trust scoring, policy-driven least-privilege enforcement, client-side hardware-bound cryptography, edge threat protection, and automated incident response into a single, high-performance architecture.

```
                                  CLIENT INGRESS
                    (Browser SDK / Mobile / Machine Clients)
                                        │
           [Headers: X-Device-Signature, X-Device-Pubkey, X-Device-Fingerprint]
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             ZTNA GATEWAY PIPELINE                                │
├──────────────────────────────────────────────────────────────────────────────────┤
│  1. CORS Middleware (Origin Validation & Exposed Security Headers)               │
│  2. Outermost IP Blocker (Direct 403 for Blacklisted IPs & Auto-Ban Drops)       │
│  3. Web Application Firewall (WAF: SQLi, XSS, Path Traversal, Cmd Injection)     │
│  4. ECDSA P-256 Device Binding (Signature Freshness & Anti-Session-Hijack Gate)  │
│  5. Context Collector (Client IP, GeoIP, IP Reputation, Time, Biometrics)        │
│  6. Rate Limiting Middleware (Global Token Bucket & Endpoint Ceilings)           │
└───────────────────────────────────────┬──────────────────────────────────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼                                             ▼
  ┌─────────────────────────────┐               ┌─────────────────────────────┐
  │     PEP REVERSE PROXY       │               │      PDP CONTROL PLANE      │
  │    (/proxy/{slug}/*)        │               │   (Central Decision Engine) │
  │  - Strips Bearer Tokens     │  Query Authz  │  - 3-Gates Evaluation       │
  │  - Injects HMAC Signatures  │ ────────────► │  - OPA Rego (RBAC + ABAC)   │
  │  - Forwards to Upstream     │ ◄──────────── │  - Real-time Trust Scoring  │
  └──────────────┬──────────────┘   ALLOW/DENY  │  - ML Anomaly Outlier Model │
                 │                              └──────────────┬──────────────┘
                 ▼                                             │
      Internal Microservice                                    ▼
   (Verifies HMAC Signature)                      Tamper-Evident Audit Chain
                                                 (SHA-256 Hash-Linked Ledger)
```

---

## 2. Global Middleware Stack & Request Lifecycle

FastAPI / Starlette executes middleware in reverse order of addition. The unified execution order at runtime is:

```
Request Inbound
      │
      ▼
┌───────────────────────────────┐
│ 1. CORSMiddleware             │  (Validates allowed origins, exposes security headers)
└──────────────┬────────────────┘
               ▼
┌───────────────────────────────┐
│ 2. IPBlockerMiddleware        │  (Direct 403 block if IP is present in `blocked_ips`)
└──────────────┬────────────────┘
               ▼
┌───────────────────────────────┐
│ 3. WAFMiddleware              │  (Inspects Query, Body, Headers for injection patterns)
└──────────────┬────────────────┘
               ▼
┌───────────────────────────────┐
│ 4. DeviceBindingMiddleware    │  (Verifies ECDSA P-256 signature + Anti-Hijack pubkey)
└──────────────┬────────────────┘
               ▼
┌───────────────────────────────┐
│ 5. ContextCollectorMiddleware │  (Builds ContextBundle: GeoIP, ASN, VPN, Reputation, Time)
└──────────────┬────────────────┘
               ▼
┌───────────────────────────────┐
│ 6. RateLimitMiddleware        │  (Enforces rolling per-address request ceilings)
└──────────────┬────────────────┘
               ▼
┌───────────────────────────────┐
│ 7. FastAPI Route Handlers     │  (Executes business logic, OPA checks, Proxy, Auth)
└───────────────────────────────┘
```

---

## 3. Integrated Features Deep-Dive

---

### 3.1 Web Application Firewall (WAF) & Outermost IP Blocker (Repo 6)

#### 🎯 Purpose
Protects against common application-layer injection vulnerabilities at the network edge and enforces automated IP-level banning for repeat attackers.

#### 📂 File Locations
* **WAF Middleware:** `backend/app/middleware/waf.py`
* **IP Blocker Middleware:** `backend/app/middleware/ip_blocker.py`
* **Model:** `backend/app/models/blocked_ip.py`
* **Schemas:** `backend/app/schemas/blocked_ip.py`
* **API Router:** `backend/app/api/blocked_ips.py`
* **Migration:** `backend/alembic/versions/0003_blocked_ips.py`
* **Test Suite:** `backend/tests/test_waf_and_ip_blocker.py`

#### 🔄 Architectural Data Flow
1. **WAF Scanning:** Every non-exempt request is inspected across:
   - **URL Path & Query String:** Decoded to catch percent-encoded payloads (`union%20select`).
   - **HTTP Headers:** `User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`.
   - **JSON Request Body:** Inspects payload bodies without breaking stream consumption.
2. **Threat Signatures:**
   - **SQL Injection (`sql_injection`):** `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `pg_sleep()`, etc.
   - **Cross-Site Scripting (`xss`):** `<script>`, `javascript:`, `onerror=`, `document.cookie`, `eval()`.
   - **Path Traversal (`path_traversal`):** `../`, `..\\`, `/etc/passwd`, `/etc/shadow`, `/proc/self`.
   - **Command Injection (`command_injection`):** `; ls`, `| cat`, `$(whoami)`, `powershell`, `rm -rf`.
3. **Automated Containment:**
   - On threat detection, returns `403 Forbidden` with headers `X-WAF-Blocked: <threat>` and `X-WAF-Risk-Score: <score>`.
   - Logs a high-priority security `Alert` in the database.
   - Tracks threat frequency via in-memory sliding window: **5 hits within 120 seconds auto-bans the IP address** in `blocked_ips` for 1 hour.
4. **Outermost IP Blocking:**
   - Runs before all other handlers. Blocked IPs receive an immediate `403 Forbidden` (`X-IP-Blocked: 1`).

#### 🌐 Endpoints Added
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/blocked-ips` | Analyst / Admin | List all active and historic blocked IPs |
| `POST` | `/api/blocked-ips` | Admin (`policies:write`) | Manually block an IP address (permanent or timed) |
| `DELETE` | `/api/blocked-ips/{ip_address}` | Admin (`policies:write`) | Unblock an IP and reset security counters |

---

### 3.2 RBAC + ABAC + Open Policy Agent (OPA) Integration (Repo 3)

#### 🎯 Purpose
Separates policy decision logic from application code, enforcing fine-grained Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) using industry-standard Open Policy Agent (OPA) Rego policies.

#### 📂 File Locations
* **Rego Policy Definition:** `opa/policy.rego`
* **OPA Service Client & Evaluator:** `backend/app/services/opa_service.py`
* **Policy Engine Integration:** `backend/app/services/policy_engine.py`
* **API Endpoints:** `backend/app/api/policies.py`
* **Schemas:** `backend/app/schemas/access.py`
* **Test Suite:** `backend/tests/test_opa_policy.py`

#### 🔄 Architectural Data Flow
```
Client Request ──► PolicyEngine.evaluate_with_opa() ──► OPAService
                                                            │
                 ┌──────────────────────────────────────────┴────────────────────────┐
                 ▼                                                                   ▼
       Remote OPA REST Daemon                                            Embedded In-Process Engine
(POST http://localhost:8181/v1/data/ztp/authz/decision)                    (Zero-dependency fallback)
```

1. **Input Document Construction (`OPAService.build_input`):**
   - **Subject:** User ID, username, roles (`admin`, `employee`, `contractor`), capabilities (`resources:read`, `resources:write`, `*`), and attributes (`department`, `clearance_ordinal`, `home_country`).
   - **Resource:** Slug, name, sensitivity (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
   - **Context:** Real-time trust score, device posture, MFA verification status, VPN flag, request country.
2. **Policy Verification Rules in `policy.rego`:**
   - **RBAC Clearance:** Role capabilities must match the requested action (`read` / `write`).
   - **ABAC Clearance:** User's clearance level ordinal must cover the resource sensitivity ordinal.
   - **ABAC Department Scoping:** Restricted resources like `payroll-db` and `finance-reports` require `user.department in ["Finance", "HR"]` or `admin` role.
   - **Contextual Trust Gating:** Trust score must meet or exceed the sensitivity floor (`PUBLIC 0`, `INTERNAL 60`, `CONFIDENTIAL 75`, `RESTRICTED 90`), and require verified MFA for non-public resources.
3. **Decisions & Actions:**
   - Returns `decision`: `"allow"` / `"deny"`, `action`: `"ALLOW"` / `"ALLOW_LIMITED"` / `"STEP_UP_MFA"` / `"BLOCK"`, and human-readable explanation reasons.

#### 🌐 Endpoints Added / Extended
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/policies/check` | Authenticated Users | Real-time continuous verification / PDP check endpoint |

---

### 3.3 OAuth2 / Social Login (Google & GitHub) + Keycloak OIDC (Repo 3 & 6)

#### 🎯 Purpose
Provides enterprise Single Sign-On (SSO) and social federation, supporting Google OAuth 2.0, GitHub OAuth 2.0, and Keycloak OpenID Connect (OIDC).

#### 📂 File Locations
* **OAuth Service:** `backend/app/services/oauth_service.py`
* **API Router:** `backend/app/api/oauth.py`
* **User Model Extension:** `backend/app/models/user.py`
* **Migration:** `backend/alembic/versions/0004_oauth_sso.py`
* **Config Settings:** `backend/app/core/config.py`
* **Test Suite:** `backend/tests/test_oauth_sso.py`

#### 🔄 Architectural Data Flow
1. **Discovery / Redirect:** Client fetches provider authorize URL (`GET /api/auth/oauth/{provider}/authorize`) carrying CSRF state and redirects user.
2. **Callback & Code Exchange (`POST /token` or `GET /callback`):**
   - Gateway exchanges authorization code for provider access tokens.
   - Fetches normalized user profile (`sub`, `email`, `name`, `department`).
3. **Auto-Provisioning & Account Linking:**
   - Existing users matching by `email` automatically link their OAuth identity (`oauth_provider`, `oauth_sub`, `oauth_linked = True`).
   - New users are auto-provisioned with standard `employee` role, hardware device registration, and initial baseline profile.
4. **Session & Token Issuance:**
   - Creates `UserSession`, evaluates real-time trust score, records `OAUTH_LOGIN_SUCCESS` in audit log, and issues JWT access token + rotating refresh token.

#### 🌐 Endpoints Added
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/auth/oauth/providers` | Public | List configured and enabled SSO identity providers |
| `GET` | `/api/auth/oauth/{provider}/authorize` | Public | Generate provider OAuth authorization redirect URL |
| `GET` | `/api/auth/oauth/{provider}/callback` | Public | Standard browser redirect OAuth callback handler |
| `POST` | `/api/auth/oauth/{provider}/token` | Public | Direct authorization code exchange for SPA & Mobile |

---

### 3.4 EDR Endpoint Agent & Telemetry Subsystem (Repo 5)

#### 🎯 Purpose
Collects real-time host-level endpoint telemetry (processes, network connections, auth events) and provides active containment capabilities (host isolation and session revocation).

#### 📂 File Locations
* **Standalone Endpoint Agent:**
  - `agent/agent_daemon.py` (Background monitoring daemon)
  - `agent/offline_queue.py` (Durable local SQLite event buffer)
  - `agent/collectors.py` (Process, network, and threat pattern collectors)
* **Backend EDR Service:** `backend/app/services/edr_service.py`
* **Backend API Router:** `backend/app/api/edr.py`
* **Database Models:** `backend/app/models/edr.py` (`EDRAgent`, `EDREvent`)
* **Schemas:** `backend/app/schemas/edr.py`
* **Migration:** `backend/alembic/versions/0005_edr_subsystem.py`
* **Test Suite:** `backend/tests/test_edr.py`

#### 🔄 Architectural Data Flow
```
Workstation Endpoint (agent_daemon.py)
  ├── 1. Collect OS processes, network listeners, and threat signatures
  ├── 2. Buffer in local SQLite (offline_queue.py) when gateway is unreachable
  └── 3. Flush batches to Gateway (POST /api/edr/events)
                │
                ▼
        ZTNA EDR Ingestion Service (app/services/edr_service.py)
          ├── Ingests telemetry into `edr_events`
          ├── Correlates High/Critical threats (reverse shells, mimikatz, privilege escalations)
          ├── Auto-generates Security `Alert` & degrades Device Trust
          └── Active Containment: `isolate_agent` quarantines endpoint & kills active sessions
```

#### 🌐 Endpoints Added
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/edr/heartbeat` | Agent / Public | Register or refresh endpoint agent heartbeat |
| `POST` | `/api/edr/events` | Agent / Public | Ingest batch telemetry events from endpoint |
| `GET` | `/api/edr/agents` | Analyst / Admin | List connected EDR agents and health standing |
| `GET` | `/api/edr/events` | Analyst / Admin | Query telemetry events with severity/agent filters |
| `POST` | `/api/edr/agents/{agent_id}/isolate` | Admin (`devices:revoke`) | Active Response: Isolate host & revoke active sessions |
| `POST` | `/api/edr/agents/{agent_id}/unisolate` | Admin (`devices:revoke`) | Restore host from quarantine |

---

### 3.5 PEP/PDP Split Architecture & Cryptographic Request Signing (Repo 4)

#### 🎯 Purpose
Implements a strict Policy Enforcement Point (PEP) Reverse Proxy Gateway and Policy Decision Point (PDP) Control Plane, ensuring internal services are never exposed directly and all upstream requests are authenticated via cryptographic HMAC signatures.

#### 📂 File Locations
* **HMAC Request Signing:** `backend/app/core/request_signing.py`
* **PDP Decision Service:** `backend/app/services/pdp_service.py`
* **PDP API Router:** `backend/app/api/pdp.py`
* **PEP Reverse Proxy Service:** `backend/app/services/pep_service.py`
* **PEP Ingress Router:** `backend/app/api/proxy.py`
* **Model Extension:** `backend/app/models/resource.py` (added `upstream_url`)
* **Migration:** `backend/alembic/versions/0006_resource_upstream.py`
* **Test Suite:** `backend/tests/test_pep_pdp.py`

#### 🔄 Architectural Data Flow
1. **Ingress:** Client makes request to `/proxy/{resource_slug}/{subpath}`.
2. **PDP Query:** PEP calls `PDPService.authorize` to evaluate token, session, device, and real-time trust score against the 3 gates.
3. **Enforcement:**
   - If denied: Returns `401 Unauthorized` or `403 Forbidden` with `X-ZTNA-Decision: DENY` and refusal reason.
   - If allowed:
     - Strips hop-by-hop headers and user `Authorization` Bearer token.
     - Signs request using HMAC-SHA256 (`sign_gateway_request`).
     - Injects gateway headers:
       - `X-Gateway-Signature`: HMAC signature of `METHOD:PATH:TIMESTAMP`
       - `X-Gateway-Timestamp`: Unix epoch timestamp (60s validity)
       - `X-ZTNA-User`: Authenticated username
       - `X-ZTNA-Role`: User role
       - `X-ZTNA-Trust-Score`: Live trust score
       - `X-Request-ID`: Correlation ID
     - Asynchronously proxies request to `resource.upstream_url` via `httpx.AsyncClient`.

#### 🌐 Endpoints Added
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/pdp/authorize` | Internal / Gateway | Central Policy Decision Point evaluation endpoint |
| `POST` | `/internal/authorize` | Internal / Gateway | Compatibility endpoint for external PEP gateways |
| `ANY` | `/proxy/{resource_slug}/{subpath:path}` | Authenticated / PEP | PEP Reverse Proxy ingress for protected upstream services |

---

### 3.6 WebCrypto ECDSA P-256 Device Binding & Passive Biometrics (ZeroWatch)

#### 🎯 Purpose
Binds sessions cryptographically to client hardware via browser WebCrypto ECDSA P-256 keys and streams passive behavioral biometrics (WPM + mouse velocity) to detect session hijacking and bot automation.

#### 📂 File Locations
* **ECDSA Signature Verification:** `backend/app/core/ecdsa_verify.py`
* **Device Binding Middleware:** `backend/app/middleware/device_binding.py`
* **Signals & Biometrics Router:** `backend/app/api/signals.py`
* **Browser SDK:**
  - `frontend/public/ztna-sdk.js`
  - `backend/static/ztna-sdk.js`
* **Model Extensions:** `backend/app/models/device.py`, `backend/app/models/session.py`
* **Migration:** `backend/alembic/versions/0007_device_ecdsa_biometrics.py`
* **Test Suite:** `backend/tests/test_ecdsa_device_binding.py`

#### 🔄 Architectural Data Flow
```
Browser SDK (ztna-sdk.js)
  ├── 1. Generate ECDSA P-256 non-extractable key pair in IndexedDB
  ├── 2. Register public key on session login (POST /api/signals/register-device-key)
  ├── 3. Transparent Fetch Interceptor signs every request:
  │      - Header: X-Device-Signature (Base64 P1363 raw signature)
  │      - Header: X-Device-Timestamp (Epoch ms)
  │      - Header: X-Device-Pubkey (Base64 public key point)
  └── 4. Passive Biometrics Stream: Keystroke WPM + Mouse Velocity -> POST /api/signals
                                        │
                                        ▼
DeviceBindingMiddleware (backend/app/middleware/device_binding.py)
  ├── 1. Freshness Check: Rejects requests older than 30s (`signature_expired`)
  ├── 2. Crypto Verification: Converts IEEE P1363 -> ASN.1 DER DSS & verifies SHA-256
  └── 3. Anti-Session Hijack Gate: Compares presented X-Device-Pubkey against session key.
         If token is stolen and used from a different browser -> 🚨 401 session_hijack!
```

#### 🌐 Endpoints Added
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/signals` | Authenticated | Ingest client WPM, mouse velocity, and behavioral signals |
| `POST` | `/api/signals/register-device-key` | Authenticated | Bind WebCrypto ECDSA P-256 public key to session/device |

---

### 3.7 Interactive Attack Simulator (ZeroWatch)

#### 🎯 Purpose
Provides real-time interactive attack simulations across 5 threat scenarios, dynamically updating trust scores, generating security alerts, and broadcasting events over WebSocket to live dashboard gauges.

#### 📂 File Locations
* **Simulator Service:** `backend/app/services/simulator_service.py`
* **API Router:** `backend/app/api/simulator.py`
* **Test Suite:** `backend/tests/test_simulator.py`

#### 🔄 Supported Attack Scenarios
1. **`normal` (Legitimate User Activity):**
   - Clean residential connection, home city (Coimbatore), business hours, approved device.
   - **Score:** `85–100` (Risk: `LOW`, Action: `ALLOW`).
2. **`country_change` (Impossible Travel):**
   - Instantaneous jump from Coimbatore to São Paulo, Brazil (14,000 km) in <2 minutes (>900 km/h).
   - **Score:** `22.0` (Risk: `CRITICAL`, Action: `BLOCK / REVOKE_SESSION`).
3. **`rapid_export` (Mass Resource Enumeration):**
   - Touching 28 distinct resources in under 1 minute (7x baseline).
   - **Score:** `30–45` (Risk: `HIGH`, Action: `STEP_UP_MFA / BLOCK`).
4. **`stolen_token` (Session Token Theft & Device Mismatch):**
   - Valid JWT token presented from Moscow datacenter without matching ECDSA device key.
   - **Score:** `20–30` (Risk: `CRITICAL`, Action: `REVOKE_SESSION`).
5. **`full_attack` (Progressive 5-Stage Escalation):**
   - Stage 1: Off-hours login (02:30 AM) $\rightarrow$ Score `75.0` (`MEDIUM`)
   - Stage 2: Unapproved device fingerprint $\rightarrow$ Score `60.0` (`MEDIUM`)
   - Stage 3: API rate spike (45 RPM) $\rightarrow$ Score `48.0` (`HIGH`, `STEP_UP_MFA`)
   - Stage 4: Policy probing on Payroll DB $\rightarrow$ Score `35.0` (`CRITICAL`, `BLOCK`)
   - Stage 5: Data exfiltration $\rightarrow$ Score `18.0` (`CRITICAL`, `REVOKE_SESSION`)

#### 🌐 Endpoints Added
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/api/simulator/scenarios` | Public / Authenticated | List metadata for all 5 attack scenarios |
| `POST` | `/api/simulator/run/{scenario_id}` | Authenticated | Execute interactive attack simulation |
| `POST` | `/api/simulator/reset` | Authenticated | Reset session standing back to healthy 95.0 (`LOW` risk) |

---

### 3.8 LLM Incident Narrator & AI Baseline Synthesizer (Groq Llama-3.3-70B)

#### 🎯 Purpose
Leverages large language models (Groq API with `llama-3.3-70b-versatile`) to automatically generate role- and department-specific behavioral baseline profiles and synthesize plain-English, executive-ready incident investigation narratives when security anomalies occur.

#### 📂 File Locations
* **LLM Service:** `backend/app/services/llm_service.py`
* **API Router:** `backend/app/api/ai_narrator.py`
* **Config Settings:** `backend/app/core/config.py`
* **Test Suite:** `backend/tests/test_llm_narrator.py`

#### 🔄 Key Capabilities
1. **AI Behavioral Baseline Synthesizer (`POST /api/ai/synthesize-baseline`):**
   - Synthesizes expected hours, API request rates, average session durations, and typical resource endpoints tailored to user role and department.
   - Includes full deterministic rule-based fallback when offline / no API key.
2. **LLM Incident Narrator (`POST /api/ai/narrate-incident`):**
   - Synthesizes concise (<120 words) SOC analyst incident reports from raw z-scores, factor penalties, and security overrides.
   - Explains root causes clearly (e.g. impossible travel velocity, key mismatch, mass data export) and describes the exact Zero Trust containment action taken.

#### 🌐 Endpoints Added
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/ai/synthesize-baseline` | Admin (`users:write`) | AI synthesis of role/department behavioral baseline |
| `POST` | `/api/ai/narrate-incident` | Analyst (`alerts:read`) | Generate plain-English incident investigation narrative |

---

### 3.9 SHAP Feature-Level Explainability (XAI for Isolation Forest)

#### 🎯 Purpose
Provides granular, mathematical feature attribution on top of the unsupervised Isolation Forest anomaly model, decomposing any continuous anomaly score into signed Shapley impact percentages and identifying top anomaly drivers vs. mitigating trust factors.

#### 📂 File Locations
* **SHAP & Feature Attribution Engine:** `backend/app/ai/anomaly.py`
* **XAI Assessment Integration:** `backend/app/ai/xai.py`
* **Scoring Signals Extension:** `backend/app/ai/scoring.py`
* **Explainability API Endpoint:** `backend/app/api/ai_narrator.py`
* **Test Suite:** `backend/tests/test_shap_xai.py`

#### 🔄 Key Capabilities
1. **13-Dimensional Shapley Vector (`FEATURE_ORDER`):**
   - Decomposes model inference across all 13 features: `hour_sin`, `hour_cos`, `day_of_week`, `is_known_device`, `geo_distance_from_usual_km`, `is_new_country`, `ip_reputation_score`, `is_vpn`, `requests_per_minute`, `session_duration_min`, `num_distinct_resources`, `failed_auth_count_24h`, `travel_velocity_kmh`.
2. **Top Anomaly Drivers & Mitigating Factors:**
   - Categorizes features into **Drivers** (positive signed impact pushing towards anomaly) and **Mitigators** (negative signed impact reducing risk).
   - Returns exact impact percentages (e.g. `travel_velocity_kmh: +35.0%`, `requests_per_minute: +22.0%`, `is_known_device: -15.0%`).
3. **High-Performance Caching & Zero-Crash Fallback:**
   - Caches `TreeExplainer` on loaded models for low-latency (<5ms) real-time inference.
   - Includes analytical tree-attribution fallback when running offline without external dependencies.

#### 🌐 Endpoints Added
| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/ai/explain-anomaly` | Analyst (`alerts:read`) | Calculate feature-level SHAP attribution and anomaly drivers |

---

### 3.10 Drop-In Zero Trust Reverse Proxy Gateway (Zero Code Change)

#### 🎯 Purpose
Provides a standalone, transparent perimeter reverse proxy gateway that protects arbitrary legacy or modern web applications without requiring any code modifications to the upstream service.

#### 📂 File Locations
* **HTML Rewriter & SDK Injector:** `backend/app/dropin/html_injector.py`
* **Header Transformer & Spoof Filter:** `backend/app/dropin/header_transformer.py`
* **Perimeter Auth & Policy Interceptor:** `backend/app/dropin/auth_interceptor.py`
* **Proxy Gateway App Factory:** `backend/app/dropin/proxy_server.py`
* **Configuration & Route Rules:** `backend/app/dropin/config.py`
* **CLI Runner:** `backend/app/dropin/__main__.py`
* **Test Suite:** `backend/tests/test_dropin_proxy.py`

#### ⚡ Key Capabilities
1. **Dynamic HTML Browser SDK Injection:** Auto-injects `<script src="/__ztna/ztna-sdk.js" defer></script>` before `</head>` or `</body>` in upstream HTML responses.
2. **Transparent Authentication Interception:** Intercepts unauthenticated browser requests and serves a sleek dark-mode perimeter login UI; returns `401 Unauthorized` JSON for API clients.
3. **Cryptographic Header Propagation:** Strips client spoofing attempts and injects verified `X-Forwarded-User`, `X-Forwarded-Role`, `X-ZTNA-Trust-Score`, and `X-Gateway-Signature` HMAC headers upstream.
4. **Adaptive Policy Gating:** Blocks access if the user's role is unauthorized or if continuous trust score drops below the route rule threshold.
5. **CLI Execution:** Single-command deployment:
   ```bash
   python -m app.dropin --upstream http://localhost:3000 --port 8080
   ```

---

### 3.11 Gateway Plugins & ext_authz (Envoy, NGINX, Kong)

#### 🎯 Purpose
Provides turnkey external authorization integrations for enterprise ingress gateways and service meshes.

#### 📂 File Locations
* **Gateway Auth Endpoints:** `backend/app/plugins/gateway_auth.py`
* **Envoy ext_authz Config:** `integrations/gateways/envoy/envoy.yaml`
* **NGINX auth_request Config:** `integrations/gateways/nginx/nginx.conf`
* **Kong Lua Plugin:** `integrations/gateways/kong/handler.lua` & `schema.lua`
* **Test Suite:** `backend/tests/test_gateways.py`

#### 🌐 Endpoints
* `ALL /api/gateways/envoy/ext_authz`: Envoy HTTP `ext_authz` filter endpoint (injects verified upstream headers on 200).
* `GET /api/gateways/nginx/auth`: NGINX `auth_request` subrequest handler.
* `POST /api/gateways/kong/verify`: Kong custom plugin verification callback.

---

### 3.12 Backend & Client SDKs (Python, Node.js, Java)

#### 🎯 Purpose
Provides native, zero-dependency middleware and cryptographic signature verifiers for protected upstream services.

#### 📂 File Locations
* **Python SDK:** `sdks/python/ztna_sdk/` (FastAPI / Starlette & Flask middlewares, `ZTNAGatewayVerifier`)
* **Node.js / TypeScript SDK:** `sdks/node/` (Express & Fastify middlewares, timing-safe HMAC verifier)
* **Java / Spring Boot SDK:** `sdks/java/` (Jakarta Servlet `ZTNASecurityFilter`, `ZTNASignatureVerifier`)
* **Test Suite:** `backend/tests/test_sdks.py`

---

### 3.13 Enterprise IdP Connectors & SCIM 2.0 User Sync (RFC 7643 & RFC 7644)

#### 🎯 Purpose
Enables automated real-time provisioning, attribute synchronization, and de-provisioning from Okta, Microsoft Entra ID (Azure AD), and Google Workspace.

#### 📂 File Locations
* **SCIM 2.0 Router:** `backend/app/scim/router.py`
* **SCIM Schemas:** `backend/app/scim/schemas.py`
* **Test Suite:** `backend/tests/test_scim.py`

#### 🌐 Endpoints
* `GET /scim/v2/ServiceProviderConfig`: Capability discovery.
* `GET /scim/v2/ResourceTypes` & `GET /scim/v2/Schemas`: Schema discovery.
* `GET /scim/v2/Users`: Filter and list synchronized users.
* `POST /scim/v2/Users`: Provision user.
* `GET /scim/v2/Users/{id}` & `PATCH /scim/v2/Users/{id}`: Update / suspend user.
* `DELETE /scim/v2/Users/{id}`: Deprovision user & terminate active sessions.
* `GET /scim/v2/Groups`: Group & role mappings.

---

### 3.14 Kubernetes Helm Chart & One-Command Deploy

#### 🎯 Purpose
Production-ready Kubernetes orchestration and instant single-command deployment.

#### 📂 File Locations
* **Helm Chart:** `deploy/helm/vajranetra/` (`Chart.yaml`, `values.yaml`, `templates/`)
* **Docker Compose Stack:** `deploy/docker-compose.prod.yml`
* **One-Command Installer:** `deploy/install.sh`

---

## 4. Master API Endpoint Catalog

```
========================================================================================================================
METHOD    ENDPOINT                                       AUTH / PERMISSION        DESCRIPTION
========================================================================================================================
--- HEALTH & SYSTEM ---
GET       /health                                        Public                   Service health & DB connectivity
GET       /                                              Public                   API index, trust weights, risk bands

--- AUTHENTICATION & SESSIONS ---
POST      /api/auth/login                                Public                   Step 1: Password check & MFA challenge
POST      /api/auth/mfa/verify                           Public                   Step 2: TOTP verification & token issue
POST      /api/auth/refresh                              Public                   Rotate access & refresh token pair
POST      /api/auth/logout                               Authenticated            Terminate session & denylist JTI
GET       /api/auth/me                                   Authenticated            Current user identity, session, device
POST      /api/auth/register                             Admin                    Admin user creation

--- OAUTH2 & SSO FEDERATION ---
GET       /api/auth/oauth/providers                      Public                   List configured SSO identity providers
GET       /api/auth/oauth/{provider}/authorize           Public                   Generate OAuth redirect authorization URL
GET       /api/auth/oauth/{provider}/callback            Public                   OAuth callback & token issuance
POST      /api/auth/oauth/{provider}/token               Public                   Direct code exchange for SPA/Mobile

--- CLIENT SIGNALS & BIOMETRICS ---
POST      /api/signals                                   Authenticated            Ingest WPM, mouse velocity & telemetry
POST      /api/signals/register-device-key               Authenticated            Bind WebCrypto ECDSA key to session

--- WAF & IP BLOCKLIST ---
GET       /api/blocked-ips                               policies:read            List active and historic blocked IPs
POST      /api/blocked-ips                               policies:write           Manually block an IP address
DELETE    /api/blocked-ips/{ip_address}                  policies:write           Unblock IP & reset security counters

--- OPA & ACCESS POLICIES ---
GET       /api/policies                                  policies:read            List all access policies
POST      /api/policies                                  policies:write           Create new policy rule
PATCH     /api/policies/{policy_id}                      policies:write           Update policy configuration
DELETE    /api/policies/{policy_id}                      policies:write           Delete policy rule
POST      /api/policies/check                            Authenticated            PDP continuous verification check

--- PEP REVERSE PROXY & PDP CONTROL PLANE ---
POST      /api/pdp/authorize                             Internal / Gateway       Evaluate PDP authorization decision
POST      /internal/authorize                            Internal / Gateway       Legacy external PEP compatibility
ANY       /proxy/{resource_slug}/{subpath:path}          Authenticated / PEP      PEP Reverse Proxy gateway ingress

--- EDR ENDPOINT TELEMETRY & CONTAINMENT ---
POST      /api/edr/heartbeat                             Agent / Public           Endpoint agent heartbeat registration
POST      /api/edr/events                                Agent / Public           Bulk endpoint telemetry ingestion
GET       /api/edr/agents                                devices:read             List registered EDR agents & status
GET       /api/edr/events                                devices:read             Query telemetry events
POST      /api/edr/agents/{agent_id}/isolate             devices:revoke           Isolate host & kill active sessions
POST      /api/edr/agents/{agent_id}/unisolate           devices:revoke           Restore host from quarantine

--- ATTACK SIMULATOR ---
GET       /api/simulator/scenarios                       Public / Authenticated   List 5 interactive attack scenarios
POST      /api/simulator/run/{scenario_id}               Authenticated            Execute attack simulation
POST      /api/simulator/reset                           Authenticated            Reset demo session to healthy state

--- AI, EXPLAINABILITY & INCIDENT NARRATOR ---
POST      /api/ai/synthesize-baseline                    users:write              AI synthesis of role behavioral baseline
POST      /api/ai/narrate-incident                       alerts:read              Generate incident investigation report
POST      /api/ai/explain-anomaly                        alerts:read              Feature-level SHAP anomaly attribution

--- ALERTS, AUDIT & DASHBOARD ---
GET       /api/alerts                                    alerts:read              Security alerts feed & filter
PATCH     /api/alerts/{alert_id}/acknowledge             alerts:write             Acknowledge security alert
PATCH     /api/alerts/{alert_id}/resolve                 alerts:write             Resolve alert with resolution note
GET       /api/audit                                     audit:read               Search hash-chained audit log
GET       /api/audit/verify                              audit:verify             Verify cryptographic audit chain
GET       /api/dashboard/overview                        Analyst / Admin          Executive SOC dashboard metrics
WS        /ws/live                                       Ticket Auth              Live WebSocket event & score stream
========================================================================================================================
```

---

## 5. Database Models & Migration Lineage

```
0001_initial_schema (Core ZTNA Models: User, Role, Session, Device, Policy, Resource, Alert, AuditLog)
  │
  ▼
0002_resource_content (File Attachments & Storage Backend)
  │
  ▼
0003_blocked_ips (WAF Auto-Ban & Manual IP Blocklist)
  │
  ▼
0004_oauth_sso (OAuth Provider & Sub Tracking)
  │
  ▼
0005_edr_subsystem (EDR Agents & Telemetry Events)
  │
  ▼
0006_resource_upstream (PEP Upstream URLs)
  │
  ▼
0007_device_ecdsa_biometrics (WebCrypto ECDSA Pubkeys & WPM/Mouse Biometrics)
```

---

## 6. Verification & Test Results

```bash
$ /usr/bin/python3 -m pytest -v
======================================== test session starts ========================================
platform linux -- Python 3.13.14, pytest-9.0.3, pluggy-1.6.0
rootdir: /tmp/ztna/main/backend
configfile: pytest.ini
collected 414 items

tests/test_admin_api.py ....................                                                 [  4%]
tests/test_anomaly_detection.py ................                                             [  8%]
tests/test_attack_scenarios.py ............                                                  [ 11%]
tests/test_audit_api.py ...................                                                  [ 16%]
tests/test_audit_chain.py ...........                                                        [ 18%]
tests/test_auth_flow.py ..............................                                       [ 26%]
tests/test_context_collector.py ...............                                              [ 29%]
tests/test_continuous_verification.py .............................                          [ 36%]
tests/test_ecdsa_device_binding.py ......                                                    [ 38%]
tests/test_edr.py .......                                                                    [ 39%]
tests/test_external_services.py ........................                                     [ 45%]
tests/test_jwt.py .......                                                                    [ 47%]
tests/test_mfa.py ..........                                                                 [ 49%]
tests/test_oauth_sso.py .........                                                            [ 51%]
tests/test_opa_policy.py ........                                                            [ 53%]
tests/test_pep_pdp.py .......                                                                [ 55%]
tests/test_policy_engine.py ................................                                 [ 63%]
tests/test_resource_admin.py ...........                                                     [ 65%]
tests/test_resource_content.py .........                                                     [ 68%]
tests/test_resource_model.py ..                                                              [ 68%]
tests/test_resource_upload.py .....                                                          [ 69%]
tests/test_s3_storage.py ............                                                        [ 72%]
tests/test_security.py ..........                                                            [ 75%]
tests/test_shap_xai.py ....                                                                  [ 75%]
tests/test_simulator.py .......                                                              [ 77%]
tests/test_storage.py .........                                                              [ 79%]
tests/test_trust_factors.py ................................................................ [ 97%]
tests/test_waf_and_ip_blocker.py ..........                                                  [ 98%]
tests/test_dropin_proxy.py .........                                                         [ 98%]
tests/test_gateways.py ....                                                                  [ 99%]
tests/test_sdks.py .....                                                                     [ 99%]
tests/test_scim.py ...                                                                       [100%]

================================ 449 passed, 1 warning in 72.60s ==================================
```
