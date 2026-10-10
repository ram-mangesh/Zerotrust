# Zero Trust Network Access — Complete Sidebar Features Guide (A to Z)

Ek concise aur viva/presentation-ready guide jo platform ke har sidebar module ko explain karti hai.

---

## 📂 1. Workspace

### ◫ Overview (`/`)
- **What it is:** Platform ka main executive SOC Dashboard.
- **Key Capabilities:**
  - Active sessions, Mean Trust Score (0–100), open alerts, aur blocked attempts ka live counter.
  - Risk Distribution Donut Chart (Low, Medium, High, Critical).
  - Continuous Verification trigger button (**"Run sweep now"**) aur incident Twilio call trigger.
- **Explain in Viva/Interview:** *"Ye real-time health aur aggregate security posture ka single-pane-of-glass overview deta hai."*

---

### ◉ Users & Devices (`/users`)
- **What it is:** User identity directory aur hardware device registry.
- **Key Capabilities:**
  - Role Management (`admin`, `security_analyst`, `employee`, `contractor`).
  - Device Trust-on-First-Use (TOFU): Naye devices `PENDING` state mein aate hain jinko admin Approve ya Revoke karta hai.
  - User lockout recovery and failed login streak monitoring.
- **Explain in Viva/Interview:** *"Yahan se zero-trust hardware binding enforce hoti hai — bina approved device ke user login allow nahi hota."*

---

### ▤ Resources (`/resources`)
- **What it is:** Protected applications, databases, aur files ka access catalogue.
- **Key Capabilities:**
  - 4 Sensitivity Tiers: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
  - Dynamic Trust Floors: Har resource ke liye minimum trust score set karna (e.g., Restricted files need Score $\ge 90$).
  - **Zero-Trust Self-Destructing Vault Export:** Sensitive file ko encrypted `.py` container mein download karna (galat password par self-destruct).
- **Explain in Viva/Interview:** *"Resources par static IP ke badle dynamic policy aur trust score ke base par access decision hota hai."*

---

## 🔒 2. Access Controls

### ⌘ Policies (`/policies`)
- **What it is:** Rule-based aur Attribute-Based Access Control (ABAC/RBAC) Policy Engine.
- **Key Capabilities:**
  - Policy Decision Point (PDP) rules manage karna (Sensitivity vs Role vs Trust).
  - Time-of-day, Geolocation, aur Device posture conditions bind karna.
  - Enforced Actions: `ALLOW`, `ALLOW_LIMITED` (Read-only), `STEP_UP_MFA`, `BLOCK`, `REVOKE`.
- **Explain in Viva/Interview:** *"Ye platform ka brain hai jahan business access rules decide aur enforce hote hain."*

---

### ◌ Trust Scoring (`/trust`)
- **What it is:** 6-Factor Continuous Behavioral Trust Engine Configuration.
- **Key Capabilities:**
  - **6 Factor Sliders:** Identity (25%), Device (20%), Network (20%), Behavior (20%), Location (10%), Temporal (5%).
  - Dynamic Risk Band Thresholds configure karna (Low: 80, Medium: 60, High: 40).
  - Real-time factor weight tuning aur instant mathematical re-scoring.
- **Explain in Viva/Interview:** *"Yahan se AI Trust weights tune hote hain jo har 30 second me live session ko re-score karte hain."*

---

### ⌁ Risk Scores (`/risk`)
- **What it is:** Per-user historical risk & trust telemetry analysis.
- **Key Capabilities:**
  - Unified Scoring Formula: $\text{Risk Score} = 100 - \text{Trust Score}$.
  - Interactive Trust Trajectory chart over time.
  - Security Triggers & Shifts list (e.g., Impossible travel, unusual login hour, VPN detection).
- **Explain in Viva/Interview:** *"Ye individual user ki timeline par score fluctuations aur anomalies track karne ke liye forensic telemetry hai."*

---

### ≋ Audit Trail (`/audit`)
- **What it is:** Cryptographically verifiable, immutable SHA-256 hash-chained security log.
- **Key Capabilities:**
  - Har authentication, access decision, aur tamper attempt linked block banta hai:
    $$\text{record\_hash} = \text{SHA256}(\text{prev\_hash} + \text{timestamp} + \text{actor} + \text{action} + \text{payload\_hash})$$
  - **"Verify Chain"** button: Mathematical proof check karta hai ki database mein kisi ne 1 byte bhi tamper nahi kiya.
  - CSV export for regulatory and compliance audits.
- **Explain in Viva/Interview:** *"Blockchain jaisa tamper-proof audit chain hai jisme agar insider record edit kare to chain mathematically break ho jati hai."*

---

## 🚨 3. Response & Operations

### ◎ Live Sessions (`/live`)
- **What it is:** Sabhi active user sessions ka real-time WebSocket monitoring table.
- **Key Capabilities:**
  - Live trust score, risk chip, IP address, city, VPN status, aur request count.
  - Real-time score changes automatically update without page refresh.
  - 1-Click Session Revocation (instantly logs user out and blacklists JWT).
- **Explain in Viva/Interview:** *"SOC analyst yahan se live users ko monitor karta hai aur malicious session ko instant kill kar sakta hai."*

---

### ◇ Alerts (`/alerts`)
- **What it is:** High & Critical threat triage and incident response console.
- **Key Capabilities:**
  - Severities: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
  - Categories: Stolen Token, Impossible Travel, Brute Force, Exfiltration, Vault Tampering.
  - Acknowledge aur Resolve workflow (with mandatory SOC resolution note written to audit chain).
  - **Twilio Voice Call Button:** Urgent incident par phone call trigger karna.
- **Explain in Viva/Interview:** *"Threat alerts ka triage center jahan analyst evidence inspect karke remediation actions leta hai."*

---

### ▦ Security Operations (`/security-operations`)
- **What it is:** Central Response Center combining EDR containment, network blocking, and attack lab.
- **Key Capabilities:**
  - **Managed Endpoints (EDR):** Endpoint health, agent check-ins, OS tracking.
  - **Endpoint Containment:** Infected laptop/server ko corporate network se 1-click isolate karna.
  - **Network Blocks:** IP address blocklist for brute-force bots and Tor nodes.
  - **Attack Lab:** Live attack simulations execute karna.
- **Explain in Viva/Interview:** *"EDR endpoint containment aur active firewall blocking ka central command center hai."*

---

### ⊘ Revocation (`/revocation`)
- **What it is:** Immediate emergency kill-switch for sessions, devices, and user credentials.
- **Key Capabilities:**
  - Redis Token Denylist management.
  - Device-level revocation (blacklists device hardware fingerprint).
  - Complete account quarantine during active breach investigation.
- **Explain in Viva/Interview:** *"Emergency response kill-switch jahan se compromised credentials ya devices ko zero delay me revoke kiya jata hai."*

---

## ⚡ 4. Platform & AI

### ✦ AI Intelligence (`/intelligence`)
- **What it is:** Unsupervised Machine Learning (Isolation Forest) & Explainable AI (XAI/SHAP) engine.
- **Key Capabilities:**
  - 13-feature multidimensional vector anomaly detection.
  - Circular temporal harmonics ($\sin/\cos$) for circadian behavioral modeling.
  - Mathematical feature breakdown (why an anomaly was flagged).
- **Explain in Viva/Interview:** *"Ye machine learning model hai jo normal user behavior learn karta hai aur zero-day insider anomalies detect karta hai."*

---

### ⇄ Integrations (`/integrations`)
- **What it is:** External enforcement gateways, SSO identity providers, and directory connectors.
- **Key Capabilities:**
  - Reverse Proxy Gateways: Envoy (`ext_authz`), NGINX (`auth_request`), Kong plugin, Drop-in proxy.
  - SSO Identity: OAuth 2.0 / OIDC (Google, GitHub, Keycloak).
  - Directory Sync: SCIM v2 User & Group provisioning.
  - **Twilio Voice Integration Card:** Voice alerting service testing.
- **Explain in Viva/Interview:** *"Enterprise ecosystem ke saath policy decision plane connect karne ka fabric hai."*

---

### ◈ System Status (`/system`)
- **What it is:** Infrastructure telemetry, health check, and microservice status.
- **Key Capabilities:**
  - Backend API, Database (SQLite / PostgreSQL), Cache (Redis / In-memory) status.
  - GeoIP engine, IP Reputation provider, and ML model training state.
  - System uptime and latency benchmarks.
- **Explain in Viva/Interview:** *"Underlying infrastructure aur dependencies ka operational health check monitor hai."*

---

## 🔐 5. Special Feature: Zero-Trust Self-Destructing Data Vault
- **Concept:** Exfiltrated files ko protect karne ke liye encrypted Python container (`SecureVault_<file>.py`).
- **Mechanism:**
  - **Correct Key:** Volatile RAM-only decryption + Burn-After-Reading cleanup.
  - **Wrong Key:** Instant 3-Pass DoD Cryptographic Shredding $\rightarrow$ File vanishes from disk $\rightarrow$ SOC alert + Twilio phone call.
