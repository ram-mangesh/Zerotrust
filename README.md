# AI-Based Zero Trust Network Access & Exfiltration Defense (CIPHER04)

Adaptive trust scoring, continuous risk monitoring, live endpoint containment, and **Zero-Trust Self-Destructing Data Containers**. Every access request — and every few seconds of an active session — is re-evaluated across identity, device, network, behavioural, location, and temporal signals. 

An AI engine transforms these signals into a dynamic **0–100 Trust Score**, and a policy engine enforces granular verdicts: **Allow / Allow-Limited / Step-Up MFA / Block / Revoke Session**.

---

## Key Capabilities (A to Z)

### 1. 🛡️ 6-Factor Continuous Trust Engine
Evaluates every request context dynamically:
- **Identity & Credentials:** Password strength, MFA status, credential age, failed-login streaks.
- **Device Posture:** Hardware fingerprinting, OS/browser consistency, WebCrypto hardware keys, admin approval state.
- **Network Intel:** Source IP reputation, Tor/VPN/proxy detection, datacenter ASN classification, mid-session network drift.
- **Behavioral Dynamics:** Isolation Forest ML anomaly scoring, request frequency, navigation velocity, deviation from personal profile.
- **Geographic Signals:** Haversine distance from home baseline, new country entry, impossible travel velocity (>900 km/h).
- **Temporal Circadian:** Sine/Cosine circular harmonics of access hour, weekend vs weekday patterns, session duration outliers.

### 2. 💣 Zero-Trust Self-Destructing Data Vaults (DRM / Ephemeral Containers)
- **Problem Solved:** When sensitive data is exfiltrated or copied to a USB/remote drive, standard files sit exposed.
- **Solution:** Packages sensitive assets (`CONFIDENTIAL` / `RESTRICTED`) into standalone, encrypted, self-destructing Python containers (`SecureVault_<name>.py`).
- **AES-256-GCM Military Encryption:** Derived from password via PBKDF2-HMAC-SHA256 (120,000 rounds).
- **Active Dead-Man's Switch:** 
  - If an intruder enters the **wrong password**, the container immediately executes a **3-Pass DoD Cryptographic Wipe** (Random bytes + Zeroes + Random bytes) and deletes itself permanently from the disk.
  - Dispatches a stealth JSON alert to the ZTNA SOC and initiates an urgent voice alert call.
- **Volatile RAM-Only Decryption & Burn-After-Reading:** On correct password, data is decrypted only into memory (RAM) and shredded immediately after viewing to prevent lingering files.

### 3. 🚨 CIPHER04: Real-Time Insider Exfiltration Detection
- Detects unauthorized employee data movement as it happens across vectors:
  - USB mass storage attachments
  - Personal cloud drive sync uploads
  - Webmail and messaging attachments
  - Bulk enumeration and mass API downloads
  - Clipboard burst and printing anomalies
- **Approved Exceptions Engine:** Allows analysts to grant temporary whitelists/exemptions to eliminate false alarms for verified operations.

### 4. 📞 Twilio Voice Incident Alerting & Triage
- **Outbound Voice Calling:** Automatically calls security administrators upon Critical security violations or Vault tampering.
- **Interactive IVR Keypad Actions:** 
  - *Press 1:* Grant emergency access / Contain endpoint
  - *Press 2:* Block and isolate user session
- **Twimlets Echo Fallback:** Direct public TwiML URL generation allowing reliable execution on Twilio Trial accounts without complex tunneling.

### 5. 🖥️ Security Operations & Endpoint Containment (Response Center)
- **Managed Endpoints:** Real-time visibility into Windows, macOS, Linux, and Kubernetes worker telemetry.
- **1-Click Endpoint Isolation:** Immediately isolates infected/compromised devices from the corporate network and revokes active JWT sessions.
- **Automated Network Blocklist:** Live IP blocking for Tor nodes, brute-force bots, and anomalous scanners.

### 6. 🔗 Cryptographically Verifiable Audit Chain
- **Tamper-Evident Ledger:** Every authentication, access evaluation, vault export, and tamper event is linked via SHA-256:
  ```
  record_hash = SHA256(prev_hash + timestamp + actor + action + payload_hash)
  ```
- **Integrity Verification:** Built-in cryptographic walker verifies the entire chain from the Genesis record with 0% tolerance for modification.

---

## Architecture Overview

```
[ User / Browser / EDR Client ]
         │ (Device Fingerprint + WebCrypto Assertion)
         ▼
[ FastAPI Gateway & Security Middlewares ]
   ├── CORS Middleware & IP Blocker
   ├── WAF (Web Application Firewall)
   ├── Device Binding & Context Collector Middleware
   └── Token & Session Verification
         │
         ├── Policy Decision Point (PDP) & Policy Engine
         │     ├── Trust Score Evaluation (6 Factors)
         │     ├── Unsupervised ML (Isolation Forest)
         │     └── Role Clearance & Resource Sensitivity
         │
         ├── Self-Destructing Vault Service (AES-256-GCM + Dead-Man's Switch)
         ├── Twilio Voice Alerting & Webhooks
         ├── EDR Telemetry & Active Response Engine
         └── Immutable SHA-256 Hash Chain Logger
```

---

## Quick Start Guide

### Prerequisites
- **Python:** 3.11 or newer
- **Node.js:** 18 or newer
- **Git**

---

### Option A: Local Run (No Docker Required)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ram-mangesh/Zerotrust.git
   cd Zerotrust
   ```

2. **Backend Setup:**
   ```bash
   # Install Python dependencies
   pip install -r backend/requirements.txt

   # Create your environment file from example
   cp .env.example .env
   ```

3. **Frontend Setup:**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

4. **Seed Database (Initial Corporate Corpus & EDR Telemetry):**
   ```bash
   python scripts/seed.py --reset
   ```

5. **Start Both Servers:**
   - **Terminal 1 (Backend API):**
     ```powershell
     cd backend
     python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
     ```
   - **Terminal 2 (Frontend Web Console):**
     ```powershell
     cd frontend
     npm run dev
     ```

6. Open your browser:
   - **Frontend Console:** [http://localhost:5174](http://localhost:5174)
   - **Interactive API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option B: Docker Compose

```bash
cp .env.example .env
docker compose up --build
docker compose exec api python scripts/seed.py --reset
```

---

## Default Demo Credentials

| Role | Username | Password | Static MFA Code (Demo) |
|---|---|---|---|
| **Administrator** | `admin` | `admin123` | `123456` |
| **Security Analyst** | `ananya` | `Ztna@Demo2026` | Use Authenticator / TOTP script |
| **Standard Employee** | `rahul` | `Ztna@Demo2026` | Use Authenticator / TOTP script |

*To generate TOTP codes for any seeded user live:*
```bash
python scripts/totp.py admin --watch
```

---

## Live Demonstrations

### 1. Test Self-Destructing Vault (Wrong Password vs Right Password)
Run the automated end-to-end self-destruct demo:
```powershell
python scripts/demo_self_destruct.py
```
- **Test 1:** Enters wrong password $\rightarrow$ Instant 3-pass cryptographic wipe and file vanishes from disk.
- **Test 2:** Enters correct password $\rightarrow$ RAM-only decryption + single-use Burn-After-Reading cleanup.

### 2. Verify Cryptographic Audit Chain
Verify the cryptographic integrity of the entire audit ledger:
```powershell
python scripts/verify_chain.py
```

### 3. Test Attack Scenarios
```powershell
pytest backend/tests/test_attack_scenarios.py -v
```

---

## Environment Configuration (`.env`)

```env
# Application
APP_NAME=AI-Based Zero Trust Network Access
APP_ENV=development
DEBUG=true
API_PORT=8000
WEB_PORT=5174

# Security
SECRET_KEY=CHANGE_ME_generate_a_64_byte_random_string
DEMO_STATIC_ADMIN_MFA_CODE=123456

# Twilio Voice Alerts (Optional)
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_FROM_NUMBER=+15551234567
TWILIO_TO_NUMBER=+91xxxxxxxxxx
TWILIO_PUBLIC_BASE_URL=https://your-domain-or-ip
```

---

## License
MIT License. Built for enterprise Zero Trust & Insider Threat Defense.
