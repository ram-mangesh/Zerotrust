#!/usr/bin/env python3
"""CIPHER02: Zero-Trust Self-Destructing Data Container Live Demonstration.

Demonstrates:
1. Packaging a sensitive asset into an encrypted, tamper-resistant vault container.
2. Unauthorized opening attempt with wrong credentials -> 3-Pass cryptographic shredding & immediate file deletion.
3. Authorized opening with correct credentials -> Decryption in volatile memory (RAM only).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from app.services.vault_service import generate_vault_script

SAMPLE_PAYROLL_DATA = b"""EMPLOYEE_ID,FULL_NAME,ROLE,SALARY_USD,BANK_ACCOUNT,SSN
EMP-1001,Alice Johnson,Senior Architect,$195000,US99-0012-9988-4411,987-65-4321
EMP-1002,Bob Miller,VP Engineering,$240000,US88-9922-3344-5566,876-54-3210
EMP-1003,Charlie Davis,Principal Security Eng,$210000,US77-4455-6677-8899,765-43-2109
"""

def print_header(text: str):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def main():
    print_header("CIPHER02: ZERO-TRUST SELF-DESTRUCTING DATA CONTAINER DEMO")
    print("This demo proves that exfiltrated sensitive files cannot be accessed")
    print("without authentication, and instantly self-destruct upon failed credentials.\n")

    vault_filename = "SecureVault_Payroll_2026.py"
    password = "CorrectPass2026"
    vault_path = ROOT_DIR / vault_filename

    print("[Step 1] Creating encrypted Zero-Trust Vault container...")
    alert_url = "http://127.0.0.1:8000/api/vault/tamper-alert"
    vault_code = generate_vault_script(
        plaintext=SAMPLE_PAYROLL_DATA,
        filename="payroll_confidential.csv",
        password=password,
        max_attempts=1,
        alert_url=alert_url,
        resource_id="res-demo-payroll",
    )

    with open(vault_path, "w", encoding="utf-8") as f:
        f.write(vault_code)

    print(f"[+] Encrypted container generated at: {vault_filename}")
    print(f"    Asset: payroll_confidential.csv (Encrypted with AES-256-GCM)")
    print(f"    Authorized Password: '{password}'")
    print(f"    Dead-Man's Switch: Active (Max Failed Attempts: 1)\n")

    print_header("DEMO TEST 1: WRONG PASSWORD (Self-Destruct Trigger)")
    print("Simulating an insider / attacker trying to guess the decryption key...")
    time.sleep(1)

    print(f"\n[*] Executing '{vault_filename}' with INVALID credentials (Attacker: 'mallory', Pass: 'WrongPassword123')...\n")
    proc = subprocess.run(
        [sys.executable, str(vault_path)],
        input="mallory\nWrongPassword123\n",
        capture_output=True,
        text=True,
    )

    print(proc.stdout)
    if proc.stderr:
        print("STDERR:", proc.stderr)

    time.sleep(1)
    file_still_exists = vault_path.exists()
    print("-" * 70)
    print(f"[Verification] Checking disk for '{vault_filename}'...")
    if not file_still_exists:
        print(f"[+] SUCCESS: File '{vault_filename}' was PERMANENTLY SHREDDED AND DELETED FROM DISK!")
    else:
        print(f"[X] FAIL: File still exists on disk.")

    print_header("DEMO TEST 2: AUTHORIZED ACCESS (RAM Decryption)")
    print("Regenerating vault container for authorized user access...")
    with open(vault_path, "w", encoding="utf-8") as f:
        f.write(vault_code)

    print(f"[*] Executing '{vault_filename}' with AUTHORIZED credentials (User: 'admin', Pass: '{password}')...\n")
    proc2 = subprocess.run(
        [sys.executable, str(vault_path)],
        input=f"admin\n{password}\nv\n",
        capture_output=True,
        text=True,
    )

    print(proc2.stdout)
    # Cleanup after demo
    if vault_path.exists():
        vault_path.unlink()

    print_header("DEMONSTRATION COMPLETE")
    print("Summary:")
    print("1. File requires multi-factor username/key authentication to decrypt.")
    print("2. Wrong password triggers immediate 3-pass disk shredding and deletion.")
    print("3. Stealth alert dispatched to ZTNA SOC and logged into Audit Chain.")

if __name__ == "__main__":
    main()
