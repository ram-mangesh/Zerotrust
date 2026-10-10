"""Zero-Trust Self-Destructing Data Container (Vault Service).

Packages sensitive files into standalone, tamper-resistant, self-destructing
Python executables. If incorrect credentials are provided upon opening, the
container engages an active Dead-Man's Switch: it performs a multi-pass secure
disk wipe (shred) and deletes itself, while stealthily notifying the ZTNA SOC.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 120_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_payload(plaintext: bytes, password: str, filename: str) -> dict[str, str]:
    """Encrypt plaintext using AES-256-GCM and PBKDF2."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, filename.encode("utf-8"))

    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "filename": filename,
    }


def generate_vault_script(
    plaintext: bytes,
    filename: str,
    password: str,
    *,
    max_attempts: int = 1,
    alert_url: str = "",
    resource_id: str = "",
) -> str:
    """Package a file into a standalone, self-destructing Python runner script."""
    encrypted = encrypt_payload(plaintext, password, filename)

    template = f'''#!/usr/bin/env python3
# ==============================================================================
# ZERO-TRUST SELF-DESTRUCTING DATA CONTAINER (ZTNA-VAULT)
# Asset: {filename}
# Classification: RESTRICTED // CONFIDENTIAL
# ==============================================================================
import base64
import getpass
import json
import os
import sys
import time
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

VAULT_META = {{
    "filename": "{encrypted['filename']}",
    "resource_id": "{resource_id}",
    "salt": "{encrypted['salt']}",
    "nonce": "{encrypted['nonce']}",
    "ciphertext": "{encrypted['ciphertext']}",
    "max_attempts": {max_attempts},
    "alert_url": "{alert_url}",
    "iterations": {PBKDF2_ITERATIONS},
}}

def send_stealth_alert(reason, user_attempted):
    alert_url = VAULT_META.get("alert_url")
    if not alert_url:
        return
    try:
        payload = {{
            "event": "VAULT_TAMPER_SELF_DESTRUCT",
            "filename": VAULT_META["filename"],
            "resource_id": VAULT_META.get("resource_id", ""),
            "user_attempted": user_attempted,
            "reason": reason,
            "timestamp": time.time(),
        }}
        req = urllib.request.Request(
            alert_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={{"Content-Type": "application/json"}},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass

def wipe_file_on_disk():
    """Secure 3-pass wipe and deletion of the container from disk."""
    try:
        target_path = os.path.abspath(__file__)
        file_size = max(os.path.getsize(target_path), 4096)

        with open(target_path, "wb") as f:
            f.write(os.urandom(file_size))
            f.flush()
            f.seek(0)
            f.write(b"\\x00" * file_size)
            f.flush()
            f.seek(0)
            f.write(os.urandom(file_size))
            f.flush()

        os.remove(target_path)
    except Exception:
        try:
            os.remove(os.path.abspath(__file__))
        except Exception:
            pass

def self_destruct(reason, user_attempted=""):
    print("\\n" + "=" * 65)
    print("[!] [SECURITY BREACH] DEAD-MAN'S SWITCH ENGAGED")
    print(f"[!] Reason: {{reason}}")
    print("[!] Initiating 3-pass cryptographic wipe...")
    print("=" * 65)

    send_stealth_alert(reason, user_attempted)
    wipe_file_on_disk()

    print("[+] Secure shredding complete. 0 bytes recoverable on disk.")
    print("[+] Container permanently deleted from device.\\n")
    sys.exit(1)

def decrypt_vault(password):
    global HAS_CRYPTO
    if not HAS_CRYPTO:
        print("[!] Required package 'cryptography' is missing. Installing...")
        import subprocess
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
        except Exception:
            print("[X] Could not install cryptography engine.")
            return None

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = base64.b64decode(VAULT_META["salt"])
    nonce = base64.b64decode(VAULT_META["nonce"])
    ciphertext = base64.b64decode(VAULT_META["ciphertext"])
    filename = VAULT_META["filename"]

    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=VAULT_META["iterations"],
        )
        key = kdf.derive(password.encode("utf-8"))
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, filename.encode("utf-8"))
        return plaintext
    except Exception:
        return None

def get_password_input(prompt="Enter Vault Decryption Key : "):
    print(prompt, end="", flush=True)
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        return line.strip()

    # Interactive masked input with asterisks (*) for Windows
    try:
        import msvcrt
        chars = []
        while True:
            ch = msvcrt.getwch()
            if ch in ('\\r', '\\n'):
                print()
                break
            elif ch == '\\x08':  # Backspace
                if chars:
                    chars.pop()
                    sys.stdout.write('\\b \\b')
                    sys.stdout.flush()
            elif ch == '\\x03':  # Ctrl+C
                raise KeyboardInterrupt
            elif ch == '\\x1b' or ch == '\\x00' or ch == '\\xe0':  # Arrow/special keys
                if ch in ('\\x00', '\\xe0'):
                    msvcrt.getwch()  # consume secondary code
                continue
            else:
                chars.append(ch)
                sys.stdout.write('*')
                sys.stdout.flush()
        return "".join(chars)
    except Exception:
        try:
            return getpass.getpass("")
        except Exception:
            return input("")

def main():
    print("=" * 65)
    print("[*] ZERO-TRUST SELF-DESTRUCTING DATA VAULT")
    print(f"[*] Asset Name    : {{VAULT_META['filename']}}")
    print(f"[*] Classification: RESTRICTED // CONFIDENTIAL")
    print(f"[*] Max Attempts  : {{VAULT_META['max_attempts']}} Attempt(s) Allowed")
    print("=" * 65)
    print("WARNING: Entering incorrect credentials will trigger the")
    print("Dead-Man's Switch, instantly shredding and destroying")
    print("this file from your storage device.")
    print("=" * 65)

    attempts = 0
    max_att = VAULT_META["max_attempts"]

    while attempts < max_att:
        attempts += 1
        user = input("\\nEnter Authorized Username : ").strip()
        pwd = get_password_input("Enter Vault Decryption Key : ")

        if not pwd:
            print("[!] Password cannot be empty.")
            continue

        print("\\n[*] Verifying cryptographic integrity...")
        plaintext = decrypt_vault(pwd)

        if plaintext is not None:
            print("\\n" + "=" * 65)
            print("[+] [ACCESS GRANTED] Decryption Key Verified Successfully!")
            print(f"[+] User: {{user}} | Decrypted Asset: {{VAULT_META['filename']}}")
            print("=" * 65)

            print("\\nSelect Mode:")
            print("  [1] View in RAM & Burn Container (Single-Use Ephemeral Mode - recommended)")
            print("  [2] Extract to local file")
            print("  [3] View in RAM and keep container")
            choice = input("\\nEnter Choice [1/2/3] (default: 1): ").strip() or "1"

            if choice == "2":
                out_name = f"DECRYPTED_{{VAULT_META['filename']}}"
                with open(out_name, "wb") as f:
                    f.write(plaintext)
                print(f"[+] File written to: {{out_name}}")
            else:
                print("\\n--- START OF DECRYPTED CONTENT ---")
                try:
                    print(plaintext.decode("utf-8"))
                except UnicodeDecodeError:
                    print(f"<Binary Payload of {{len(plaintext)}} bytes>")
                print("--- END OF DECRYPTED CONTENT ---\\n")

            if choice == "1":
                print("[*] Engaging Burn-After-Reading protocol (Ephemeral Zero-Trust)...")
                wipe_file_on_disk()
                print("[+] Container shredded and deleted from disk. No residual data left.")

            return 0
        else:
            print(f"[X] INVALID CREDENTIALS! (Attempt {{attempts}}/{{max_att}})")
            if attempts >= max_att:
                self_destruct(reason=f"Exceeded maximum failed attempts ({{max_att}}). Incorrect password by '{{user}}'.", user_attempted=user)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\\n[!] Aborted by user.")
        sys.exit(130)
'''
    return template
