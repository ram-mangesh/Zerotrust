"""Tests for Zero-Trust Self-Destructing Vault Service and Tamper Alerts."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import pytest

from app.services.vault_service import (
    derive_key,
    encrypt_payload,
    generate_vault_script,
)
from tests.conftest import auth_headers, sign_in


def test_vault_encryption_and_key_derivation():
    password = "SuperSecretPassword123"
    salt = os.urandom(16)
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2
    assert len(key1) == 32

    payload = b"CRITICAL_PAYROLL_DATA_2026,Alice,$150000"
    filename = "payroll.csv"
    encrypted = encrypt_payload(payload, password, filename)

    assert "salt" in encrypted
    assert "nonce" in encrypted
    assert "ciphertext" in encrypted
    assert encrypted["filename"] == filename


def test_generated_vault_script_syntax_and_structure():
    payload = b"CONFIDENTIAL_SOURCE_CODE = True"
    filename = "source.py"
    script = generate_vault_script(
        payload, filename, password="MySecretPassword", max_attempts=1
    )

    assert "ZERO-TRUST SELF-DESTRUCTING DATA CONTAINER" in script
    assert "self_destruct" in script
    assert "decrypt_vault" in script


def test_vault_self_destruct_execution_on_wrong_password():
    payload = b"RESTRICTED_DATABASE_BACKUP_DUMP"
    filename = "db_dump.sql"
    script = generate_vault_script(
        payload, filename, password="CorrectPassword123", max_attempts=1
    )

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(script.encode("utf-8"))
        vault_path = f.name

    assert os.path.exists(vault_path)

    # Run the vault script with WRONG password piped in
    proc = subprocess.run(
        [sys.executable, vault_path],
        input="attacker\nWrongPassword999\n",
        capture_output=True,
        text=True,
    )

    # The script should have failed and self-destructed (deleted itself)
    assert not os.path.exists(vault_path), "Vault file should have been deleted on wrong password!"
    assert "DEAD-MAN'S SWITCH ENGAGED" in proc.stdout or proc.returncode != 0


def test_tamper_alert_api_endpoint(client):
    response = client.post(
        "/api/vault/tamper-alert",
        json={
            "event": "VAULT_TAMPER_SELF_DESTRUCT",
            "filename": "payroll_q3.csv",
            "resource_id": "res-123",
            "user_attempted": "malicious_insider",
            "reason": "Exceeded maximum failed attempts (1).",
            "timestamp": 1791544000.0,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alert_recorded"
    assert data["action"] == "self_destruct_logged"
