#!/usr/bin/env python3
"""Seed mock EDR agents, telemetry events, and network blocklists."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from app.core.database import SessionLocal
from app.models.blocked_ip import BlockedIP
from app.models.device import Device
from app.models.edr import EDRAgent, EDREvent


def seed_edr():
    now = datetime.now(timezone.utc)

    with SessionLocal() as db:
        devices = db.query(Device).all()
        dev_map = {i: d.id for i, d in enumerate(devices)}

        # Clear existing
        db.query(EDREvent).delete()
        db.query(EDRAgent).delete()
        db.query(BlockedIP).delete()

        agents_data = [
            {
                "agent_id": "edr-win-dev-01",
                "hostname": "CORP-DEV-WIN11",
                "os_type": "Windows 11 Enterprise",
                "ip_address": "172.10.23.45",
                "status": "ONLINE",
                "is_isolated": False,
                "version": "2.4.1",
                "last_heartbeat_at": now - timedelta(seconds=12),
                "device_id": dev_map.get(0),
            },
            {
                "agent_id": "edr-mac-alice-02",
                "hostname": "ALICE-MACBOOK-PRO",
                "os_type": "macOS Sonoma 14.5",
                "ip_address": "172.10.23.68",
                "status": "ONLINE",
                "is_isolated": False,
                "version": "2.4.1",
                "last_heartbeat_at": now - timedelta(seconds=28),
                "device_id": dev_map.get(1),
            },
            {
                "agent_id": "edr-k8s-prod-03",
                "hostname": "PROD-K8S-WORKER-01",
                "os_type": "Ubuntu 22.04 LTS",
                "ip_address": "10.0.4.15",
                "status": "ONLINE",
                "is_isolated": False,
                "version": "2.4.0",
                "last_heartbeat_at": now - timedelta(seconds=5),
                "device_id": dev_map.get(2),
            },
            {
                "agent_id": "edr-fin-desk-04",
                "hostname": "FINANCE-DESKTOP-04",
                "os_type": "Windows 10 Pro",
                "ip_address": "172.10.23.99",
                "status": "ISOLATED",
                "is_isolated": True,
                "version": "2.3.9",
                "last_heartbeat_at": now - timedelta(minutes=4),
                "device_id": dev_map.get(3),
            },
            {
                "agent_id": "edr-edge-gw-05",
                "hostname": "EDGE-GATEWAY-02",
                "os_type": "Alpine Linux 3.19",
                "ip_address": "10.0.1.1",
                "status": "ONLINE",
                "is_isolated": False,
                "version": "2.4.1",
                "last_heartbeat_at": now - timedelta(seconds=18),
                "device_id": None,
            },
            {
                "agent_id": "edr-hr-lap-06",
                "hostname": "HR-PAYROLL-LAPTOP",
                "os_type": "Windows 11 Pro",
                "ip_address": "172.10.23.112",
                "status": "ONLINE",
                "is_isolated": False,
                "version": "2.4.1",
                "last_heartbeat_at": now - timedelta(seconds=45),
                "device_id": dev_map.get(4),
            },
        ]

        for a in agents_data:
            db.add(EDRAgent(**a))

        events_data = [
            {
                "agent_id": "edr-fin-desk-04",
                "event_type": "DATA_EXFILTRATION_BURST",
                "severity": "CRITICAL",
                "source": "edr.filesystem_monitor",
                "details": {
                    "process": "7z.exe",
                    "pid": 4192,
                    "command": "7z.exe a payroll_backup.zip C:\\Finance\\Q3_Salaries.xlsx",
                    "files_touched": 18,
                    "destination": "E:\\USB_DRIVE\\",
                    "threat_classification": "Unauthorized Insider Data Archive",
                },
                "timestamp": now - timedelta(minutes=6),
            },
            {
                "agent_id": "edr-win-dev-01",
                "event_type": "CREDENTIAL_ACCESS_ATTEMPT",
                "severity": "CRITICAL",
                "source": "edr.process_monitor",
                "details": {
                    "process": "powershell.exe",
                    "pid": 8840,
                    "command": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHc...",
                    "technique": "T1003.001 - LSASS Memory Dump",
                    "action_taken": "Process Terminated & Token Revoked",
                },
                "timestamp": now - timedelta(minutes=14),
            },
            {
                "agent_id": "edr-hr-lap-06",
                "event_type": "USB_MASS_STORAGE_ATTACHED",
                "severity": "HIGH",
                "source": "edr.device_control",
                "details": {
                    "device_vendor": "SanDisk Ultra USB 3.0",
                    "serial_number": "4C530001290822119283",
                    "mount_point": "F:\\",
                    "policy_violation": "Removable media forbidden on HR endpoints",
                    "action_taken": "Read-Only clamped by EDR policy",
                },
                "timestamp": now - timedelta(minutes=22),
            },
            {
                "agent_id": "edr-mac-alice-02",
                "event_type": "SUSPICIOUS_NETWORK_BEACON",
                "severity": "HIGH",
                "source": "edr.network_socket",
                "details": {
                    "remote_ip": "185.220.101.5",
                    "remote_port": 9001,
                    "protocol": "TCP",
                    "asn_type": "Tor Exit Node",
                    "process": "curl",
                    "action_taken": "Connection dropped",
                },
                "timestamp": now - timedelta(minutes=35),
            },
            {
                "agent_id": "edr-k8s-prod-03",
                "event_type": "PRIVILEGE_ESCALATION_DETECTED",
                "severity": "MEDIUM",
                "source": "edr.auditd_engine",
                "details": {
                    "user": "developer_service",
                    "command": "sudo /bin/bash -c cat /etc/shadow",
                    "parent_process": "sshd",
                    "status": "DENIED by AppArmor",
                },
                "timestamp": now - timedelta(hours=1, minutes=10),
            },
            {
                "agent_id": "edr-edge-gw-05",
                "event_type": "FILE_INTEGRITY_VIOLATION",
                "severity": "MEDIUM",
                "source": "edr.fim_engine",
                "details": {
                    "file_path": "/etc/pam.d/sshd",
                    "action": "MODIFIED",
                    "old_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "new_hash": "7d793037a0760186574b0282f2f435e7b1e50774690f69799f4ec91fa2fe3714",
                    "actor": "root",
                },
                "timestamp": now - timedelta(hours=2),
            },
            {
                "agent_id": "edr-k8s-prod-03",
                "event_type": "CONTAINER_LIFECYCLE_EVENT",
                "severity": "INFO",
                "source": "edr.k8s_agent",
                "details": {
                    "namespace": "production-mesh",
                    "pod": "pdp-engine-67d98b5-x8q1",
                    "event": "ContainerStarted",
                    "image": "ztna/pdp:latest",
                },
                "timestamp": now - timedelta(hours=3),
            },
        ]

        for ev in events_data:
            db.add(EDREvent(**ev))

        blocks_data = [
            {
                "ip_address": "185.220.101.5",
                "reason": "Active Tor exit node - anomalous beaconing from ALICE-MACBOOK-PRO",
                "blocked_until": now + timedelta(days=7),
            },
            {
                "ip_address": "45.154.255.89",
                "reason": "Automated brute-force credential stuffing against API gateway",
                "blocked_until": now + timedelta(days=14),
            },
            {
                "ip_address": "194.26.29.114",
                "reason": "High-risk C2 malware infrastructure (Threat Intel confidence 98%)",
                "blocked_until": now + timedelta(days=30),
            },
            {
                "ip_address": "103.145.13.88",
                "reason": "Aggressive port scanning on Edge Gateway ports 22, 443, 8000",
                "blocked_until": now + timedelta(days=3),
            },
        ]

        for b in blocks_data:
            db.add(BlockedIP(**b))

        db.commit()
        print(f"Seeded {len(agents_data)} EDR Agents, {len(events_data)} Telemetry Events, {len(blocks_data)} Blocked IPs.")


if __name__ == "__main__":
    seed_edr()
