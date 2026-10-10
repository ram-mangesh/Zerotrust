"""Endpoint telemetry collectors for EDR agent."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class SystemTelemetryCollector:
    """Collects OS posture, running processes, and network listeners."""

    @staticmethod
    def collect_snapshot() -> dict[str, Any]:
        """Collect static and dynamic endpoint state."""
        return {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "pid": os.getpid(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def collect_processes() -> list[dict[str, Any]]:
        """Collect running process telemetry (cross-platform)."""
        processes: list[dict[str, Any]] = []
        if os.name == "posix":
            try:
                out = subprocess.run(
                    ["ps", "-eo", "pid,user,comm,args"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                for line in out.stdout.strip().split("\n")[1:30]:
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 3:
                        processes.append({
                            "pid": int(parts[0]) if parts[0].isdigit() else 0,
                            "user": parts[1],
                            "name": parts[2],
                            "cmd": parts[3] if len(parts) > 3 else parts[2],
                        })
            except Exception as exc:
                logger.debug("Failed to list posix processes: %s", exc)
        return processes

    @staticmethod
    def detect_suspicious_patterns(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Scan processes for obvious suspicious indicators."""
        threats: list[dict[str, Any]] = []
        suspicious_keywords = ("nc -e", "/bin/sh -i", "mimikatz", "meterpreter", "xmrig")

        for p in processes:
            cmd = p.get("cmd", "").lower()
            for kw in suspicious_keywords:
                if kw in cmd:
                    threats.append({
                        "event_type": "THREAT_DETECTED",
                        "severity": "CRITICAL",
                        "source": "process_scanner",
                        "details": {
                            "summary": f"Suspicious process pattern: {kw}",
                            "process": p,
                        },
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
        return threats
