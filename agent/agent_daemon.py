"""EDR Endpoint Agent Daemon.

Collects local OS telemetry, maintains durable offline SQLite queue,
sends heartbeats and events to ZTNA Gateway, and handles active containment.
"""

from __future__ import annotations

import logging
import os
import platform
import threading
import time
from typing import Any

import httpx

from agent.collectors import SystemTelemetryCollector
from agent.offline_queue import OfflineQueue

logger = logging.getLogger("edr_agent")


class EDRAgentDaemon:
    def __init__(
        self,
        gateway_url: str = "http://127.0.0.1:8000",
        agent_id: str | None = None,
        db_path: str = "storage/edr_agent_offline.db",
        fingerprint: str | None = None,
        poll_interval: int = 10,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.agent_id = agent_id or os.environ.get("EDR_AGENT_ID") or f"edr-{platform.node()}"
        self.hostname = platform.node()
        self.os_type = platform.system()
        self.fingerprint = fingerprint
        self.poll_interval = poll_interval
        self.queue = OfflineQueue(db_path=db_path)
        self.is_running = False
        self.is_isolated = False
        self._stop_event = threading.Event()

    def send_heartbeat(self) -> bool:
        """Transmit alive heartbeat to ZTNA Gateway."""
        url = f"{self.gateway_url}/api/edr/heartbeat"
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os_type": self.os_type,
            "version": "1.0.0",
            "fingerprint": self.fingerprint,
        }
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    self.is_isolated = bool(data.get("is_isolated", False))
                    return True
        except Exception as exc:
            logger.debug("Heartbeat transmission failed (offline): %s", exc)
        return False

    def collect_and_queue(self) -> None:
        """Sample local endpoint state and enqueue events."""
        processes = SystemTelemetryCollector.collect_processes()
        threats = SystemTelemetryCollector.detect_suspicious_patterns(processes)

        for t in threats:
            self.queue.enqueue(
                event_type=t["event_type"],
                severity=t["severity"],
                source=t["source"],
                details=t["details"],
                timestamp=t["timestamp"],
            )

        # Periodically log regular process snapshot
        self.queue.enqueue(
            event_type="PROCESS_SNAPSHOT",
            severity="INFO",
            source="system_collector",
            details={
                "process_count": len(processes),
                "snapshot": SystemTelemetryCollector.collect_snapshot(),
            },
        )

    def flush_queue(self) -> int:
        """Send queued events to ZTNA Gateway."""
        if self.queue.queue_depth() == 0:
            return 0

        batch = self.queue.pop_batch(limit=30)
        if not batch:
            return 0

        url = f"{self.gateway_url}/api/edr/events"
        payload = {
            "agent_id": self.agent_id,
            "events": [
                {
                    "event_type": e["event_type"],
                    "severity": e["severity"],
                    "source": e["source"],
                    "details": e["details"],
                    "timestamp": e["timestamp"],
                }
                for e in batch
            ],
        }

        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    return len(batch)
        except Exception as exc:
            logger.debug("Telemetry flush failed: %s", exc)

        # Re-enqueue on failure so no events are lost
        for e in batch:
            self.queue.enqueue(
                event_type=e["event_type"],
                severity=e["severity"],
                source=e["source"],
                details=e["details"],
                timestamp=e["timestamp"],
            )
        return 0

    def run_cycle(self) -> None:
        """Execute one collection, heartbeat, and transmission cycle."""
        self.send_heartbeat()
        self.collect_and_queue()
        self.flush_queue()

    def start(self) -> None:
        """Start the background monitoring thread."""
        self.is_running = True
        self._stop_event.clear()

        def _loop():
            while not self._stop_event.is_set():
                self.run_cycle()
                self._stop_event.wait(self.poll_interval)

        t = threading.Thread(target=_loop, daemon=True, name="EDRAgentThread")
        t.start()

    def stop(self) -> None:
        """Stop the background monitoring."""
        self.is_running = False
        self._stop_event.set()
