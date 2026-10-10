"""Durable SQLite-backed offline event queue for EDR endpoint agent."""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class OfflineQueue:
    """Manages offline telemetry events in local SQLite database when gateway is unreachable."""

    def __init__(self, db_path: str = "storage/edr_agent_offline.db", max_size: int = 5000):
        target = Path(db_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = str(target)
        self.max_size = max_size
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS offline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            conn.commit()

    def enqueue(
        self,
        *,
        event_type: str,
        severity: str,
        source: str,
        details: dict[str, Any],
        timestamp: str | None = None,
    ) -> str:
        """Enqueue an event locally."""
        event_id = str(uuid.uuid4())
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        payload = json.dumps(details)

        with self._get_connection() as conn:
            # Check capacity
            cur = conn.execute("SELECT COUNT(*) FROM offline_events")
            count = cur.fetchone()[0]
            if count >= self.max_size:
                # Evict oldest 100 entries
                conn.execute("DELETE FROM offline_events WHERE id IN (SELECT id FROM offline_events ORDER BY id ASC LIMIT 100)")

            conn.execute(
                """
                INSERT INTO offline_events (event_id, event_type, severity, source, details_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_id, event_type, severity, source, payload, ts),
            )
            conn.commit()
        return event_id

    def pop_batch(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch and remove a batch of queued events for transmission."""
        events: list[dict[str, Any]] = []
        ids_to_remove: list[int] = []

        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT id, event_id, event_type, severity, source, details_json, timestamp FROM offline_events ORDER BY id ASC LIMIT ?",
                (limit,),
            )
            for row in cur.fetchall():
                ids_to_remove.append(row["id"])
                events.append({
                    "event_id": row["event_id"],
                    "event_type": row["event_type"],
                    "severity": row["severity"],
                    "source": row["source"],
                    "details": json.loads(row["details_json"]),
                    "timestamp": row["timestamp"],
                })

            if ids_to_remove:
                placeholders = ",".join("?" for _ in ids_to_remove)
                conn.execute(f"DELETE FROM offline_events WHERE id IN ({placeholders})", ids_to_remove)
                conn.commit()

        return events

    def queue_depth(self) -> int:
        """Return total un-flushed events in queue."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM offline_events")
            return cur.fetchone()[0]
