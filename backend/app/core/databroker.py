import asyncio
import logging
from typing import Dict, Any, Optional
from app.services.events import bus, Event

logger = logging.getLogger("databroker_mesh")

# The zero-latency local memory cache
LOCAL_STATE: Dict[str, Any] = {
    "sessions": {},
    "users": {},
    "policies": {}
}

class DatabrokerMesh:
    def __init__(self):
        self.task: Optional[asyncio.Task] = None

    async def _sync_loop(self):
        async with bus.subscribe() as queue:
            logger.info("📡 Databroker Mesh subscribed to internal event bus for 0-latency sync.")
            try:
                while True:
                    event: Event = await queue.get()
                    self._handle_event(event)
            except asyncio.CancelledError:
                logger.info("Databroker Mesh sync loop cancelled.")

    def _handle_event(self, event: Event):
        if event.type == "session.score":
            sid = event.payload.get("session_id")
            uid = event.payload.get("user_id")
            revoked = event.payload.get("revoked", False)
            score = event.payload.get("score")
            
            if revoked:
                logger.warning(f"⚡ [DATABROKER] Session {sid} revoked! Invalidating local edge cache instantly.")
                LOCAL_STATE["sessions"][sid] = {"status": "REVOKED"}
            else:
                logger.info(f"⚡ [DATABROKER] Session {sid} trust score updated to {score} in edge cache.")
                LOCAL_STATE["sessions"][sid] = {
                    "status": "ACTIVE",
                    "trust_score": score
                }
                
        elif event.type in ("session.expired", "session.revoked"):
            sid = event.payload.get("session_id")
            logger.warning(f"⚡ [DATABROKER] Session {sid} expired. Purging.")
            LOCAL_STATE["sessions"][sid] = {"status": "REVOKED"}

    def start(self):
        self.task = asyncio.create_task(self._sync_loop())

    def stop(self):
        if self.task:
            self.task.cancel()

databroker_mesh = DatabrokerMesh()

def get_cached_session(session_id: str) -> Optional[dict]:
    return LOCAL_STATE["sessions"].get(session_id)

def get_cached_user(user_id: str) -> Optional[dict]:
    return LOCAL_STATE["users"].get(user_id)

def set_cached_session(session_id: str, data: dict):
    LOCAL_STATE["sessions"][session_id] = data

def set_cached_user(user_id: str, data: dict):
    LOCAL_STATE["users"][user_id] = data
