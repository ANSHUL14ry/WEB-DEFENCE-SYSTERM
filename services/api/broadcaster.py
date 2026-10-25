"""
AEGIS Ω — Real-Time Event Broadcaster
Manages active WebSocket connections to SOC dashboards and broadcasts normalized telemetry events.
"""

import asyncio
import json
import logging
from typing import Set, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger("aegis.broadcaster")


class EventBroadcaster:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"SOC Dashboard WebSocket connected. Active subscribers: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info(f"SOC Dashboard WebSocket disconnected. Remaining subscribers: {len(self.active_connections)}")

    async def broadcast(self, event_data: Dict[str, Any]):
        """Broadcast a normalized security event to all connected dashboard clients."""
        if not self.active_connections:
            return

        message = json.dumps(event_data)
        disconnected = set()

        async with self._lock:
            for connection in list(self.active_connections):
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.debug(f"Failed to send to client ({e}); marking for removal.")
                    disconnected.add(connection)

            for dead_conn in disconnected:
                self.active_connections.discard(dead_conn)


# Global singleton broadcaster instance
broadcaster = EventBroadcaster()
