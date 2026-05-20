import asyncio
import logging
from typing import Dict, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        if client_id not in self.active_connections:
            self.active_connections[client_id] = set()
        self.active_connections[client_id].add(websocket)
        logger.info("WebSocket connected: %s", client_id)

    def disconnect(self, websocket: WebSocket, client_id: str):
        if client_id in self.active_connections:
            self.active_connections[client_id].discard(websocket)
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]
        logger.info("WebSocket disconnected: %s", client_id)

    async def send_personal(self, message: dict, client_id: str):
        if client_id in self.active_connections:
            dead = set()
            for conn in self.active_connections[client_id]:
                try:
                    await conn.send_json(message)
                except Exception:
                    dead.add(conn)
            for d in dead:
                self.active_connections[client_id].discard(d)

    async def broadcast(self, message: dict):
        for client_id in list(self.active_connections.keys()):
            await self.send_personal(message, client_id)


manager = ConnectionManager()
