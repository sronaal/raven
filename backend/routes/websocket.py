from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from services.ws_manager import manager

router = APIRouter()


@router.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.send_personal({"type": "pong", "message": data}, client_id)
    except WebSocketDisconnect:
        manager.disconnect(websocket, client_id)
