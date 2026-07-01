"""WebSocket endpoint streaming live alerts to authenticated dashboards.

Browsers cannot set an ``Authorization`` header on a WebSocket, so the JWT is
passed as a ``token`` query parameter and validated on connect. The wire
protocol is a small envelope: a ``{"type": "ready"}`` frame once subscribed,
then ``{"type": "alert", "data": {...}}`` for each new alert.
"""

from __future__ import annotations

import asyncio

import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.core.security import decode_access_token
from app.realtime.broadcaster import broadcaster

router = APIRouter()


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket, token: str = "") -> None:
    try:
        decode_access_token(token)
    except jwt.PyJWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    queue = await broadcaster.subscribe()

    async def forward() -> None:
        try:
            while True:
                await websocket.send_json(await queue.get())
        except (WebSocketDisconnect, RuntimeError):
            pass  # client went away mid-send

    await websocket.send_json({"type": "ready"})
    forward_task = asyncio.create_task(forward())
    try:
        # We don't expect inbound frames; this loop just detects disconnect.
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        forward_task.cancel()
        broadcaster.unsubscribe(queue)
