"""Tests for the alert WebSocket endpoint (auth + streaming)."""

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from app.core.security import create_access_token
from app.realtime.broadcaster import broadcaster


def test_ws_rejects_invalid_token(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):  # noqa: PT012
        with client.websocket_connect("/api/ws/alerts?token=not-a-jwt") as ws:
            ws.receive_text()


def test_ws_streams_published_alert(client: TestClient) -> None:
    token = create_access_token(subject="tester", role="analyst")
    with client.websocket_connect(f"/api/ws/alerts?token={token}") as ws:
        # The ready frame guarantees the client is subscribed before we publish.
        assert ws.receive_json() == {"type": "ready"}

        broadcaster.publish({"type": "alert", "data": {"id": 99, "title": "Test"}})
        message = ws.receive_json()
        assert message["type"] == "alert"
        assert message["data"]["id"] == 99
