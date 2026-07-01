"""In-process pub/sub for streaming alerts to connected WebSocket clients.

A single :class:`AlertBroadcaster` fans each new alert out to every subscribed
client through an ``asyncio.Queue``. Detection runs in FastAPI's threadpool
(a sync path), so :meth:`publish` is safe to call from a worker thread — it
hands work to the event loop via ``call_soon_threadsafe``.

This is intentionally process-local. Scaling to multiple workers would swap
this for Redis pub/sub behind the same interface.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

Message = dict[str, Any]


class AlertBroadcaster:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[Message]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    async def subscribe(self) -> asyncio.Queue[Message]:
        """Register a new client queue (call from within the event loop)."""
        queue: asyncio.Queue[Message] = asyncio.Queue(maxsize=100)
        self._loop = asyncio.get_running_loop()
        with self._lock:
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Message]) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    def publish(self, message: Message) -> None:
        """Fan ``message`` out to all subscribers. Safe to call from any thread."""
        loop = self._loop
        if loop is None:
            return  # nothing has subscribed yet
        with self._lock:
            queues = list(self._subscribers)
        for queue in queues:
            loop.call_soon_threadsafe(self._offer, queue, message)

    @staticmethod
    def _offer(queue: asyncio.Queue[Message], message: Message) -> None:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            pass  # drop for a slow client rather than block the loop


broadcaster = AlertBroadcaster()
