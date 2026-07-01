"""Tests for the in-process alert broadcaster (cross-thread publish path)."""

import asyncio

from app.realtime.broadcaster import AlertBroadcaster


async def test_publish_reaches_subscriber_from_worker_thread() -> None:
    broadcaster = AlertBroadcaster()
    queue = await broadcaster.subscribe()

    # Mimic the sync detection path: publish runs in a threadpool worker.
    await asyncio.get_running_loop().run_in_executor(None, broadcaster.publish, {"id": 7})

    message = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert message == {"id": 7}


async def test_unsubscribe_stops_delivery() -> None:
    broadcaster = AlertBroadcaster()
    queue = await broadcaster.subscribe()
    broadcaster.unsubscribe(queue)

    broadcaster.publish({"id": 1})
    await asyncio.sleep(0.05)
    assert queue.empty()
