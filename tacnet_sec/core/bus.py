"""
Synchronous in-process event bus.

Every detector's handler runs in the caller's thread the moment publish() is
invoked. This keeps the agent simple (no event loop bookkeeping) and still
lets the dashboard server use FastAPI's async stack independently.

If you ever need async handlers, use publish_async() and declare your handler
as `async def`; it will be awaited. Sync handlers continue to work either way.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, List

log = logging.getLogger(__name__)

Handler = Callable[[Dict[str, Any]], Any]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Handler]] = {}

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._subscribers.setdefault(topic, []).append(handler)

    def publish(self, topic: str, event: Dict[str, Any]) -> None:
        """Synchronous publish. Detector handlers are invoked in order.

        A single misbehaving handler never takes the bus down - we log and
        move on so one noisy detector can't blind the others.
        """
        for handler in self._subscribers.get(topic, []):
            try:
                result = handler(event)
            except Exception:  # noqa: BLE001
                log.exception("handler for %s raised", topic)
                continue
            if asyncio.iscoroutine(result):
                # Someone registered an async handler against the sync bus.
                # Drive it to completion so we don't silently drop work.
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # Can't block - schedule it.
                        asyncio.ensure_future(result)
                    else:
                        loop.run_until_complete(result)
                except RuntimeError:
                    asyncio.run(result)

    async def publish_async(self, topic: str, event: Dict[str, Any]) -> None:
        """Async equivalent of publish(); awaits coroutine handlers."""
        for handler in self._subscribers.get(topic, []):
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:  # noqa: BLE001
                log.exception("handler for %s raised", topic)