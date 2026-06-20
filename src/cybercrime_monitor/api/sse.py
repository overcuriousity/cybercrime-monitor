"""Server-Sent Events broadcaster — fan-out to all connected dashboard clients."""
import asyncio
import json
import logging
from typing import AsyncIterator

from ..settings import settings

log = logging.getLogger(__name__)


class TooManySubscribers(Exception):
    """Raised by subscribe() when the SSE fan-out is already at its cap (see
    settings.sse_max_subscribers). This dashboard is meant for one analyst's
    own browser tabs, not arbitrary public load — broadcast() already fans
    out to every queue synchronously per item, so an unbounded subscriber
    count is a real memory/CPU DoS surface on a publicly-reachable instance."""


class SSEBroadcaster:
    def __init__(self) -> None:
        self._queues: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        if len(self._queues) >= settings.sse_max_subscribers:
            log.warning(
                "SSE subscriber cap reached (%d) — rejecting new connection",
                settings.sse_max_subscribers,
            )
            raise TooManySubscribers()
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._queues.append(q)
        log.debug("SSE subscriber added (total: %d)", len(self._queues))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._queues.remove(q)
        except ValueError:
            pass
        log.debug("SSE subscriber removed (total: %d)", len(self._queues))

    async def broadcast(self, payload: dict) -> None:
        if not self._queues:
            return
        msg = json.dumps(payload, default=str)
        dead: list[asyncio.Queue] = []
        for q in self._queues:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                log.warning("SSE queue full — dropping slow subscriber")
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

    async def broadcast_status(self, subsystem: str, payload: dict) -> None:
        """Lightweight status event for live dashboard updates."""
        await self.broadcast({"type": "status", "subsystem": subsystem, **payload})

    async def broadcast_activity(self, event: dict) -> None:
        """One row from ai_activity (db.log_ai_activity's return value),
        pushed live to the public Activity tab. Separate "type" from
        broadcast_status so the client can route AI-activity rows straight
        into the activity log feed without filtering "status" spam out of
        it (and vice versa)."""
        await self.broadcast({"type": "activity", **event})

    async def stream(self, q: asyncio.Queue) -> AsyncIterator[str]:
        """Yield SSE-formatted strings from the subscriber queue."""
        try:
            while True:
                msg = await asyncio.wait_for(q.get(), timeout=25.0)
                yield f"data: {msg}\n\n"
        except asyncio.TimeoutError:
            # heartbeat to keep connection alive through proxies
            yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            return


broadcaster = SSEBroadcaster()
