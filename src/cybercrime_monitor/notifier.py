"""Optional Gotify push notifications for critical matches."""
import asyncio
import logging

import httpx

from .settings import settings

log = logging.getLogger(__name__)


async def push_gotify(title: str, message: str, priority: int = 8) -> None:
    if not settings.gotify_url or not settings.gotify_token:
        return

    url = settings.gotify_url.rstrip("/") + "/message"
    payload = {"title": title, "message": message, "priority": priority}
    headers = {"X-Gotify-Key": settings.gotify_token}

    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                return
        except Exception as exc:
            log.warning("Gotify push attempt %d failed: %s", attempt + 1, exc)
            if attempt < 2:
                await asyncio.sleep(2 ** attempt * 2)
