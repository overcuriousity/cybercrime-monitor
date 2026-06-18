"""Nitter RSS collector for X/Twitter accounts."""
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser

from .. import health
from ..http import clearnet_client
from ..models import Item
from .base import BaseCollector

log = logging.getLogger(__name__)


class NitterCollector(BaseCollector):
    def __init__(self, config, db_conn, sse_broadcaster) -> None:
        super().__init__(config, db_conn, sse_broadcaster)
        self._instances: list[str] = config.get("instances", ["https://nitter.net"])
        self._account: str = config["account"]

    async def fetch(self) -> list[Item]:
        for instance in self._instances:
            rss_url = f"{instance.rstrip('/')}/{self._account}/rss"
            items = await self._try_instance(rss_url)
            if items is not None:
                return items
        log.warning("[%s] all Nitter instances failed", self.source_id)
        health.record_error(self.source_id, "all Nitter instances failed")
        return []

    async def _try_instance(self, rss_url: str) -> list[Item] | None:
        try:
            async with clearnet_client(timeout=20.0) as client:
                resp = await client.get(rss_url)
                if resp.status_code != 200:
                    return None
                text = resp.text
        except Exception as exc:
            log.debug("[%s] nitter instance error: %s", self.source_id, exc)
            return None

        feed = feedparser.parse(text)
        if feed.bozo and not feed.entries:
            return None

        items: list[Item] = []
        for entry in feed.entries:
            title = entry.get("title", "")[:300]
            url = entry.get("link", "")
            if not url:
                continue
            snippet = _strip_html(entry.get("summary", ""))[:500]
            pub_at = _parse_rss_date(entry.get("published", ""))
            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title,
                    url=url,
                    snippet=snippet,
                    published_at=pub_at,
                    source_tags=["x", "social", "rss"],
                )
            )
        return items


def _parse_rss_date(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return parsedate_to_datetime(s)
    except Exception:
        return None


def _strip_html(s: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", s)
