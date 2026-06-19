"""Generic RSS/Atom collector — far more stable than HTML scraping since the
feed format is a stable contract, unlike forum markup (see html_forum.py/
tor_forum.py, most of which are disabled in sources.yaml due to layout
drift). Modeled directly on nitter.py, which is itself just an RSS reader
for a single account."""
import logging
from datetime import datetime
from email.utils import parsedate_to_datetime

import feedparser

from .. import health
from ..http import clearnet_client
from ..models import Item
from .base import BaseCollector
from .nitter import _strip_html

log = logging.getLogger(__name__)


class RSSCollector(BaseCollector):
    async def fetch(self) -> list[Item]:
        url = self.config["url"]
        extra_tags = self.config.get("source_tags", [])

        try:
            async with clearnet_client(timeout=20.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            log.warning("[%s] RSS fetch error: %s", self.source_id, exc)
            health.record_error(self.source_id, str(exc) or repr(exc))
            return []

        feed = feedparser.parse(text)
        if feed.bozo and not feed.entries:
            log.warning("[%s] RSS parse error: %s", self.source_id, feed.get("bozo_exception"))
            health.record_error(self.source_id, str(feed.get("bozo_exception") or "unparseable feed"))
            return []

        items: list[Item] = []
        for entry in feed.entries:
            title = entry.get("title", "")[:300]
            url_link = entry.get("link", "")
            if not url_link:
                continue
            summary = entry.get("summary", "") or entry.get("description", "")
            snippet = _strip_html(summary)[:500]
            pub_at = _parse_feed_date(entry.get("published", "") or entry.get("updated", ""))
            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title,
                    url=url_link,
                    snippet=snippet,
                    published_at=pub_at,
                    source_tags=["rss", *extra_tags],
                )
            )
        return items


def _parse_feed_date(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return parsedate_to_datetime(s)
    except Exception:
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None
