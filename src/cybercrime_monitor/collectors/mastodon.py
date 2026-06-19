"""Mastodon public tag timeline collector — no auth required."""
import logging
from datetime import datetime

from .. import health
from ..http import clearnet_client
from ..models import Item
from .base import BaseCollector

log = logging.getLogger(__name__)


class MastodonCollector(BaseCollector):
    def __init__(self, config, db_conn, sse_broadcaster) -> None:
        super().__init__(config, db_conn, sse_broadcaster)
        self._instance = config.get("instance", "infosec.exchange")
        self._tag = config["tag"]

    async def fetch(self) -> list[Item]:
        url = f"https://{self._instance}/api/v1/timelines/tag/{self._tag}?limit=40"
        try:
            async with clearnet_client() as client:
                resp = await client.get(url)
                resp.raise_for_status()
                statuses = resp.json()
        except Exception as exc:
            log.warning("[%s] Mastodon error: %s", self.source_id, exc)
            health.record_error(self.source_id, str(exc) or repr(exc))
            return []

        items: list[Item] = []
        for status in statuses:
            url_link = status.get("url", "")
            if not url_link:
                continue
            account = status.get("account", {}).get("acct", "unknown")
            content_html = status.get("content", "")
            snippet = _strip_html(content_html)[:500]
            title = f"@{account}: {snippet[:120]}"
            pub_at = _parse_date(status.get("created_at", ""))
            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title,
                    url=url_link,
                    snippet=snippet,
                    published_at=pub_at,
                    source_tags=["mastodon", "social", f"#{self._tag}"],
                )
            )
        return items


def _strip_html(s: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", s).strip()


def _parse_date(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None
