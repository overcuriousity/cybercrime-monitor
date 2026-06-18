"""Forum listing scraper routed through the Tor SOCKS proxy."""
import logging
from datetime import datetime
from urllib.parse import urljoin

from selectolax.parser import HTMLParser

from .. import health
from ..http import tor_client
from ..models import Item
from .base import BaseCollector
from .html_forum import _parse_date

log = logging.getLogger(__name__)


class TorForumCollector(BaseCollector):
    async def fetch(self) -> list[Item]:
        url = self.config["url"]
        row_sel = self.config.get("row_selector", "tr")
        title_sel = self.config.get("title_selector", "a")
        url_sel = self.config.get("url_selector", "a")
        date_sel = self.config.get("date_selector", "")

        try:
            async with tor_client() as client:
                resp = await client.get(url)
                resp.raise_for_status()
        except Exception as exc:
            log.warning("[%s] Tor fetch error: %s", self.source_id, exc)
            health.record_error(self.source_id, str(exc) or repr(exc))
            return []

        tree = HTMLParser(resp.text)
        items: list[Item] = []

        for row in tree.css(row_sel):
            title_node = row.css_first(title_sel)
            url_node = row.css_first(url_sel)
            if not title_node or not url_node:
                continue

            title = title_node.text(strip=True)
            href = url_node.attributes.get("href", "")
            if not href:
                continue
            full_url = urljoin(url, href)

            pub_at = None
            if date_sel:
                date_node = row.css_first(date_sel)
                if date_node:
                    pub_at = _parse_date(
                        date_node.attributes.get("datetime", "") or date_node.text(strip=True)
                    )

            snippet = row.text(strip=True)[:500]

            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title,
                    url=full_url,
                    snippet=snippet,
                    published_at=pub_at,
                    source_tags=["tor", "forum"],
                )
            )

        return items
