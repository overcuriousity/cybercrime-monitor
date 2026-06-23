"""Generic clearnet forum listing scraper using selectolax."""
import asyncio
import logging
from typing import Any
from urllib.parse import urljoin

from selectolax.parser import HTMLParser

from .. import health
from ..http import clearnet_client
from ..models import Item
from ._text import parse_date as _parse_date
from .base import BaseCollector

log = logging.getLogger(__name__)


class HTMLForumCollector(BaseCollector):
    async def fetch(self) -> list[Item]:
        url = self.config["url"]
        row_sel = self.config.get("row_selector", "tr")
        title_sel = self.config.get("title_selector", "a")
        url_sel = self.config.get("url_selector", "a")
        date_sel = self.config.get("date_selector", "")

        async with clearnet_client() as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
            except Exception as exc:
                log.warning("[%s] HTTP error: %s", self.source_id, exc)
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

            # Grab full row text as snippet
            snippet = row.text(strip=True)[:500]

            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title,
                    url=full_url,
                    snippet=snippet,
                    published_at=pub_at,
                    source_tags=["clearnet", "forum"],
                )
            )

        return items
