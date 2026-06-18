"""Paste site collectors — pastebin archive index and rentry."""
import logging
import re
from datetime import datetime
from urllib.parse import urljoin

from selectolax.parser import HTMLParser

from .. import health
from ..http import clearnet_client
from ..models import Item
from .base import BaseCollector

log = logging.getLogger(__name__)


class PasteCollector(BaseCollector):
    async def fetch(self) -> list[Item]:
        url = self.config["url"]
        if "pastebin.com" in url:
            return await self._fetch_pastebin(url)
        if "rentry" in url:
            return await self._fetch_rentry(url)
        log.warning("[%s] unknown paste URL pattern: %s", self.source_id, url)
        return []

    async def _fetch_pastebin(self, url: str) -> list[Item]:
        try:
            async with clearnet_client() as client:
                resp = await client.get(url)
                resp.raise_for_status()
        except Exception as exc:
            log.warning("[%s] pastebin error: %s", self.source_id, exc)
            health.record_error(self.source_id, str(exc) or repr(exc))
            return []

        tree = HTMLParser(resp.text)
        items: list[Item] = []
        fetch_content = self.config.get("fetch_content", False)

        for row in tree.css("table tr"):
            link = row.css_first("td a")
            if not link:
                continue
            href = link.attributes.get("href", "")
            if not href or href.startswith("/archive"):
                continue
            # strip ?source=archive query param for canonical URL
            canonical = href.split("?")[0]
            title = link.text(strip=True)
            full_url = "https://pastebin.com" + canonical

            snippet = ""
            if fetch_content:
                raw_url = "https://pastebin.com/raw" + canonical
                try:
                    async with clearnet_client(timeout=10) as client:
                        r = await client.get(raw_url)
                        if r.status_code == 200:
                            snippet = r.text[:1000]
                except Exception:
                    pass

            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title or href,
                    url=full_url,
                    snippet=snippet,
                    source_tags=["paste", "clearnet"],
                )
            )
        return items

    async def _fetch_rentry(self, url: str) -> list[Item]:
        try:
            async with clearnet_client() as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            log.warning("[%s] rentry error: %s", self.source_id, exc)
            health.record_error(self.source_id, str(exc) or repr(exc))
            return []

        items: list[Item] = []
        pages = data if isinstance(data, list) else data.get("pages", [])
        for page in pages[:50]:
            code = page.get("code", page.get("url", ""))
            if not code:
                continue
            full_url = f"https://rentry.co/{code}"
            title = page.get("title", code)
            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title,
                    url=full_url,
                    snippet="",
                    source_tags=["paste", "rentry"],
                )
            )
        return items
