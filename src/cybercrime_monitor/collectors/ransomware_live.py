"""ransomware.live recent-victims collector — structured JSON, no scraping,
no Tor. Gives real actor/victim/country data instead of the free-text actor
extraction in db.py:_extract_actor_name, and is far more stable than any of
the disabled Tor/clearnet forum scrapers in sources.yaml.

API: https://api.ransomware.live/v2/recentvictims (v2, free tier, no auth,
rate-limited to 1 req/min — keep interval_seconds >= 90 in sources.yaml).
"""
import logging
from datetime import datetime

from ..http import clearnet_client
from ..models import Item
from .base import BaseCollector

log = logging.getLogger(__name__)

_RECENT_VICTIMS_URL = "https://api.ransomware.live/v2/recentvictims"


class RansomwareLiveCollector(BaseCollector):
    async def fetch(self) -> list[Item]:
        try:
            async with clearnet_client(timeout=20.0) as client:
                resp = await client.get(_RECENT_VICTIMS_URL)
                resp.raise_for_status()
                victims = resp.json()
        except Exception as exc:
            log.warning("[%s] ransomware.live error: %s", self.source_id, exc)
            return []

        if not isinstance(victims, list):
            log.warning("[%s] unexpected response shape: %r", self.source_id, type(victims))
            return []

        items: list[Item] = []
        for v in victims:
            name = (v.get("victim") or "").strip()
            group = (v.get("group") or "").strip()
            if not name or not group:
                continue

            country = v.get("country") or ""
            domain = v.get("domain") or ""
            activity = v.get("activity") or ""
            description = (v.get("description") or "")[:400]
            attack_date = v.get("attackdate") or v.get("discovered") or ""

            # claim_url is the .onion leak-site posting; url is ransomware.live's
            # own (base64-encoded) reference page. Prefer the latter as the
            # clickable link — clearnet, stable, no Tor required to view.
            link = v.get("url") or v.get("claim_url") or f"https://www.ransomware.live/#/v2/group/{group}"

            title = f"[{group}] {name} — ransomware victim"
            if country:
                title += f" ({country})"
            snippet_parts = [p for p in (
                f"Group: {group}",
                f"Domain: {domain}" if domain else "",
                f"Sector: {activity}" if activity else "",
                description,
            ) if p]
            snippet = " | ".join(snippet_parts)

            source_tags = ["ransomware", "leak-site"]
            if country:
                source_tags.append(f"country:{country.lower()}")

            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title,
                    url=link,
                    snippet=snippet,
                    published_at=_parse_date(attack_date),
                    source_tags=source_tags,
                    # Structured fields — consumed by db.py:stats_top_actors to
                    # ground the "top ransomware groups" chart in real data
                    # instead of regex-extracted free text (see _extract_actor_name).
                    extra={"actor": group, "victim": name, "country": country},
                )
            )
        return items


def _parse_date(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        pass
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None
