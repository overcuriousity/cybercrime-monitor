"""HaveIBeenPwned breach catalog collector — diffs on each poll."""
import json
import logging
from datetime import datetime
from pathlib import Path

from ..http import clearnet_client
from ..models import Item
from .base import BaseCollector

log = logging.getLogger(__name__)

_HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"
_STATE_FILE = Path("data/hibp_seen.json")


class HIBPCollector(BaseCollector):
    def __init__(self, config, db_conn, sse_broadcaster) -> None:
        super().__init__(config, db_conn, sse_broadcaster)
        self._seen: set[str] = _load_seen()

    async def fetch(self) -> list[Item]:
        try:
            async with clearnet_client() as client:
                resp = await client.get(
                    _HIBP_URL,
                    headers={"hibp-api-key": "", "User-Agent": "cybercrime-monitor/0.1 (security research)"},
                )
                resp.raise_for_status()
                breaches = resp.json()
        except Exception as exc:
            log.warning("[%s] HIBP error: %s", self.source_id, exc)
            return []

        all_names = {b.get("Name", "") for b in breaches if b.get("Name")}

        # First run: silently baseline the entire catalog so we only alert on future additions
        if not self._seen:
            log.info("[%s] first run — baselining %d existing breaches, will only report new ones", self.source_id, len(all_names))
            self._seen = all_names
            _save_seen(self._seen)
            return []

        items: list[Item] = []
        new_names: set[str] = set()

        for breach in breaches:
            name = breach.get("Name", "")
            if not name or name in self._seen:
                continue
            new_names.add(name)

            domain = breach.get("Domain", "")
            breach_date = breach.get("BreachDate", "")
            description = _strip_html(breach.get("Description", ""))[:400]
            data_classes = ", ".join(breach.get("DataClasses", []))
            is_verified = breach.get("IsVerified", False)
            count = breach.get("PwnCount", 0)

            title = f"[HIBP] {name} breach — {count:,} records"
            if not is_verified:
                title += " (unverified)"
            snippet = (
                f"Domain: {domain} | Date: {breach_date} | "
                f"Data: {data_classes}\n{description}"
            )

            items.append(
                Item(
                    source_id=self.source_id,
                    source_name=self.source_name,
                    title=title,
                    url=f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                    snippet=snippet,
                    published_at=_parse_date(breach_date),
                    source_tags=["hibp", "breach-catalog"],
                )
            )

        if new_names:
            self._seen.update(new_names)
            _save_seen(self._seen)

        return items


def _load_seen() -> set[str]:
    try:
        return set(json.loads(_STATE_FILE.read_text()))
    except Exception:
        return set()


def _save_seen(seen: set[str]) -> None:
    """Write atomically (temp file + rename) so a crash mid-write can't
    corrupt the dedupe baseline and re-alert the entire HIBP catalog."""
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(sorted(seen)))
    tmp.replace(_STATE_FILE)


def _parse_date(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        return None


def _strip_html(s: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", s).strip()
