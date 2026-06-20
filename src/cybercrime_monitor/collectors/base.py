"""Base collector — defines the ABC and shared ingestion pipeline."""
import asyncio
import hashlib
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from .. import health
from ..db import insert_item
from ..models import Item
from ..settings import settings

log = logging.getLogger(__name__)


class BaseCollector(ABC):
    def __init__(self, config: dict[str, Any], db_conn, sse_broadcaster) -> None:
        self.config = config
        self.source_id: str = config["id"]
        self.source_name: str = config.get("name", config["id"])
        self.db = db_conn
        self.sse = sse_broadcaster

    @abstractmethod
    async def fetch(self) -> list[Item]:
        """Fetch new items from the source. Must be idempotent."""
        ...

    async def run(self) -> None:
        """Full pipeline: fetch → dedupe → store → broadcast."""
        log.info("[%s] collector tick", self.source_id)
        health.record_run_start(self.source_id)
        # Collectors often catch their own errors and return [] (logged as a
        # WARNING) rather than raising, so success can't just be "fetch()
        # didn't throw" — check whether an error was recorded *during this
        # tick* via consecutive_errors before treating the tick as healthy.
        errors_before = (health.get(self.source_id) or health.SourceHealth(self.source_id)).consecutive_errors
        try:
            items = await self.fetch()
        except Exception as exc:
            log.error("[%s] fetch error: %s", self.source_id, exc)
            health.record_error(self.source_id, str(exc) or repr(exc))
            return
        errors_after = (health.get(self.source_id) or health.SourceHealth(self.source_id)).consecutive_errors
        if errors_after == errors_before:
            health.record_success(self.source_id, len(items))

        for item in items:
            item.dedupe_key = _dedupe_key(self.source_id, item.url)
            item.content_key = _content_key(item)
            row_id = await insert_item(self.db, item)
            if row_id is None:
                continue  # duplicate
            item.id = row_id
            item.seen_at = datetime.now(timezone.utc)

            # insert_item deliberately doesn't commit itself (see its
            # docstring) — commit here once the row is durable, then
            # broadcast only after that.
            try:
                await self.db.commit()
            except Exception as exc:
                log.error("[%s] failed to commit item: %s", self.source_id, exc)
                await self.db.rollback()
                continue

            payload = _build_payload(item)
            await self.sse.broadcast(payload)

        log.info("[%s] done — %d items fetched", self.source_id, len(items))


def _dedupe_key(source_id: str, url: str) -> str:
    return hashlib.sha256(f"{source_id}|{url}".encode()).hexdigest()


_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _content_key(item: Item) -> str:
    """Cross-source clustering signal (see models.Item.content_key and
    db.fetch_items' cluster_size). Prefers extra.actor+victim when a
    collector provides structured data (e.g. ransomware_live.py) — exact and
    unambiguous. Otherwise falls back to the normalized title: the same
    breach syndicated across multiple forum/social accounts tends to carry
    near-identical headline text, so an exact match after stripping
    case/punctuation/whitespace is a conservative (no-false-merge-prone)
    clustering signal. Returns '' (no clustering) for a blank title."""
    actor = item.extra.get("actor") if isinstance(item.extra, dict) else None
    victim = item.extra.get("victim") if isinstance(item.extra, dict) else None
    raw = f"{actor}|{victim}" if actor and victim else item.title
    normalized = _NON_ALNUM.sub("", raw.lower())
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _build_payload(item: Item) -> dict:
    return {
        "id": item.id,
        "source_id": item.source_id,
        "source_name": item.source_name,
        "title": item.title,
        "url": item.url,
        "snippet": item.snippet,
        "published_at": item.published_at.isoformat() if item.published_at else None,
        "seen_at": item.seen_at.isoformat() if item.seen_at else None,
        "source_tags": item.source_tags,
        # Mirrors the classifier fields db.fetch_items returns so SSE-live
        # and REST-loaded cards render identically. A brand-new item is
        # always unclassified at broadcast time — the classifier job runs
        # later — so these (including priority/tags/entities, which are
        # entirely classifier-derived now that the regex matcher is gone)
        # are the "pending" defaults; the frontend's /api/classifier/recent
        # poll patches them in place once classified.
        "max_priority": "",
        "all_tags": [],
        "is_false_positive": False,
        "classified": False,
        "classifier_confidence": None,
        "classifier_reasoning": None,
        "crime_type": None,
        "victim": None,
        "victim_sector": None,
        "victim_country": None,
        "actor": None,
        "cve_ids": [],
        "iocs": [],
        # cluster_size needs a DB scan (see db.fetch_items) we don't want to
        # pay per-item on the hot ingest path; default to 1 ("first sighting")
        # at broadcast time — the next full /api/items reload picks up the
        # real count if another source already reported the same content_key.
        "cluster_size": 1,
    }
