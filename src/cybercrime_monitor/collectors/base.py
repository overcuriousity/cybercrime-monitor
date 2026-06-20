"""Base collector — defines the ABC and shared ingestion pipeline."""
import asyncio
import hashlib
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from .. import health
from ..db import insert_item, insert_matches
from ..matcher import matcher
from ..models import Item, Match
from ..notifier import push_gotify
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
        """Full pipeline: fetch → dedupe → match → store → broadcast."""
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

            matches = matcher.match(item)
            for m in matches:
                m.item_id = row_id
            # insert_item/insert_matches deliberately don't commit themselves
            # (see their docstrings) — commit both together here so an item
            # and its regex matches land atomically, then broadcast/alert
            # only once that's actually durable.
            try:
                await insert_matches(self.db, matches)
                await self.db.commit()
            except Exception as exc:
                log.error("[%s] failed to commit item+matches: %s", self.source_id, exc)
                await self.db.rollback()
                continue

            payload = _build_payload(item, matches)
            await self.sse.broadcast(payload)

            # Instant Gotify on regex 'critical' is ONLY used when the LLM
            # extraction layer is disabled (zero-config fallback). Otherwise
            # the llm/job.py background job owns alerting — it waits for
            # confirmation (cuts false-positive pages) but still guarantees
            # an alert via its own fallback sweep if the backend is down, so
            # disabling this here doesn't risk silently losing real alerts.
            if settings.llm_backend == "none":
                for m in matches:
                    if m.priority == "critical":
                        await push_gotify(
                            title=f"[CRITICAL] {self.source_name}: {item.title[:80]}",
                            message=f"{item.url}\n\n{item.snippet[:300]}",
                            priority=8,
                        )
                        break

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


def _build_payload(item: Item, matches: list[Match]) -> dict:
    priority_rank = {"info": 1, "warn": 2, "critical": 3}
    max_prio = ""
    all_tags: set[str] = set()
    match_data = []
    for m in matches:
        if priority_rank.get(m.priority, 0) > priority_rank.get(max_prio, 0):
            max_prio = m.priority
        all_tags.update(m.tags)
        match_data.append(
            {"pattern": m.keyword_pattern, "priority": m.priority, "tags": m.tags, "spans": m.spans}
        )
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
        "max_priority": max_prio,
        "all_tags": sorted(all_tags),
        "matches": match_data,
        # Mirrors the classifier fields db.fetch_items returns (see plan) so
        # SSE-live and REST-loaded cards render identically. A brand-new item
        # is always unclassified at broadcast time — the classifier job runs
        # later — so these are the "pending" defaults; the frontend's
        # /api/classifier/recent poll patches them in place once classified.
        "is_false_positive": False,
        "classified": False,
        "classifier_confidence": None,
        "classifier_reasoning": None,
        # cluster_size needs a DB scan (see db.fetch_items) we don't want to
        # pay per-item on the hot ingest path; default to 1 ("first sighting")
        # at broadcast time — the next full /api/items reload picks up the
        # real count if another source already reported the same content_key.
        "cluster_size": 1,
    }
