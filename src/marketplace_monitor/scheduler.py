"""APScheduler wiring — loads sources.yaml and schedules one job per source."""
import logging
import random
from typing import Any

import yaml
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .settings import settings

log = logging.getLogger(__name__)


def load_sources() -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(settings.sources_config.read_text()) or {}
        if isinstance(data, dict):
            return data.get("sources", [])
        # Legacy flat list
        return [s for s in data if isinstance(s, dict) and s.get("id")]
    except Exception as exc:
        log.error("Failed to load sources.yaml: %s", exc)
        return []


def build_scheduler(db_conn, sse_broadcaster) -> AsyncIOScheduler:
    from .collectors.html_forum import HTMLForumCollector
    from .collectors.tor_forum import TorForumCollector
    from .collectors.nitter import NitterCollector
    from .collectors.mastodon import MastodonCollector
    from .collectors.paste import PasteCollector
    from .collectors.hibp import HIBPCollector
    from .collectors.rss import RSSCollector
    from .collectors.ransomware_live import RansomwareLiveCollector

    # Load nitter instance list from top-level yaml key
    nitter_instances: list[str] = []
    try:
        raw = yaml.safe_load(settings.sources_config.read_text()) or {}
        if isinstance(raw, dict):
            nitter_instances = raw.get("nitter_instances", [])
    except Exception:
        pass

    type_map = {
        "html_forum": HTMLForumCollector,
        "tor_forum": TorForumCollector,
        "nitter": NitterCollector,
        "mastodon": MastodonCollector,
        "paste": PasteCollector,
        "hibp": HIBPCollector,
        "rss": RSSCollector,
        "ransomware_live": RansomwareLiveCollector,
    }

    scheduler = AsyncIOScheduler()
    sources = load_sources()
    scheduled = 0

    for src in sources:
        if not src.get("enabled", True):
            log.info("Source %s disabled — skipping", src["id"])
            continue
        collector_cls = type_map.get(src.get("type", ""))
        if not collector_cls:
            log.warning("Unknown source type '%s' for %s", src.get("type"), src.get("id"))
            continue

        interval = src.get("interval_seconds", 600)
        jitter = src.get("jitter", 60)

        kwargs = dict(src)
        if src["type"] == "nitter" and nitter_instances:
            kwargs["instances"] = nitter_instances

        collector = collector_cls(kwargs, db_conn, sse_broadcaster)

        # Stagger first run: random offset within [5, interval] seconds.
        # Passed as next_run_time on the recurring job itself — a *single*
        # job covers both the staggered first run and all subsequent runs.
        # (Previously this was `next_run_time=... and None`, which APScheduler
        # treats as "add the job paused" — it never fired again after the
        # separate one-time `_init` job ran once. A second `_init` date job
        # also double-scheduled every source. Both are fixed by using one job.)
        start_offset = random.randint(5, max(10, interval // 4))

        scheduler.add_job(
            collector.run,
            trigger=IntervalTrigger(seconds=interval + random.randint(0, jitter)),
            id=src["id"],
            name=src.get("name", src["id"]),
            next_run_time=_offset_now(start_offset),
            misfire_grace_time=interval,
            coalesce=True,
            kwargs={},
        )
        scheduled += 1

    log.info("Scheduled %d collectors", scheduled)

    if settings.classifier_backend != "none":
        from .classifier.job import run_classification_batch

        scheduler.add_job(
            run_classification_batch,
            trigger=IntervalTrigger(seconds=settings.classifier_interval_seconds),
            id="_classifier",
            name="LLM classifier",
            next_run_time=_offset_now(10),
            misfire_grace_time=settings.classifier_interval_seconds,
            # A batch (N items x LLM latency) can exceed the interval; without
            # these, concurrent runs could grab the same unclassified rows
            # and double-process. coalesce collapses any backlog of missed
            # ticks into one run instead of bursting them all at once.
            max_instances=1,
            coalesce=True,
            kwargs={"db_conn": db_conn},
        )
        log.info("Scheduled LLM classifier job (backend=%s)", settings.classifier_backend)
    else:
        log.info("LLM classifier disabled (classifier_backend=none)")

    from . import db as db_module
    from . import health

    async def _persist_health(conn) -> None:
        try:
            await db_module.save_health_snapshot(conn, health.snapshot())
        except Exception as exc:
            log.error("[health] snapshot persist failed: %s", exc)

    scheduler.add_job(
        _persist_health,
        trigger=IntervalTrigger(seconds=60),
        id="_health_persist",
        name="Source health snapshot",
        next_run_time=_offset_now(30),
        misfire_grace_time=60,
        max_instances=1,
        coalesce=True,
        kwargs={"conn": db_conn},
    )
    log.info("Scheduled source health persistence job")

    if settings.retention_days > 0:

        async def _run_retention(conn) -> None:
            try:
                await db_module.prune_old_items(conn, retention_days=settings.retention_days)
            except Exception as exc:
                log.error("[retention] prune failed: %s", exc)

        scheduler.add_job(
            _run_retention,
            trigger=IntervalTrigger(seconds=86400),
            id="_retention",
            name="DB retention/pruning",
            next_run_time=_offset_now(120),
            misfire_grace_time=3600,
            max_instances=1,
            coalesce=True,
            kwargs={"conn": db_conn},
        )
        log.info("Scheduled retention job (retention_days=%d)", settings.retention_days)
    else:
        log.info("Retention disabled (retention_days <= 0)")

    return scheduler


def _offset_now(seconds: int):
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)
