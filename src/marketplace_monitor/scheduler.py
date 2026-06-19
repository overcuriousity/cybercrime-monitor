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

    if settings.llm_backend != "none":
        from .llm.job import run_extraction_batch

        scheduler.add_job(
            run_extraction_batch,
            trigger=IntervalTrigger(seconds=settings.llm_interval_seconds),
            id="_extract",
            name="LLM extraction",
            next_run_time=_offset_now(10),
            misfire_grace_time=settings.llm_interval_seconds,
            # A batch (N items x LLM latency) can exceed the interval; without
            # these, concurrent runs could grab the same unextracted rows
            # and double-process. coalesce collapses any backlog of missed
            # ticks into one run instead of bursting them all at once.
            max_instances=1,
            coalesce=True,
            kwargs={"db_conn": db_conn},
        )
        log.info("Scheduled LLM extraction job (backend=%s)", settings.llm_backend)
    else:
        log.info("LLM extraction disabled (llm_backend=none)")

    from .pipeline.correlate import run_correlation_batch

    scheduler.add_job(
        run_correlation_batch,
        trigger=IntervalTrigger(seconds=settings.correlate_interval_seconds),
        id="_correlate",
        name="Case correlation",
        next_run_time=_offset_now(20),
        misfire_grace_time=settings.correlate_interval_seconds,
        max_instances=1,
        coalesce=True,
        kwargs={"db_conn": db_conn},
    )
    log.info("Scheduled case correlation job")

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

    if settings.kev_refresh_interval_seconds > 0:
        from .enrich.kev import refresh_kev_catalog

        async def _refresh_kev(conn) -> None:
            await refresh_kev_catalog(conn)

        scheduler.add_job(
            _refresh_kev,
            trigger=IntervalTrigger(seconds=settings.kev_refresh_interval_seconds),
            id="_kev_refresh",
            name="CISA KEV catalog refresh",
            next_run_time=_offset_now(15),
            misfire_grace_time=3600,
            max_instances=1,
            coalesce=True,
            kwargs={"conn": db_conn},
        )
        log.info("Scheduled CISA KEV catalog refresh job")

    if settings.hermes_research_interval_seconds > 0:
        from .research.agent import run_research_batch

        scheduler.add_job(
            run_research_batch,
            trigger=IntervalTrigger(seconds=settings.hermes_research_interval_seconds),
            id="_research",
            name="hermes-agent OSINT research",
            next_run_time=_offset_now(60),
            misfire_grace_time=settings.hermes_research_interval_seconds,
            # A research run can take minutes (hermes_timeout_seconds) — never
            # let two overlap and double-dispatch hermes-agent.
            max_instances=1,
            coalesce=True,
            kwargs={"db_conn": db_conn},
        )
        log.info("Scheduled hermes-agent OSINT research job")
    else:
        log.info("hermes-agent research disabled (hermes_research_interval_seconds <= 0)")

    if settings.hermes_heal_interval_seconds > 0:
        from .research.heal import run_heal_batch

        scheduler.add_job(
            run_heal_batch,
            trigger=IntervalTrigger(seconds=settings.hermes_heal_interval_seconds),
            id="_heal",
            name="hermes-agent source self-healing",
            next_run_time=_offset_now(90),
            misfire_grace_time=settings.hermes_heal_interval_seconds,
            # Same reasoning as "_research" — a heal investigation can take
            # minutes; never let two overlap.
            max_instances=1,
            coalesce=True,
            kwargs={"db_conn": db_conn},
        )
        log.info("Scheduled hermes-agent source self-healing job")
    else:
        log.info("hermes-agent self-healing disabled (hermes_heal_interval_seconds <= 0)")

    return scheduler


def _offset_now(seconds: int):
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)
