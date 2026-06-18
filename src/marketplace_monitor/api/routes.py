import asyncio
import hmac
import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from .. import health
from ..classifier import health as classifier_health
from ..db import (
    count_items,
    count_unclassified,
    fetch_items,
    get_recent_classifications,
    stats_by_priority,
    stats_by_source,
    stats_timeseries,
    stats_top_actors,
    stats_top_keywords,
)
from ..matcher import matcher
from ..scheduler import load_sources
from ..settings import settings
from .sse import TooManySubscribers, broadcaster

log = logging.getLogger(__name__)
router = APIRouter()


async def get_db(request: Request):
    return request.app.state.db


# ── Liveness/readiness ───────────────────────────────────────────────────────
# For systemd/uptime checks (see systemd/marketplace-monitor.service) — no
# auth, no sensitive data, just enough to tell "process is up and the DB/
# scheduler are functioning" from "process is wedged."

@router.get("/healthz")
async def healthz(request: Request):
    db = request.app.state.db
    try:
        await db.execute_fetchall("SELECT 1")
        db_ok = True
    except Exception as exc:
        log.error("[healthz] DB ping failed: %s", exc)
        db_ok = False

    scheduler = getattr(request.app.state, "scheduler", None)
    scheduler_ok = bool(scheduler and scheduler.running)

    sources = load_sources()
    enabled_sources = [s for s in sources if s.get("enabled", True)]
    failing = [s["id"] for s in enabled_sources if (health.get(s["id"]) or health.SourceHealth(s["id"])).consecutive_errors >= 3]

    body = {
        "db": "ok" if db_ok else "error",
        "scheduler": "ok" if scheduler_ok else "error",
        "classifier_backend": settings.classifier_backend,
        "sources_total": len(enabled_sources),
        "sources_failing": failing,
    }
    status_code = 200 if (db_ok and scheduler_ok) else 503
    return JSONResponse(content=body, status_code=status_code)


def _is_valid_admin_token(token: str | None) -> bool:
    return bool(settings.admin_token) and bool(token) and hmac.compare_digest(token, settings.admin_token)


async def require_admin(x_admin_token: str | None = Header(default=None)):
    """Gate for the keyword editor — it can read the investigation TARGET
    indicators and write arbitrary regex to disk. Fails closed: if no
    ADMIN_TOKEN is configured, the endpoints are unreachable rather than
    silently public."""
    if not _is_valid_admin_token(x_admin_token):
        raise HTTPException(status_code=403, detail="Admin token required")


# ── Items ─────────────────────────────────────────────────────────────────────

@router.get("/api/items")
async def api_items(
    db=Depends(get_db),
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
    # Repeatable: ?source_id=a&source_id=b — the dashboard's source checkboxes
    # send every checked source so multi-source filtering happens server-side
    # (previously client-side post-filtering shrank pages without adjusting
    # offset, breaking "load more" pagination once any source was unchecked).
    source_id: list[str] | None = Query(default=None),
    priority: str | None = Query(default=None),
    search: str | None = Query(default=None),
    matched_only: bool = Query(default=False),
    show_filtered: bool = Query(default=False),
    x_admin_token: str | None = Header(default=None),
):
    # show_filtered reveals classifier-flagged false positives — admin-gated
    # rather than public, since which items got suppressed (and why, via
    # classifier_reasoning) is a more sensitive signal than the items
    # themselves. The base feed stays fully public either way.
    if show_filtered and not _is_valid_admin_token(x_admin_token):
        raise HTTPException(status_code=403, detail="Admin token required to view filtered items")
    items = await fetch_items(
        db,
        limit=limit,
        offset=offset,
        source_id=source_id,
        min_priority=priority,
        search=search,
        matched_only=matched_only,
        show_filtered=show_filtered,
    )
    # total must reflect the SAME filters as the items query, or the
    # frontend's hasMore/"load more" math goes stale the moment any filter
    # narrows the result set below the unfiltered total.
    total = await count_items(
        db,
        source_id=source_id,
        min_priority=priority,
        search=search,
        matched_only=matched_only,
        show_filtered=show_filtered,
    )
    return {"total": total, "items": items}


# ── SSE stream ────────────────────────────────────────────────────────────────

@router.get("/api/stream")
async def api_stream():
    try:
        q = broadcaster.subscribe()
    except TooManySubscribers:
        raise HTTPException(status_code=503, detail="Too many live connections — retry shortly")

    async def event_generator():
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=25.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            broadcaster.unsubscribe(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Sources ───────────────────────────────────────────────────────────────────

@router.get("/api/sources")
async def api_sources(request: Request):
    sources = load_sources()
    scheduler = getattr(request.app.state, "scheduler", None)
    result = []
    for s in sources:
        h = health.get(s["id"])
        # "unknown" status (no last_run_at yet) is otherwise unexplained —
        # staggered startup offsets mean an hourly source can sit unticked
        # for up to ~15 minutes after a restart, which reads as broken
        # unless the dashboard can say "first run scheduled at X."
        job = scheduler.get_job(s["id"]) if scheduler else None
        next_run_at = job.next_run_time.isoformat() if job and job.next_run_time else None
        result.append(
            {
                "id": s["id"],
                "name": s.get("name", s["id"]),
                "type": s.get("type", ""),
                "enabled": s.get("enabled", True),
                "interval_seconds": s.get("interval_seconds", 600),
                "last_run_at": h.last_run_at if h else None,
                "last_success_at": h.last_success_at if h else None,
                "last_items_fetched": h.last_items_fetched if h else 0,
                "total_items_fetched": h.total_items_fetched if h else 0,
                "last_error": h.last_error if h else None,
                "last_error_at": h.last_error_at if h else None,
                "consecutive_errors": h.consecutive_errors if h else 0,
                "last_empty_at": h.last_empty_at if h else None,
                "consecutive_empty": h.consecutive_empty if h else 0,
                "next_run_at": next_run_at,
            }
        )
    return result


# ── Keywords ──────────────────────────────────────────────────────────────────

@router.get("/api/keywords", dependencies=[Depends(require_admin)])
async def api_keywords_get():
    return {"yaml": matcher.rules_raw}


class KeywordsUpdate(BaseModel):
    yaml: str


@router.put("/api/keywords", dependencies=[Depends(require_admin)])
async def api_keywords_put(body: KeywordsUpdate):
    ok, msg = matcher.reload_from_text(body.yaml)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "ok", "message": msg}


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/api/stats")
async def api_stats(db=Depends(get_db)):
    total = await count_items(db)
    return {"total_items": total}


# ── Dashboard aggregations (public, read-only, no TARGET-pattern leakage) ────

@router.get("/api/stats/timeseries")
async def api_stats_timeseries(
    db=Depends(get_db),
    bucket: str = Query(default="hour", pattern="^(hour|day)$"),
    since_hours: int = Query(default=48, ge=1, le=24 * 30),
):
    return {"buckets": await stats_timeseries(db, bucket=bucket, since_hours=since_hours)}


@router.get("/api/stats/by_source")
async def api_stats_by_source(db=Depends(get_db)):
    sources_by_id = {s["id"]: s for s in load_sources()}
    rows = await stats_by_source(db)
    for r in rows:
        h = health.get(r["source_id"])
        src = sources_by_id.get(r["source_id"], {})
        r["enabled"] = src.get("enabled", True)
        r["consecutive_errors"] = h.consecutive_errors if h else 0
        r["last_success_at"] = h.last_success_at if h else None
    return {"sources": rows}


@router.get("/api/stats/by_priority")
async def api_stats_by_priority(
    db=Depends(get_db),
    since_hours: int | None = Query(default=None, ge=1, le=24 * 30),
):
    return await stats_by_priority(db, since_hours=since_hours)


@router.get("/api/stats/top_keywords")
async def api_stats_top_keywords(db=Depends(get_db), limit: int = Query(default=10, le=50)):
    return {"keywords": await stats_top_keywords(db, limit=limit)}


@router.get("/api/stats/top_actors")
async def api_stats_top_actors(db=Depends(get_db), limit: int = Query(default=10, le=50)):
    return {"actors": await stats_top_actors(db, limit=limit)}


# ── Classifier ────────────────────────────────────────────────────────────────
# Public, read-only — backend health/backlog and "what changed recently" are
# no more sensitive than the rest of the public dashboard.

@router.get("/api/classifier/health")
async def api_classifier_health(db=Depends(get_db)):
    h = classifier_health.get()
    return {
        "backend": settings.classifier_backend,
        "last_run_at": h.last_run_at,
        "last_success_at": h.last_success_at,
        "last_batch_size": h.last_batch_size,
        "total_classified": h.total_classified,
        "last_error": h.last_error,
        "last_error_at": h.last_error_at,
        "consecutive_errors": h.consecutive_errors,
        "backlog": await count_unclassified(db),
    }


@router.get("/api/classifier/recent")
async def api_classifier_recent(db=Depends(get_db), since: str = Query(...)):
    """Items classified after `since` (ISO-8601) — powers the frontend's
    incremental poll so already-rendered cards can be patched in place
    instead of a full feed re-render."""
    return {"updates": await get_recent_classifications(db, since_iso=since)}
