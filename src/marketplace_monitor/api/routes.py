import asyncio
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from .. import health
from ..llm import health as llm_health
from ..db import (
    count_cases,
    count_cases_needing_research,
    count_heal_proposals_by_status,
    count_items,
    count_kev_catalog,
    count_running_research_runs,
    count_uncorrelated_extracted_items,
    count_unextracted,
    fetch_cases,
    fetch_items,
    get_case_by_id,
    get_case_items,
    get_recent_extractions,
    stats_by_priority,
    stats_by_source,
    stats_cases_by_crime_type,
    stats_cases_in_kev,
    stats_timeseries,
    stats_top_actors,
    stats_top_keywords,
)
from ..matcher import matcher
from ..pipeline import correlate as correlate_health
from ..research import agent as research_health
from ..research import discover as discover_health
from ..research import heal as heal_health
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
        "classifier_backend": settings.llm_backend,
        "sources_total": len(enabled_sources),
        "sources_failing": failing,
    }
    status_code = 200 if (db_ok and scheduler_ok) else 503
    return JSONResponse(content=body, status_code=status_code)


def _is_valid_admin_token(token: str | None) -> bool:
    return bool(settings.admin_token) and bool(token) and hmac.compare_digest(token, settings.admin_token)


async def require_admin(x_admin_token: str | None = Header(default=None)):
    """Gate for the keyword editor — it can write arbitrary regex to disk.
    Fails closed: if no ADMIN_TOKEN is configured, the endpoints are
    unreachable rather than silently public."""
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
    crime_type: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    victim: str | None = Query(default=None),
    cve_id: str | None = Query(default=None),
    ioc: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    classified: bool | None = Query(default=None),
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    cluster_size: int | None = Query(default=None, ge=1),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    extra_key: str | None = Query(default=None),
    x_admin_token: str | None = Header(default=None),
):
    # show_filtered reveals classifier-flagged false positives — admin-gated
    # rather than public, since which items got suppressed (and why, via
    # classifier_reasoning) is a more sensitive signal than the items
    # themselves. The base feed stays fully public either way.
    if show_filtered and not _is_valid_admin_token(x_admin_token):
        raise HTTPException(status_code=403, detail="Admin token required to view filtered items")

    filter_kwargs = {
        "crime_type": crime_type,
        "actor": actor,
        "victim": victim,
        "cve_id": cve_id,
        "ioc": ioc,
        "tag": tag,
        "classified": classified,
        "min_confidence": min_confidence,
        "cluster_size": cluster_size,
        "since": since,
        "until": until,
        "extra_key": extra_key,
    }

    items = await fetch_items(
        db,
        limit=limit,
        offset=offset,
        source_id=source_id,
        min_priority=priority,
        search=search,
        matched_only=matched_only,
        show_filtered=show_filtered,
        **filter_kwargs,
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
        **filter_kwargs,
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
    h = llm_health.get()
    return {
        "backend": settings.llm_backend,
        "using_fallback": h.using_fallback,
        "last_run_at": h.last_run_at,
        "last_success_at": h.last_success_at,
        "last_batch_size": h.last_batch_size,
        "total_classified": h.total_classified,
        "last_error": h.last_error,
        "last_error_at": h.last_error_at,
        "consecutive_errors": h.consecutive_errors,
        "backlog": await count_unextracted(db),
    }


@router.get("/api/classifier/recent")
async def api_classifier_recent(db=Depends(get_db), since: str = Query(...)):
    """Items extracted after `since` (ISO-8601) — powers the frontend's
    incremental poll so already-rendered cards can be patched in place
    instead of a full feed re-render."""
    return {"updates": await get_recent_extractions(db, since_iso=since)}


@router.get("/api/status")
async def api_status(request: Request, db=Depends(get_db)):
    """Unified live subsystem status — scheduler, collectors, classifier,
    case correlator, KEV refresh, hermes-agent research/heal. Read-only and
    safe for public dashboard use (only counts/scheduler metadata)."""
    scheduler = getattr(request.app.state, "scheduler", None)
    scheduler_running = bool(scheduler and scheduler.running)

    jobs = []
    if scheduler:
        for job in scheduler.get_jobs():
            jobs.append(
                {
                    "id": job.id,
                    "name": job.name,
                    "next_run_at": job.next_run_time.isoformat() if job.next_run_time else None,
                    "pending": getattr(job, "pending", None),
                }
            )

    sources = load_sources()
    enabled_sources = [s for s in sources if s.get("enabled", True)]
    failing = [
        s["id"]
        for s in enabled_sources
        if (health.get(s["id"]) or health.SourceHealth(s["id"])).consecutive_errors >= 3
    ]

    h = llm_health.get()
    ch = correlate_health.get()
    rh = research_health.get()
    hh = heal_health.get()
    dh = discover_health.get()

    cooldown_iso = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    # Approximate KEV age from the catalog's most recent date_added (CISA
    # publishes the date each CVE was added to the catalog). The scheduler
    # next_run_time is also returned for "next refresh" visibility.
    kev_next_run = None
    for job in jobs:
        if job["id"] == "_kev_refresh":
            kev_next_run = job["next_run_at"]
            break

    return {
        "scheduler": {"running": scheduler_running, "jobs": jobs},
        "sources": {
            "total": len(enabled_sources),
            "failing": failing,
            "failing_count": len(failing),
        },
        "classifier": {
            "backend": settings.llm_backend,
            "using_fallback": h.using_fallback,
            "last_run_at": h.last_run_at,
            "last_success_at": h.last_success_at,
            "last_batch_size": h.last_batch_size,
            "total_classified": h.total_classified,
            "last_error": h.last_error,
            "last_error_at": h.last_error_at,
            "consecutive_errors": h.consecutive_errors,
            "backlog": await count_unextracted(db),
        },
        "correlation": {
            "last_run_at": ch.last_run_at,
            "last_success_at": ch.last_success_at,
            "last_processed_count": ch.last_processed_count,
            "last_error": ch.last_error,
            "last_error_at": ch.last_error_at,
            "consecutive_errors": ch.consecutive_errors,
            "backlog": await count_uncorrelated_extracted_items(db),
        },
        "kev": {
            "count": await count_kev_catalog(db),
            "next_refresh_at": kev_next_run,
        },
        "research": {
            "last_run_at": rh.last_run_at,
            "last_success_at": rh.last_success_at,
            "last_processed_count": rh.last_processed_count,
            "last_error": rh.last_error,
            "last_error_at": rh.last_error_at,
            "consecutive_errors": rh.consecutive_errors,
            "running": await count_running_research_runs(db),
            "queued": await count_cases_needing_research(db, cooldown_iso=cooldown_iso),
        },
        "heal": {
            "last_run_at": hh.last_run_at,
            "last_success_at": hh.last_success_at,
            "last_processed_count": hh.last_processed_count,
            "last_error": hh.last_error,
            "last_error_at": hh.last_error_at,
            "consecutive_errors": hh.consecutive_errors,
            "proposals": await count_heal_proposals_by_status(db),
            "autoapply_enabled": settings.source_autoapply_enabled,
        },
        "discover": {
            "last_run_at": dh.last_run_at,
            "last_success_at": dh.last_success_at,
            "last_processed_count": dh.last_processed_count,
            "last_error": dh.last_error,
            "last_error_at": dh.last_error_at,
            "consecutive_errors": dh.consecutive_errors,
        },
    }


# ── Cases (deduplicated incidents) ──────────────────────────────────────────
# See pipeline/correlate.py — the structured, deduplicated view on top of
# the raw item feed above.

@router.get("/api/cases")
async def api_cases(
    db=Depends(get_db),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    min_significance: str | None = Query(default=None),
    crime_type: str | None = Query(default=None),
    in_kev: bool | None = Query(default=None),
    search: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
):
    cases = await fetch_cases(
        db,
        limit=limit,
        offset=offset,
        min_significance=min_significance,
        crime_type=crime_type,
        in_kev=in_kev,
        search=search,
        since=since,
        until=until,
    )
    total = await count_cases(db)
    return {"total": total, "cases": cases}


@router.get("/api/cases/{case_id}")
async def api_case_detail(case_id: int, db=Depends(get_db)):
    from ..db import get_case_links, get_research_runs_for_case

    case = await get_case_by_id(db, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    case["cve_ids"] = json.loads(case["cve_ids"]) if case["cve_ids"] else []
    case["iocs"] = json.loads(case["iocs"]) if case["iocs"] else []
    case["in_kev"] = bool(case["in_kev"])
    items = await get_case_items(db, case_id)
    research_runs = await get_research_runs_for_case(db, case_id)
    related = await get_case_links(db, case_id)
    return {"case": case, "items": items, "research_runs": research_runs, "related_cases": related}


@router.post("/api/cases/{case_id}/research", dependencies=[Depends(require_admin)])
async def api_case_request_research(case_id: int, request: Request, db=Depends(get_db)):
    """Force a deep-research pass on this case, bypassing the normal
    significance/cooldown gating (see db.get_cases_needing_research) — for
    "re-research this with whatever's missing" from the case detail pane.
    Admin-gated: each call spends a Hermes run, same cost class as the
    keyword editor's write access."""
    from ..db import request_case_research

    ok = await request_case_research(db, case_id=case_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")

    # Nudge the research job to run soon rather than waiting out its full
    # interval — best-effort: if the job isn't registered (research
    # disabled) this just no-ops and the flag sits until/unless research is
    # re-enabled.
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is not None:
        job = scheduler.get_job("_research")
        if job is not None:
            scheduler.modify_job("_research", next_run_time=datetime.now(timezone.utc))

    return {"status": "queued"}


@router.get("/api/stats/cases")
async def api_stats_cases(db=Depends(get_db)):
    return {
        "total": await count_cases(db),
        "by_crime_type": await stats_cases_by_crime_type(db),
        "in_kev": await stats_cases_in_kev(db),
    }


# ── Analyst feedback ─────────────────────────────────────────────────────────
# Public-write like the rest of the dashboard (this is a single-analyst
# tool, not multi-tenant) but bounded by the existing per-IP rate limit
# (api/app.py's rate_limit_middleware) — feeds sources/value.py's scoring
# and the heal/discover prompts (research/heal.py, research/discover.py).

class FeedbackCreate(BaseModel):
    case_id: int | None = None
    item_id: int | None = None
    verdict: str
    note: str | None = None


@router.post("/api/feedback")
async def api_feedback_create(body: FeedbackCreate, db=Depends(get_db)):
    from ..db import VALID_FEEDBACK_VERDICTS, add_feedback

    if not body.case_id and not body.item_id:
        raise HTTPException(status_code=400, detail="case_id or item_id required")
    if body.verdict not in VALID_FEEDBACK_VERDICTS:
        raise HTTPException(status_code=400, detail=f"verdict must be one of {sorted(VALID_FEEDBACK_VERDICTS)}")
    feedback_id = await add_feedback(
        db, case_id=body.case_id, item_id=body.item_id, verdict=body.verdict, note=body.note
    )
    return {"id": feedback_id, "status": "ok"}


# ── Self-healing source proposals ───────────────────────────────────────────
# Read-only surface for research/heal.py's output — see that module's
# docstring for why proposals are never auto-applied to sources.yaml.
# Admin-gated: a proposal can echo back scraped page content via its notes.

@router.get("/api/heal/proposals", dependencies=[Depends(require_admin)])
async def api_heal_proposals(db=Depends(get_db), status: str | None = Query(default=None)):
    from ..db import get_heal_proposals

    return {"proposals": await get_heal_proposals(db, status=status)}
