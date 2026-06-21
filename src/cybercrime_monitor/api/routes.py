import asyncio
import hmac
import json
import logging
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from .. import health
from ..embeddings import backend as embed_backend
from ..embeddings import index as vec_index
from ..llm import health as llm_health
from ..db import (
    count_cases,
    count_cases_needing_research,
    count_heal_proposals_by_status,
    count_items,
    count_kev_catalog,
    count_queued_investigations,
    count_running_research_runs,
    count_uncorrelated_extracted_items,
    count_unextracted,
    create_investigation,
    cases_country_counts,
    fetch_cases,
    fetch_items,
    get_actor_profile,
    get_all_source_values,
    get_case_by_id,
    get_case_items,
    get_case_links,
    get_investigation,
    get_recent_extractions,
    get_research_runs_for_case,
    list_ai_activity,
    list_investigations,
    log_ai_activity,
    merge_cases,
    stats_cases_by_actor,
    stats_cases_by_country,
    stats_cases_by_sector,
    stats_cases_timeseries,
    stats_trends,
    stats_by_priority,
    stats_by_source,
    stats_cases_by_crime_type,
    stats_cases_in_kev,
    stats_timeseries,
)
from ..pipeline import correlate as correlate_health
from ..research import agent as research_health
from ..research import discover as discover_health
from ..research import heal as heal_health
from ..research import investigate as investigate_health
from ..scheduler import load_sources
from ..settings import settings
from .sse import TooManySubscribers, broadcaster

log = logging.getLogger(__name__)
router = APIRouter()


async def get_db(request: Request):
    return request.app.state.db


# ── Liveness/readiness ───────────────────────────────────────────────────────
# For systemd/uptime checks (see systemd/cybercrime-monitor.service) — no
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
    """Gate for admin-only actions (forcing a re-research run, viewing
    classifier-filtered items, submitting a targeted investigation). Fails
    closed: if no ADMIN_TOKEN is configured, the endpoints are unreachable
    rather than silently public."""
    if not _is_valid_admin_token(x_admin_token):
        raise HTTPException(status_code=403, detail="Admin token required")


# ── Semantic search ──────────────────────────────────────────────────────────
# Shared by api_items/api_cases' mode="semantic" branch. Keyword mode (the
# default, and the only mode when embeddings are disabled) is the existing
# plain SQL LIKE search via fetch_items/fetch_cases' `search` param — the
# two modes are kept strictly separate (see settings.embed_backend's
# docstring): a failed/unavailable semantic request must be surfaced to the
# UI as unavailable, never silently re-run as a keyword search.

# Wide enough that structured filters (significance, date range, etc.)
# applied after the vector search still leave a full page of results in
# the common case, without making every semantic query scan the whole
# vector index.
_SEMANTIC_CANDIDATE_K = 300


async def _semantic_rank(db, kind: str, query: str) -> list[int]:
    """Embeds `query` and returns case/item ids ranked nearest-first by
    vector similarity. Raises embed_backend.EmbeddingUnavailable if the
    configured backend can't serve the embed call."""
    qvec = (await embed_backend.embed_texts([query]))[0]
    candidates = await vec_index.search(db, kind, qvec, k=_SEMANTIC_CANDIDATE_K)
    return [ref_id for ref_id, _distance in candidates]


def _paginate_ranked(rows_by_id: dict[int, dict], ranked_ids: list[int], *, limit: int, offset: int) -> tuple[list[dict], int]:
    """Re-applies the vector-similarity order (rows_by_id came back from a
    SQL query ordered by seen_at/last_seen, not similarity) and paginates
    in Python — the ranking only exists in the candidate-id order, not as a
    SQL ORDER BY. Returns (page, total_after_filters)."""
    ordered = [rows_by_id[i] for i in ranked_ids if i in rows_by_id]
    return ordered[offset : offset + limit], len(ordered)


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
    mode: str = Query(default="keyword", pattern="^(keyword|semantic)$"),  # "keyword" | "semantic"
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

    if mode == "semantic" and search:
        try:
            ranked_ids = await _semantic_rank(db, "items", search)
        except embed_backend.EmbeddingUnavailable:
            return {"total": 0, "items": [], "mode": "semantic", "semantic_unavailable": True}
        if not ranked_ids:
            return {"total": 0, "items": [], "mode": "semantic"}
        # No `search=` here — id_in (the vector-search candidate set) takes
        # over search's job; every other structured filter still applies.
        candidates = await fetch_items(
            db,
            limit=len(ranked_ids),
            offset=0,
            source_id=source_id,
            min_priority=priority,
            matched_only=matched_only,
            show_filtered=show_filtered,
            id_in=ranked_ids,
            **filter_kwargs,
        )
        by_id = {item["id"]: item for item in candidates}
        page, total = _paginate_ranked(by_id, ranked_ids, limit=limit, offset=offset)
        return {"total": total, "items": page, "mode": "semantic"}

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
    return {"total": total, "items": items, "mode": "keyword"}


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
async def api_sources(request: Request, db=Depends(get_db)):
    sources = load_sources()
    scheduler = getattr(request.app.state, "scheduler", None)
    values = await get_all_source_values(db)
    result = []
    for s in sources:
        h = health.get(s["id"])
        # "unknown" status (no last_run_at yet) is otherwise unexplained —
        # staggered startup offsets mean an hourly source can sit unticked
        # for up to ~15 minutes after a restart, which reads as broken
        # unless the dashboard can say "first run scheduled at X."
        job = scheduler.get_job(s["id"]) if scheduler else None
        next_run_at = job.next_run_time.isoformat() if job and job.next_run_time else None
        value = values.get(s["id"])
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
                # Cached investigation-value classification from the
                # autonomous heal/prune loop (sources/value.py) — lets the
                # dashboard explain *why* a disabled source was disabled
                # (e.g. "dead" vs a human's manual "# needs:" disable, which
                # has no classification yet).
                "value_classification": value.get("classification") if value else None,
            }
        )
    return result


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


@router.get("/api/stats/top_actors")
async def api_stats_top_actors(db=Depends(get_db), limit: int = Query(default=10, le=50)):
    # Case-based (deduplicated incidents), not item-mention counts — see
    # stats_cases_by_actor's docstring. Kept at this URL/shape ("actors":
    # [{"actor","count"}]) so the Feed dashboard's existing chart call works
    # unchanged; this is the same leaderboard the Landscape tab uses.
    rows = await stats_cases_by_actor(db, limit=limit)
    return {"actors": [{"actor": r["actor"], "count": r["n"]} for r in rows]}


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
    ih = investigate_health.get()

    # Must mirror research.agent.run_research_batch's eligibility windows
    # exactly, or this "queued" count would disagree with what the scheduler
    # is actually about to pick up next tick.
    _status_now = datetime.now(timezone.utc)
    cooldown_iso = (_status_now - timedelta(hours=research_health._RESEARCH_COOLDOWN_HOURS)).isoformat()
    failure_cooldown_iso = (_status_now - timedelta(hours=settings.research_failure_retry_hours)).isoformat()

    # Approximate KEV age from the catalog's most recent date_added (CISA
    # publishes the date each CVE was added to the catalog). The scheduler
    # next_run_time is also returned for "next refresh" visibility.
    kev_next_run = None
    for job in jobs:
        if job["id"] == "_kev_refresh":
            kev_next_run = job["next_run_at"]
            break

    return {
        "admin": {"enabled": bool(settings.admin_token)},
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
        # Lets the frontend show/disable the keyword/semantic search toggle
        # without a failed search round-trip first — "enabled" only means
        # the backend is configured, not that the vector index is fully
        # populated yet (a fresh DB or one mid-reindex just returns fewer
        # results, not an error).
        "semantic_search": {
            "enabled": settings.embed_backend != "none",
            "backend": settings.embed_backend,
        },
        "research": {
            "last_run_at": rh.last_run_at,
            "last_success_at": rh.last_success_at,
            "last_processed_count": rh.last_processed_count,
            "last_error": rh.last_error,
            "last_error_at": rh.last_error_at,
            "consecutive_errors": rh.consecutive_errors,
            "running": await count_running_research_runs(db),
            "queued": await count_cases_needing_research(
                db, cooldown_iso=cooldown_iso, failure_cooldown_iso=failure_cooldown_iso
            ),
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
        "investigate": {
            "last_run_at": ih.last_run_at,
            "last_success_at": ih.last_success_at,
            "last_processed_count": ih.last_processed_count,
            "last_error": ih.last_error,
            "last_error_at": ih.last_error_at,
            "consecutive_errors": ih.consecutive_errors,
            "queued": await count_queued_investigations(db),
        },
    }


# ── Cases (deduplicated incidents) ──────────────────────────────────────────
# See pipeline/correlate.py — the structured, deduplicated view on top of
# the raw item feed above.

_DATE_ONLY_LEN = len("YYYY-MM-DD")


def _normalize_date_filter(value: str | None, *, end_of_day: bool) -> str | None:
    """Expand a UI date-only string (YYYY-MM-DD) to a bound that compares
    correctly against ISO timestamps stored in the DB. `since` gets the
    start of the day; `until` gets the end of the day so the full day is
    included rather than excluding timestamps after 00:00:00."""
    if value is None or len(value) != _DATE_ONLY_LEN:
        return value
    if end_of_day:
        return f"{value}T23:59:59.999999+00:00"
    return f"{value}T00:00:00+00:00"


@router.get("/api/cases")
async def api_cases(
    db=Depends(get_db),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    min_significance: str | None = Query(default=None),
    crime_type: str | None = Query(default=None),
    in_kev: bool | None = Query(default=None),
    search: str | None = Query(default=None),
    cve_id: str | None = Query(default=None),
    ioc: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    country: str | None = Query(default=None),
    mode: str = Query(default="keyword", pattern="^(keyword|semantic)$"),  # "keyword" | "semantic"
):
    since_norm = _normalize_date_filter(since, end_of_day=False)
    until_norm = _normalize_date_filter(until, end_of_day=True)

    if mode == "semantic" and search:
        try:
            ranked_ids = await _semantic_rank(db, "cases", search)
        except embed_backend.EmbeddingUnavailable:
            return {"total": 0, "cases": [], "mode": "semantic", "semantic_unavailable": True}
        if not ranked_ids:
            return {"total": 0, "cases": [], "mode": "semantic"}
        candidates = await fetch_cases(
            db,
            limit=len(ranked_ids),
            offset=0,
            min_significance=min_significance,
            crime_type=crime_type,
            in_kev=in_kev,
            cve_id=cve_id,
            ioc=ioc,
            since=since_norm,
            until=until_norm,
            country=country,
            id_in=ranked_ids,
        )
        by_id = {case["id"]: case for case in candidates}
        page, total = _paginate_ranked(by_id, ranked_ids, limit=limit, offset=offset)
        return {"total": total, "cases": page, "mode": "semantic"}

    cases = await fetch_cases(
        db,
        limit=limit,
        offset=offset,
        min_significance=min_significance,
        crime_type=crime_type,
        in_kev=in_kev,
        search=search,
        cve_id=cve_id,
        ioc=ioc,
        since=since_norm,
        until=until_norm,
        country=country,
    )
    total = await count_cases(
        db,
        min_significance=min_significance,
        crime_type=crime_type,
        in_kev=in_kev,
        search=search,
        cve_id=cve_id,
        ioc=ioc,
        since=since_norm,
        until=until_norm,
        country=country,
    )
    return {"total": total, "cases": cases, "mode": "keyword"}


@router.get("/api/cases/by-country")
async def api_cases_by_country(
    db=Depends(get_db),
    min_significance: str | None = Query(default=None),
    crime_type: str | None = Query(default=None),
    in_kev: bool | None = Query(default=None),
    search: str | None = Query(default=None),
    cve_id: str | None = Query(default=None),
    ioc: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
):
    """Per-country case counts for the Cases tab's map — honors the same
    filters as GET /api/cases (last_seen-based since/until) rather than
    Landscape's first_seen window, so the map always matches what's in the
    filtered case list."""
    since_norm = _normalize_date_filter(since, end_of_day=False)
    until_norm = _normalize_date_filter(until, end_of_day=True)
    by_country = await cases_country_counts(
        db,
        min_significance=min_significance,
        crime_type=crime_type,
        in_kev=in_kev,
        search=search,
        cve_id=cve_id,
        ioc=ioc,
        since=since_norm,
        until=until_norm,
    )
    return {"by_country": by_country}


async def _load_case_bundle(db, case_id: int) -> tuple[dict, list[dict], list[dict], list[dict]]:
    """Shared data fetch for the case detail pane and Markdown/JSON export.
    Returns (case, items, research_runs, related_cases) with JSON fields already
    decoded and booleans normalised. Raises 404 if the case does not exist."""
    case = await get_case_by_id(db, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    case["cve_ids"] = json.loads(case["cve_ids"]) if case["cve_ids"] else []
    case["iocs"] = json.loads(case["iocs"]) if case["iocs"] else []
    case["in_kev"] = bool(case["in_kev"])
    items = await get_case_items(db, case_id)
    research_runs = await get_research_runs_for_case(db, case_id)
    related = await get_case_links(db, case_id)
    return case, items, research_runs, related


@router.get("/api/cases/{case_id}")
async def api_case_detail(case_id: int, db=Depends(get_db)):
    case, items, research_runs, related = await _load_case_bundle(db, case_id)
    return {"case": case, "items": items, "research_runs": research_runs, "related_cases": related}


_MD_ESCAPE_RE = re.compile(r"([*_`\[\]|#])")


def _escape_markdown(text: str) -> str:
    """Escape characters that have Markdown meaning so user-controlled case
    fields (titles, summaries, IoCs) render literally in exported reports."""
    return _MD_ESCAPE_RE.sub(r"\\\1", str(text))


def _case_to_markdown(case: dict, items: list[dict], research_runs: list[dict], related: list[dict]) -> str:
    lines = [f"# {_escape_markdown(case['title'])}", ""]
    lines.append(f"- **Significance:** {case.get('significance', 'unknown')}")
    lines.append(f"- **Crime type:** {case.get('crime_type', 'unknown')}")
    if case.get("damaged_party"):
        lines.append(f"- **Victim:** {_escape_markdown(case['damaged_party'])}")
    if case.get("damaged_party_sector"):
        lines.append(f"- **Sector:** {_escape_markdown(case['damaged_party_sector'])}")
    if case.get("damaged_party_country"):
        lines.append(f"- **Country:** {_escape_markdown(case['damaged_party_country'])}")
    if case.get("attribution"):
        lines.append(f"- **Attribution:** {_escape_markdown(case['attribution'])}")
    lines.append(f"- **Status:** {case.get('status', 'unknown')}")
    lines.append(f"- **In CISA KEV:** {'yes' if case.get('in_kev') else 'no'}")
    lines.append(f"- **First seen:** {case.get('first_seen') or ''}")
    lines.append(f"- **Last seen:** {case.get('last_seen') or ''}")
    lines.append(f"- **Sources:** {case.get('source_count', 0)}")
    if case.get("cve_ids"):
        lines.append(f"- **CVEs:** {', '.join(_escape_markdown(c) for c in case['cve_ids'])}")
    lines.append("")

    if case.get("summary"):
        lines += ["## Summary", "", _escape_markdown(case["summary"]), ""]

    if case.get("iocs"):
        lines += ["## Indicators of compromise", ""]
        lines += [f"- `{_escape_markdown(ioc)}`" for ioc in case["iocs"]]
        lines.append("")

    if items:
        lines += ["## Corroborating reports", ""]
        for it in items:
            ts = it.get("published_at") or it.get("seen_at") or ""
            source = _escape_markdown(it.get("source_name") or it.get("source_id") or "?")
            title = _escape_markdown(it.get("title") or "")
            url = str(it.get("url") or "")
            if url:
                lines.append(f"- [{source}](<{url}>) — {title} ({ts})")
            else:
                lines.append(f"- {source} — {title} ({ts})")
        lines.append("")

    if research_runs:
        lines += ["## Autonomous research", ""]
        for r in research_runs[:5]:
            findings = (r.get("findings") or {}).get("summary") if isinstance(r.get("findings"), dict) else None
            status = _escape_markdown(r.get("status") or "")
            started = r.get("started_at") or ""
            findings_part = f": {_escape_markdown(findings)}" if findings else ""
            lines.append(f"- **{status}** ({started}){findings_part}")
        lines.append("")

    if related:
        lines += ["## Related cases", ""]
        for r in related:
            reasons = ", ".join(r.get("reasons") or [])
            title = _escape_markdown(r.get("title") or "")
            lines.append(
                f"- Case #{r['case_id']}: {title} — {_escape_markdown(reasons)} "
                f"(score {r.get('score', 0):.2f})"
            )
        lines.append("")

    return "\n".join(lines)


@router.get("/api/cases/{case_id}/export")
async def api_case_export(case_id: int, db=Depends(get_db), format: str = Query(default="md")):
    """Markdown/JSON case report for sharing intel out of this single-
    analyst console — same underlying data as GET /api/cases/{id}, just
    rendered for a human reading it outside the dashboard rather than the
    UI's detail pane."""
    if format not in ("md", "json"):
        raise HTTPException(status_code=400, detail="format must be 'md' or 'json'")

    case, items, research_runs, related = await _load_case_bundle(db, case_id)

    if format == "json":
        return {"case": case, "items": items, "research_runs": research_runs, "related_cases": related}

    markdown = _case_to_markdown(case, items, research_runs, related)
    filename = f"case-{case_id}.md"
    return PlainTextResponse(
        markdown, media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/actors/{actor}")
async def api_actor_profile(actor: str, db=Depends(get_db)):
    """Full aggregate profile for one attributed actor — see
    db.get_actor_profile's docstring. Backs the Landscape tab's actor
    leaderboard click-through and the case detail pane's actor pivot."""
    profile = await get_actor_profile(db, actor)
    if profile is None:
        raise HTTPException(status_code=404, detail="No cases attributed to this actor")
    return profile


@router.post("/api/cases/{case_id}/research", dependencies=[Depends(require_admin)])
async def api_case_request_research(case_id: int, request: Request, db=Depends(get_db)):
    """Force a deep-research pass on this case, bypassing the normal
    significance/cooldown gating (see db.get_cases_needing_research) — for
    "re-research this with whatever's missing" from the case detail pane.
    Admin-gated: each call spends a Hermes run."""
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


@router.post("/api/cases/{case_id}/merge/{other_case_id}", dependencies=[Depends(require_admin)])
async def api_merge_cases(case_id: int, other_case_id: int, db=Depends(get_db)):
    """Manually merge two cases. The case at `case_id` survives; the case at
    `other_case_id` is deleted after its items and aggregates are folded in.
    Admin-gated because it mutates the incident graph."""
    if case_id == other_case_id:
        raise HTTPException(status_code=400, detail="Cannot merge a case with itself")

    try:
        merged = await merge_cases(db, keep_case_id=case_id, drop_case_id=other_case_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    event = await log_ai_activity(
        db,
        subsystem="api",
        action="cases_merged",
        summary=f"Merged case #{other_case_id} into case #{case_id}",
        detail={"keep_case_id": case_id, "drop_case_id": other_case_id},
        status="ok",
        ref_type="case",
        ref_id=case_id,
    )
    await broadcaster.broadcast_activity(event)

    return {"merged": True, "case_id": merged["id"], "dropped_case_id": other_case_id}


def _since_iso(since_days: int | None, *, all_time: bool = False) -> str | None:
    """Convert a Landscape window selector to a first_seen cutoff. When
    `all_time` is true (or no window is given), return None so the query is
    genuinely unbounded."""
    if all_time or since_days is None:
        return None
    return (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()


@router.get("/api/stats/cases")
async def api_stats_cases(
    db=Depends(get_db),
    since_days: int | None = Query(default=None, ge=1, le=3650),
    all_time: bool = Query(default=False),
):
    # since_days/all_time power the Landscape tab's 24h/7d/30d/90d/all window
    # selector — cases are never pruned by retention (see db.prune_old_items,
    # which only ages out non-critical *items*), so "all" genuinely means
    # the whole case history, not just what's left after retention.
    since_iso = _since_iso(since_days, all_time=all_time)
    return {
        "total": await count_cases(db, since_iso=since_iso),
        "by_crime_type": await stats_cases_by_crime_type(db, since_iso=since_iso),
        "by_sector": await stats_cases_by_sector(db, since_iso=since_iso),
        "by_country": await stats_cases_by_country(db, since_iso=since_iso),
        "by_actor": await stats_cases_by_actor(db, since_iso=since_iso),
        "in_kev": await stats_cases_in_kev(db, since_iso=since_iso),
    }


@router.get("/api/stats/cases/timeseries")
async def api_stats_cases_timeseries(
    db=Depends(get_db),
    since_days: int | None = Query(default=30, ge=1, le=3650),
    bucket: str = Query(default="day"),
    all_time: bool = Query(default=False),
):
    since_iso = _since_iso(since_days, all_time=all_time)
    return {"buckets": await stats_cases_timeseries(db, bucket=bucket, since_iso=since_iso)}


@router.get("/api/stats/trends")
async def api_stats_trends(
    db=Depends(get_db),
    dimension: str = Query(default="actor"),
    window_days: int = Query(default=7, ge=1, le=180),
    limit: int = Query(default=10, le=50),
):
    if dimension not in ("actor", "sector", "crime_type", "cve"):
        raise HTTPException(status_code=400, detail="dimension must be one of actor, sector, crime_type, cve")
    return {"trends": await stats_trends(db, dimension=dimension, window_days=window_days, limit=limit)}


def _landscape_snapshot_markdown(
    *, since_iso: str | None, since_days: int | None, stats: dict, actor_trends: list[dict],
    sector_trends: list[dict], cve_trends: list[dict],
) -> str:
    window_label = f"last {since_days} day(s)" if since_iso else "all time"
    lines = [f"# Cybercrime Landscape Snapshot — {window_label}", "", f"Generated: {datetime.now(timezone.utc).isoformat()}", ""]

    lines.append(f"- **Cases:** {stats['total']}")
    lines.append(f"- **In CISA KEV:** {stats['in_kev']}")
    lines.append("")

    def _bullet_section(title: str, rows: list[dict], key: str) -> None:
        lines.append(f"## {title}")
        lines.append("")
        if not rows:
            lines.append("_None._")
        for r in rows[:15]:
            lines.append(f"- {_escape_markdown(r[key])}: {r['n']}")
        lines.append("")

    _bullet_section("Crime types", stats["by_crime_type"], "crime_type")
    _bullet_section("Top sectors", stats["by_sector"], "sector")
    _bullet_section("Top countries", stats["by_country"], "country")
    _bullet_section("Most active actors", stats["by_actor"], "actor")

    def _trend_section(title: str, rows: list[dict]) -> None:
        lines.append(f"## {title}")
        lines.append("")
        if not rows:
            lines.append("_No movement this window._")
        for r in rows[:10]:
            kev = " ⚠ KEV" if r.get("in_kev") else ""
            lines.append(f"- {_escape_markdown(r['value'])}{kev}: {r['status']} ({r['current']}, Δ{r['delta']:+d})")
        lines.append("")

    _trend_section("Emerging/rising actors", [r for r in actor_trends if r["status"] in ("emerging", "rising")])
    _trend_section("Emerging/rising sectors", [r for r in sector_trends if r["status"] in ("emerging", "rising")])
    _trend_section("Emerging/rising CVEs", [r for r in cve_trends if r["status"] in ("emerging", "rising")])

    return "\n".join(lines)


@router.get("/api/stats/landscape/export")
async def api_landscape_export(
    db=Depends(get_db),
    since_days: int | None = Query(default=None, ge=1, le=3650),
    trend_window_days: int = Query(default=7, ge=1, le=180),
    all_time: bool = Query(default=False),
):
    """Markdown snapshot of the Landscape tab's current window — top actors/
    sectors/countries/crime-types plus week-over-week (trend_window_days)
    movement — for sharing a point-in-time read of the landscape outside
    the dashboard. Built from the same db.stats_cases_*/stats_trends calls
    the Landscape tab itself uses."""
    since_iso = _since_iso(since_days, all_time=all_time)
    stats = {
        "total": await count_cases(db, since_iso=since_iso),
        "by_crime_type": await stats_cases_by_crime_type(db, since_iso=since_iso),
        "by_sector": await stats_cases_by_sector(db, since_iso=since_iso),
        "by_country": await stats_cases_by_country(db, since_iso=since_iso),
        "by_actor": await stats_cases_by_actor(db, since_iso=since_iso),
        "in_kev": await stats_cases_in_kev(db, since_iso=since_iso),
    }
    actor_trends = await stats_trends(db, dimension="actor", window_days=trend_window_days, limit=15)
    sector_trends = await stats_trends(db, dimension="sector", window_days=trend_window_days, limit=15)
    cve_trends = await stats_trends(db, dimension="cve", window_days=trend_window_days, limit=15)

    markdown = _landscape_snapshot_markdown(
        since_iso=since_iso, since_days=since_days, stats=stats,
        actor_trends=actor_trends, sector_trends=sector_trends, cve_trends=cve_trends,
    )
    return PlainTextResponse(
        markdown, media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="landscape-snapshot.md"'},
    )


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


class InvestigationCreate(BaseModel):
    brief: str


@router.post("/api/feedback")
async def api_feedback_create(body: FeedbackCreate, db=Depends(get_db)):
    from ..db import VALID_FEEDBACK_VERDICTS, add_feedback

    if (body.case_id is None) == (body.item_id is None):
        raise HTTPException(status_code=400, detail="exactly one of case_id or item_id is required")
    if body.verdict not in VALID_FEEDBACK_VERDICTS:
        raise HTTPException(
            status_code=400,
            detail=f"verdict must be one of {sorted(VALID_FEEDBACK_VERDICTS)}",
        )
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


# ── Targeted investigations ──────────────────────────────────────────────────
# Investigator-submitted briefs that trigger an agentic research pass. Admin-
# gated because each submission spends a Hermes run. The run is async: this
# endpoint just queues the investigation and nudges the scheduler job.

@router.post("/api/investigations", dependencies=[Depends(require_admin)])
async def api_investigation_create(body: InvestigationCreate, request: Request, db=Depends(get_db)):
    brief = body.brief.strip()
    if not brief:
        raise HTTPException(status_code=400, detail="brief is required")
    if len(brief) > 5000:
        raise HTTPException(status_code=400, detail="brief must be at most 5000 characters")

    investigation_id = await create_investigation(db, brief=brief)

    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is not None:
        job = scheduler.get_job("_investigate")
        if job is not None:
            scheduler.modify_job("_investigate", next_run_time=datetime.now(timezone.utc))

    return {"investigation_id": investigation_id, "status": "queued"}


@router.get("/api/investigations", dependencies=[Depends(require_admin)])
async def api_investigations(db=Depends(get_db), limit: int = Query(default=50, le=200)):
    return {"investigations": await list_investigations(db, limit=limit)}


@router.get("/api/investigations/{investigation_id}", dependencies=[Depends(require_admin)])
async def api_investigation_detail(investigation_id: int, db=Depends(get_db)):
    inv = await get_investigation(db, investigation_id=investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


# ── AI activity log ───────────────────────────────────────────────────────────
# Deliberately public, no admin token — every subsystem here (discover/heal/
# prune/research/classifier/correlator/cross_correlator) already acts fully
# autonomously with no human approval gate; this is the transparency
# counterpart, not an admin control surface. See db.py's ai_activity table
# docstring and db.log_ai_activity.

@router.get("/api/activity")
async def api_activity(
    db=Depends(get_db),
    subsystem: str | None = Query(default=None),
    status: str | None = Query(default=None),
    since: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
):
    return await list_ai_activity(
        db, subsystem=subsystem, status=status, since=since, limit=limit, offset=offset
    )
