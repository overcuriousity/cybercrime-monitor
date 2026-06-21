"""Investigator-triggered targeted research — see api/routes.py's
POST /api/investigations. An investigator who picks up a new case often has
information our passive collectors haven't seen yet (a victim name, modus
operandi, anything known). This module takes that free-text brief, asks
Hermes to research it across this monitor's existing source sites *and* the
open web, and — only when Hermes reports a genuine, reasonably confident
match — folds the findings in exactly like organic ingestion:

  1. Findings become real `items` rows (db.insert_item), tagged with a
     reserved `targeted_research` provenance source (not a configured
     collector — no schedule, just a record of where the row came from).
  2. Each item gets an extraction row immediately (we already have the
     structured fields from Hermes — no need to wait for the extraction
     job's queue).
  3. Each item is handed to pipeline/correlate.py's normal create-or-merge
     logic (`_correlate_one`), so a brief that turns out to describe an
     already-known incident corroborates that case instead of spawning a
     duplicate — "the case is then normally aggregated, correlated and
     processed as any other case."
  4. Any new source candidates Hermes turns up are run through
     research/discover.py's existing probe/validate/apply pipeline, so they
     get the same probationary tagging and enter the same heal/prune
     lifecycle as autonomously-discovered sources — "each source is
     evaluated whether it is kept for the future."

A submission that finds nothing convincing creates nothing — no case, no
items, no sources. See _INVESTIGATE_PROMPT_TEMPLATE / settings.
investigate_min_confidence for the gate.

Runs on its own APScheduler interval (scheduler.py's "_investigate" job),
draining queued investigations one at a time (a run can legitimately take
minutes, same cost class as research/agent.py). The submitting API call
nudges the job to run immediately rather than waiting out the interval —
same pattern as the case-research force-trigger.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .. import db
from ..api.sse import broadcaster
from ..collectors.base import _content_key, _dedupe_key
from ..hermes.runner import _is_transient, run_agent
from ..models import Item
from ..pipeline.correlate import _correlate_one
from ..scheduler import load_sources
from ..settings import settings
from . import discover as discover_research

log = logging.getLogger(__name__)


# ── Runtime health registry (mirrors research/agent.py) ──────────────────────
# Surfaced via /api/status so the dashboard can show whether an investigation
# is currently running or backing up.

@dataclass
class InvestigateHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_processed_count: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0


_health = InvestigateHealth()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(payload: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcaster.broadcast_status("investigate", payload))
    except RuntimeError:
        pass


def record_run_start() -> None:
    _health.last_run_at = _now_iso()


def record_success(processed_count: int) -> None:
    _health.last_success_at = _now_iso()
    _health.last_processed_count = processed_count
    _health.consecutive_errors = 0
    _emit({"last_processed_count": processed_count})


def record_error(error: str) -> None:
    _health.last_error = error[:300]
    _health.last_error_at = _now_iso()
    _health.consecutive_errors += 1
    _emit({"error": error[:300], "consecutive_errors": _health.consecutive_errors})


def get() -> InvestigateHealth:
    return _health


async def _log_activity(
    db_conn, *, action: str, summary: str, detail: dict | None = None,
    status: str = "ok", ref_type: str = "case", ref_id: int | str | None = None,
) -> None:
    """Write to ai_activity and fan it out over SSE — see db.log_ai_activity's
    docstring. Swallows its own errors: activity logging must never be the
    reason an investigation fails."""
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem="investigate", action=action, summary=summary,
            detail=detail, status=status, ref_type=ref_type, ref_id=ref_id,
            model=settings.hermes_model or None,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[investigate] activity log failed: %s", exc)


# Provenance for items created by this module — not a configured collector,
# so it never appears in sources.yaml/scheduling, only as items.source_id.
_SOURCE_ID = "targeted_research"
_SOURCE_NAME = "Targeted Investigation"

# Process at most this many queued investigations per tick — each one can
# take minutes (hermes_timeout_seconds), same reasoning as research/agent.py's
# _CASES_PER_TICK.
_PER_TICK = 1
# How many already-collected items to surface to Hermes as local context.
_LOCAL_CONTEXT_LIMIT = 8
# Cap on how many finding items / new-source candidates one investigation
# can produce, mirroring research/agent.py's iocs cap and discover.py's
# 5-candidate cap — bounds the blast radius of a single Hermes response.
_MAX_ITEMS = 20
_MAX_NEW_FEEDS = 5

_INVESTIGATE_PROMPT_TEMPLATE = """\
You are assisting a cybercrime intelligence monitor. An investigator has a \
new case that the monitor's automated collection has not picked up yet. \
Research the following case brief using web search and any pages you need \
to fetch — check whether it is reported on the monitor's EXISTING source \
sites listed below, and also search the open web more broadly.

CASE BRIEF:
{brief}

EXISTING SOURCE SITES (check these specifically, in addition to general web \
search): {existing_domains}

ITEMS ALREADY IN THIS MONITOR THAT MIGHT BE RELATED (for context only — \
verify, don't assume these are the same incident):
{local_context}

Only report found=true if you find genuine, corroborated evidence of a \
specific, identifiable incident matching this brief — a named victim and/or \
named actor, with concrete reporting (not just the brief restated back at \
you). If you find nothing convincing, report found=false and nothing else \
matters.

If found, also list every distinct piece of reporting you found as a \
separate "items" entry (title, url, a short snippet/quote, the site/source \
name, and a publish date if known) — these become the monitor's record of \
where this incident was reported. And if you discover a site that reports \
this kind of cybercrime well but is NOT one of the monitor's existing \
sources, list it under "new_feeds" so it can be considered for ongoing \
collection — same "kind" classification as source discovery: "rss" (give \
feed_url), "tor_forum" or "html_forum" (give listing_url).

When you are done, respond with ONLY a single-line JSON object as your \
final message, no markdown fencing, no commentary, exactly these keys:
{{"found": true|false, "confidence": <0.0-1.0>, "title": <string|null>, \
"crime_type": <string|null>, "victim": <string|null>, \
"victim_sector": <string|null>, \
"victim_country": <ISO 3166-1 alpha-2 country code of the victim, or null>, \
"attribution": <string|null>, "summary": "<2-3 sentence summary>", \
"cve_ids": [<string>...], "iocs": [<string>...], \
"items": [{{"title": "<string>", "url": "<string>", "snippet": "<string>", \
"source_name": "<string>", "published_at": <string|null>}}, ...], \
"new_feeds": [{{"name": "<string>", "kind": "rss"|"tor_forum"|"html_forum", \
"feed_url": <string|null>, "listing_url": <string|null>, "reason": "<string>"}}, ...]}}
Use empty arrays for "items"/"new_feeds" if found=false.
"""


def _local_context(items: list[dict]) -> str:
    if not items:
        return "(none found)"
    lines = [f"- {it['title']} ({it.get('source_name', '')})" for it in items]
    return "\n".join(lines)


def _build_prompt(brief: str, existing_sources: list[dict], local_items: list[dict]) -> str:
    domains = sorted(discover_research._existing_domains(existing_sources))
    return _INVESTIGATE_PROMPT_TEMPLATE.format(
        brief=brief.strip()[:2000],
        existing_domains=", ".join(domains) or "none configured",
        local_context=_local_context(local_items),
    )


def _str_list(value, *, cap: int = 50) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None][:cap]


def _significance_for(confidence: float) -> str:
    if confidence >= 0.8:
        return "critical"
    if confidence >= 0.5:
        return "warn"
    return "info"


async def run_investigation_batch(db_conn, scheduler=None, sse_broadcaster=None) -> int:
    """One tick: drain a bounded number of queued investigations. Returns
    the number processed (regardless of outcome — no_match/failed/re-queued
    all count, since they consumed a Hermes run this tick; no_match/failed
    are terminal (the investigator can resubmit), while a transient failure
    is re-queued with a cooldown instead — see _is_transient and
    settings.investigate_max_attempts)."""
    if settings.hermes_investigate_interval_seconds <= 0:
        return 0

    record_run_start()
    processed = 0
    try:
        queued = await db.get_queued_investigations(db_conn, limit=_PER_TICK)
        for inv in queued:
            try:
                await _investigate_one(db_conn, inv, scheduler, sse_broadcaster)
            except Exception as exc:
                log.error("[investigate] investigation %s failed: %s", inv["id"], exc)
                error = str(exc) or repr(exc)
                try:
                    # Same transient/permanent split as the in-flow failure
                    # branch in _investigate_one — an exception escaping
                    # that function (e.g. a crash mid-integration after a
                    # transient hermes hiccup) shouldn't be treated as more
                    # terminal than a hermes-reported failure would be.
                    if _is_transient(error) and inv["attempts"] < settings.investigate_max_attempts:
                        next_retry_at = (
                            datetime.now(timezone.utc)
                            + timedelta(minutes=settings.investigate_failure_retry_minutes)
                        ).isoformat()
                        await db.requeue_investigation(
                            db_conn, investigation_id=inv["id"], error=error, next_retry_at=next_retry_at,
                        )
                    else:
                        await db.finish_investigation(
                            db_conn, investigation_id=inv["id"], status="failed",
                            findings={}, error=error,
                        )
                except Exception:
                    pass
            processed += 1

        if processed:
            log.info("[investigate] processed %d investigation(s)", processed)
        record_success(processed)
    except Exception as exc:
        log.error("[investigate] batch failed: %s", exc)
        record_error(str(exc) or repr(exc))
        raise

    return processed


async def _investigate_one(db_conn, inv: dict, scheduler, sse_broadcaster) -> None:
    investigation_id = inv["id"]
    brief = inv["brief"]
    await db.mark_investigation_running(db_conn, investigation_id=investigation_id)

    # run_investigation_batch() may be invoked without an explicit broadcaster
    # (tests/CLI), so fall back to the module-level broadcaster for item broadcasts.
    sse_broadcaster = sse_broadcaster or broadcaster

    existing_sources = load_sources()
    local_items = await db.fetch_items(db_conn, limit=_LOCAL_CONTEXT_LIMIT, search=_search_terms(brief))

    prompt = _build_prompt(brief, existing_sources, local_items)
    result = await run_agent(
        prompt, toolsets=settings.hermes_toolsets, timeout=settings.hermes_timeout_seconds,
        model=settings.hermes_model or None, expect_json=True,
    )

    if not result.ok or result.data is None:
        error = result.error or "no parseable result"
        # A transient provider hop (rate limit, a broken fallback-chain link
        # — see hermes/runner.py's _is_transient) gets a bounded re-queue
        # instead of going straight to terminal "failed": the investigator
        # is often waiting on this result, and the same brief frequently
        # succeeds minutes later once the provider recovers (observed live
        # 2026-06-21: a 404 in the hermes fallback chain made every targeted
        # investigation fail on the first hop). attempts counts how many
        # times this row has already been re-queued, so "< max" allows up to
        # investigate_max_attempts retries — investigate_max_attempts + 1
        # total runs, including the initial try.
        if _is_transient(error) and inv["attempts"] < settings.investigate_max_attempts:
            next_retry_at = (
                datetime.now(timezone.utc) + timedelta(minutes=settings.investigate_failure_retry_minutes)
            ).isoformat()
            await db.requeue_investigation(
                db_conn, investigation_id=investigation_id, error=error, next_retry_at=next_retry_at,
            )
            await _log_activity(
                db_conn, action="investigation_retry", status="warn", ref_type="investigation",
                summary=f"Investigation #{investigation_id}: transient failure, retrying (retry {inv['attempts'] + 1}/{settings.investigate_max_attempts})",
                detail={"error": error, "brief": brief[:200]}, ref_id=investigation_id,
            )
            return

        await db.finish_investigation(
            db_conn, investigation_id=investigation_id, status="failed",
            findings={}, error=error,
        )
        await _log_activity(
            db_conn, action="investigation_failed", status="error",
            summary=f"Investigation #{investigation_id} failed", ref_type="investigation",
            detail={"error": error, "brief": brief[:200]}, ref_id=investigation_id,
        )
        return

    data = result.data
    found = bool(data.get("found"))
    try:
        confidence = float(data.get("confidence")) if data.get("confidence") is not None else 0.0
    except (TypeError, ValueError):
        confidence = 0.0

    if not found or confidence < settings.investigate_min_confidence:
        await db.finish_investigation(db_conn, investigation_id=investigation_id, status="no_match", findings=data)
        await _log_activity(
            db_conn, action="investigation_no_match", status="skipped", ref_type="investigation",
            summary=f"Investigation #{investigation_id}: no confident match (confidence {confidence:.2f})",
            detail={"brief": brief[:200], "confidence": confidence}, ref_id=investigation_id,
        )
        return

    # ── Integrate: items → feed, each with an immediate extraction row ────
    inserted_items: list[Item] = []
    raw_items = data.get("items") if isinstance(data.get("items"), list) else []
    significance = _significance_for(confidence)
    cve_ids = _str_list(data.get("cve_ids"))
    iocs = _str_list(data.get("iocs"))

    for raw in raw_items[:_MAX_ITEMS]:
        item = _build_item(raw)
        if item is None:
            continue
        item.dedupe_key = _dedupe_key(item.source_id, item.url)
        item.content_key = _content_key(item)
        row_id = await db.insert_item(db_conn, item)
        if row_id is None:
            continue  # duplicate of something already collected
        item.id = row_id
        item.seen_at = datetime.now(timezone.utc)
        await db.upsert_extraction(
            db_conn, item_id=row_id,
            crime_type=str(data.get("crime_type") or "other")[:50],
            victim=_opt_str(data.get("victim")), victim_sector=_opt_str(data.get("victim_sector")),
            victim_country=_opt_str(data.get("victim_country")), actor=_opt_str(data.get("attribution")),
            cve_ids=cve_ids, iocs=iocs, significance=significance, false_positive=False,
            confidence=confidence, reasoning=f"Targeted investigation #{investigation_id}",
            model=settings.hermes_model or "hermes-agent",
        )
        await db_conn.commit()
        inserted_items.append(item)
        await sse_broadcaster.broadcast(_item_payload(item, data, confidence, significance, cve_ids, iocs))

    if not inserted_items:
        # If the investigation is being retried (e.g. crash/restart while it
        # was "running"), its targeted_research items may already exist. Try
        # to recover a linked case_id from those items before declaring no_match.
        case_id = None
        for raw in raw_items[:_MAX_ITEMS]:
            url = str(raw.get("url") or "").strip()
            if not url:
                continue
            rows = await db_conn.execute_fetchall(
                "SELECT id FROM items WHERE source_id = :sid AND url = :url LIMIT 1",
                {"sid": _SOURCE_ID, "url": url},
            )
            if rows:
                case_id = await db.get_case_id_for_item(db_conn, rows[0]["id"])
                if case_id is not None:
                    break

        status = "completed" if case_id is not None else "no_match"
        await db.finish_investigation(
            db_conn,
            investigation_id=investigation_id,
            status=status,
            findings=data,
            case_id=case_id,
        )
        await _log_activity(
            db_conn,
            action="investigation_completed" if status == "completed" else "investigation_no_match",
            status="ok" if status == "completed" else "skipped",
            ref_type="investigation",
            ref_id=investigation_id,
            summary=(
                f"Investigation #{investigation_id}: already integrated" + (f" (case #{case_id})" if case_id else "")
                if status == "completed"
                else f"Investigation #{investigation_id}: match claimed but no new items produced"
            ),
            detail={"brief": brief[:200]},
        )
        return

    # ── Correlate: reuse the normal item→case create-or-merge pipeline ─────
    case_id = None
    for item in inserted_items:
        corr_item = _to_correlate_item(item, data, confidence, significance, cve_ids, iocs)
        await _correlate_one(db_conn, corr_item)
        linked_case_id = await db.get_case_id_for_item(db_conn, item.id)
        if linked_case_id is not None:
            case_id = linked_case_id

    # ── New sources: reuse discover.py's probe/validate/apply pipeline ─────
    new_feeds = data.get("new_feeds") if isinstance(data.get("new_feeds"), list) else []
    existing_domains = discover_research._existing_domains(existing_sources)
    existing_ids = {s["id"] for s in existing_sources}
    for cand in new_feeds[:_MAX_NEW_FEEDS]:
        try:
            await discover_research._try_add_candidate(
                db_conn, cand, existing_domains, existing_ids, scheduler, sse_broadcaster
            )
        except Exception as exc:
            log.error("[investigate] new_feeds candidate %r failed: %s", cand, exc)

    # Nudge cross-correlation so the new/corroborated case links to related
    # cases immediately rather than waiting out its own interval — same
    # "surface results without delay" reasoning as the research force-trigger.
    if scheduler is not None:
        job = scheduler.get_job("_cross_correlate")
        if job is not None:
            scheduler.modify_job("_cross_correlate", next_run_time=datetime.now(timezone.utc))

    await db.finish_investigation(db_conn, investigation_id=investigation_id, status="completed",
                                   findings=data, case_id=case_id)
    await _log_activity(
        db_conn, action="investigation_completed", ref_type="case", ref_id=case_id,
        summary=(
            f"Investigation #{investigation_id} confirmed — {len(inserted_items)} item(s), "
            f"{len(new_feeds)} candidate source(s)" + (f", case #{case_id}" if case_id else "")
        ),
        detail={
            "brief": brief[:200], "confidence": confidence, "items_added": len(inserted_items),
            "new_feeds_proposed": len(new_feeds), "case_id": case_id,
        },
    )


def _search_terms(brief: str) -> str:
    """A short substring to LIKE-search already-collected items against —
    the brief is free text, not a query, so just take its leading words
    (the investigator typically leads with the most identifying detail:
    victim name, actor, etc.)."""
    words = brief.strip().split()
    return " ".join(words[:6])[:200]


def _opt_str(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s[:200] or None


def _build_item(raw: dict) -> Item | None:
    if not isinstance(raw, dict):
        return None
    title = str(raw.get("title") or "").strip()[:500]
    url = str(raw.get("url") or "").strip()
    if not title or not url.startswith(("http://", "https://")):
        return None
    published_at = None
    raw_date = raw.get("published_at")
    if raw_date:
        try:
            published_at = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
        except ValueError:
            published_at = None
    return Item(
        source_id=_SOURCE_ID,
        source_name=str(raw.get("source_name") or _SOURCE_NAME)[:100],
        title=title,
        url=url,
        snippet=str(raw.get("snippet") or "")[:1000],
        published_at=published_at,
        source_tags=["targeted-investigation"],
    )


def _item_payload(item: Item, data: dict, confidence: float, significance: str,
                   cve_ids: list[str], iocs: list[str]) -> dict:
    """SSE broadcast for an investigation-sourced item. Unlike a freshly-
    scraped item (collectors/base.py's _build_payload), we already have the
    classification — Hermes produced it — so this is NOT the usual "pending"
    placeholder shape; it reflects the known verdict immediately."""
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
        "max_priority": significance,
        "all_tags": db.extraction_tags(crime_type=data.get("crime_type"), cve_ids=cve_ids, iocs=iocs),
        "is_false_positive": False,
        "classified": True,
        "classifier_confidence": confidence,
        "classifier_reasoning": "Found via targeted investigation",
        "crime_type": data.get("crime_type"),
        "victim": data.get("victim"),
        "victim_sector": data.get("victim_sector"),
        "victim_country": data.get("victim_country"),
        "actor": data.get("attribution"),
        "cve_ids": cve_ids,
        "iocs": iocs,
        "cluster_size": 1,
    }


def _to_correlate_item(item: Item, data: dict, confidence: float, significance: str,
                        cve_ids: list[str], iocs: list[str]) -> dict:
    """Shape pipeline/correlate.py's _correlate_one expects — mirrors
    db.get_uncorrelated_extracted_items' output dict."""
    return {
        "id": item.id,
        "title": item.title,
        "snippet": item.snippet,
        "source_id": item.source_id,
        "source_name": item.source_name,
        "url": item.url,
        "seen_at": item.seen_at.isoformat() if item.seen_at else None,
        "published_at": item.published_at.isoformat() if item.published_at else None,
        "content_key": item.content_key,
        "crime_type": data.get("crime_type"),
        "victim": data.get("victim"),
        "victim_sector": data.get("victim_sector"),
        "victim_country": data.get("victim_country"),
        "actor": data.get("attribution"),
        "cve_ids": cve_ids,
        "iocs": iocs,
        "significance": significance,
        "confidence": confidence,
    }
