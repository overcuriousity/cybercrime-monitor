"""Background extraction job — runs on its own APScheduler interval,
decoupled from collector ingest ticks (an LLM call on the shared event loop
during a collector tick would stall the whole app; see scheduler.py wiring,
which sets max_instances=1 + coalesce=True so a slow batch never overlaps
itself and double-processes the same items).

Each tick:
  1. Extract structured fields for a LIFO batch of newest-unextracted items
     (db.get_unextracted_items).
  2. Fire Gotify for any newly-confirmed critical (not false_positive).
"""
import logging
import time

from .. import db
from ..api.sse import broadcaster
from ..notifier import push_gotify
from ..settings import settings
from . import backend
from . import health as llm_health

log = logging.getLogger(__name__)

# Item-level extraction would flood ai_activity (every classified item, all
# day) — so the classifier logs one summary row per batch tick, plus an
# item-level row only for the verdicts an analyst actually wants surfaced
# individually (critical, or a flagged false positive).

# A model that systematically fails on certain items (wrong chat template,
# JSON mode misconfigured, etc.) must never get a fabricated/regex-derived
# extraction substituted in its place — that would silently mask a real
# extraction problem. Instead: track consecutive failures per item
# (process-local, like health.py) and back off retrying it with increasing
# delay, so a stuck item stops monopolizing every batch slot without ever
# giving up on getting a real extraction. Other items get a turn via the
# over-fetched candidate pool below.
_BASE_BACKOFF_SECONDS = 15
_MAX_BACKOFF_SECONDS = 600  # cap at 10 min between retries of the same item
_OVERFETCH_MULTIPLIER = 5   # candidate pool size = batch_size * this
_failed_attempts: dict[int, int] = {}
_next_retry_at: dict[int, float] = {}  # item_id -> time.monotonic() deadline


def _backoff_seconds(attempt: int) -> int:
    return min(_MAX_BACKOFF_SECONDS, _BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))


def _gotify_payload(item: dict, *, low_confidence: bool = False) -> tuple[str, str]:
    title = f"[CRITICAL] {item['source_name']}: {item['title'][:80]}"
    message = f"{item['url']}\n\n{item['snippet'][:300]}"
    if low_confidence:
        message = "[low extraction confidence — verify manually]\n\n" + message
    return title, message


def _effective_false_positive(extraction) -> bool:
    """A false_positive verdict below llm_min_confidence is not trusted to
    suppress the item — better to show a possible false positive than
    silently drop a real one on a low-confidence guess. Confidence is a
    required schema field (see backend.py's response_format), so a missing
    value here means the model didn't follow instructions; treat that as
    untrusted too rather than letting it suppress silently."""
    if not extraction.false_positive:
        return False
    if settings.llm_min_confidence <= 0.0:
        return True
    return extraction.confidence is not None and extraction.confidence >= settings.llm_min_confidence


def _is_low_confidence(extraction) -> bool:
    return settings.llm_min_confidence > 0.0 and (
        extraction.confidence is None or extraction.confidence < settings.llm_min_confidence
    )


async def _log_activity(
    db_conn, *, action: str, summary: str, detail: dict | None = None,
    status: str = "ok", ref_type: str | None = None, ref_id: int | str | None = None,
    model: str | None = None,
) -> None:
    """Write to ai_activity and fan it out over SSE — see db.log_ai_activity's
    docstring. Swallows its own errors: activity logging must never be the
    reason an extraction batch fails."""
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem="classifier", action=action, summary=summary,
            detail=detail, status=status, ref_type=ref_type, ref_id=ref_id, model=model,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[llm] activity log failed: %s", exc)


async def run_extraction_batch(db_conn) -> None:
    if settings.llm_backend == "none":
        return

    llm_health.record_run_start()
    try:
        extracted_count = await _extract_batch(db_conn)
        if extracted_count:
            llm_health.record_success(extracted_count)
    except Exception as exc:
        log.error("[llm] batch error: %s", exc)
        llm_health.record_error(str(exc) or repr(exc))


async def _extract_batch(db_conn) -> int:
    # Over-fetch a larger LIFO candidate pool than one batch needs, so a
    # handful of stuck-and-backing-off items at the front can't blockade
    # every slot forever — the rest of the pool still gets attempted this
    # tick. (Without this, a model that fails on the newest few items would
    # otherwise stall the entire queue, since "newest unextracted N" would
    # be the same N every tick.)
    pool = await db.get_unextracted_items(
        db_conn, limit=settings.llm_batch_size * _OVERFETCH_MULTIPLIER
    )
    now = time.monotonic()
    ready = [it for it in pool if _next_retry_at.get(it["id"], 0.0) <= now]
    batch = ready[: settings.llm_batch_size]

    extracted_count = 0

    # One /chat/completions call extracts the whole batch (see
    # backend.extract_batch) instead of N sequential calls — cuts batch
    # latency roughly N-fold, which matters because get_unextracted_items
    # serves LIFO: a slow per-item loop is exactly what lets a sustained
    # ingest burst starve older items indefinitely.
    extractions = await backend.extract_batch(batch, conn=db_conn)

    critical_count = 0
    false_positive_count = 0
    model_used = None

    for item, extraction in zip(batch, extractions):
        if extraction is None:
            # Never substitute a fabricated/regex-derived extraction here —
            # the item stays genuinely unextracted and is retried for real,
            # just with backoff so it stops eating every batch slot.
            attempts = _failed_attempts.get(item["id"], 0) + 1
            _failed_attempts[item["id"]] = attempts
            delay = _backoff_seconds(attempts)
            _next_retry_at[item["id"]] = now + delay
            log.warning(
                "[llm] item %s failed (attempt %d) — retrying in %ds",
                item["id"], attempts, delay,
            )
            continue

        _failed_attempts.pop(item["id"], None)
        _next_retry_at.pop(item["id"], None)

        effective_false_positive = _effective_false_positive(extraction)
        low_confidence = _is_low_confidence(extraction)

        # Write the extraction before alerting: once this row exists the
        # item drops out of both this batch's source query and the fallback
        # sweep, which is the sole idempotency guard against double-firing.
        # Store the effective (threshold-adjusted) false_positive — not the
        # raw verdict — since that's what the dashboard's show_filtered
        # logic and item_priority view key off of.
        await db.upsert_extraction(
            db_conn,
            item_id=item["id"],
            crime_type=extraction.crime_type,
            victim=extraction.victim,
            victim_sector=extraction.victim_sector,
            victim_country=extraction.victim_country,
            actor=extraction.actor,
            cve_ids=extraction.cve_ids,
            iocs=extraction.iocs,
            significance=extraction.significance,
            false_positive=effective_false_positive,
            confidence=extraction.confidence,
            reasoning=extraction.reasoning,
            model=extraction.model,
        )
        extracted_count += 1
        model_used = extraction.model or model_used
        if effective_false_positive:
            false_positive_count += 1

        if extraction.significance == "critical" and not effective_false_positive:
            critical_count += 1
            title, message = _gotify_payload(item, low_confidence=low_confidence)
            await push_gotify(title=title, message=message, priority=8)
            await _log_activity(
                db_conn, action="item_classified_critical",
                summary=f"Critical: {item['source_name']} — {item['title'][:80]}",
                detail={
                    "crime_type": extraction.crime_type, "victim": extraction.victim,
                    "actor": extraction.actor, "confidence": extraction.confidence,
                    "low_confidence": low_confidence, "url": item["url"],
                },
                ref_type="item", ref_id=item["id"], model=extraction.model,
            )
        elif effective_false_positive:
            await _log_activity(
                db_conn, action="item_classified_false_positive", status="skipped",
                summary=f"Flagged as false positive: {item['source_name']} — {item['title'][:80]}",
                detail={"reasoning": extraction.reasoning, "confidence": extraction.confidence, "url": item["url"]},
                ref_type="item", ref_id=item["id"], model=extraction.model,
            )

    if extracted_count:
        await _log_activity(
            db_conn, action="batch_classified",
            summary=(
                f"Classified {extracted_count} item(s) — {critical_count} critical, "
                f"{false_positive_count} false positive"
            ),
            detail={
                "extracted_count": extracted_count, "critical_count": critical_count,
                "false_positive_count": false_positive_count,
            },
            model=model_used,
        )

    return extracted_count
