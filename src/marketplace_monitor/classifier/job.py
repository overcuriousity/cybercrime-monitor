"""Background classification job — runs on its own APScheduler interval,
decoupled from collector ingest ticks (an LLM call on the shared event loop
during a collector tick would stall the whole app; see scheduler.py wiring,
which sets max_instances=1 + coalesce=True so a slow batch never overlaps
itself and double-processes the same items).

Each tick:
  1. Classify a LIFO batch of newest-unclassified items (db.get_unclassified_items).
  2. Fire Gotify for any newly-confirmed critical (not false_positive).
  3. Sweep for regex-critical items that have sat unclassified past
     classifier_fallback_alert_minutes and alert on those too — a classifier
     backend outage must never silently swallow a real critical alert.
"""
import logging
import time
from datetime import datetime, timedelta, timezone

from .. import db
from ..notifier import push_gotify
from ..settings import settings
from . import backend
from . import health as classifier_health

log = logging.getLogger(__name__)

# A model that systematically fails on certain items (wrong chat template,
# JSON mode misconfigured, etc.) must never get a fabricated/regex-derived
# verdict substituted in its place — that would silently mask a real
# classifier problem. Instead: track consecutive failures per item
# (process-local, like health.py) and back off retrying it with increasing
# delay, so a stuck item stops monopolizing every batch slot without ever
# giving up on getting a real verdict. Other items get a turn via the
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
        message = "[low classifier confidence — verify manually]\n\n" + message
    return title, message


def _effective_false_positive(verdict) -> bool:
    """A false_positive verdict below classifier_min_confidence is not
    trusted to suppress the item — better to show a possible false positive
    than silently drop a real one on a low-confidence guess. Confidence is
    a required schema field (see backend.py's response_format), so a missing
    value here means the model didn't follow instructions; treat that as
    untrusted too rather than letting it suppress silently."""
    if not verdict.false_positive:
        return False
    if settings.classifier_min_confidence <= 0.0:
        return True
    return verdict.confidence is not None and verdict.confidence >= settings.classifier_min_confidence


def _is_low_confidence(verdict) -> bool:
    return settings.classifier_min_confidence > 0.0 and (
        verdict.confidence is None or verdict.confidence < settings.classifier_min_confidence
    )


async def run_classification_batch(db_conn) -> None:
    if settings.classifier_backend == "none":
        return

    classifier_health.record_run_start()
    try:
        classified_count = await _classify_batch(db_conn)
        await _run_fallback_sweep(db_conn)
        if classified_count:
            classifier_health.record_success(classified_count)
    except Exception as exc:
        log.error("[classifier] batch error: %s", exc)
        classifier_health.record_error(str(exc) or repr(exc))


async def _classify_batch(db_conn) -> int:
    # Over-fetch a larger LIFO candidate pool than one batch needs, so a
    # handful of stuck-and-backing-off items at the front can't blockade
    # every slot forever — the rest of the pool still gets attempted this
    # tick. (Without this, a model that fails on the newest few items would
    # otherwise stall the entire queue, since "newest unclassified N" would
    # be the same N every tick.)
    pool = await db.get_unclassified_items(
        db_conn, limit=settings.classifier_batch_size * _OVERFETCH_MULTIPLIER
    )
    now = time.monotonic()
    ready = [it for it in pool if _next_retry_at.get(it["id"], 0.0) <= now]
    batch = ready[: settings.classifier_batch_size]

    classified_count = 0

    # One /chat/completions call classifies the whole batch (see
    # backend.classify_batch) instead of N sequential calls — cuts batch
    # latency roughly N-fold, which matters because get_unclassified_items
    # serves LIFO: a slow per-item loop is exactly what lets a sustained
    # ingest burst starve older items indefinitely.
    verdicts = await backend.classify_batch(batch)

    for item, verdict in zip(batch, verdicts):
        if verdict is None:
            # Never substitute a fabricated/regex-derived verdict here — the
            # item stays genuinely unclassified and is retried for real,
            # just with backoff so it stops eating every batch slot.
            attempts = _failed_attempts.get(item["id"], 0) + 1
            _failed_attempts[item["id"]] = attempts
            delay = _backoff_seconds(attempts)
            _next_retry_at[item["id"]] = now + delay
            log.warning(
                "[classifier] item %s failed (attempt %d) — retrying in %ds",
                item["id"], attempts, delay,
            )
            continue

        _failed_attempts.pop(item["id"], None)
        _next_retry_at.pop(item["id"], None)

        effective_false_positive = _effective_false_positive(verdict)
        low_confidence = _is_low_confidence(verdict)

        # Write the verdict before alerting: once this row exists the item
        # drops out of both this batch's source query and the fallback
        # sweep, which is the sole idempotency guard against double-firing.
        # Store the effective (threshold-adjusted) false_positive — not the
        # raw verdict — since that's what the dashboard's show_filtered
        # logic and item_priority view key off of.
        await db.upsert_classification(
            db_conn,
            item_id=item["id"],
            priority=verdict.priority,
            false_positive=effective_false_positive,
            confidence=verdict.confidence,
            reasoning=verdict.reasoning,
            model=verdict.model,
        )
        classified_count += 1

        if verdict.priority == "critical" and not effective_false_positive:
            title, message = _gotify_payload(item, low_confidence=low_confidence)
            await push_gotify(title=title, message=message, priority=8)

    return classified_count


async def _run_fallback_sweep(db_conn) -> None:
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=settings.classifier_fallback_alert_minutes)
    ).isoformat()
    stale = await db.get_unclassified_critical_older_than(db_conn, cutoff_iso=cutoff)

    for item in stale:
        await db.upsert_classification(
            db_conn,
            item_id=item["id"],
            priority="critical",
            false_positive=False,
            confidence=None,
            reasoning="classifier unreachable; alerted via regex fallback after grace period",
            model="fallback-timeout",
        )
        title, message = _gotify_payload(item)
        await push_gotify(title=title, message=message, priority=8)
        log.warning(
            "[classifier] fallback-alerted item %s after %d min unclassified "
            "(backend unreachable?)",
            item["id"],
            settings.classifier_fallback_alert_minutes,
        )
