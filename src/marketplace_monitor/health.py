"""In-memory per-source health tracking — last run/success/error, item counts.

Sources fail silently otherwise: a dead Nitter instance or a 422'd Mastodon
tag just logs a WARNING forever with no surface in the API or dashboard.

The registry itself is still process-local/synchronous for hot-path simplicity
(every collector tick calls record_* without an await) — but a snapshot is
periodically persisted to the source_health DB table (see scheduler.py's
"_health_persist" job and db.py's save/load_health_snapshot) and restored at
startup (api/app.py's lifespan), so the dashboard doesn't blank out on every
restart. snapshot()/restore() are the (de)serialization boundary for that;
nothing else needs to know persistence exists.
"""
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

log = logging.getLogger(__name__)


@dataclass
class SourceHealth:
    source_id: str
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_items_fetched: int = 0
    total_items_fetched: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0
    # A 200/success response that parses zero items is NOT recorded via
    # record_error — it's not a fetch failure. But a scraper whose CSS
    # selectors drifted from the live markup looks identical to "source had
    # nothing new" unless tracked separately: repeated empties are the signal
    # that something broke silently (see record_empty).
    last_empty_at: str | None = None
    consecutive_empty: int = 0


_health: dict[str, SourceHealth] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_run_start(source_id: str) -> None:
    h = _health.setdefault(source_id, SourceHealth(source_id=source_id))
    h.last_run_at = _now_iso()


def record_success(source_id: str, items_fetched: int) -> None:
    h = _health.setdefault(source_id, SourceHealth(source_id=source_id))
    h.last_success_at = _now_iso()
    h.last_items_fetched = items_fetched
    h.total_items_fetched += items_fetched
    h.consecutive_errors = 0
    if items_fetched == 0:
        h.last_empty_at = h.last_success_at
        h.consecutive_empty += 1
    else:
        h.consecutive_empty = 0


def record_error(source_id: str, error: str) -> None:
    h = _health.setdefault(source_id, SourceHealth(source_id=source_id))
    h.last_error = error[:300]
    h.last_error_at = _now_iso()
    h.consecutive_errors += 1


def get(source_id: str) -> SourceHealth | None:
    return _health.get(source_id)


def all_health() -> dict[str, SourceHealth]:
    return dict(_health)


def snapshot() -> dict[str, dict]:
    """Plain-dict form of the whole registry, for db.save_health_snapshot."""
    return {sid: asdict(h) for sid, h in _health.items()}


def restore(data: dict[str, dict]) -> None:
    """Load a previously-persisted snapshot (db.load_health_snapshot) into the
    in-memory registry — called once at startup, before the scheduler starts
    ticking, so the very first /api/sources response after a restart already
    reflects pre-restart health instead of a blank "unknown" dashboard.
    Per-source: a row that doesn't match the current SourceHealth shape
    (e.g. an older snapshot missing a field added since) is skipped rather
    than crashing startup — that source just starts fresh, same as before
    persistence existed."""
    for source_id, fields in data.items():
        try:
            _health[source_id] = SourceHealth(**fields)
        except TypeError as exc:
            log.warning("Skipping stale health snapshot for %s: %s", source_id, exc)
