"""Copies hermes-agent's own measured token usage into our db.

hermes (the locally-installed CLI runner.py shells out to) tracks real,
measured per-session token counts in its own SQLite db at
settings.hermes_state_db_path (default ~/.hermes/state.db, `sessions` table:
input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
started_at, model, source). runner.py's `hermes -z` headless invocations
write `source='cli'` rows there as a side effect of hermes' own process —
verified live (2026-06-23): a 64,228-input/2,558-output token session showed
up under source='cli' with no extra flags needed.

runner.py's HermesResult never sees this data (the subprocess only returns
stdout/exit code), and there's no reliable way to correlate one specific
`hermes -z` call to one specific session row in-process (concurrent runs,
hermes' own retry/fallback chain, no session id echoed to stdout). So instead
of fragile per-call correlation, this module polls hermes' db on its own
schedule (settings.token_ingest_interval_seconds) and upserts every
'cli'-sourced session into our own token_usage table, keyed on hermes' own
session id — see db.upsert_hermes_token_usage. An in-progress session whose
counts grow between polls is simply corrected in place on the next poll.

This is the only place in the project that opens an external SQLite db (not
settings.db_path) — kept read-only and entirely separate from db.open_db's
shared connection. Must never break the app: hermes may not be installed, or
its state.db may not exist yet, or may be mid-write (a transient "database is
locked" read) — every failure mode here is logged and swallowed.
"""
import logging
from datetime import datetime, timezone

import aiosqlite

from ..db import max_ingested_hermes_started_at, upsert_hermes_token_usage
from ..settings import settings

log = logging.getLogger(__name__)

# Re-scan this far behind our own high-water mark on every poll, so a session
# that was still running (and so had a lower token count) at the last poll
# gets its growing totals corrected rather than frozen at their first-seen
# value. Generous relative to token_ingest_interval_seconds since hermes
# research/heal runs can take minutes (see hermes_timeout_seconds).
_OVERLAP_SECONDS = 1800

_warned_missing = False


def _epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


async def ingest_hermes_token_usage(conn: aiosqlite.Connection) -> int:
    """One poll: copy new/updated hermes-agent sessions into token_usage.
    Returns the number of rows upserted. Never raises — see module docstring."""
    global _warned_missing
    state_db = settings.hermes_state_db_path.expanduser()
    if not state_db.exists():
        if not _warned_missing:
            log.debug("[token_ingest] hermes state db not found at %s — skipping (hermes not installed?)", state_db)
            _warned_missing = True
        return 0
    _warned_missing = False

    watermark = await max_ingested_hermes_started_at(conn)
    since_epoch = 0.0
    if watermark:
        try:
            since_epoch = datetime.fromisoformat(watermark).timestamp() - _OVERLAP_SECONDS
        except ValueError:
            since_epoch = 0.0

    try:
        rows = await _read_hermes_sessions(state_db, since_epoch=since_epoch)
    except aiosqlite.Error as exc:
        # Most commonly "database is locked" mid-write by hermes itself, or a
        # schema we don't recognize — either way, try again next poll.
        log.warning("[token_ingest] failed to read hermes state db: %s", exc)
        return 0

    ingested = 0
    for row in rows:
        try:
            await upsert_hermes_token_usage(
                conn,
                session_id=row["id"],
                ts=_epoch_to_iso(row["started_at"]),
                model=row["model"],
                input_tokens=row["input_tokens"] or 0,
                output_tokens=row["output_tokens"] or 0,
                cache_read_tokens=row["cache_read_tokens"] or 0,
                cache_write_tokens=row["cache_write_tokens"] or 0,
                cost_usd=row["actual_cost_usd"] if row["actual_cost_usd"] else row["estimated_cost_usd"],
            )
            ingested += 1
        except Exception as exc:
            log.warning("[token_ingest] failed to upsert hermes session %s: %s", row["id"], exc)
    if ingested:
        log.debug("[token_ingest] ingested %d hermes-agent session(s)", ingested)
    return ingested


async def _read_hermes_sessions(state_db, *, since_epoch: float) -> list[aiosqlite.Row]:
    """Read-only query against hermes' own db — a short-lived connection
    opened and closed within this one poll, entirely separate from our
    shared db.open_db() connection. ?mode=ro guarantees we never write to a
    db we don't own."""
    uri = f"file:{state_db}?mode=ro"
    async with aiosqlite.connect(uri, uri=True, timeout=5) as conn:
        conn.row_factory = aiosqlite.Row
        return await conn.execute_fetchall(
            """
            SELECT id, started_at, model, input_tokens, output_tokens,
                   cache_read_tokens, cache_write_tokens, estimated_cost_usd, actual_cost_usd
            FROM sessions
            WHERE source = 'cli' AND started_at >= :since AND input_tokens > 0
            ORDER BY started_at
            """,
            {"since": since_epoch},
        )
