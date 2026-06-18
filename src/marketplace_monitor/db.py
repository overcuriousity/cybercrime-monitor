import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator

import aiosqlite

from .models import Item, Match
from .settings import settings


def _utcnow() -> datetime:
    """datetime.utcnow() is deprecated (naive, easy to silently mix up with
    local time) and produces a different isoformat() string than
    datetime.now(timezone.utc) (no "+00:00" suffix) — health.py already uses
    the tz-aware form, so this keeps every timestamp in the DB and API
    consistent with that. See api/static/app.js:fmtTime for the matching
    frontend-side parsing fix."""
    return datetime.now(timezone.utc)


log = logging.getLogger(__name__)

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   TEXT NOT NULL,
    source_name TEXT NOT NULL,
    title       TEXT NOT NULL,
    url         TEXT NOT NULL,
    snippet     TEXT NOT NULL DEFAULT '',
    published_at TEXT,
    dedupe_key  TEXT NOT NULL UNIQUE,
    seen_at     TEXT NOT NULL,
    source_tags TEXT NOT NULL DEFAULT '[]',
    extra       TEXT NOT NULL DEFAULT '{}',
    -- Cross-source clustering key (see models.Item.content_key) — '' means
    -- "don't cluster". Added via ALTER TABLE migration for pre-existing DBs;
    -- see _migrate() below, since CREATE TABLE IF NOT EXISTS won't add
    -- columns to an already-created table.
    content_key TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_items_seen_at     ON items(seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_source_id   ON items(source_id);
-- idx_items_content_key is created in _migrate() below, not here: on a
-- pre-existing DB this executescript runs BEFORE the ALTER TABLE that adds
-- the content_key column, and CREATE INDEX on a not-yet-existing column
-- fails outright (verified: sqlite3.OperationalError: no such column).

CREATE TABLE IF NOT EXISTS matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id         INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    keyword_pattern TEXT NOT NULL,
    priority        TEXT NOT NULL,
    tags            TEXT NOT NULL DEFAULT '[]',
    spans           TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_matches_item_id  ON matches(item_id);
CREATE INDEX IF NOT EXISTS idx_matches_priority ON matches(priority);

-- One verdict per item from the LLM classifier (see classifier/ package).
-- item_id is UNIQUE: reclassifying an item upserts this row rather than
-- accumulating history. false_positive is a soft-flag, never a delete —
-- flagged items stay queryable (see show_filtered below) for audit purposes.
CREATE TABLE IF NOT EXISTS classifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id         INTEGER NOT NULL UNIQUE REFERENCES items(id) ON DELETE CASCADE,
    priority        TEXT NOT NULL,
    false_positive  INTEGER NOT NULL DEFAULT 0,
    confidence      REAL,
    reasoning       TEXT,
    model           TEXT NOT NULL,
    classified_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_classifications_item_id ON classifications(item_id);
CREATE INDEX IF NOT EXISTS idx_classifications_classified_at ON classifications(classified_at);

-- Periodic snapshot of health.py's in-memory per-source registry (see
-- scheduler.py's "_health_persist" job and health.snapshot/restore) — purely
-- so the dashboard doesn't blank out on every process restart. One row per
-- source_id; "data" is the whole SourceHealth dataclass as JSON, so adding a
-- field there never requires a migration here.
CREATE TABLE IF NOT EXISTS source_health (
    source_id TEXT PRIMARY KEY,
    data      TEXT NOT NULL
);

-- Resolves one effective priority rank + false_positive flag per item:
-- the classifier's verdict if one exists, else the regex matcher's max
-- priority (mirrors the CASE/MAX logic every query used to repeat
-- independently). NOTE: CREATE VIEW IF NOT EXISTS is frozen at creation —
-- if this formula ever changes, existing DBs need a manual `DROP VIEW
-- item_priority` before restart, since IF NOT EXISTS won't redefine it.
CREATE VIEW IF NOT EXISTS item_priority AS
SELECT i.id AS item_id,
       CASE
         WHEN c.priority IS NOT NULL THEN
           CASE c.priority WHEN 'critical' THEN 3 WHEN 'warn' THEN 2 WHEN 'info' THEN 1 ELSE 0 END
         ELSE
           COALESCE(
             (SELECT MAX(CASE m.priority WHEN 'critical' THEN 3 WHEN 'warn' THEN 2 WHEN 'info' THEN 1 ELSE 0 END)
              FROM matches m WHERE m.item_id = i.id),
             0
           )
       END AS prio_rank,
       COALESCE(c.false_positive, 0) AS false_positive
FROM items i
LEFT JOIN classifications c ON c.item_id = i.id;
"""


async def open_db() -> aiosqlite.Connection:
    path = settings.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    conn.row_factory = aiosqlite.Row
    await conn.executescript(_SCHEMA)
    await _migrate(conn)
    await conn.commit()
    return conn


async def _migrate(conn: aiosqlite.Connection) -> None:
    """One-off ALTER TABLE steps for columns added after a DB already
    existed — CREATE TABLE IF NOT EXISTS in _SCHEMA only applies to brand-new
    DBs, so a column added there is invisible to a pre-existing items.db."""
    cols = {r["name"] for r in await conn.execute_fetchall("PRAGMA table_info(items)")}
    if "content_key" not in cols:
        await conn.execute("ALTER TABLE items ADD COLUMN content_key TEXT NOT NULL DEFAULT ''")
        log.info("Migrated items table: added content_key column")
    # Safe to (re)create unconditionally here — by this point the column
    # exists on both brand-new (via _SCHEMA's CREATE TABLE) and migrated DBs.
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_items_content_key ON items(content_key)")


async def insert_item(conn: aiosqlite.Connection, item: Item) -> int | None:
    """Insert item; returns new row id or None if duplicate. Deliberately
    does NOT commit — the caller (collectors/base.py:run) commits once after
    insert_matches also succeeds, so an item and the regex matches against it
    land atomically. Without this, a crash between the two separate commits
    could leave an item permanently with zero matches even though the regex
    rules did match it at ingest time."""
    try:
        async with conn.execute(
            """INSERT INTO items
               (source_id, source_name, title, url, snippet, published_at,
                dedupe_key, seen_at, source_tags, extra, content_key)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                item.source_id,
                item.source_name,
                item.title,
                item.url,
                item.snippet,
                item.published_at.isoformat() if item.published_at else None,
                item.dedupe_key,
                _utcnow().isoformat(),
                json.dumps(item.source_tags),
                json.dumps(item.extra),
                item.content_key,
            ),
        ) as cur:
            return cur.lastrowid
    except aiosqlite.IntegrityError:
        # Nothing was actually written, but sqlite opened an implicit
        # transaction for the attempted INSERT — roll it back explicitly so
        # the connection starts clean for the next item in the same tick
        # rather than carrying a dangling empty transaction forward.
        await conn.rollback()
        return None


async def insert_matches(conn: aiosqlite.Connection, matches: list[Match]) -> None:
    """Deliberately does NOT commit — see insert_item's docstring; the
    caller commits both inserts together in one transaction."""
    if not matches:
        return
    await conn.executemany(
        """INSERT INTO matches (item_id, keyword_pattern, priority, tags, spans)
           VALUES (?,?,?,?,?)""",
        [
            (m.item_id, m.keyword_pattern, m.priority, json.dumps(m.tags), json.dumps(m.spans))
            for m in matches
        ],
    )


_RANK_TO_PRIORITY_STR = {0: "", 1: "info", 2: "warn", 3: "critical"}
_PRIORITY_RANK = {"info": 1, "warn": 2, "critical": 3}


def _build_items_where(
    *,
    source_ids: list[str] | None,
    search: str | None,
    matched_only: bool,
    min_priority: str | None,
    show_filtered: bool,
) -> tuple[str, dict]:
    """Shared WHERE-clause + named-params builder for fetch_items and
    count_items. These two queries used to build their filters independently
    and drifted: count_items ignored source_id/search/priority/matched_only
    entirely, so the "total" badge the frontend shows could silently disagree
    with what fetch_items actually returned for any filtered request. One
    builder, used by both, makes that impossible to repeat.

    Named params throughout — can't mix named (:matched_only etc.) and
    positional (?) placeholders in one query, so every dynamic value goes
    through named params instead of f-string interpolation."""
    parts: list[str] = []
    params: dict = {}
    idx = 0
    if source_ids:
        placeholders = ", ".join(f":p{idx + i}" for i in range(len(source_ids)))
        parts.append(f"i.source_id IN ({placeholders})")
        for i, sid in enumerate(source_ids):
            params[f"p{idx + i}"] = sid
        idx += len(source_ids)
    if search:
        parts.append(f"(i.title LIKE :p{idx} OR i.snippet LIKE :p{idx+1})")
        params[f"p{idx}"] = f"%{search}%"
        params[f"p{idx+1}"] = f"%{search}%"
        idx += 2
    parts.append("(:matched_only = 0 OR ep.prio_rank > 0)")
    parts.append("(:min_rank = 0 OR ep.prio_rank >= :min_rank)")
    parts.append("(:show_filtered = 1 OR ep.false_positive = 0)")
    params.update(
        {
            "matched_only": 1 if matched_only else 0,
            "min_rank": _PRIORITY_RANK.get(min_priority or "", 0),
            "show_filtered": 1 if show_filtered else 0,
        }
    )
    return "WHERE " + " AND ".join(parts), params


async def fetch_items(
    conn: aiosqlite.Connection,
    *,
    limit: int = 200,
    offset: int = 0,
    source_id: str | list[str] | None = None,
    min_priority: str | None = None,
    search: str | None = None,
    matched_only: bool = False,
    show_filtered: bool = False,
) -> list[dict]:
    """Return items enriched with match + classifier data as JSON-serialisable
    dicts. Priority filtering/ordering reads the `item_priority` view (the
    classifier's verdict if present, else the regex matcher's max priority);
    false-positive items are excluded unless show_filtered=True.

    source_id accepts either a single id (back-compat) or a list — the
    dashboard's source checkboxes send a list so multi-source filtering
    happens server-side instead of the old client-side post-filter, which
    silently shrank pages and broke "load more" pagination (a 100-item server
    page minus client-dropped rows is not 100 items, but offset still
    advanced by 100)."""
    source_ids = [source_id] if isinstance(source_id, str) else (source_id or None)

    named_where, named_params = _build_items_where(
        source_ids=source_ids,
        search=search,
        matched_only=matched_only,
        min_priority=min_priority,
        show_filtered=show_filtered,
    )

    rows = await conn.execute_fetchall(
        f"""
        SELECT i.*, ep.prio_rank, ep.false_positive,
               c.priority AS classifier_priority, c.confidence AS classifier_confidence,
               c.reasoning AS classifier_reasoning, c.model AS classifier_model,
               c.classified_at AS classified_at,
               -- Cross-source clustering (see models.Item.content_key): how many
               -- DISTINCT sources reported something with this same content_key.
               -- '' content_key never clusters (e.g. blank-title items).
               CASE WHEN i.content_key = '' THEN 1 ELSE (
                 SELECT COUNT(DISTINCT i2.source_id) FROM items i2 WHERE i2.content_key = i.content_key
               ) END AS cluster_size
        FROM items i
        LEFT JOIN item_priority ep ON ep.item_id = i.id
        LEFT JOIN classifications c ON c.item_id = i.id
        {named_where}
        ORDER BY i.seen_at DESC
        LIMIT :limit OFFSET :offset
        """,
        {**named_params, "limit": limit, "offset": offset},
    )

    if not rows:
        return []

    item_ids = [r["id"] for r in rows]
    placeholders = ",".join("?" * len(item_ids))
    match_rows = await conn.execute_fetchall(
        f"SELECT * FROM matches WHERE item_id IN ({placeholders}) ORDER BY item_id",
        item_ids,
    )

    matches_by_item: dict[int, list] = {}
    for mr in match_rows:
        matches_by_item.setdefault(mr["item_id"], []).append(mr)

    result = []
    for r in rows:
        item_matches = matches_by_item.get(r["id"], [])
        all_tags: set[str] = set()
        serialised_matches = []
        for m in item_matches:
            all_tags.update(json.loads(m["tags"]))
            serialised_matches.append(
                {
                    "pattern": m["keyword_pattern"],
                    "priority": m["priority"],
                    "tags": json.loads(m["tags"]),
                    "spans": json.loads(m["spans"]),
                }
            )
        result.append(
            {
                "id": r["id"],
                "source_id": r["source_id"],
                "source_name": r["source_name"],
                "title": r["title"],
                "url": r["url"],
                "snippet": r["snippet"],
                "published_at": r["published_at"],
                "seen_at": r["seen_at"],
                "source_tags": json.loads(r["source_tags"]),
                # effective priority: classifier verdict if present, else regex max
                "max_priority": _RANK_TO_PRIORITY_STR.get(r["prio_rank"] or 0, ""),
                "all_tags": sorted(all_tags),
                "matches": serialised_matches,
                "is_false_positive": bool(r["false_positive"]),
                "classified": r["classified_at"] is not None,
                "classifier_confidence": r["classifier_confidence"],
                "classifier_reasoning": r["classifier_reasoning"],
                # >1 means other sources reported the same content_key — a
                # display/triage aid only, never a filter (see fetch_items
                # docstring and stats_top_actors for the same don't-hide
                # principle applied elsewhere).
                "cluster_size": r["cluster_size"],
            }
        )
    return result


async def count_items(
    conn: aiosqlite.Connection,
    *,
    source_id: str | list[str] | None = None,
    min_priority: str | None = None,
    search: str | None = None,
    matched_only: bool = False,
    show_filtered: bool = False,
) -> int:
    """Must accept the exact same filters as fetch_items — see
    _build_items_where's docstring for why these two queries share one
    builder instead of each defining its own WHERE clause."""
    source_ids = [source_id] if isinstance(source_id, str) else (source_id or None)
    named_where, named_params = _build_items_where(
        source_ids=source_ids,
        search=search,
        matched_only=matched_only,
        min_priority=min_priority,
        show_filtered=show_filtered,
    )
    row = await conn.execute_fetchall(
        f"""
        SELECT COUNT(*) AS n
        FROM items i
        LEFT JOIN item_priority ep ON ep.item_id = i.id
        {named_where}
        """,
        named_params,
    )
    return row[0]["n"] if row else 0


# ── Public dashboard aggregations ──────────────────────────────────────────────
# Read-only, parameterized, bounded-range queries. None of these expose raw
# matched text from "target"-tagged rules (the investigation indicators) —
# only counts, so they're safe to serve without the admin token.

_RANK_TO_PRIORITY = {0: "none", 1: "info", 2: "warn", 3: "critical"}


async def stats_timeseries(
    conn: aiosqlite.Connection, *, bucket: str = "hour", since_hours: int = 48
) -> list[dict]:
    """Item counts per time bucket, stacked by effective priority (classifier
    verdict if present, else regex max). Excludes false positives."""
    since_hours = max(1, min(since_hours, 24 * 30))
    since = (_utcnow() - timedelta(hours=since_hours)).isoformat()
    rows = await conn.execute_fetchall(
        """
        SELECT i.seen_at, ep.prio_rank AS prio_rank
        FROM items i
        LEFT JOIN item_priority ep ON ep.item_id = i.id
        WHERE i.seen_at >= :since AND ep.false_positive = 0
        """,
        {"since": since},
    )
    buckets: dict[str, dict[str, int]] = {}
    for r in rows:
        seen_at = r["seen_at"] or ""
        key = seen_at[:10] if bucket == "day" else (seen_at[:13] + ":00:00")
        prio = _RANK_TO_PRIORITY.get(r["prio_rank"] or 0, "none")
        b = buckets.setdefault(key, {"none": 0, "info": 0, "warn": 0, "critical": 0})
        b[prio] += 1
    return [{"bucket": k, **v} for k, v in sorted(buckets.items())]


async def stats_by_source(conn: aiosqlite.Connection) -> list[dict]:
    rows = await conn.execute_fetchall(
        """
        SELECT source_id, source_name, COUNT(*) AS total, MAX(seen_at) AS last_seen
        FROM items
        GROUP BY source_id
        ORDER BY total DESC
        """
    )
    return [dict(r) for r in rows]


async def stats_by_priority(conn: aiosqlite.Connection, *, since_hours: int | None = None) -> dict:
    """Effective-priority breakdown (classifier verdict if present, else
    regex max). Excludes false positives."""
    where = "WHERE ep.false_positive = 0"
    params: dict = {}
    if since_hours is not None:
        since_hours = max(1, min(since_hours, 24 * 30))
        where += " AND i.seen_at >= :since"
        params["since"] = (_utcnow() - timedelta(hours=since_hours)).isoformat()
    rows = await conn.execute_fetchall(
        f"""
        SELECT ep.prio_rank AS prio_rank
        FROM items i
        LEFT JOIN item_priority ep ON ep.item_id = i.id
        {where}
        """,
        params,
    )
    counts = {"none": 0, "info": 0, "warn": 0, "critical": 0}
    for r in rows:
        counts[_RANK_TO_PRIORITY.get(r["prio_rank"] or 0, "none")] += 1
    return counts


async def stats_top_keywords(conn: aiosqlite.Connection, *, limit: int = 10) -> list[dict]:
    limit = max(1, min(limit, 50))
    rows = await conn.execute_fetchall(
        """
        SELECT m.keyword_pattern, m.priority, COUNT(*) AS n
        FROM matches m
        JOIN item_priority ep ON ep.item_id = m.item_id
        WHERE m.tags NOT LIKE '%"target"%' AND ep.false_positive = 0
        GROUP BY m.keyword_pattern, m.priority
        ORDER BY n DESC
        LIMIT :limit
        """,
        {"limit": limit},
    )
    return [dict(r) for r in rows]


# Ransomware-tracking accounts/sites name the threat actor in a handful of
# recurring structural slots — a labeled field, a hashtag, or immediately
# adjacent to the word "ransomware" — regardless of which group it is. These
# patterns extract whatever name sits in that slot instead of matching
# against a fixed, hand-maintained list of group names, so a brand-new group
# shows up the same way an established one does. Ordered most-specific-first;
# the first pattern that matches an item wins.
# Permissive — used right after an explicit, unambiguous label (brackets,
# "Threat actor:", a hashtag) where the surrounding context already pins
# down exactly where the name starts and ends, so multi-word names like
# "Space Bears" or "INC RANSOM" are safe to capture in full.
_ACTOR_NAME = r"([A-Z][A-Za-z0-9](?:[A-Za-z0-9 .&-]{0,38}[A-Za-z0-9])?)"
# A single lowercase-led compact token (e.g. "payload", "spacebears") — for
# labels whose value is consistently a short slug, with no delimiter between
# this value and a following label when the source's HTML-to-text stripping
# drops whitespace (observed: "Group name: payloadPost title: SPORTON...").
_ACTOR_SLUG = r"([A-Za-z][a-z0-9]*)"
# Strict — used in free prose with no explicit label, where the name is
# merely "the capitalized word(s) right before 'ransomware'". Requires every
# word to be capitalized (proper-noun form) so it can't swallow a whole
# preceding clause like "Breached by Akira" (lowercase "by" stops the chain,
# leaving "Akira" as the actual match).
_ACTOR_NAME_STRICT = r"([A-Z][A-Za-z0-9]*(?:\s[A-Z][A-Za-z0-9]*){0,2})"
_ACTOR_PATTERNS = [
    re.compile(r"\[" + _ACTOR_NAME + r"\]\s*-\s*Ransomware Victim", re.IGNORECASE),
    re.compile(r"Threat\s*[Aa]ctor:\s*" + _ACTOR_NAME),
    # Case-insensitivity scoped to the label only — applying it to the whole
    # pattern would make the slug's [a-z0-9] class match uppercase too and
    # erase the camelCase boundary the slug relies on to stop early.
    re.compile(r"(?i:Group\s*name:)\s*" + _ACTOR_SLUG),
    re.compile(r"New post from #" + _ACTOR_NAME + r"\s*:"),
    re.compile(r"fallen victim to (?:the )?" + _ACTOR_NAME_STRICT + r"\s+[Rr]ansomware"),
    re.compile(_ACTOR_NAME_STRICT + r"\s+[Rr]ansomware(?:\s+group)?\s+(?:has added|claims|group has)"),
    re.compile(_ACTOR_NAME_STRICT + r"\s+[Rr]ansomware\b"),
]
# Generic words that can land in the same grammatical slot but aren't actor
# names — filtered after extraction, not used to define what *is* a name.
_ACTOR_STOPWORDS = {
    "the", "new", "this", "update", "alert", "cyber", "data", "double",
    "group", "ransomware", "victim", "breaking", "report", "reported",
}


def _extract_actor_name(text: str) -> str | None:
    for pattern in _ACTOR_PATTERNS:
        m = pattern.search(text)
        if m:
            name = m.group(1).strip()
            if name and name.lower() not in _ACTOR_STOPWORDS:
                return name
    return None


async def stats_top_actors(conn: aiosqlite.Connection, *, limit: int = 10) -> list[dict]:
    """Most-mentioned ransomware threat actors. Prefers the structured
    extra.actor field (set by collectors/ransomware_live.py from
    ransomware.live's tracked group name — no free-text guessing involved)
    when present; falls back to the heuristic _extract_actor_name regex for
    every other source, so sources without structured data still contribute."""
    limit = max(1, min(limit, 50))
    rows = await conn.execute_fetchall(
        """
        SELECT i.title, i.snippet, i.extra
        FROM items i
        LEFT JOIN item_priority ep ON ep.item_id = i.id
        WHERE (i.title LIKE '%ansom%' OR i.snippet LIKE '%ansom%' OR i.extra LIKE '%"actor"%')
          AND ep.false_positive = 0
        """
    )
    # Group by a loosely-normalized key (lowercase, punctuation/whitespace
    # stripped) so "Space Bears" / "spacebears" / "SPACE BEARS" merge, but
    # display the most common surface form seen.
    counts: dict[str, int] = {}
    display: dict[str, dict[str, int]] = {}
    for r in rows:
        name = None
        try:
            extra = json.loads(r["extra"] or "{}")
        except (json.JSONDecodeError, TypeError):
            extra = {}
        if isinstance(extra, dict) and extra.get("actor"):
            name = str(extra["actor"])
        if not name:
            name = _extract_actor_name(r["title"] + "\n" + r["snippet"])
        if not name:
            continue
        key = re.sub(r"[^a-z0-9]", "", name.lower())
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
        variants = display.setdefault(key, {})
        variants[name] = variants.get(name, 0) + 1
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [
        {"actor": max(display[k].items(), key=lambda kv: kv[1])[0], "count": v}
        for k, v in top
    ]


# ── Classifier support ──────────────────────────────────────────────────────
# Used by the classifier/ background job and the /api/classifier/* routes.

async def get_unclassified_items(conn: aiosqlite.Connection, *, limit: int) -> list[dict]:
    """Newest-first (LIFO) items with no classifications row yet, ordered by
    the indexed PK (not seen_at — monotonic, no ties, cheap). This is a live
    feed: under sustained backlog, freshness matters more than chronological
    completeness, so the classifier always works the front of the queue
    instead of grinding through old history while new items pile up
    unclassified. The fallback-alert sweep (get_unclassified_critical_older_
    than) is what guarantees old regex-critical items still can't be
    silently starved forever — everything else degrades gracefully to its
    regex-derived priority if it's never reached."""
    rows = await conn.execute_fetchall(
        """
        SELECT i.id, i.title, i.snippet, i.source_name, i.url
        FROM items i
        WHERE NOT EXISTS (SELECT 1 FROM classifications c WHERE c.item_id = i.id)
        ORDER BY i.id DESC
        LIMIT :limit
        """,
        {"limit": limit},
    )
    items = [dict(r) for r in rows]
    if not items:
        return items

    # Attach the regex-derived priority/tags as a prompt hint (not
    # authoritative — see classifier/backend.py's system prompt).
    priority_rank = {"info": 1, "warn": 2, "critical": 3}
    item_ids = [it["id"] for it in items]
    placeholders = ",".join("?" * len(item_ids))
    match_rows = await conn.execute_fetchall(
        f"SELECT item_id, priority, tags FROM matches WHERE item_id IN ({placeholders})",
        item_ids,
    )
    by_item: dict[int, list] = {}
    for mr in match_rows:
        by_item.setdefault(mr["item_id"], []).append(mr)
    for it in items:
        item_matches = by_item.get(it["id"], [])
        max_prio = ""
        tags: set[str] = set()
        for m in item_matches:
            if priority_rank.get(m["priority"], 0) > priority_rank.get(max_prio, 0):
                max_prio = m["priority"]
            tags.update(json.loads(m["tags"]))
        it["regex_priority"] = max_prio
        it["regex_tags"] = sorted(tags)
    return items


async def get_unclassified_critical_older_than(
    conn: aiosqlite.Connection, *, cutoff_iso: str
) -> list[dict]:
    """Items with a regex 'critical' match, still unclassified, ingested
    before cutoff_iso — the fallback-alert sweep's candidate set."""
    rows = await conn.execute_fetchall(
        """
        SELECT i.id, i.title, i.snippet, i.source_name, i.url
        FROM items i
        JOIN matches m ON m.item_id = i.id
        WHERE m.priority = 'critical'
          AND i.seen_at <= :cutoff
          AND NOT EXISTS (SELECT 1 FROM classifications c WHERE c.item_id = i.id)
        GROUP BY i.id
        """,
        {"cutoff": cutoff_iso},
    )
    return [dict(r) for r in rows]


async def upsert_classification(
    conn: aiosqlite.Connection,
    *,
    item_id: int,
    priority: str,
    false_positive: bool,
    confidence: float | None,
    reasoning: str | None,
    model: str,
) -> None:
    """Insert or replace the verdict for an item. Writing this row is the
    single idempotency mechanism for both the classify batch and the
    fallback sweep — once it exists, the item drops out of both candidate
    queries above, so callers should write it before/atomically-with firing
    any alert to avoid double-firing on a retry."""
    await conn.execute(
        """
        INSERT INTO classifications (item_id, priority, false_positive, confidence, reasoning, model, classified_at)
        VALUES (:item_id, :priority, :false_positive, :confidence, :reasoning, :model, :classified_at)
        ON CONFLICT(item_id) DO UPDATE SET
            priority=excluded.priority, false_positive=excluded.false_positive,
            confidence=excluded.confidence, reasoning=excluded.reasoning,
            model=excluded.model, classified_at=excluded.classified_at
        """,
        {
            "item_id": item_id,
            "priority": priority,
            "false_positive": 1 if false_positive else 0,
            "confidence": confidence,
            "reasoning": reasoning,
            "model": model,
            "classified_at": _utcnow().isoformat(),
        },
    )
    await conn.commit()


async def count_unclassified(conn: aiosqlite.Connection) -> int:
    """Backlog depth — surfaced via classifier health/dashboard."""
    row = await conn.execute_fetchall(
        """
        SELECT COUNT(*) AS n FROM items i
        WHERE NOT EXISTS (SELECT 1 FROM classifications c WHERE c.item_id = i.id)
        """
    )
    return row[0]["n"] if row else 0


async def get_recent_classifications(conn: aiosqlite.Connection, *, since_iso: str) -> list[dict]:
    """Items classified after since_iso — powers the frontend's incremental
    poll (GET /api/classifier/recent) so live cards can be patched in place
    without a full feed re-render."""
    rows = await conn.execute_fetchall(
        """
        SELECT c.item_id AS id, c.priority AS classifier_priority,
               c.false_positive AS is_false_positive, c.confidence AS classifier_confidence,
               c.reasoning AS classifier_reasoning, c.classified_at
        FROM classifications c
        WHERE c.classified_at > :since
        ORDER BY c.classified_at ASC
        """,
        {"since": since_iso},
    )
    return [
        {
            "id": r["id"],
            "max_priority": r["classifier_priority"],
            "is_false_positive": bool(r["is_false_positive"]),
            "classifier_confidence": r["classifier_confidence"],
            "classifier_reasoning": r["classifier_reasoning"],
            "classified_at": r["classified_at"],
        }
        for r in rows
    ]


# ── Retention ─────────────────────────────────────────────────────────────────

async def prune_old_items(conn: aiosqlite.Connection, *, retention_days: int) -> int:
    """Delete items older than retention_days, EXCEPT:
      - effective-critical items (classifier verdict if present, else regex
        max — same precedence as item_priority everywhere else), and
      - anything matched by a "target"-tagged keyword rule (the investigation
        indicators in config/keywords.yaml's TARGET section).
    matches/classifications rows cascade via ON DELETE CASCADE (see _SCHEMA's
    foreign_keys=ON pragma). Returns the number of rows deleted. Runs a WAL
    checkpoint afterward (not VACUUM — VACUUM rewrites the whole file and can
    block I/O for a long time on a live DB; a checkpoint reclaims WAL space
    without that cost, which is the right tradeoff for an unattended job that
    runs daily on the running service rather than during planned maintenance)."""
    cutoff = (_utcnow() - timedelta(days=retention_days)).isoformat()
    cur = await conn.execute(
        """
        DELETE FROM items
        WHERE seen_at < :cutoff
          AND NOT EXISTS (
            SELECT 1 FROM item_priority ep WHERE ep.item_id = items.id AND ep.prio_rank = 3
          )
          AND NOT EXISTS (
            SELECT 1 FROM matches m WHERE m.item_id = items.id AND m.tags LIKE '%"target"%'
          )
        """,
        {"cutoff": cutoff},
    )
    deleted = cur.rowcount or 0
    await conn.commit()
    if deleted:
        await conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        log.info("Retention: pruned %d item(s) older than %d days", deleted, retention_days)
    return deleted


# ── Source health persistence ────────────────────────────────────────────────
# See health.py's module docstring — the live registry stays in-memory/sync;
# these two functions are just its periodic save/restore boundary.

async def save_health_snapshot(conn: aiosqlite.Connection, snapshot: dict[str, dict]) -> None:
    if not snapshot:
        return
    await conn.executemany(
        """INSERT INTO source_health (source_id, data) VALUES (:source_id, :data)
           ON CONFLICT(source_id) DO UPDATE SET data = excluded.data""",
        [{"source_id": sid, "data": json.dumps(data)} for sid, data in snapshot.items()],
    )
    await conn.commit()


async def load_health_snapshot(conn: aiosqlite.Connection) -> dict[str, dict]:
    rows = await conn.execute_fetchall("SELECT source_id, data FROM source_health")
    out: dict[str, dict] = {}
    for r in rows:
        try:
            out[r["source_id"]] = json.loads(r["data"])
        except (json.JSONDecodeError, TypeError):
            continue
    return out
