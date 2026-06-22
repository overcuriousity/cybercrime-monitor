import json
import logging
import random
import re
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import AsyncIterator

import aiosqlite

from . import significance as sig
from .country import normalize_country
from .models import Item
from .settings import settings


_NON_ALNUM = re.compile(r"[^a-z0-9]+")
# Loose legal-form suffixes stripped for fuzzy victim-name matching.
# Word-boundary aware so "Sage" isn't mangled.
_COMMON_SUFFIXES = re.compile(r"\b(ag|gmbh|inc|llc|ltd|corp|plc|sa|srl|llp|kg|ohg|ug|se)\b")


def _normalize(value: str | None) -> str:
    if not value:
        return ""
    return _NON_ALNUM.sub("", value.lower())


def _core_name(value: str | None) -> str:
    """Victim/actor name with bracketed qualifiers and common legal forms
    removed, used for fuzzy similarity matching."""
    if not value:
        return ""
    value = re.sub(r"\s*\([^)]*\)", "", value)
    value = _COMMON_SUFFIXES.sub("", value.lower())
    return _NON_ALNUM.sub("", value)


def _victim_similar(a: str | None, b: str | None, min_ratio: float = 0.85) -> bool:
    """Conservative fuzzy victim matcher. Returns True for exact normalized
    equality, one string containing the other's core name, or a high-enough
    SequenceMatcher ratio on the core names."""
    if not a or not b:
        return False
    na, nb = _normalize(a), _normalize(b)
    if na == nb:
        return True
    ca, cb = _core_name(a), _core_name(b)
    if not ca or not cb:
        return False
    if ca == cb:
        return True
    if ca in cb or cb in ca:
        return True
    return SequenceMatcher(None, ca, cb).ratio() >= min_ratio


def _utcnow() -> datetime:
    """datetime.utcnow() is deprecated (naive, easy to silently mix up with
    local time) and produces a different isoformat() string than
    datetime.now(timezone.utc) (no "+00:00" suffix) — health.py already uses
    the tz-aware form, so this keeps every timestamp in the DB and API
    consistent with that. See api/static/app.js:fmtTime for the matching
    frontend-side parsing fix."""
    return datetime.now(timezone.utc)


def _normalize_published_at(dt: datetime | None) -> str | None:
    """Collectors hand back published_at in whatever timezone the source
    used (e.g. RSS feeds commonly carry an explicit "-04:00" offset). Stored
    naively, that breaks every later string comparison against seen_at/
    other items' published_at (case first_seen/last_seen MIN/MAX, the
    since/until date filters) — lexicographic ordering of ISO strings is
    only chronological when every string shares the same offset. Normalize
    to UTC at the single point of insertion so every stored timestamp is
    "+00:00" consistently, same as seen_at via _utcnow(). A naive datetime
    (no tzinfo — rare, but some date formats omit an offset) is assumed
    already UTC rather than rejected, since "unknown offset" is a worse
    failure mode than "off by a few hours in an edge case.\""""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


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

-- One structured-extraction record per item from the LLM extraction layer
-- (see llm/ package) — supersedes the old triage-only "classifications"
-- table with crime_type/victim/actor/CVE/IOC fields the case layer needs.
-- item_id is UNIQUE: re-extracting an item upserts this row rather than
-- accumulating history. false_positive is a soft-flag, never a delete —
-- flagged items stay queryable (see show_filtered below) for audit purposes.
CREATE TABLE IF NOT EXISTS extractions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id         INTEGER NOT NULL UNIQUE REFERENCES items(id) ON DELETE CASCADE,
    crime_type      TEXT NOT NULL DEFAULT 'other',
    victim          TEXT,
    victim_sector   TEXT,
    victim_country  TEXT,
    actor           TEXT,
    cve_ids         TEXT NOT NULL DEFAULT '[]',
    iocs            TEXT NOT NULL DEFAULT '[]',
    significance    TEXT NOT NULL,
    false_positive  INTEGER NOT NULL DEFAULT 0,
    confidence      REAL,
    reasoning       TEXT,
    model           TEXT NOT NULL,
    extracted_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_extractions_item_id ON extractions(item_id);
CREATE INDEX IF NOT EXISTS idx_extractions_extracted_at ON extractions(extracted_at);

-- The deduplicated incident — one or more `items` (raw observations) that
-- pipeline/correlate.py has determined describe the same underlying event
-- are linked here via case_items. See db.py's case query helpers and
-- pipeline/correlate.py for how case_key/merging works.
CREATE TABLE IF NOT EXISTS cases (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_key                TEXT NOT NULL UNIQUE,
    title                   TEXT NOT NULL,
    summary                 TEXT NOT NULL DEFAULT '',
    crime_type              TEXT NOT NULL DEFAULT 'other',
    attribution             TEXT,
    attribution_confidence  REAL,
    damaged_party           TEXT,
    damaged_party_sector    TEXT,
    damaged_party_country   TEXT,
    significance            TEXT NOT NULL DEFAULT 'info',
    significance_score      REAL NOT NULL DEFAULT 0,
    status                  TEXT NOT NULL DEFAULT 'new',
    cve_ids                 TEXT NOT NULL DEFAULT '[]',
    in_kev                  INTEGER NOT NULL DEFAULT 0,
    first_seen              TEXT NOT NULL,
    last_seen               TEXT NOT NULL,
    source_count            INTEGER NOT NULL DEFAULT 0,
    extra                   TEXT NOT NULL DEFAULT '{}',
    -- IoCs aggregated across all linked items + research findings (union,
    -- same precedence as cve_ids). Added via ALTER TABLE migration for
    -- pre-existing DBs — see _migrate() below.
    iocs                    TEXT NOT NULL DEFAULT '[]',
    -- Set by POST /api/cases/{id}/research to force a deep-research pass on
    -- this case regardless of significance/cooldown gating (see
    -- get_cases_needing_research). NULL = no forced request pending.
    -- Added via ALTER TABLE migration for pre-existing DBs.
    research_requested_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_cases_last_seen ON cases(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_cases_significance ON cases(significance);
CREATE INDEX IF NOT EXISTS idx_cases_in_kev ON cases(in_kev);

-- M:N link between raw items and the case(s) they were merged into — the
-- corroboration record. A single item normally belongs to exactly one case,
-- but the table is M:N so a future re-correlation pass can re-link without
-- a schema change.
CREATE TABLE IF NOT EXISTS case_items (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, item_id)
);

CREATE INDEX IF NOT EXISTS idx_case_items_item_id ON case_items(item_id);

-- Local cache of CISA's Known Exploited Vulnerabilities catalog (see
-- enrich/kev.py, refreshed on kev_refresh_interval_seconds). Looked up by
-- CVE id to flag cases.in_kev and surface exploitation details.
CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id            TEXT PRIMARY KEY,
    vendor            TEXT,
    product           TEXT,
    vuln_name         TEXT,
    date_added        TEXT,
    due_date          TEXT,
    known_ransomware  TEXT,
    notes             TEXT
);

-- Log of autonomous hermes-agent research runs dispatched against cases
-- (see research/agent.py). One row per run, not per case — a case can be
-- researched more than once as new information accumulates.
CREATE TABLE IF NOT EXISTS research_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'pending',
    findings    TEXT NOT NULL DEFAULT '{}',
    sources     TEXT NOT NULL DEFAULT '[]',
    error       TEXT,
    model       TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_research_runs_case_id ON research_runs(case_id);

-- Self-healing proposals for broken/disabled collectors (see research/heal.py
-- — hermes-agent investigates a failing source and proposes an updated
-- sources.yaml entry). NOT human-gated: "validated" proposals are applied to
-- sources.yaml automatically (see should_apply_heal/should_prune in
-- sources/value.py, and source_autoapply_enabled in settings.py to disable
-- autoapply entirely). The loop runs fully unattended; this table plus
-- ai_activity (below) exist for after-the-fact transparency, not approval —
-- every applied change is backed up by sources/writer.py (.bak-<ts>) and
-- reversible by restoring that file, but nothing here blocks the write. One
-- row per proposal attempt, not per source, so the history of past attempts
-- is kept.
CREATE TABLE IF NOT EXISTS source_heal_proposals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id     TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending', -- pending | validated | probe_failed | rejected
    proposal      TEXT NOT NULL DEFAULT '{}',
    notes         TEXT,
    error         TEXT,
    created_at    TEXT NOT NULL,
    validated_at  TEXT,
    -- ── Autonomous apply audit trail (sources/writer.py + research/heal.py) ──
    -- action: heal | prune | discover. applied=1 means writer.py actually
    -- touched sources.yaml for this proposal (and a .bak-<ts> exists to
    -- revert it). before/after are JSON snapshots of the affected source
    -- entry's mutated fields, for transparency without diffing the file —
    -- also surfaced live via ai_activity/GET /api/activity.
    -- All columns added via ALTER TABLE migration for pre-existing DBs.
    action        TEXT,
    applied       INTEGER NOT NULL DEFAULT 0,
    before_value  TEXT,
    after_value   TEXT
);

CREATE INDEX IF NOT EXISTS idx_heal_proposals_source_id ON source_heal_proposals(source_id);

-- One row per analyst verdict on a case or item — feeds sources/value.py's
-- investigation-value scoring and is summarized into heal/discover prompts
-- (research/heal.py, research/discover.py) so Hermes knows *why* a source
-- is being reconsidered. case_id/item_id are both nullable but exactly one
-- should be set; enforced in db.add_feedback, not at the schema level (kept
-- simple — this is a single-analyst tool, not a multi-tenant write path).
CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    item_id     INTEGER REFERENCES items(id) ON DELETE CASCADE,
    verdict     TEXT NOT NULL, -- useful | not_useful | noise | wrong_attribution
    note        TEXT,
    origin      TEXT NOT NULL DEFAULT 'human', -- human | agent (research/evaluator.py)
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_case_id ON feedback(case_id);
CREATE INDEX IF NOT EXISTS idx_feedback_item_id ON feedback(item_id);

-- Cached investigation-value snapshot per source (sources/value.py) — a
-- score + classification computed from yield quality, case contribution,
-- health, feedback and recency. Read by the dashboard and by the autonomous
-- source loop's should_apply() guardrail instead of recomputing on every
-- request. One row per source_id, overwritten on each refresh.
CREATE TABLE IF NOT EXISTS source_value (
    source_id       TEXT PRIMARY KEY,
    score           REAL NOT NULL,
    classification  TEXT NOT NULL, -- valuable | marginal | dead
    components      TEXT NOT NULL DEFAULT '{}',
    computed_at     TEXT NOT NULL
);

-- Algorithmic (non-LLM) case-to-case relationships — shared victim/actor/
-- CVE/IoC overlap within a temporal window (pipeline/cross_correlate.py).
-- Symmetric: case_a < case_b by convention so a pair is stored once.
CREATE TABLE IF NOT EXISTS case_links (
    case_a       INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    case_b       INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    score        REAL NOT NULL,
    reasons      TEXT NOT NULL DEFAULT '[]',
    computed_at  TEXT NOT NULL,
    PRIMARY KEY (case_a, case_b)
);

CREATE INDEX IF NOT EXISTS idx_case_links_b ON case_links(case_b);

-- Periodic snapshot of health.py's in-memory per-source registry (see
-- scheduler.py's "_health_persist" job and health.snapshot/restore) — purely
-- so the dashboard doesn't blank out on every process restart. One row per
-- source_id; "data" is the whole SourceHealth dataclass as JSON, so adding a
-- field there never requires a migration here.
CREATE TABLE IF NOT EXISTS source_health (
    source_id TEXT PRIMARY KEY,
    data      TEXT NOT NULL
);

-- Unified, append-only log of every autonomous AI/agentic action across the
-- whole system — discover/heal/prune (research/discover.py, research/
-- heal.py), research (research/agent.py), the LLM classifier (llm/job.py),
-- and the deterministic+LLM correlators (pipeline/correlate.py,
-- pipeline/cross_correlate.py). This is the public surface for "what did
-- the AI do" (see GET /api/activity, no admin token required) — the
-- detailed per-subsystem tables (source_heal_proposals, research_runs,
-- extractions) remain the system of record; this table is a denormalized,
-- human-readable index over all of them plus the two correlators, which
-- otherwise leave no audit trail at all. Every subsystem here acts fully
-- autonomously (no approval gate) — this table exists for transparency,
-- not control.
CREATE TABLE IF NOT EXISTS ai_activity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    subsystem   TEXT NOT NULL, -- discover | heal | prune | research | classifier | correlator | cross_correlator
    action      TEXT NOT NULL, -- e.g. source_added, source_removed, case_created, cases_linked, item_classified
    summary     TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '{}', -- JSON: before/after, scores, reasons, model output
    status      TEXT NOT NULL DEFAULT 'ok', -- ok | error | skipped
    ref_type    TEXT, -- case | source | item | null
    ref_id      TEXT,
    model       TEXT
);

CREATE INDEX IF NOT EXISTS idx_ai_activity_ts ON ai_activity(ts DESC);
CREATE INDEX IF NOT EXISTS idx_ai_activity_subsystem ON ai_activity(subsystem);

-- Investigator-submitted targeted-research briefs (POST /api/investigations,
-- see research/investigate.py). One row per submission. case_id is set only
-- if Hermes reported a confident match and findings were integrated — most
-- of the heavy lifting (items, case, sources) is NOT tracked here directly;
-- it's tracked the same way as any other ingest (items/cases/
-- source_heal_proposals/ai_activity), this table just remembers what brief
-- led to it and lets the UI poll for completion.
CREATE TABLE IF NOT EXISTS investigations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    brief         TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'queued', -- queued | running | completed | no_match | failed
    created_at    TEXT NOT NULL,
    finished_at   TEXT,
    case_id       INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    findings      TEXT NOT NULL DEFAULT '{}',
    error         TEXT,
    -- attempts/next_retry_at back a bounded failure-retry/cooldown for
    -- transient Hermes failures (see research/investigate.py and
    -- settings.investigate_max_attempts) — same idea as research_runs'
    -- failure cooldown, just scoped to one investigation row instead of a
    -- separate run table, since a re-queued investigation reuses its own row.
    attempts      INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);

-- Semantic search (embeddings/ package). embedding_meta is a single-row
-- table identifying which backend/model produced the vectors *currently*
-- stored in vec_cases/vec_items (those vec0 virtual tables are created
-- lazily by embeddings/index.py, not here, since their column width
-- depends on the active model's dimension). vec_index_state tracks, per
-- embedded row, the content hash it was embedded from — lets the embedding
-- job detect both "this case's summary changed since it was indexed" and,
-- via embedding_meta's fingerprint check at startup, "this backend changed
-- and the whole index needs rebuilding." See embeddings/index.py's
-- module docstring for the full integrity contract.
CREATE TABLE IF NOT EXISTS embedding_meta (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    fingerprint TEXT NOT NULL,
    backend     TEXT NOT NULL,
    model       TEXT NOT NULL,
    dim         INTEGER,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vec_index_state (
    kind          TEXT NOT NULL, -- 'cases' | 'items'
    ref_id        INTEGER NOT NULL,
    content_hash  TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    PRIMARY KEY (kind, ref_id)
);

-- Resolves one effective priority rank + false_positive flag per item, from
-- the LLM extraction's significance — the sole classification signal (the
-- old regex-matcher fallback was removed; an item simply has no priority
-- until the extraction job reaches it). The rank below is a raw-SQL mirror
-- of significance.SIG_RANK and must be kept in sync by hand (SQL can't
-- import it — known sync trap, see significance.py's module docstring).
DROP VIEW IF EXISTS item_priority;
CREATE VIEW item_priority AS
SELECT i.id AS item_id,
       CASE e.significance WHEN 'critical' THEN 3 WHEN 'warn' THEN 2 WHEN 'info' THEN 1 ELSE 0 END AS prio_rank,
       COALESCE(e.false_positive, 0) AS false_positive
FROM items i
LEFT JOIN extractions e ON e.item_id = i.id;
"""


async def open_db() -> aiosqlite.Connection:
    path = settings.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    conn.row_factory = aiosqlite.Row
    await conn.executescript(_SCHEMA)
    await _migrate(conn)
    await conn.commit()
    # Semantic-search vector index lifecycle/integrity check — see
    # embeddings/index.py's module docstring. No-op when
    # settings.embed_backend == "none".
    from .embeddings.index import init_vectors
    await init_vectors(conn)
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

    case_cols = {r["name"] for r in await conn.execute_fetchall("PRAGMA table_info(cases)")}
    if "iocs" not in case_cols:
        await conn.execute("ALTER TABLE cases ADD COLUMN iocs TEXT NOT NULL DEFAULT '[]'")
        log.info("Migrated cases table: added iocs column")
    if "research_requested_at" not in case_cols:
        await conn.execute("ALTER TABLE cases ADD COLUMN research_requested_at TEXT")
        log.info("Migrated cases table: added research_requested_at column")

    heal_cols = {r["name"] for r in await conn.execute_fetchall("PRAGMA table_info(source_heal_proposals)")}
    for col, ddl in (
        ("action", "ALTER TABLE source_heal_proposals ADD COLUMN action TEXT"),
        ("applied", "ALTER TABLE source_heal_proposals ADD COLUMN applied INTEGER NOT NULL DEFAULT 0"),
        ("before_value", "ALTER TABLE source_heal_proposals ADD COLUMN before_value TEXT"),
        ("after_value", "ALTER TABLE source_heal_proposals ADD COLUMN after_value TEXT"),
    ):
        if col not in heal_cols:
            await conn.execute(ddl)
            log.info("Migrated source_heal_proposals table: added %s column", col)

    inv_cols = {r["name"] for r in await conn.execute_fetchall("PRAGMA table_info(investigations)")}
    for col, ddl in (
        ("attempts", "ALTER TABLE investigations ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"),
        ("next_retry_at", "ALTER TABLE investigations ADD COLUMN next_retry_at TEXT"),
    ):
        if col not in inv_cols:
            await conn.execute(ddl)
            log.info("Migrated investigations table: added %s column", col)

    feedback_cols = {r["name"] for r in await conn.execute_fetchall("PRAGMA table_info(feedback)")}
    if "origin" not in feedback_cols:
        await conn.execute("ALTER TABLE feedback ADD COLUMN origin TEXT NOT NULL DEFAULT 'human'")
        log.info("Migrated feedback table: added origin column")

    await _migrate_normalize_countries(conn)


async def _migrate_normalize_countries(conn: aiosqlite.Connection) -> None:
    """One-time retrograde backfill: rewrite damaged_party_country/
    victim_country to canonical ISO alpha-2 codes (see country.py). Values
    came from free-form LLM extraction before write-side normalization was
    added (upsert_extraction/create_case/merge_item_into_case), so existing
    rows may hold full names ("Germany") instead of codes ("DE"). Gated by
    PRAGMA user_version so this only runs once per DB rather than re-scanning
    on every startup."""
    version_row = await conn.execute_fetchall("PRAGMA user_version")
    if (version_row[0][0] if version_row else 0) >= 1:
        return

    rewritten = 0
    for table, column in (("cases", "damaged_party_country"), ("extractions", "victim_country")):
        rows = await conn.execute_fetchall(
            f"SELECT DISTINCT {column} AS v FROM {table} WHERE {column} IS NOT NULL AND TRIM({column}) != ''"
        )
        for r in rows:
            old = r["v"]
            new = normalize_country(old)
            if new and new != old:
                await conn.execute(
                    f"UPDATE {table} SET {column} = :new WHERE {column} = :old",
                    {"new": new, "old": old},
                )
                rewritten += 1

    await conn.execute("PRAGMA user_version = 1")
    if rewritten:
        log.info("Migrated country values: normalized %d distinct value(s) to ISO alpha-2", rewritten)

async def insert_item(conn: aiosqlite.Connection, item: Item) -> int | None:
    """Insert item; returns new row id or None if duplicate. Deliberately
    does NOT commit — the caller (collectors/base.py:run) commits once the
    insert succeeds, so the row is only ever durable in one atomic step
    before being broadcast/alerted on."""
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
                _normalize_published_at(item.published_at),
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


_RANK_TO_PRIORITY_STR = {0: "", 1: "info", 2: "warn", 3: "critical"}
_PRIORITY_RANK = {"info": 1, "warn": 2, "critical": 3}


def extraction_tags(*, crime_type: str | None, cve_ids: list, iocs: list) -> list[str]:
    """Per-item display tags derived from the LLM extraction (replaces the
    old regex-matcher tags) — used by both fetch_items and
    get_recent_extractions so a live-patched card and a freshly-loaded one
    compute the same chips."""
    tags: set[str] = set()
    if crime_type and crime_type != "other":
        tags.add(crime_type)
    if cve_ids:
        tags.add("cve")
    if iocs:
        tags.add("ioc")
    return sorted(tags)


def _build_items_where(
    *,
    source_ids: list[str] | None,
    search: str | None,
    matched_only: bool,
    min_priority: str | None,
    show_filtered: bool,
    crime_type: str | None = None,
    actor: str | None = None,
    victim: str | None = None,
    cve_id: str | None = None,
    ioc: str | None = None,
    tag: str | None = None,
    classified: bool | None = None,
    min_confidence: float | None = None,
    cluster_size: int | None = None,
    since: str | None = None,
    until: str | None = None,
    extra_key: str | None = None,
    id_in: list[int] | None = None,
) -> tuple[str, dict, bool]:
    """Shared WHERE-clause + named-params builder for fetch_items and
    count_items. These two queries used to build their filters independently
    and drifted: count_items ignored source_id/search/priority/matched_only
    entirely, so the "total" badge the frontend shows could silently disagree
    with what fetch_items actually returned for any filtered request. One
    builder, used by both, makes that impossible to repeat.

    Named params throughout — can't mix named (:matched_only etc.) and
    positional (?) placeholders in one query, so every dynamic value goes
    through named params instead of f-string interpolation.

    Returns (where_clause, params, needs_extractions_join). The third flag
    tells count_items whether it must LEFT JOIN extractions to evaluate
    filters that reference extraction columns."""
    parts: list[str] = []
    params: dict = {}
    idx = 0
    needs_extractions = False

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

    if crime_type:
        parts.append(f"e.crime_type = :p{idx}")
        params[f"p{idx}"] = crime_type
        idx += 1
        needs_extractions = True

    if actor:
        parts.append(f"LOWER(e.actor) LIKE :p{idx}")
        params[f"p{idx}"] = f"%{actor.lower()}%"
        idx += 1
        needs_extractions = True

    if victim:
        parts.append(f"LOWER(e.victim) LIKE :p{idx}")
        params[f"p{idx}"] = f"%{victim.lower()}%"
        idx += 1
        needs_extractions = True

    if cve_id:
        parts.append(f"e.cve_ids LIKE :p{idx}")
        params[f"p{idx}"] = f'%"{cve_id.upper()}"%'
        idx += 1
        needs_extractions = True

    if ioc:
        parts.append(f"e.iocs LIKE :p{idx}")
        params[f"p{idx}"] = f'%"{ioc}"%'
        idx += 1
        needs_extractions = True

    if tag:
        parts.append(f"i.source_tags LIKE :p{idx}")
        params[f"p{idx}"] = f'%"{tag}"%'
        idx += 1

    if classified is not None:
        if classified:
            parts.append("e.item_id IS NOT NULL")
        else:
            parts.append("e.item_id IS NULL")
        needs_extractions = True

    if min_confidence is not None:
        parts.append(f"e.confidence IS NOT NULL AND e.confidence >= :p{idx}")
        params[f"p{idx}"] = min_confidence
        idx += 1
        needs_extractions = True

    if cluster_size is not None:
        parts.append(
            f"""CASE WHEN i.content_key = '' THEN 1 ELSE (
                 SELECT COUNT(DISTINCT i2.source_id) FROM items i2 WHERE i2.content_key = i.content_key
               ) END >= :p{idx}"""
        )
        params[f"p{idx}"] = cluster_size
        idx += 1

    if since:
        # COALESCE to the real event date when the collector captured one
        # (RSS/Mastodon/HIBP/ransomware.live/dated forum posts) — "items
        # from last week" should mean the incident happened last week, not
        # merely that our scraper saw it last week. Falls back to seen_at
        # for sources that never carry a publish date (paste sites).
        parts.append(f"COALESCE(i.published_at, i.seen_at) >= :p{idx}")
        params[f"p{idx}"] = since
        idx += 1

    if until:
        parts.append(f"COALESCE(i.published_at, i.seen_at) <= :p{idx}")
        params[f"p{idx}"] = until
        idx += 1

    if extra_key:
        parts.append(f"i.extra LIKE :p{idx}")
        params[f"p{idx}"] = f"%{extra_key}%"
        idx += 1

    if id_in is not None:
        # Semantic search mode: ranking comes from vector similarity (see
        # api/routes.py's mode="semantic" branch), not a SQL ORDER BY — this
        # scopes the row set to whatever the vector search returned so every
        # *other* structured filter (significance, date range, etc.) still
        # applies on top, then the caller re-sorts by similarity in Python.
        if not id_in:
            parts.append("0")  # empty candidate set -> no rows, not "no filter"
        else:
            placeholders = ", ".join(f":idin{idx + i}" for i in range(len(id_in)))
            parts.append(f"i.id IN ({placeholders})")
            for i, v in enumerate(id_in):
                params[f"idin{idx + i}"] = v
            idx += len(id_in)

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
    return "WHERE " + " AND ".join(parts), params, needs_extractions


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
    crime_type: str | None = None,
    actor: str | None = None,
    victim: str | None = None,
    cve_id: str | None = None,
    ioc: str | None = None,
    tag: str | None = None,
    classified: bool | None = None,
    min_confidence: float | None = None,
    cluster_size: int | None = None,
    since: str | None = None,
    until: str | None = None,
    extra_key: str | None = None,
    id_in: list[int] | None = None,
) -> list[dict]:
    """Return items enriched with classifier data as JSON-serialisable dicts.
    Priority filtering/ordering reads the `item_priority` view (the
    classifier's verdict — the sole significance signal); false-positive
    items are excluded unless show_filtered=True.

    source_id accepts either a single id (back-compat) or a list — the
    dashboard's source checkboxes send a list so multi-source filtering
    happens server-side instead of the old client-side post-filter, which
    silently shrank pages and broke "load more" pagination (a 100-item server
    page minus client-dropped rows is not 100 items, but offset still
    advanced by 100)."""
    source_ids = [source_id] if isinstance(source_id, str) else (source_id or None)

    named_where, named_params, _ = _build_items_where(
        source_ids=source_ids,
        search=search,
        matched_only=matched_only,
        min_priority=min_priority,
        show_filtered=show_filtered,
        crime_type=crime_type,
        actor=actor,
        victim=victim,
        cve_id=cve_id,
        ioc=ioc,
        tag=tag,
        classified=classified,
        min_confidence=min_confidence,
        cluster_size=cluster_size,
        since=since,
        until=until,
        extra_key=extra_key,
        id_in=id_in,
    )

    rows = await conn.execute_fetchall(
        f"""
        SELECT i.*, ep.prio_rank, ep.false_positive,
               e.significance AS classifier_priority, e.confidence AS classifier_confidence,
               e.reasoning AS classifier_reasoning, e.model AS classifier_model,
               e.extracted_at AS classified_at,
               e.crime_type AS crime_type, e.victim AS victim, e.victim_sector AS victim_sector,
               e.victim_country AS victim_country, e.actor AS actor,
               e.cve_ids AS cve_ids, e.iocs AS iocs,
               -- Cross-source clustering (see models.Item.content_key): how many
               -- DISTINCT sources reported something with this same content_key.
               -- '' content_key never clusters (e.g. blank-title items).
               CASE WHEN i.content_key = '' THEN 1 ELSE (
                 SELECT COUNT(DISTINCT i2.source_id) FROM items i2 WHERE i2.content_key = i.content_key
               ) END AS cluster_size
        FROM items i
        LEFT JOIN item_priority ep ON ep.item_id = i.id
        LEFT JOIN extractions e ON e.item_id = i.id
        {named_where}
        -- Deliberately seen_at, not published_at: this is the live feed's
        -- pagination/SSE order — a freshly-ingested item must always land at
        -- the top regardless of its (possibly old) publish date, or live
        -- prepending and "load more" offsets would desync from what the
        -- user is actually scrolled through. The *displayed* timestamp on
        -- each card prefers published_at when known (see api/static/app.js
        -- buildCard) — only the ordering stays ingest-time.
        ORDER BY i.seen_at DESC
        LIMIT :limit OFFSET :offset
        """,
        {**named_params, "limit": limit, "offset": offset},
    )

    if not rows:
        return []

    result = []
    for r in rows:
        cve_ids = json.loads(r["cve_ids"]) if r["cve_ids"] else []
        iocs = json.loads(r["iocs"]) if r["iocs"] else []
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
                # effective priority: the classifier's verdict, "" until classified
                "max_priority": _RANK_TO_PRIORITY_STR.get(r["prio_rank"] or 0, ""),
                "all_tags": extraction_tags(crime_type=r["crime_type"], cve_ids=cve_ids, iocs=iocs),
                "is_false_positive": bool(r["false_positive"]),
                "classified": r["classified_at"] is not None,
                "classifier_confidence": r["classifier_confidence"],
                "classifier_reasoning": r["classifier_reasoning"],
                # Structured extraction fields (see llm/backend.py's
                # Extraction dataclass) — null/empty until the item has been
                # through the extraction job. Also doubles as the source of
                # entity highlighting in the frontend (see app.js
                # highlightEntities), which replaced the old regex-span
                # highlighting now that there's no regex matcher.
                "crime_type": r["crime_type"],
                "victim": r["victim"],
                "victim_sector": r["victim_sector"],
                "victim_country": r["victim_country"],
                "actor": r["actor"],
                "cve_ids": cve_ids,
                "iocs": iocs,
                # >1 means other sources reported the same content_key — a
                # display/triage aid only, never a filter (see fetch_items
                # docstring's don't-hide principle).
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
    crime_type: str | None = None,
    actor: str | None = None,
    victim: str | None = None,
    cve_id: str | None = None,
    ioc: str | None = None,
    tag: str | None = None,
    classified: bool | None = None,
    min_confidence: float | None = None,
    cluster_size: int | None = None,
    since: str | None = None,
    until: str | None = None,
    extra_key: str | None = None,
) -> int:
    """Must accept the exact same filters as fetch_items — see
    _build_items_where's docstring for why these two queries share one
    builder instead of each defining its own WHERE clause."""
    source_ids = [source_id] if isinstance(source_id, str) else (source_id or None)
    named_where, named_params, needs_extractions = _build_items_where(
        source_ids=source_ids,
        search=search,
        matched_only=matched_only,
        min_priority=min_priority,
        show_filtered=show_filtered,
        crime_type=crime_type,
        actor=actor,
        victim=victim,
        cve_id=cve_id,
        ioc=ioc,
        tag=tag,
        classified=classified,
        min_confidence=min_confidence,
        cluster_size=cluster_size,
        since=since,
        until=until,
        extra_key=extra_key,
    )
    join_extractions = "LEFT JOIN extractions e ON e.item_id = i.id" if needs_extractions else ""
    row = await conn.execute_fetchall(
        f"""
        SELECT COUNT(*) AS n
        FROM items i
        LEFT JOIN item_priority ep ON ep.item_id = i.id
        {join_extractions}
        {named_where}
        """,
        named_params,
    )
    return row[0]["n"] if row else 0


# ── Public dashboard aggregations ──────────────────────────────────────────────
# Read-only, parameterized, bounded-range queries — only counts/aggregates,
# so they're safe to serve without the admin token.

_RANK_TO_PRIORITY = {0: "none", 1: "info", 2: "warn", 3: "critical"}


async def stats_timeseries(
    conn: aiosqlite.Connection, *, bucket: str = "hour", since_hours: int = 48
) -> list[dict]:
    """Item counts per time bucket, stacked by effective priority (the
    classifier's verdict). Excludes false positives."""
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
    """Effective-priority breakdown (the classifier's verdict). Excludes
    false positives."""
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


# ── LLM extraction support ────────────────────────────────────────────────
# Used by the llm/ background job and the /api/classifier/* routes.

async def get_unextracted_items(conn: aiosqlite.Connection, *, limit: int) -> list[dict]:
    """Newest-first (LIFO) items with no extractions row yet, ordered by
    the indexed PK (not seen_at — monotonic, no ties, cheap). This is a live
    feed: under sustained backlog, freshness matters more than chronological
    completeness, so the extraction job always works the front of the queue
    instead of grinding through old history while new items pile up
    unextracted. An item simply has no priority/tags until it's reached —
    there is no regex-derived fallback signal anymore."""
    rows = await conn.execute_fetchall(
        """
        SELECT i.id, i.title, i.snippet, i.source_name, i.url
        FROM items i
        WHERE NOT EXISTS (SELECT 1 FROM extractions e WHERE e.item_id = i.id)
        ORDER BY i.id DESC
        LIMIT :limit
        """,
        {"limit": limit},
    )
    return [dict(r) for r in rows]


async def upsert_extraction(
    conn: aiosqlite.Connection,
    *,
    item_id: int,
    crime_type: str,
    victim: str | None,
    victim_sector: str | None,
    victim_country: str | None,
    actor: str | None,
    cve_ids: list[str],
    iocs: list[str],
    significance: str,
    false_positive: bool,
    confidence: float | None,
    reasoning: str | None,
    model: str,
) -> None:
    """Insert or replace the structured extraction for an item. Writing this
    row is the single idempotency mechanism for both the extract batch and
    the fallback sweep — once it exists, the item drops out of both
    candidate queries above, so callers should write it before/atomically-
    with firing any alert to avoid double-firing on a retry."""
    await conn.execute(
        """
        INSERT INTO extractions
            (item_id, crime_type, victim, victim_sector, victim_country, actor,
             cve_ids, iocs, significance, false_positive, confidence, reasoning,
             model, extracted_at)
        VALUES
            (:item_id, :crime_type, :victim, :victim_sector, :victim_country, :actor,
             :cve_ids, :iocs, :significance, :false_positive, :confidence, :reasoning,
             :model, :extracted_at)
        ON CONFLICT(item_id) DO UPDATE SET
            crime_type=excluded.crime_type, victim=excluded.victim,
            victim_sector=excluded.victim_sector, victim_country=excluded.victim_country,
            actor=excluded.actor, cve_ids=excluded.cve_ids, iocs=excluded.iocs,
            significance=excluded.significance, false_positive=excluded.false_positive,
            confidence=excluded.confidence, reasoning=excluded.reasoning,
            model=excluded.model, extracted_at=excluded.extracted_at
        """,
        {
            "item_id": item_id,
            "crime_type": crime_type,
            "victim": victim,
            "victim_sector": victim_sector,
            "victim_country": normalize_country(victim_country),
            "actor": actor,
            "cve_ids": json.dumps(cve_ids),
            "iocs": json.dumps(iocs),
            "significance": significance,
            "false_positive": 1 if false_positive else 0,
            "confidence": confidence,
            "reasoning": reasoning,
            "model": model,
            "extracted_at": _utcnow().isoformat(),
        },
    )
    await conn.commit()


async def count_unextracted(conn: aiosqlite.Connection) -> int:
    """Backlog depth — surfaced via extraction health/dashboard."""
    row = await conn.execute_fetchall(
        """
        SELECT COUNT(*) AS n FROM items i
        WHERE NOT EXISTS (SELECT 1 FROM extractions e WHERE e.item_id = i.id)
        """
    )
    return row[0]["n"] if row else 0


async def get_recent_topics(conn: aiosqlite.Connection, *, since_days: int = 30, limit: int = 10) -> list[str]:
    """Distinct crime types + most-mentioned actors from recent extractions —
    feeds research/discover.py's prompt with "what this monitor cares about"
    now that there's no regex matcher tag list to read instead. Excludes
    false positives and the generic 'other' crime_type bucket."""
    since = (_utcnow() - timedelta(days=since_days)).isoformat()
    crime_rows = await conn.execute_fetchall(
        """
        SELECT DISTINCT e.crime_type FROM extractions e
        WHERE e.extracted_at >= :since AND e.false_positive = 0 AND e.crime_type != 'other'
        ORDER BY e.crime_type ASC
        LIMIT :limit
        """,
        {"since": since, "limit": limit},
    )
    actor_rows = await conn.execute_fetchall(
        """
        SELECT e.actor, COUNT(*) AS n FROM extractions e
        WHERE e.extracted_at >= :since AND e.false_positive = 0 AND e.actor IS NOT NULL
        GROUP BY e.actor ORDER BY n DESC LIMIT :limit
        """,
        {"since": since, "limit": limit},
    )
    topics = [r["crime_type"] for r in crime_rows] + [r["actor"] for r in actor_rows]
    return topics[:limit]


async def get_recent_extractions(conn: aiosqlite.Connection, *, since_iso: str) -> list[dict]:
    """Items extracted after since_iso — powers the frontend's incremental
    poll (GET /api/classifier/recent) so live cards can be patched in place
    without a full feed re-render."""
    rows = await conn.execute_fetchall(
        """
        SELECT e.item_id AS id, e.significance AS classifier_priority,
               e.false_positive AS is_false_positive, e.confidence AS classifier_confidence,
               e.reasoning AS classifier_reasoning, e.extracted_at AS classified_at,
               e.crime_type, e.victim, e.victim_sector, e.victim_country, e.actor,
               e.cve_ids, e.iocs
        FROM extractions e
        WHERE e.extracted_at > :since
        ORDER BY e.extracted_at ASC
        """,
        {"since": since_iso},
    )
    result = []
    for r in rows:
        cve_ids = json.loads(r["cve_ids"]) if r["cve_ids"] else []
        iocs = json.loads(r["iocs"]) if r["iocs"] else []
        result.append(
            {
                "id": r["id"],
                "max_priority": r["classifier_priority"],
                "all_tags": extraction_tags(crime_type=r["crime_type"], cve_ids=cve_ids, iocs=iocs),
                "is_false_positive": bool(r["is_false_positive"]),
                "classifier_confidence": r["classifier_confidence"],
                "classifier_reasoning": r["classifier_reasoning"],
                "classified_at": r["classified_at"],
                "crime_type": r["crime_type"],
                "victim": r["victim"],
                "victim_sector": r["victim_sector"],
                "victim_country": r["victim_country"],
                "actor": r["actor"],
                "cve_ids": cve_ids,
                "iocs": iocs,
            }
        )
    return result


# ── Retention ─────────────────────────────────────────────────────────────────

async def prune_old_items(conn: aiosqlite.Connection, *, retention_days: int) -> int:
    """Delete items older than retention_days, EXCEPT effective-critical
    items (the LLM extraction's verdict — see item_priority). extractions/
    case_items rows cascade via ON DELETE CASCADE (see _SCHEMA's
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
        """,
        {"cutoff": cutoff},
    )
    deleted = cur.rowcount or 0
    await conn.commit()
    if deleted:
        await conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        log.info("Retention: pruned %d item(s) older than %d days", deleted, retention_days)
    return deleted


async def prune_old_activity(conn: aiosqlite.Connection, *, retention_days: int) -> int:
    """Delete ai_activity rows older than retention_days. Unlike items, every
    row here is already a summary (no cascading children to worry about), so
    this is an unconditional age-based prune — no "keep critical" carve-out."""
    cutoff = (_utcnow() - timedelta(days=retention_days)).isoformat()
    cur = await conn.execute("DELETE FROM ai_activity WHERE ts < :cutoff", {"cutoff": cutoff})
    deleted = cur.rowcount or 0
    await conn.commit()
    if deleted:
        log.info("Retention: pruned %d ai_activity row(s) older than %d days", deleted, retention_days)
    return deleted


# ── AI activity log ──────────────────────────────────────────────────────────
# See _SCHEMA's ai_activity table docstring. log_ai_activity is the single
# write path every subsystem calls; list_ai_activity backs GET /api/activity.

async def log_ai_activity(
    conn: aiosqlite.Connection,
    *,
    subsystem: str,
    action: str,
    summary: str,
    detail: dict | None = None,
    status: str = "ok",
    ref_type: str | None = None,
    ref_id: int | str | None = None,
    model: str | None = None,
) -> dict:
    """Insert one activity row and commit. Returns the row as a dict (already
    JSON-decoded) so callers can immediately broadcast it over SSE without a
    second query. Never raises on a bad `detail` value — activity logging is
    observability, not a path that should be able to take down the subsystem
    it's reporting on; non-serializable detail is coerced via default=str."""
    ts = _utcnow().isoformat()
    detail_json = json.dumps(detail or {}, default=str)
    # Return exactly what went into the DB so SSE broadcasts and the stored
    # row are consistent; json.loads also guarantees the payload is serializable.
    detail_out = json.loads(detail_json)
    cur = await conn.execute(
        """
        INSERT INTO ai_activity (ts, subsystem, action, summary, detail, status, ref_type, ref_id, model)
        VALUES (:ts, :subsystem, :action, :summary, :detail, :status, :ref_type, :ref_id, :model)
        """,
        {
            "ts": ts,
            "subsystem": subsystem,
            "action": action,
            "summary": summary,
            "detail": detail_json,
            "status": status,
            "ref_type": ref_type,
            "ref_id": str(ref_id) if ref_id is not None else None,
            "model": model,
        },
    )
    await conn.commit()
    return {
        "id": cur.lastrowid,
        "ts": ts,
        "subsystem": subsystem,
        "action": action,
        "summary": summary,
        "detail": detail_out,
        "status": status,
        "ref_type": ref_type,
        "ref_id": str(ref_id) if ref_id is not None else None,
        "model": model,
    }


async def list_ai_activity(
    conn: aiosqlite.Connection,
    *,
    subsystem: str | None = None,
    status: str | None = None,
    since: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Paginated, newest-first activity feed for the public Activity tab.
    Mirrors list_items' {total, items}-shaped response (see api/routes.py)."""
    where = []
    params: dict = {}
    if subsystem:
        where.append("subsystem = :subsystem")
        params["subsystem"] = subsystem
    if status:
        where.append("status = :status")
        params["status"] = status
    if since:
        where.append("ts >= :since")
        params["since"] = since
    clause = f"WHERE {' AND '.join(where)}" if where else ""

    total_row = await conn.execute_fetchall(f"SELECT COUNT(*) AS n FROM ai_activity {clause}", params)
    total = total_row[0]["n"] if total_row else 0

    rows = await conn.execute_fetchall(
        f"""
        SELECT id, ts, subsystem, action, summary, detail, status, ref_type, ref_id, model
        FROM ai_activity {clause}
        ORDER BY ts DESC, id DESC
        LIMIT :limit OFFSET :offset
        """,
        {**params, "limit": limit, "offset": offset},
    )
    events = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d["detail"]) if d["detail"] else {}
        except (TypeError, ValueError):
            d["detail"] = {}
        events.append(d)
    return {"total": total, "events": events}


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


# ── CISA KEV catalog ─────────────────────────────────────────────────────────
# See enrich/kev.py — refreshed daily from CISA's feed into kev_catalog,
# looked up per-CVE to flag cases.in_kev.

async def replace_kev_catalog(conn: aiosqlite.Connection, entries: list[dict]) -> int:
    """Wholesale-replace the kev_catalog table with a freshly-downloaded
    feed. CISA's feed is the full current catalog each time (entries don't
    individually expire, but a vuln can in principle be removed), so a
    delete+reinsert in one transaction is simpler and safer than diffing —
    a partial/failed refresh leaves the old catalog untouched since this
    only commits once the whole batch is staged."""
    await conn.execute("DELETE FROM kev_catalog")
    if entries:
        await conn.executemany(
            """INSERT INTO kev_catalog
                   (cve_id, vendor, product, vuln_name, date_added, due_date,
                    known_ransomware, notes)
               VALUES (:cve_id, :vendor, :product, :vuln_name, :date_added,
                        :due_date, :known_ransomware, :notes)""",
            entries,
        )
    await conn.commit()
    return len(entries)


async def lookup_kev(conn: aiosqlite.Connection, cve_ids: list[str]) -> list[dict]:
    """Return kev_catalog rows matching any of the given CVE ids (already
    normalized to uppercase by enrich/cve.py)."""
    if not cve_ids:
        return []
    placeholders = ",".join("?" * len(cve_ids))
    rows = await conn.execute_fetchall(
        f"SELECT * FROM kev_catalog WHERE cve_id IN ({placeholders})", cve_ids
    )
    return [dict(r) for r in rows]


async def count_kev_catalog(conn: aiosqlite.Connection) -> int:
    row = await conn.execute_fetchall("SELECT COUNT(*) AS n FROM kev_catalog")
    return row[0]["n"] if row else 0


# ── Cases (deduplicated incidents) ──────────────────────────────────────────
# See pipeline/correlate.py — items with a usable extraction get blocked
# against existing cases (exact case_key, then fuzzy candidates), merged or
# turned into a new case. case_items is the corroboration record.

async def get_uncorrelated_extracted_items(conn: aiosqlite.Connection, *, limit: int) -> list[dict]:
    """Newest-first (LIFO) items that have a non-false-positive extraction
    but aren't linked into any case yet — pipeline/correlate.py's input
    queue. Mirrors get_unextracted_items' LIFO-with-fallback-sweep shape
    (see that function's docstring) since the same "freshness over
    chronological completeness" reasoning applies."""
    rows = await conn.execute_fetchall(
        """
        SELECT i.id, i.title, i.snippet, i.source_id, i.source_name, i.url,
               i.seen_at, i.published_at, i.content_key,
               e.crime_type, e.victim, e.victim_sector, e.victim_country, e.actor,
               e.cve_ids, e.iocs, e.significance, e.confidence
        FROM items i
        JOIN extractions e ON e.item_id = i.id
        WHERE e.false_positive = 0
          AND NOT EXISTS (SELECT 1 FROM case_items ci WHERE ci.item_id = i.id)
        ORDER BY i.id DESC
        LIMIT :limit
        """,
        {"limit": limit},
    )
    items = [dict(r) for r in rows]
    for it in items:
        it["cve_ids"] = json.loads(it["cve_ids"]) if it["cve_ids"] else []
        it["iocs"] = json.loads(it["iocs"]) if it["iocs"] else []
    return items


async def count_uncorrelated_extracted_items(conn: aiosqlite.Connection) -> int:
    """Backlog depth for the case correlator — surfaced in /api/status."""
    row = await conn.execute_fetchall(
        """
        SELECT COUNT(*) AS n
        FROM items i
        JOIN extractions e ON e.item_id = i.id
        WHERE e.false_positive = 0
          AND NOT EXISTS (SELECT 1 FROM case_items ci WHERE ci.item_id = i.id)
        """
    )
    return row[0]["n"] if row else 0


async def get_case_by_key(conn: aiosqlite.Connection, case_key: str) -> dict | None:
    rows = await conn.execute_fetchall("SELECT * FROM cases WHERE case_key = :k", {"k": case_key})
    return dict(rows[0]) if rows else None


async def get_case_id_for_item(conn: aiosqlite.Connection, item_id: int) -> int | None:
    """Which case (if any) an item ended up linked into — used by
    research/investigate.py after delegating to pipeline/correlate.py's
    create-or-merge logic, since that path can land an item in a
    pre-existing case (exact key or fuzzy LLM merge) as easily as a brand
    new one; case_items is the one place that's true regardless of which
    branch fired."""
    rows = await conn.execute_fetchall(
        "SELECT case_id FROM case_items WHERE item_id = :item_id LIMIT 1", {"item_id": item_id}
    )
    return rows[0]["case_id"] if rows else None


async def find_candidate_cases(
    conn: aiosqlite.Connection,
    *,
    victim: str | None,
    actor: str | None,
    cve_ids: list[str],
    iocs: list[str] | None = None,
    since_iso: str,
) -> list[dict]:
    """Fuzzy candidate set for correlate.py's adjudication step: cases last
    updated since `since_iso` that share a normalized victim OR actor OR any
    CVE id OR any IoC. Exact case_key matches are handled separately by
    get_case_by_key — this is only consulted when that misses, so candidates
    here are "maybe the same incident," not "definitely."

    Victim matching is intentionally fuzzy: "V-Bank" and "V-Bank (Munich)"
    should surface each other because extraction sometimes adds or drops
    bracketed location qualifiers. Actor/CVE/IoC matching stays exact because
    those are strong, structured signals."""
    clauses = []
    params: dict = {"since": since_iso}
    if victim:
        clauses.append("lower(damaged_party) = :victim")
        params["victim"] = victim.lower()
    if actor:
        clauses.append("lower(attribution) = :actor")
        params["actor"] = actor.lower()
    if cve_ids:
        cve_clauses = []
        for i, cve in enumerate(cve_ids):
            key = f"cve{i}"
            cve_clauses.append(f"cve_ids LIKE :{key}")
            params[key] = f'%"{cve}"%'
        clauses.append("(" + " OR ".join(cve_clauses) + ")")
    if iocs:
        ioc_clauses = []
        for i, ioc in enumerate(iocs):
            key = f"ioc{i}"
            ioc_clauses.append(f"lower(iocs) LIKE :{key}")
            params[key] = f'%"{ioc.lower()}"%'
        clauses.append("(" + " OR ".join(ioc_clauses) + ")")

    candidates: dict[int, dict] = {}

    if clauses:
        rows = await conn.execute_fetchall(
            f"""
            SELECT * FROM cases
            WHERE last_seen >= :since AND ({" OR ".join(clauses)})
            ORDER BY last_seen DESC
            LIMIT 10
            """,
            params,
        )
        for row in rows:
            candidates[row["id"]] = dict(row)

    # Fuzzy victim pass: load recent cases with any victim name and filter in
    # Python. Kept separate from the exact SQL so we don't weaken actor/CVE/IoC
    # matching, and capped by the same recency window to avoid scanning the
    # whole table.
    if victim:
        fuzzy_rows = await conn.execute_fetchall(
            """
            SELECT * FROM cases
            WHERE last_seen >= :since AND damaged_party IS NOT NULL
            ORDER BY last_seen DESC
            LIMIT 50
            """,
            {"since": since_iso},
        )
        for row in fuzzy_rows:
            if row["id"] in candidates:
                continue
            if _victim_similar(victim, row["damaged_party"]):
                candidates[row["id"]] = dict(row)

    return sorted(candidates.values(), key=lambda c: c["last_seen"], reverse=True)


async def create_case(
    conn: aiosqlite.Connection,
    *,
    case_key: str,
    title: str,
    summary: str,
    crime_type: str,
    attribution: str | None,
    attribution_confidence: float | None,
    damaged_party: str | None,
    damaged_party_sector: str | None,
    damaged_party_country: str | None,
    significance: str,
    significance_score: float,
    cve_ids: list[str],
    in_kev: bool,
    item_id: int,
    event_at: str,
    iocs: list[str] | None = None,
) -> int:
    """Create a new case and link its founding item in one go. Returns the
    new case id.

    event_at: the founding item's real-world date — its published_at if the
    collector captured one (RSS/Mastodon/HIBP/ransomware.live/dated forum
    posts), else its seen_at. Seeds both first_seen and last_seen so a case's
    timeline reflects when the incident actually happened/was reported, not
    merely when our scraper first noticed it — see merge_item_into_case for
    how subsequent items extend this range."""
    cur = await conn.execute(
        """
        INSERT INTO cases
            (case_key, title, summary, crime_type, attribution, attribution_confidence,
             damaged_party, damaged_party_sector, damaged_party_country,
             significance, significance_score, status, cve_ids, in_kev,
             first_seen, last_seen, source_count, extra, iocs)
        VALUES
            (:case_key, :title, :summary, :crime_type, :attribution, :attribution_confidence,
             :damaged_party, :damaged_party_sector, :damaged_party_country,
             :significance, :significance_score, 'new', :cve_ids, :in_kev,
             :event_at, :event_at, 1, '{}', :iocs)
        """,
        {
            "case_key": case_key,
            "title": title,
            "summary": summary,
            "crime_type": crime_type,
            "attribution": attribution,
            "attribution_confidence": attribution_confidence,
            "damaged_party": damaged_party,
            "damaged_party_sector": damaged_party_sector,
            "damaged_party_country": normalize_country(damaged_party_country),
            "significance": significance,
            "significance_score": significance_score,
            "cve_ids": json.dumps(cve_ids),
            "in_kev": 1 if in_kev else 0,
            "event_at": event_at,
            "iocs": json.dumps(iocs or []),
        },
    )
    case_id = cur.lastrowid
    await conn.execute(
        "INSERT INTO case_items (case_id, item_id) VALUES (:case_id, :item_id)",
        {"case_id": case_id, "item_id": item_id},
    )
    await conn.commit()
    return case_id


async def merge_item_into_case(
    conn: aiosqlite.Connection,
    *,
    case_id: int,
    item_id: int,
    significance: str,
    cve_ids: list[str],
    in_kev: bool,
    crime_type: str | None,
    attribution: str | None,
    attribution_confidence: float | None,
    damaged_party_sector: str | None,
    damaged_party_country: str | None,
    event_at: str,
    iocs: list[str] | None = None,
) -> None:
    """Link a corroborating item into an existing case and recompute its
    aggregate fields: significance/score, cve_ids (union), iocs (union),
    in_kev (OR), first_seen/last_seen (widened to cover this item's real
    event date — see event_at), source_count (recount of distinct item
    sources). Sparse fields (crime_type/attribution/sector/country) are only
    filled in when the case doesn't have a value yet — first reporter's
    structured data wins unless blank, rather than the newest report
    silently overwriting an established attribution.

    Significance precedence: until a case has had its first *completed*
    research run, corroboration is max-merge — never lowers significance,
    same as before. Once a case has been researched, the researcher (and the
    mechanical staleness-decay job, see run_significance_decay) own its
    level; a new corroborating item no longer re-escalates it on its own —
    otherwise a researcher's deliberate degrade (case turned out stale/
    irrelevant) would be silently undone by the next matching item. The
    level can still change, but only via the next research pass or decay
    tick. See research/agent.py's _research_one docstring for the other side
    of this precedence rule.

    event_at: the merging item's published_at if known, else its seen_at —
    same convention as create_case. A corroborating report can be OLDER than
    the case's current first_seen (e.g. someone finds an earlier mention of
    the same incident) or simply confirm the same window; MIN/MAX widen the
    range rather than assuming reports arrive in chronological order."""
    case = await get_case_by_id(conn, case_id)
    if case is None:
        return

    existing_cve_ids = json.loads(case["cve_ids"]) if case["cve_ids"] else []
    merged_cve_ids = list(dict.fromkeys([*existing_cve_ids, *cve_ids]))

    existing_iocs = json.loads(case["iocs"]) if case["iocs"] else []
    merged_iocs = list(dict.fromkeys([*existing_iocs, *(iocs or [])]))

    researched_row = await conn.execute_fetchall(
        "SELECT 1 FROM research_runs WHERE case_id = :case_id AND status = 'completed' LIMIT 1",
        {"case_id": case_id},
    )
    if researched_row:
        new_significance = case["significance"]
        new_score = case["significance_score"]
    else:
        new_significance = sig.max_significance(case["significance"], significance)
        new_score = sig.significance_score(new_significance)

    await conn.execute(
        "INSERT OR IGNORE INTO case_items (case_id, item_id) VALUES (:case_id, :item_id)",
        {"case_id": case_id, "item_id": item_id},
    )
    source_count_row = await conn.execute_fetchall(
        """
        SELECT COUNT(DISTINCT i.source_id) AS n
        FROM case_items ci JOIN items i ON i.id = ci.item_id
        WHERE ci.case_id = :case_id
        """,
        {"case_id": case_id},
    )
    source_count = source_count_row[0]["n"] if source_count_row else case["source_count"]

    await conn.execute(
        """
        UPDATE cases SET
            significance = :significance,
            significance_score = :significance_score,
            cve_ids = :cve_ids,
            iocs = :iocs,
            in_kev = MAX(in_kev, :in_kev),
            crime_type = COALESCE(NULLIF(crime_type, 'other'), :crime_type, crime_type),
            attribution = COALESCE(attribution, :attribution),
            attribution_confidence = COALESCE(attribution_confidence, :attribution_confidence),
            damaged_party_sector = COALESCE(damaged_party_sector, :damaged_party_sector),
            damaged_party_country = COALESCE(damaged_party_country, :damaged_party_country),
            first_seen = MIN(first_seen, :event_at),
            last_seen = MAX(last_seen, :event_at),
            source_count = :source_count
        WHERE id = :case_id
        """,
        {
            "case_id": case_id,
            "significance": new_significance,
            "significance_score": new_score,
            "cve_ids": json.dumps(merged_cve_ids),
            "iocs": json.dumps(merged_iocs),
            "in_kev": 1 if in_kev else 0,
            "crime_type": crime_type,
            "attribution": attribution,
            "attribution_confidence": attribution_confidence,
            "damaged_party_sector": damaged_party_sector,
            "damaged_party_country": normalize_country(damaged_party_country),
            "event_at": event_at,
            "source_count": source_count,
        },
    )
    await conn.commit()


def _prefer_more_specific(base: str | None, other: str | None) -> str | None:
    """Return the more specific of two names when one clearly extends the
    other (e.g. "V-Bank" vs "V-Bank (Munich)"). Prefers `other` only when it
    contains the normalized base and is longer; otherwise keeps `base`."""
    if not other:
        return base
    if not base:
        return other
    nb, no = _normalize(base), _normalize(other)
    if len(other) > len(base) and (nb in no or no in nb):
        return other
    return base


async def merge_cases(
    conn: aiosqlite.Connection,
    *,
    keep_case_id: int,
    drop_case_id: int,
) -> dict:
    """Merge two cases into one. All items, CVEs, IoCs and research runs from
    `drop_case_id` are moved to `keep_case_id`; `drop_case_id` is deleted.
    Aggregated fields are recomputed so the surviving case reflects the union.
    Returns the updated keep case. Raises ValueError if a case is missing."""
    keep = await get_case_by_id(conn, keep_case_id)
    drop = await get_case_by_id(conn, drop_case_id)
    if keep is None or drop is None:
        raise ValueError("One or both cases not found")

    # Re-link all items from the dropped case into the surviving case.
    await conn.execute(
        """
        INSERT OR IGNORE INTO case_items (case_id, item_id)
        SELECT :keep_case_id, item_id
        FROM case_items
        WHERE case_id = :drop_case_id
        """,
        {"keep_case_id": keep_case_id, "drop_case_id": drop_case_id},
    )

    # Recompute source count from the unified item set.
    source_count_row = await conn.execute_fetchall(
        """
        SELECT COUNT(DISTINCT i.source_id) AS n
        FROM case_items ci JOIN items i ON i.id = ci.item_id
        WHERE ci.case_id = :case_id
        """,
        {"case_id": keep_case_id},
    )
    source_count = source_count_row[0]["n"] if source_count_row else keep["source_count"]

    keep_cves = json.loads(keep["cve_ids"]) if keep["cve_ids"] else []
    drop_cves = json.loads(drop["cve_ids"]) if drop["cve_ids"] else []
    merged_cve_ids = list(dict.fromkeys([*keep_cves, *drop_cves]))

    keep_iocs = json.loads(keep["iocs"]) if keep["iocs"] else []
    drop_iocs = json.loads(drop["iocs"]) if drop["iocs"] else []
    merged_iocs = list(dict.fromkeys([*keep_iocs, *drop_iocs]))

    # Same precedence rule as merge_item_into_case: once the surviving case
    # has a completed research run, its significance is owned by the
    # researcher/decay job and an incoming (possibly stale) dropped case
    # must not silently re-escalate it.
    keep_researched_row = await conn.execute_fetchall(
        "SELECT 1 FROM research_runs WHERE case_id = :case_id AND status = 'completed' LIMIT 1",
        {"case_id": keep_case_id},
    )
    if keep_researched_row:
        merged_significance = keep["significance"]
        merged_score = keep["significance_score"]
    else:
        merged_significance = sig.max_significance(keep["significance"], drop["significance"])
        merged_score = sig.significance_score(merged_significance)

    # Prefer the more specific victim/title when one clearly extends the other.
    merged_damaged_party = _prefer_more_specific(keep["damaged_party"], drop["damaged_party"])
    merged_title = _prefer_more_specific(keep["title"], drop["title"])

    await conn.execute(
        """
        UPDATE cases SET
            title = :title,
            summary = :summary,
            significance = :significance,
            significance_score = :significance_score,
            cve_ids = :cve_ids,
            iocs = :iocs,
            in_kev = MAX(in_kev, :in_kev),
            crime_type = COALESCE(NULLIF(crime_type, 'other'), :drop_crime_type, crime_type),
            attribution = COALESCE(attribution, :drop_attribution),
            attribution_confidence = COALESCE(attribution_confidence, :drop_attribution_confidence),
            damaged_party = :damaged_party,
            damaged_party_sector = COALESCE(damaged_party_sector, :drop_damaged_party_sector),
            damaged_party_country = COALESCE(damaged_party_country, :drop_damaged_party_country),
            first_seen = MIN(first_seen, :drop_first_seen),
            last_seen = MAX(last_seen, :drop_last_seen),
            source_count = :source_count,
            status = COALESCE(NULLIF(status, 'new'), :drop_status, status)
        WHERE id = :case_id
        """,
        {
            "case_id": keep_case_id,
            "title": merged_title or keep["title"],
            "summary": (keep["summary"] or "") + (f"\n\n{drop['summary']}" if drop.get("summary") else ""),
            "significance": merged_significance,
            "significance_score": merged_score,
            "cve_ids": json.dumps(merged_cve_ids),
            "iocs": json.dumps(merged_iocs),
            "in_kev": 1 if drop["in_kev"] else 0,
            "drop_crime_type": drop["crime_type"],
            "drop_attribution": drop["attribution"],
            "drop_attribution_confidence": drop["attribution_confidence"],
            "damaged_party": merged_damaged_party,
            "drop_damaged_party_sector": drop["damaged_party_sector"],
            "drop_damaged_party_country": drop["damaged_party_country"],
            "drop_first_seen": drop["first_seen"],
            "drop_last_seen": drop["last_seen"],
            "source_count": source_count,
            "drop_status": drop["status"],
        },
    )

    await conn.execute(
        "UPDATE research_runs SET case_id = :keep_case_id WHERE case_id = :drop_case_id",
        {"keep_case_id": keep_case_id, "drop_case_id": drop_case_id},
    )
    await conn.execute("DELETE FROM cases WHERE id = :drop_case_id", {"drop_case_id": drop_case_id})
    await conn.commit()

    return await get_case_by_id(conn, keep_case_id)


async def get_case_by_id(conn: aiosqlite.Connection, case_id: int) -> dict | None:
    rows = await conn.execute_fetchall("SELECT * FROM cases WHERE id = :id", {"id": case_id})
    return dict(rows[0]) if rows else None


def _build_cases_where(
    *,
    min_significance: str | None = None,
    crime_type: str | None = None,
    in_kev: bool | None = None,
    search: str | None = None,
    cve_id: str | None = None,
    ioc: str | None = None,
    since: str | None = None,
    until: str | None = None,
    country: str | None = None,
    id_in: list[int] | None = None,
) -> tuple[str, dict]:
    parts = []
    params: dict = {}
    if min_significance:
        # Raw-SQL rank mirror of significance.SIG_RANK — kept manually in
        # sync since SQL can't import it (known sync trap, see
        # significance.py's module docstring).
        parts.append("(:min_rank = 0 OR " +
                      "CASE significance WHEN 'critical' THEN 3 WHEN 'warn' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"
                      " >= :min_rank)")
        params["min_rank"] = sig.SIG_RANK.get(min_significance, 0)
    if crime_type:
        parts.append("crime_type = :crime_type")
        params["crime_type"] = crime_type
    if in_kev is not None:
        parts.append("in_kev = :in_kev")
        params["in_kev"] = 1 if in_kev else 0
    if search:
        parts.append(
            "(title LIKE :search OR damaged_party LIKE :search OR attribution LIKE :search "
            "OR iocs LIKE :search OR cve_ids LIKE :search)"
        )
        params["search"] = f"%{search}%"
    if cve_id:
        # cve_ids/iocs are stored as a JSON array string — quote-wrapped
        # match avoids "CVE-2024-1" falsely matching "CVE-2024-100" the way
        # a bare substring LIKE would (mirrors _build_items_where's same
        # trick for the item-level cve_id/ioc filters).
        parts.append("cve_ids LIKE :cve_id")
        params["cve_id"] = f'%"{cve_id.upper()}"%'
    if ioc:
        parts.append("iocs LIKE :ioc")
        params["ioc"] = f'%"{ioc}"%'
    if since:
        parts.append("last_seen >= :since")
        params["since"] = since
    if until:
        parts.append("last_seen <= :until")
        params["until"] = until
    if country:
        # Accepts either a code or a free-form name — normalize so
        # ?country=Germany and ?country=DE both match the canonical
        # alpha-2 codes stored in damaged_party_country.
        parts.append("damaged_party_country = :country")
        params["country"] = normalize_country(country) or country
    if id_in is not None:
        # Semantic search mode — see _build_items_where's id_in for the
        # same pattern: scope to the vector-search candidate set, let every
        # other structured filter still apply, caller re-sorts by
        # similarity afterward.
        if not id_in:
            parts.append("0")
        else:
            placeholders = ", ".join(f":idin{i}" for i in range(len(id_in)))
            parts.append(f"id IN ({placeholders})")
            for i, v in enumerate(id_in):
                params[f"idin{i}"] = v
    where = ("WHERE " + " AND ".join(parts)) if parts else ""
    return where, params


async def fetch_cases(
    conn: aiosqlite.Connection,
    *,
    limit: int = 100,
    offset: int = 0,
    min_significance: str | None = None,
    crime_type: str | None = None,
    in_kev: bool | None = None,
    search: str | None = None,
    cve_id: str | None = None,
    ioc: str | None = None,
    since: str | None = None,
    until: str | None = None,
    country: str | None = None,
    id_in: list[int] | None = None,
) -> list[dict]:
    """Case-centric counterpart to fetch_items — see that function's
    docstring for the shared filter/pagination shape this mirrors.
    `search` also matches IoCs (not just title/victim/actor) so an
    investigator can land on a case from an indicator alone. `since`/`until`
    bound on last_seen — a timeframe search ("what happened last week").
    `cve_id`/`ioc` back the case detail pane's indicator-pivot chips (click
    a CVE/IoC -> every case sharing it). `country` narrows to a single
    victim country (the Cases-tab map's click-to-filter)."""
    where, params = _build_cases_where(
        min_significance=min_significance, crime_type=crime_type, in_kev=in_kev,
        search=search, cve_id=cve_id, ioc=ioc, since=since, until=until,
        country=country, id_in=id_in,
    )
    rows = await conn.execute_fetchall(
        f"""
        SELECT * FROM cases
        {where}
        ORDER BY last_seen DESC
        LIMIT :limit OFFSET :offset
        """,
        {**params, "limit": limit, "offset": offset},
    )
    out = []
    for r in rows:
        d = dict(r)
        d["cve_ids"] = json.loads(d["cve_ids"]) if d["cve_ids"] else []
        d["iocs"] = json.loads(d["iocs"]) if d["iocs"] else []
        d["in_kev"] = bool(d["in_kev"])
        out.append(d)
    return out


async def count_cases(
    conn: aiosqlite.Connection,
    *,
    since_iso: str | None = None,
    min_significance: str | None = None,
    crime_type: str | None = None,
    in_kev: bool | None = None,
    search: str | None = None,
    cve_id: str | None = None,
    ioc: str | None = None,
    since: str | None = None,
    until: str | None = None,
    country: str | None = None,
) -> int:
    """Landscape's "cases opened in window" count (first_seen-based via
    since_iso) can be combined with the same last_seen filters used by
    fetch_cases so callers always get a consistent, filter-aware total."""
    where, params = _build_cases_where(
        min_significance=min_significance, crime_type=crime_type, in_kev=in_kev,
        search=search, cve_id=cve_id, ioc=ioc, since=since, until=until, country=country,
    )
    if since_iso:
        if where:
            where = f"{where} AND first_seen >= :since_iso"
        else:
            where = "WHERE first_seen >= :since_iso"
        params["since_iso"] = since_iso
    row = await conn.execute_fetchall(f"SELECT COUNT(*) AS n FROM cases {where}", params)
    return row[0]["n"] if row else 0


# ── Agentic research (research/agent.py) ────────────────────────────────────
# Dispatches hermes-agent against cases that are significant enough to merit
# autonomous OSINT but haven't been researched (recently). research_runs is
# the log; cases.status tracks where a case is in that lifecycle.

def _research_eligibility_sql() -> str:
    """Shared WHERE-clause body for "is this case due for a research pass" —
    used by BOTH get_cases_needing_research and count_cases_needing_research
    so they cannot drift out of agreement (the dashboard's queued count must
    match what the scheduler is actually about to pick up next tick).

    A case qualifies if it's explicitly forced (research_requested_at set —
    bypasses every other gate, since an analyst asking for a re-research
    means "go again right now"), OR it's past the failure-retry guard AND
    due per its significance-scaled cadence:
      - info: researched exactly ONCE — eligible iff it has zero completed
        runs ever (no interval; see settings.research_critical/warn_interval).
      - warn: eligible if its last completed run is older than
        settings.research_warn_interval_seconds.
      - critical: eligible if its last completed run is older than
        settings.research_critical_interval_seconds (an ongoing crime needs
        fresher info, so this is the shortest interval).
    The failure-retry guard (a non-completed run more recent than
    settings.research_failure_retry_hours) applies across all three levels —
    a failure means no answer was produced at all, so it shouldn't lock a
    case out for a full cadence interval just because the backend hiccuped."""
    return """
        research_requested_at IS NOT NULL
        OR (
          NOT EXISTS (
            SELECT 1 FROM research_runs r
            WHERE r.case_id = cases.id
              AND r.status != 'completed'
              AND r.started_at >= :failure_cutoff
          )
          AND (
            (significance = 'info'
             AND NOT EXISTS (
               SELECT 1 FROM research_runs r
               WHERE r.case_id = cases.id AND r.status = 'completed'
             ))
            OR (significance = 'warn'
                AND NOT EXISTS (
                  SELECT 1 FROM research_runs r
                  WHERE r.case_id = cases.id AND r.status = 'completed'
                    AND r.started_at >= :warn_cutoff
                ))
            OR (significance = 'critical'
                AND NOT EXISTS (
                  SELECT 1 FROM research_runs r
                  WHERE r.case_id = cases.id AND r.status = 'completed'
                    AND r.started_at >= :critical_cutoff
                ))
          )
        )
    """


def _research_eligibility_params(now: datetime) -> dict:
    return {
        "failure_cutoff": (now - timedelta(hours=settings.research_failure_retry_hours)).isoformat(),
        "warn_cutoff": (now - timedelta(seconds=settings.research_warn_interval_seconds)).isoformat(),
        "critical_cutoff": (now - timedelta(seconds=settings.research_critical_interval_seconds)).isoformat(),
    }


async def get_cases_needing_research(
    conn: aiosqlite.Connection, *, limit: int, now: datetime
) -> list[dict]:
    """Cases worth spending a Hermes research run on this tick — see
    _research_eligibility_sql's docstring for the exact eligibility rule.
    Forced cases sort first, then critical-before-warn-before-info, then
    oldest-first, so a backlog drains in a stable order rather than
    thrashing between cases. info cases sort last among naturally-eligible
    cases, so their one-time pass never displaces a warn/critical case
    within a bounded batch."""
    rows = await conn.execute_fetchall(
        f"""
        SELECT * FROM cases
        WHERE {_research_eligibility_sql()}
        ORDER BY
            (research_requested_at IS NOT NULL) DESC,
            CASE significance WHEN 'critical' THEN 3 WHEN 'warn' THEN 2 ELSE 1 END DESC,
            last_seen ASC
        LIMIT :limit
        """,
        {**_research_eligibility_params(now), "limit": limit},
    )
    out = []
    for r in rows:
        d = dict(r)
        d["cve_ids"] = json.loads(d["cve_ids"]) if d["cve_ids"] else []
        d["iocs"] = json.loads(d["iocs"]) if d["iocs"] else []
        out.append(d)
    return out


async def clear_case_research_request(conn: aiosqlite.Connection, *, case_id: int) -> None:
    """Clear a forced-research flag without otherwise touching the case —
    used when a research run fails/times out so a persistently-broken
    Hermes backend doesn't make a forced case retry every single tick
    forever (see research/agent.py's failure path). The analyst can always
    re-request via the API if it's still wanted."""
    await conn.execute(
        "UPDATE cases SET research_requested_at = NULL WHERE id = :id", {"id": case_id}
    )
    await conn.commit()


async def request_case_research(conn: aiosqlite.Connection, *, case_id: int) -> bool:
    """Flag a case for a forced deep-research pass (POST
    /api/cases/{id}/research) — picked up first by the next _research tick
    via get_cases_needing_research. Returns False if the case doesn't
    exist."""
    cur = await conn.execute(
        "UPDATE cases SET research_requested_at = :now WHERE id = :id",
        {"now": _utcnow().isoformat(), "id": case_id},
    )
    await conn.commit()
    return cur.rowcount > 0


async def count_cases_needing_research(conn: aiosqlite.Connection, *, now: datetime) -> int:
    """Queued cases waiting for hermes-agent research — surfaced in
    /api/status. Uses the exact same _research_eligibility_sql predicate as
    get_cases_needing_research (by construction, not just convention) so
    this count can never disagree with what the scheduler is actually about
    to pick up."""
    row = await conn.execute_fetchall(
        f"SELECT COUNT(*) AS n FROM cases WHERE {_research_eligibility_sql()}",
        _research_eligibility_params(now),
    )
    return row[0]["n"] if row else 0


async def start_research_run(conn: aiosqlite.Connection, *, case_id: int, model: str | None) -> int:
    cur = await conn.execute(
        """
        INSERT INTO research_runs (case_id, status, model, started_at)
        VALUES (:case_id, 'running', :model, :started_at)
        """,
        {"case_id": case_id, "model": model, "started_at": _utcnow().isoformat()},
    )
    await conn.commit()
    return cur.lastrowid


async def finish_research_run(
    conn: aiosqlite.Connection,
    *,
    run_id: int,
    status: str,
    findings: dict,
    sources: list[str],
    error: str | None,
) -> None:
    await conn.execute(
        """
        UPDATE research_runs SET
            status = :status, findings = :findings, sources = :sources,
            error = :error, finished_at = :finished_at
        WHERE id = :run_id
        """,
        {
            "run_id": run_id,
            "status": status,
            "findings": json.dumps(findings),
            "sources": json.dumps(sources),
            "error": error,
            "finished_at": _utcnow().isoformat(),
        },
    )
    await conn.commit()


async def apply_research_findings(
    conn: aiosqlite.Connection,
    *,
    case_id: int,
    status: str,
    attribution: str | None,
    damaged_party: str | None,
    summary_addendum: str | None,
    iocs: list[str] | None = None,
    significance: str | None = None,
) -> None:
    """Merge Hermes' research findings back into the case. Sparse fields
    (attribution/damaged_party) only fill in if the case doesn't have a
    value yet — same first-reporter-wins precedence as
    merge_item_into_case, so an autonomous research run can fill gaps but
    can't silently overwrite a human/extraction-derived attribution it
    disagrees with. iocs are unioned in (research can only add indicators,
    never remove ones extraction already found). Always clears
    research_requested_at — a forced research request is satisfied by one
    completed run, whatever it found.

    significance, when not None, is the researcher's reclassification
    verdict (research/agent.py's _reconcile_verdict) and is an
    AUTHORITATIVE OVERWRITE — unlike the sparse fields above, it can both
    raise and lower the case's level, including degrading a critical case to
    info if it turned out stale/irrelevant. This is the one place a case's
    significance is allowed to go down. When significance is None (no
    verdict, or one filtered out by the confidence gate), the case's current
    significance/significance_score are left untouched. See
    merge_item_into_case's docstring for how this interacts with later
    item corroboration."""
    case = await get_case_by_id(conn, case_id)
    if case is None:
        return
    summary = case["summary"] or ""
    if summary_addendum:
        summary = (summary + "\n\n[research] " + summary_addendum).strip()
    existing_iocs = json.loads(case["iocs"]) if case["iocs"] else []
    merged_iocs = list(dict.fromkeys([*existing_iocs, *(iocs or [])]))
    await conn.execute(
        """
        UPDATE cases SET
            status = :status,
            attribution = COALESCE(attribution, :attribution),
            damaged_party = COALESCE(damaged_party, :damaged_party),
            summary = :summary,
            iocs = :iocs,
            significance = COALESCE(:significance, significance),
            significance_score = CASE WHEN :significance IS NULL
                                       THEN significance_score
                                       ELSE :significance_score END,
            research_requested_at = NULL
        WHERE id = :case_id
        """,
        {
            "case_id": case_id,
            "status": status,
            "attribution": attribution,
            "damaged_party": damaged_party,
            "summary": summary,
            "iocs": json.dumps(merged_iocs),
            "significance": significance,
            "significance_score": sig.significance_score(significance) if significance else None,
        },
    )
    await conn.commit()


async def get_research_runs_for_case(conn: aiosqlite.Connection, case_id: int) -> list[dict]:
    rows = await conn.execute_fetchall(
        "SELECT * FROM research_runs WHERE case_id = :case_id ORDER BY started_at DESC",
        {"case_id": case_id},
    )
    out = []
    for r in rows:
        d = dict(r)
        d["findings"] = json.loads(d["findings"]) if d["findings"] else {}
        d["sources"] = json.loads(d["sources"]) if d["sources"] else []
        out.append(d)
    return out


# ── Targeted investigation (research/investigate.py) ────────────────────────

async def create_investigation(conn: aiosqlite.Connection, *, brief: str) -> int:
    cur = await conn.execute(
        "INSERT INTO investigations (brief, status, created_at) VALUES (:brief, 'queued', :created_at)",
        {"brief": brief, "created_at": _utcnow().isoformat()},
    )
    await conn.commit()
    return cur.lastrowid


async def get_queued_investigations(conn: aiosqlite.Connection, *, limit: int) -> list[dict]:
    """Drain investigations that need work. Includes 'running' rows so a
    crash/restart mid-run doesn't leave an investigation stuck forever
    (the scheduler is single-worker, so a stale 'running' row is safe to
    resume rather than duplicate). A re-queued (status='queued', attempts>0)
    row is skipped until next_retry_at elapses — see requeue_investigation."""
    rows = await conn.execute_fetchall(
        """
        SELECT * FROM investigations
        WHERE status IN ('queued', 'running')
          AND (next_retry_at IS NULL OR next_retry_at <= :now)
        ORDER BY id ASC LIMIT :limit
        """,
        {"limit": limit, "now": _utcnow().isoformat()},
    )
    return [dict(r) for r in rows]


async def count_queued_investigations(conn: aiosqlite.Connection) -> int:
    """Backlog depth — surfaced via /api/status. Mirrors get_queued_investigations'
    cooldown gate so a row waiting out a retry cooldown isn't counted as
    immediately actionable backlog."""
    row = await conn.execute_fetchall(
        """
        SELECT COUNT(*) AS n FROM investigations
        WHERE status = 'queued' AND (next_retry_at IS NULL OR next_retry_at <= :now)
        """,
        {"now": _utcnow().isoformat()},
    )
    return row[0]["n"] if row else 0


async def requeue_investigation(
    conn: aiosqlite.Connection, *, investigation_id: int, error: str, next_retry_at: str,
) -> None:
    """Send a transiently-failed investigation back to 'queued' instead of
    'failed' (see research/investigate.py, settings.investigate_max_attempts)
    — bumps attempts and sets a cooldown so it isn't immediately re-drained
    into the same failure. finish_investigation remains the terminal path
    for permanent failures / completed / no_match."""
    await conn.execute(
        """
        UPDATE investigations SET
            status = 'queued', attempts = attempts + 1,
            next_retry_at = :next_retry_at, error = :error
        WHERE id = :id
        """,
        {"id": investigation_id, "error": error, "next_retry_at": next_retry_at},
    )
    await conn.commit()


async def mark_investigation_running(conn: aiosqlite.Connection, *, investigation_id: int) -> None:
    await conn.execute(
        "UPDATE investigations SET status = 'running' WHERE id = :id",
        {"id": investigation_id},
    )
    await conn.commit()


async def finish_investigation(
    conn: aiosqlite.Connection,
    *,
    investigation_id: int,
    status: str,
    findings: dict,
    case_id: int | None = None,
    error: str | None = None,
) -> None:
    await conn.execute(
        """
        UPDATE investigations SET
            status = :status, findings = :findings, case_id = :case_id,
            error = :error, finished_at = :finished_at
        WHERE id = :id
        """,
        {
            "id": investigation_id,
            "status": status,
            "findings": json.dumps(findings),
            "case_id": case_id,
            "error": error,
            "finished_at": _utcnow().isoformat(),
        },
    )
    await conn.commit()


async def list_investigations(conn: aiosqlite.Connection, *, limit: int = 50) -> list[dict]:
    rows = await conn.execute_fetchall(
        "SELECT * FROM investigations ORDER BY id DESC LIMIT :limit", {"limit": limit}
    )
    out = []
    for r in rows:
        d = dict(r)
        d["findings"] = json.loads(d["findings"]) if d["findings"] else {}
        out.append(d)
    return out


async def get_investigation(conn: aiosqlite.Connection, investigation_id: int) -> dict | None:
    rows = await conn.execute_fetchall(
        "SELECT * FROM investigations WHERE id = :id", {"id": investigation_id}
    )
    if not rows:
        return None
    d = dict(rows[0])
    d["findings"] = json.loads(d["findings"]) if d["findings"] else {}
    return d


# ── Self-healing source proposals (research/heal.py) ────────────────────────

async def source_recently_proposed(conn: aiosqlite.Connection, *, source_id: str, since_iso: str) -> bool:
    rows = await conn.execute_fetchall(
        """
        SELECT 1 FROM source_heal_proposals
        WHERE source_id = :source_id AND created_at >= :since LIMIT 1
        """,
        {"source_id": source_id, "since": since_iso},
    )
    return bool(rows)


async def create_heal_proposal(
    conn: aiosqlite.Connection, *, source_id: str, proposal: dict, notes: str | None, action: str = "heal"
) -> int:
    """action: "heal" (fix a broken source), "prune" (disable/remove a
    low-value source), or "discover" (a brand-new candidate source) — see
    research/heal.py and research/discover.py."""
    cur = await conn.execute(
        """
        INSERT INTO source_heal_proposals (source_id, status, proposal, notes, created_at, action)
        VALUES (:source_id, 'pending', :proposal, :notes, :created_at, :action)
        """,
        {
            "source_id": source_id,
            "proposal": json.dumps(proposal),
            "notes": notes,
            "created_at": _utcnow().isoformat(),
            "action": action,
        },
    )
    await conn.commit()
    return cur.lastrowid


async def update_heal_proposal_status(
    conn: aiosqlite.Connection, *, proposal_id: int, status: str, error: str | None = None
) -> None:
    await conn.execute(
        """
        UPDATE source_heal_proposals SET status = :status, error = :error, validated_at = :validated_at
        WHERE id = :id
        """,
        {
            "id": proposal_id,
            "status": status,
            "error": error,
            "validated_at": _utcnow().isoformat(),
        },
    )
    await conn.commit()


async def record_applied_change(
    conn: aiosqlite.Connection, *, proposal_id: int, before: dict, after: dict
) -> None:
    """Mark a proposal as actually applied to sources.yaml (see
    sources/writer.py) and record the before/after snapshot for audit —
    every autonomous edit must be reviewable and revertible without diffing
    the file by hand."""
    await conn.execute(
        """
        UPDATE source_heal_proposals SET
            applied = 1, before_value = :before, after_value = :after
        WHERE id = :id
        """,
        {"id": proposal_id, "before": json.dumps(before), "after": json.dumps(after)},
    )
    await conn.commit()


async def get_heal_proposals(conn: aiosqlite.Connection, *, status: str | None = None) -> list[dict]:
    if status:
        rows = await conn.execute_fetchall(
            "SELECT * FROM source_heal_proposals WHERE status = :status ORDER BY created_at DESC",
            {"status": status},
        )
    else:
        rows = await conn.execute_fetchall(
            "SELECT * FROM source_heal_proposals ORDER BY created_at DESC LIMIT 100"
        )
    out = []
    for r in rows:
        d = dict(r)
        d["proposal"] = json.loads(d["proposal"]) if d["proposal"] else {}
        out.append(d)
    return out


async def count_heal_proposals_by_status(conn: aiosqlite.Connection) -> dict[str, int]:
    """Proposal-status summary — surfaced in /api/status."""
    rows = await conn.execute_fetchall(
        "SELECT status, COUNT(*) AS n FROM source_heal_proposals GROUP BY status"
    )
    counts: dict[str, int] = {"pending": 0, "validated": 0, "probe_failed": 0, "rejected": 0}
    for r in rows:
        if r["status"] in counts:
            counts[r["status"]] = r["n"]
    return counts


async def count_running_research_runs(conn: aiosqlite.Connection) -> int:
    """Currently in-flight hermes-agent research runs — surfaced in /api/status."""
    row = await conn.execute_fetchall(
        "SELECT COUNT(*) AS n FROM research_runs WHERE status = 'running'"
    )
    return row[0]["n"] if row else 0


# ── Analyst feedback (POST /api/feedback) ───────────────────────────────────
# Feeds sources/value.py's investigation-value scoring and is digested into
# heal/discover prompts (research/heal.py, research/discover.py) so the
# autonomous source loop knows which sources the analyst trusts.

VALID_FEEDBACK_VERDICTS = {"useful", "not_useful", "noise", "wrong_attribution"}
VALID_FEEDBACK_ORIGINS = {"human", "agent"}


async def add_feedback(
    conn: aiosqlite.Connection,
    *,
    case_id: int | None,
    item_id: int | None,
    verdict: str,
    note: str | None,
    origin: str = "human",
) -> int:
    if verdict not in VALID_FEEDBACK_VERDICTS:
        raise ValueError(f"invalid verdict: {verdict!r}")
    if origin not in VALID_FEEDBACK_ORIGINS:
        raise ValueError(f"invalid origin: {origin!r}")
    if bool(case_id) == bool(item_id):
        raise ValueError("feedback needs exactly one of case_id or item_id")
    cur = await conn.execute(
        """
        INSERT INTO feedback (case_id, item_id, verdict, note, origin, created_at)
        VALUES (:case_id, :item_id, :verdict, :note, :origin, :created_at)
        """,
        {
            "case_id": case_id,
            "item_id": item_id,
            "verdict": verdict,
            "note": (note or "")[:1000] or None,
            "origin": origin,
            "created_at": _utcnow().isoformat(),
        },
    )
    await conn.commit()
    return cur.lastrowid


async def get_case_for_evaluation(conn: aiosqlite.Connection) -> dict | None:
    """Pick a case for research/evaluator.py to judge — biased toward recent
    cases with the fewest existing feedback rows (so the agent fills gaps
    human review hasn't reached yet, rather than re-grading the same
    well-covered cases), with a random tiebreak among equally under-covered
    candidates so the agent doesn't loop on the same single case forever."""
    rows = await conn.execute_fetchall(
        """
        SELECT c.id, c.title, COUNT(f.id) AS feedback_count
        FROM cases c
        LEFT JOIN feedback f ON f.case_id = c.id
        GROUP BY c.id
        ORDER BY feedback_count ASC, c.first_seen DESC
        LIMIT 20
        """
    )
    if not rows:
        return None
    min_count = rows[0]["feedback_count"]
    candidates = [dict(r) for r in rows if r["feedback_count"] == min_count]
    return random.choice(candidates)


async def get_feedback_for_case(conn: aiosqlite.Connection, case_id: int) -> list[dict]:
    rows = await conn.execute_fetchall(
        "SELECT * FROM feedback WHERE case_id = :case_id ORDER BY created_at DESC",
        {"case_id": case_id},
    )
    return [dict(r) for r in rows]


async def aggregate_feedback_by_source(
    conn: aiosqlite.Connection, *, since_iso: str
) -> dict[str, dict[str, dict[str, int]]]:
    """Verdict counts per source_id since `since_iso`, split by feedback
    origin ("human" vs "agent" — see research/evaluator.py), joining
    feedback → item/case → originating items.source_id. A case's feedback is
    attributed to every source that contributed an item to it (a case can
    span multiple sources). Returns {source_id: {origin: {verdict: count}}}.
    Used by sources/value.py's feedback component (which weighs human and
    agent counts differently) and to digest "why" into heal/discover
    prompts."""
    rows = await conn.execute_fetchall(
        """
        SELECT i.source_id AS source_id, f.origin AS origin, f.verdict AS verdict, COUNT(*) AS n
        FROM feedback f
        JOIN items i ON i.id = f.item_id
        WHERE f.created_at >= :since AND f.item_id IS NOT NULL
        GROUP BY i.source_id, f.origin, f.verdict

        UNION ALL

        SELECT i.source_id AS source_id, f.origin AS origin, f.verdict AS verdict, COUNT(*) AS n
        FROM feedback f
        JOIN case_items ci ON ci.case_id = f.case_id
        JOIN items i ON i.id = ci.item_id
        WHERE f.created_at >= :since AND f.case_id IS NOT NULL
        GROUP BY i.source_id, f.origin, f.verdict
        """,
        {"since": since_iso},
    )
    out: dict[str, dict[str, dict[str, int]]] = {}
    for r in rows:
        by_origin = out.setdefault(r["source_id"], {})
        by_verdict = by_origin.setdefault(r["origin"], {})
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + r["n"]
    return out


# ── Investigation-value snapshot (sources/value.py) ─────────────────────────

async def save_source_value(
    conn: aiosqlite.Connection, *, source_id: str, score: float, classification: str, components: dict
) -> None:
    await conn.execute(
        """
        INSERT INTO source_value (source_id, score, classification, components, computed_at)
        VALUES (:source_id, :score, :classification, :components, :computed_at)
        ON CONFLICT(source_id) DO UPDATE SET
            score = excluded.score, classification = excluded.classification,
            components = excluded.components, computed_at = excluded.computed_at
        """,
        {
            "source_id": source_id,
            "score": score,
            "classification": classification,
            "components": json.dumps(components),
            "computed_at": _utcnow().isoformat(),
        },
    )
    await conn.commit()


async def get_source_value(conn: aiosqlite.Connection, source_id: str) -> dict | None:
    rows = await conn.execute_fetchall(
        "SELECT * FROM source_value WHERE source_id = :source_id", {"source_id": source_id}
    )
    if not rows:
        return None
    d = dict(rows[0])
    d["components"] = json.loads(d["components"]) if d["components"] else {}
    return d


async def get_all_source_values(conn: aiosqlite.Connection) -> dict[str, dict]:
    """Whole cached value snapshot — used both by the dashboard (/api/sources)
    and by the autonomous loop's relative/percentile comparisons (a source's
    classification is judged against its peers, not a fixed cutoff)."""
    rows = await conn.execute_fetchall("SELECT * FROM source_value")
    out = {}
    for r in rows:
        d = dict(r)
        d["components"] = json.loads(d["components"]) if d["components"] else {}
        out[d["source_id"]] = d
    return out


async def yield_stats_by_source(conn: aiosqlite.Connection, *, since_iso: str) -> dict[str, dict]:
    """Per-source extraction yield over the window: total extracted, non-
    false-positive rate, share reaching warn/critical, mean confidence. The
    "yield quality" component of sources/value.py's score."""
    rows = await conn.execute_fetchall(
        """
        SELECT i.source_id AS source_id,
               COUNT(*) AS total,
               SUM(CASE WHEN e.false_positive = 0 THEN 1 ELSE 0 END) AS useful,
               SUM(CASE WHEN e.significance IN ('warn', 'critical') THEN 1 ELSE 0 END) AS significant,
               AVG(e.confidence) AS mean_confidence
        FROM extractions e
        JOIN items i ON i.id = e.item_id
        WHERE e.extracted_at >= :since
        GROUP BY i.source_id
        """,
        {"since": since_iso},
    )
    return {r["source_id"]: dict(r) for r in rows}


async def case_contribution_by_source(conn: aiosqlite.Connection, *, since_iso: str) -> dict[str, dict]:
    """Per-source contribution to cases: how many distinct cases this
    source's items are linked into, weighted toward confirmed/significant
    cases. The "case contribution" component of sources/value.py's score."""
    rows = await conn.execute_fetchall(
        """
        SELECT i.source_id AS source_id,
               COUNT(DISTINCT c.id) AS cases_touched,
               SUM(CASE WHEN c.status = 'confirmed' THEN 1 ELSE 0 END) AS confirmed_links,
               SUM(CASE WHEN c.significance IN ('warn', 'critical') THEN 1 ELSE 0 END) AS significant_links
        FROM case_items ci
        JOIN items i ON i.id = ci.item_id
        JOIN cases c ON c.id = ci.case_id
        WHERE i.seen_at >= :since
        GROUP BY i.source_id
        """,
        {"since": since_iso},
    )
    return {r["source_id"]: dict(r) for r in rows}


# ── Algorithmic case-to-case correlation (pipeline/cross_correlate.py) ──────

async def save_case_link(
    conn: aiosqlite.Connection, *, case_a: int, case_b: int, score: float, reasons: list[str]
) -> bool:
    """Persist (or refresh) a symmetric case-to-case link. Returns True if
    this call inserted a new row, False if the pair already existed and was
    only updated. Callers use the return value to decide whether to emit an
    audit-log event for a genuinely new correlation."""
    lo, hi = (case_a, case_b) if case_a < case_b else (case_b, case_a)
    computed_at = _utcnow().isoformat()
    reasons_json = json.dumps(reasons)
    cur = await conn.execute(
        """
        INSERT OR IGNORE INTO case_links (case_a, case_b, score, reasons, computed_at)
        VALUES (:a, :b, :score, :reasons, :computed_at)
        """,
        {
            "a": lo,
            "b": hi,
            "score": score,
            "reasons": reasons_json,
            "computed_at": computed_at,
        },
    )
    if cur.rowcount and cur.rowcount > 0:
        await conn.commit()
        return True
    await conn.execute(
        """
        UPDATE case_links
        SET score = :score, reasons = :reasons, computed_at = :computed_at
        WHERE case_a = :a AND case_b = :b
        """,
        {
            "a": lo,
            "b": hi,
            "score": score,
            "reasons": reasons_json,
            "computed_at": computed_at,
        },
    )
    await conn.commit()
    return False


async def get_case_links(conn: aiosqlite.Connection, case_id: int) -> list[dict]:
    """Related cases for the detail pane — both directions of the symmetric
    pair, joined with the related case's headline fields so the UI doesn't
    need a second round-trip per link."""
    rows = await conn.execute_fetchall(
        """
        SELECT cl.score, cl.reasons,
               c.id AS case_id, c.title, c.significance, c.damaged_party, c.attribution
        FROM case_links cl
        JOIN cases c ON c.id = (CASE WHEN cl.case_a = :case_id THEN cl.case_b ELSE cl.case_a END)
        WHERE cl.case_a = :case_id OR cl.case_b = :case_id
        ORDER BY cl.score DESC
        LIMIT 20
        """,
        {"case_id": case_id},
    )
    out = []
    for r in rows:
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
        out.append(d)
    return out


async def get_cases_for_cross_correlation(conn: aiosqlite.Connection, *, since_iso: str) -> list[dict]:
    """Cases active within the window — the candidate pool for
    pipeline/cross_correlate.py's pairwise overlap scan. Bounded by recency
    for the same reason find_candidate_cases is: an old, settled case
    shouldn't get re-linked against every new case forever."""
    rows = await conn.execute_fetchall(
        "SELECT * FROM cases WHERE last_seen >= :since ORDER BY last_seen DESC",
        {"since": since_iso},
    )
    out = []
    for r in rows:
        d = dict(r)
        d["cve_ids"] = json.loads(d["cve_ids"]) if d["cve_ids"] else []
        d["iocs"] = json.loads(d["iocs"]) if d["iocs"] else []
        out.append(d)
    return out


async def get_case_items(conn: aiosqlite.Connection, case_id: int) -> list[dict]:
    """The raw observations linked into a case — the case detail view's
    corroboration list. Ordered by real-world event date (published_at when
    known, else seen_at) so the timeline reflects when things happened, not
    when our scraper picked them up."""
    rows = await conn.execute_fetchall(
        """
        SELECT i.id, i.source_id, i.source_name, i.title, i.url, i.snippet,
               i.published_at, i.seen_at
        FROM case_items ci JOIN items i ON i.id = ci.item_id
        WHERE ci.case_id = :case_id
        ORDER BY COALESCE(i.published_at, i.seen_at) DESC
        """,
        {"case_id": case_id},
    )
    return [dict(r) for r in rows]


async def stats_cases_by_crime_type(conn: aiosqlite.Connection, *, since_iso: str | None = None) -> list[dict]:
    where = "WHERE first_seen >= :since" if since_iso else ""
    rows = await conn.execute_fetchall(
        f"SELECT crime_type, COUNT(*) AS n FROM cases {where} GROUP BY crime_type ORDER BY n DESC",
        {"since": since_iso} if since_iso else {},
    )
    return [dict(r) for r in rows]


async def stats_cases_in_kev(conn: aiosqlite.Connection, *, since_iso: str | None = None) -> int:
    where = "WHERE in_kev = 1" + (" AND first_seen >= :since" if since_iso else "")
    row = await conn.execute_fetchall(
        f"SELECT COUNT(*) AS n FROM cases {where}", {"since": since_iso} if since_iso else {}
    )
    return row[0]["n"] if row else 0


# ── Trends ────────────────────────────────────────────────────────────────────
# Week-over-week (or whatever window_days the caller picks) movement per
# dimension value, driving the Landscape tab's "Emerging this week" panels.
# Always keyed off cases.first_seen, same reasoning as stats_cases_timeseries
# above: cases are never pruned, so a real previous-vs-current comparison is
# possible at any window size, unlike the item-based stats_* functions.

_TREND_DIMENSION_COLUMNS = {
    "actor": "attribution",
    "sector": "damaged_party_sector",
    "crime_type": "crime_type",
}


def _trend_status(current: int, previous: int) -> str:
    if current > 0 and previous == 0:
        return "emerging"
    if current > previous:
        return "rising"
    if current < previous:
        return "declining"
    return "flat"


async def stats_trends(
    conn: aiosqlite.Connection, *, dimension: str, window_days: int = 7, limit: int = 10
) -> list[dict]:
    """Compares case counts per `dimension` value between the current
    window [now - window_days, now] and the immediately preceding window
    of the same length [now - 2*window_days, now - window_days]. dimension
    is one of "actor", "sector", "crime_type", "cve" — the first three are
    a single grouped-column count; "cve" unpacks each case's cve_ids JSON
    array in Python since SQLite has no convenient way to GROUP BY a JSON
    array element inline with the rest of this module's query style.
    Returns entries sorted by current-window count, descending, dropping
    the (very common) case where both windows are zero — that's not a
    trend, just absence."""
    now = _utcnow()
    current_since = (now - timedelta(days=window_days)).isoformat()
    previous_since = (now - timedelta(days=2 * window_days)).isoformat()
    casing_counts: dict[str, dict[str, int]] = {}  # lower -> {original: n}; "cve" dimension leaves this empty

    if dimension == "cve":
        rows = await conn.execute_fetchall(
            "SELECT first_seen, cve_ids FROM cases WHERE first_seen >= :since",
            {"since": previous_since},
        )
        current_counts: dict[str, int] = {}
        previous_counts: dict[str, int] = {}
        for r in rows:
            cve_ids = json.loads(r["cve_ids"]) if r["cve_ids"] else []
            bucket = current_counts if r["first_seen"] >= current_since else previous_counts
            for cve_id in cve_ids:
                bucket[cve_id] = bucket.get(cve_id, 0) + 1
        values = list(set(current_counts) | set(previous_counts))
        kev_set: set[str] = set()
        chunk_size = 500  # stay well under SQLite's default 999 bound-variable limit
        for i in range(0, len(values), chunk_size):
            chunk = values[i : i + chunk_size]
            placeholders = ",".join(f":k{j}" for j in range(len(chunk)))
            kev_rows = await conn.execute_fetchall(
                f"SELECT cve_id FROM kev_catalog WHERE cve_id IN ({placeholders})",
                {f"k{j}": v for j, v in enumerate(chunk)},
            )
            kev_set.update(r["cve_id"] for r in kev_rows)
    else:
        kev_set = set()
        column = _TREND_DIMENSION_COLUMNS.get(dimension)
        if column is None:
            raise ValueError(f"unknown trend dimension: {dimension!r}")
        rows = await conn.execute_fetchall(
            f"""
            SELECT {column} AS value, first_seen FROM cases
            WHERE first_seen >= :since AND {column} IS NOT NULL AND {column} != ''
            """,
            {"since": previous_since},
        )
        # actor/sector are free text and vary in casing for the same entity
        # (e.g. "LockBit5" vs "lockbit5") — bucket case-insensitively and
        # track each casing's frequency so the displayed label is still a
        # real, human-readable string (most frequent casing) rather than a
        # lowercased key. crime_type is a controlled enum, no casing issue.
        casefold = dimension in ("actor", "sector")
        current_counts = {}
        previous_counts = {}
        for r in rows:
            raw = r["value"]
            key = raw.lower() if casefold else raw
            if casefold:
                c = casing_counts.setdefault(key, {})
                c[raw] = c.get(raw, 0) + 1
            bucket = current_counts if r["first_seen"] >= current_since else previous_counts
            bucket[key] = bucket.get(key, 0) + 1
        values = set(current_counts) | set(previous_counts)

    out = []
    for v in values:
        current = current_counts.get(v, 0)
        previous = previous_counts.get(v, 0)
        if current == 0 and previous == 0:
            continue
        display = v
        if dimension != "cve" and v in casing_counts:
            display = sorted(casing_counts[v].items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        entry = {
            "value": display,
            "current": current,
            "previous": previous,
            "delta": current - previous,
            "status": _trend_status(current, previous),
        }
        if dimension == "cve":
            entry["in_kev"] = v in kev_set
        out.append(entry)
    out.sort(key=lambda e: e["current"], reverse=True)
    return out[:limit]


# ── Landscape aggregations ───────────────────────────────────────────────────
# Case-layer (deduplicated incident) aggregations for the Landscape tab — the
# case is the right unit for a landscape view, vs. raw items which double-
# count every corroborating report of the same incident. All accept an
# optional since_iso window (derived from since_days in routes.py) so the
# tab's 24h/7d/30d/90d/all selector can re-slice the same queries.

# Free-text entity columns (attribution/sector/country) routinely vary in
# casing for the same real-world value (e.g. "LockBit5" vs "lockbit5" from
# different extraction passes) — a plain `GROUP BY column` then splits one
# entity into multiple leaderboard bars. This helper groups case-
# insensitively while still surfacing a real display label (the most
# frequent original casing, ties broken alphabetically) and a count summed
# across every casing variant. crime_type is a controlled enum and doesn't
# need this treatment.
#
# Single pass over `cases` (the `counted` CTE), then window-function ranking
# over the much smaller per-casing aggregate — avoids a correlated subquery
# that would re-scan the base table once per distinct lower(column) value.
def _build_casefold_leaderboard_sql(column: str, *, where: str) -> str:
    return f"""
        WITH counted AS (
            SELECT {column} AS casing, lower({column}) AS key, COUNT(*) AS casing_n
            FROM cases c
            {where}
            GROUP BY {column}
        ), totals AS (
            SELECT key, SUM(casing_n) AS n FROM counted GROUP BY key
        ), ranked AS (
            SELECT key, casing,
                   ROW_NUMBER() OVER (PARTITION BY key ORDER BY casing_n DESC, casing ASC) AS rn
            FROM counted
        )
        SELECT ranked.casing AS value, totals.n AS n
        FROM ranked JOIN totals ON totals.key = ranked.key
        WHERE ranked.rn = 1
        ORDER BY n DESC
    """


async def stats_cases_by_sector(conn: aiosqlite.Connection, *, since_iso: str | None = None) -> list[dict]:
    where = "WHERE c.damaged_party_sector IS NOT NULL AND c.damaged_party_sector != ''"
    params: dict = {}
    if since_iso:
        where += " AND c.first_seen >= :since"
        params["since"] = since_iso
    sql = _build_casefold_leaderboard_sql("damaged_party_sector", where=where)
    rows = await conn.execute_fetchall(sql, params)
    return [{"sector": r["value"], "n": r["n"]} for r in rows]


async def stats_cases_by_country(conn: aiosqlite.Connection, *, since_iso: str | None = None) -> list[dict]:
    where = "WHERE c.damaged_party_country IS NOT NULL AND TRIM(c.damaged_party_country) != ''"
    params: dict = {}
    if since_iso:
        where += " AND c.first_seen >= :since"
        params["since"] = since_iso
    sql = _build_casefold_leaderboard_sql("damaged_party_country", where=where)
    rows = await conn.execute_fetchall(sql, params)
    return [{"country": r["value"], "n": r["n"]} for r in rows]


async def cases_country_counts(
    conn: aiosqlite.Connection,
    *,
    min_significance: str | None = None,
    crime_type: str | None = None,
    in_kev: bool | None = None,
    search: str | None = None,
    cve_id: str | None = None,
    ioc: str | None = None,
    since: str | None = None,
    until: str | None = None,
    id_in: list[int] | None = None,
) -> list[dict]:
    """Per-country case counts honoring the same Cases-tab filters as
    fetch_cases (last_seen-based since/until, not Landscape's first_seen
    window) — backs the Cases tab's victim-country dropdown. Deliberately
    has no `country` parameter, unlike fetch_cases: this *is* the
    country breakdown, so filtering it down to one already-selected
    country would collapse the dropdown to a single option. Values are
    normalized ISO alpha-2 codes (see country.py), so a plain GROUP BY is
    enough — no casefold leaderboard needed here. `id_in` scopes to a
    semantic-search candidate set, mirroring fetch_cases' same parameter."""
    where, params = _build_cases_where(
        min_significance=min_significance, crime_type=crime_type, in_kev=in_kev,
        search=search, cve_id=cve_id, ioc=ioc, since=since, until=until,
        id_in=id_in,
    )
    country_clause = "damaged_party_country IS NOT NULL AND TRIM(damaged_party_country) != ''"
    where = f"{where} AND {country_clause}" if where else f"WHERE {country_clause}"
    rows = await conn.execute_fetchall(
        f"""
        SELECT damaged_party_country AS country, COUNT(*) AS n
        FROM cases
        {where}
        GROUP BY damaged_party_country
        ORDER BY n DESC
        """,
        params,
    )
    return [{"country": r["country"], "n": r["n"]} for r in rows]


async def stats_cases_timeseries(
    conn: aiosqlite.Connection, *, bucket: str = "day", since_iso: str | None = None
) -> list[dict]:
    """Case-volume-over-time for the Landscape tab's "Incident volume" chart.
    Deliberately separate from stats_timeseries (items.seen_at, hard-capped
    at 30 days) — cases are never pruned by retention (see
    prune_old_items's docstring), so this is the only series that can
    honestly cover a 90-day or "all time" window. bucket="day" for
    day-granularity (short windows); anything else buckets by calendar
    month (long windows, where per-day bars would be unreadable)."""
    where = "WHERE first_seen >= :since" if since_iso else ""
    rows = await conn.execute_fetchall(
        f"SELECT first_seen, significance FROM cases {where}", {"since": since_iso} if since_iso else {}
    )
    buckets: dict[str, dict[str, int]] = {}
    for r in rows:
        first_seen = r["first_seen"] or ""
        key = first_seen[:10] if bucket == "day" else first_seen[:7]  # YYYY-MM-DD vs YYYY-MM
        sig = r["significance"] or "info"
        if sig not in ("info", "warn", "critical"):
            sig = "info"
        b = buckets.setdefault(key, {"info": 0, "warn": 0, "critical": 0})
        b[sig] += 1
    return [{"bucket": k, **v} for k, v in sorted(buckets.items())]


async def get_actor_profile(conn: aiosqlite.Connection, actor: str, *, case_limit: int = 50) -> dict | None:
    """Full aggregate profile for one attributed actor — backs the
    Landscape tab's actor-leaderboard click-through. Unlike computing this
    client-side from a paginated /api/cases?actor= call (which the frontend
    did before this existed), the aggregates here are computed over *every*
    matching case, not just the first page, so victim/sector/CVE counts for
    a prolific actor aren't silently undercounted; `cases` itself is still
    capped (case_limit) since the UI only needs a browsable list, not every
    row in memory."""
    # Case-insensitive: the leaderboard (stats_cases_by_actor) merges casing
    # variants of the same actor into one entry, so the click-through here
    # must pull every casing too, not just an exact-cased match.
    all_rows = await conn.execute_fetchall(
        """
        SELECT id, title, damaged_party, damaged_party_sector, damaged_party_country,
               cve_ids, first_seen, last_seen, significance
        FROM cases WHERE lower(attribution) = lower(:actor)
        """,
        {"actor": actor},
    )
    if not all_rows:
        return None

    victims, sectors, countries, cve_ids = set(), set(), set(), set()
    first_seen = last_seen = None
    monthly: dict[str, int] = {}
    for r in all_rows:
        if r["damaged_party"]:
            victims.add(r["damaged_party"])
        if r["damaged_party_sector"]:
            sectors.add(r["damaged_party_sector"])
        if r["damaged_party_country"]:
            countries.add(r["damaged_party_country"])
        for cve_id in (json.loads(r["cve_ids"]) if r["cve_ids"] else []):
            cve_ids.add(cve_id)
        if first_seen is None or r["first_seen"] < first_seen:
            first_seen = r["first_seen"]
        if last_seen is None or r["last_seen"] > last_seen:
            last_seen = r["last_seen"]
        month_key = (r["first_seen"] or "")[:7]
        monthly[month_key] = monthly.get(month_key, 0) + 1

    cases_rows = await conn.execute_fetchall(
        """
        SELECT id, title, damaged_party, damaged_party_sector, damaged_party_country,
               significance, first_seen, last_seen
        FROM cases WHERE lower(attribution) = lower(:actor)
        ORDER BY last_seen DESC LIMIT :limit
        """,
        {"actor": actor, "limit": case_limit},
    )

    return {
        "actor": actor,
        "case_count": len(all_rows),
        "victim_count": len(victims),
        "sectors": sorted(sectors),
        "countries": sorted(countries),
        "cve_ids": sorted(cve_ids),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "activity": [{"bucket": k, "n": v} for k, v in sorted(monthly.items())],
        "cases": [dict(r) for r in cases_rows],
    }


async def stats_cases_by_actor(
    conn: aiosqlite.Connection, *, since_iso: str | None = None, limit: int = 15
) -> list[dict]:
    """Case-based actor leaderboard — counts each actor's activity once per
    deduplicated incident (case), not once per corroborating report. This is
    the canonical actor leaderboard, used by both the Landscape tab and the
    Feed tab's "Most active ransomware actors" chart — there is no longer a
    separate item/mention-based variant (that approach over-counted actors
    proportional to press coverage and relied on a heuristic regex guess at
    the actor name; see git history if you need the old behavior).

    Case-insensitive: see _build_casefold_leaderboard_sql's docstring —
    "LockBit5" and "lockbit5" merge into one bar with a summed count."""
    where = "WHERE c.attribution IS NOT NULL AND c.attribution != ''"
    params: dict = {"limit": limit}
    if since_iso:
        where += " AND c.first_seen >= :since"
        params["since"] = since_iso
    sql = _build_casefold_leaderboard_sql("attribution", where=where) + " LIMIT :limit"
    rows = await conn.execute_fetchall(sql, params)
    return [{"actor": r["value"], "n": r["n"]} for r in rows]


async def run_significance_decay(conn: aiosqlite.Connection, *, now: datetime | None = None) -> int:
    """Mechanical staleness safety-net — the "no research pass needed"
    half of the hybrid ongoing-metric (see research/agent.py's
    _RESEARCH_PROMPT_TEMPLATE case-level rubric for the researcher's half).

    A warn/critical case that nobody is feeding (no new corroborating item)
    AND that research hasn't actively touched within
    settings.research_stale_window_seconds is no longer "ongoing" by
    definition and gets capped down: more than one window since last_seen
    caps at "warn", more than two windows caps at "info". Only ever lowers
    significance (min(current, cap)) — it can't escalate a case, that's the
    researcher's job alone.

    Deliberately skips any case research has completed within the window —
    that case's level is owned by the researcher's own verdict (see
    merge_item_into_case's precedence note), not this job; a case that's on
    a daily critical research cadence is therefore never touched here.
    Stateless and idempotent: recomputed fresh from last_seen/research_runs
    every tick, no "last decayed" bookkeeping needed. Returns the number of
    cases stepped down."""
    now = now or _utcnow()
    window = settings.research_stale_window_seconds
    if window <= 0:
        return 0
    stale_cutoff = (now - timedelta(seconds=window)).isoformat()
    two_window_cutoff = (now - timedelta(seconds=2 * window)).isoformat()

    rows = await conn.execute_fetchall(
        """
        SELECT id, significance, last_seen FROM cases
        WHERE significance IN ('warn', 'critical')
          AND last_seen < :stale_cutoff
          AND NOT EXISTS (
            SELECT 1 FROM research_runs r
            WHERE r.case_id = cases.id
              AND r.status = 'completed'
              AND r.started_at >= :stale_cutoff
          )
        """,
        {"stale_cutoff": stale_cutoff},
    )

    decayed = 0
    for row in rows:
        cap = "info" if row["last_seen"] < two_window_cutoff else "warn"
        if sig.SIG_RANK[cap] >= sig.SIG_RANK[row["significance"]]:
            continue
        await conn.execute(
            "UPDATE cases SET significance = :sig, significance_score = :score WHERE id = :id",
            {"sig": cap, "score": sig.significance_score(cap), "id": row["id"]},
        )
        decayed += 1
    if decayed:
        await conn.commit()
    return decayed
