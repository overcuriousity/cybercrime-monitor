"""sqlite-vec lifecycle and integrity for semantic search.

Two tables back this (added to db.py's _SCHEMA, like every other table):
  - embedding_meta: single row recording which backend/model/dimension the
    *currently stored* vectors were produced with.
  - vec_index_state: per-row (kind, ref_id) -> content_hash + fingerprint,
    used to detect both "this row's text changed since it was embedded" and
    "this row was embedded under a since-replaced backend."

The vec0 virtual tables themselves (vec_cases, vec_items) are NOT created
here at startup — their column width depends on the active model's
dimension, which isn't known until the first embed call succeeds (see
backend.active_dim's docstring). ensure_vec_table() creates them lazily,
called by embeddings/job.py right before the first upsert.

INTEGRITY CONTRACT: init_vectors() runs once per process start (from
db.open_db, right after _migrate) and compares the active backend's
fingerprint (backend.active_fingerprint() — a cheap string hash, no model
load) against what's stored in embedding_meta. Any mismatch — including the
very first run, or switching local -> openai — drops vec_cases/vec_items
and clears vec_index_state outright. This is deliberate data loss: vectors
from one embedding space are not comparable to vectors from another, so
"keep the old ones around just in case" would silently corrupt every
similarity score with no visible symptom. embeddings/job.py's normal
incremental-indexing pass then rebuilds the index from scratch.
"""
import logging
import struct
from datetime import datetime, timezone

import sqlite_vec

from ..settings import settings
from . import backend as embed_backend

log = logging.getLogger(__name__)

_VEC_TABLES = {"cases": "vec_cases", "items": "vec_items"}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _table_exists(conn, name: str) -> bool:
    rows = await conn.execute_fetchall(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = :name", {"name": name}
    )
    return bool(rows)


async def init_vectors(conn) -> None:
    """See module docstring. No-op entirely when embed_backend == "none" —
    the sqlite-vec extension is never loaded and embedding_meta/
    vec_index_state stay whatever they were (empty on a fresh DB), so
    flipping the backend back on later is just a normal fingerprint
    mismatch on the next startup."""
    if settings.embed_backend == "none":
        return

    await conn.enable_load_extension(True)
    try:
        await conn.load_extension(sqlite_vec.loadable_path())
    finally:
        # Always disable, even if the load itself failed (missing binary,
        # unsupported platform) — leaving extension loading enabled on this
        # connection would be a needless attack-surface widening.
        await conn.enable_load_extension(False)

    fp = embed_backend.active_fingerprint()
    rows = await conn.execute_fetchall("SELECT fingerprint FROM embedding_meta WHERE id = 1")
    stored_fp = rows[0]["fingerprint"] if rows else None

    if stored_fp == fp:
        return

    if stored_fp is not None:
        log.warning(
            "[embeddings] backend fingerprint changed (%s -> %s) — dropping the vector "
            "index for a full re-index (see settings.embed_backend's INTEGRITY note)",
            stored_fp, fp,
        )
    else:
        log.info("[embeddings] no stored vector fingerprint yet — will build the index from scratch")

    for table in _VEC_TABLES.values():
        await conn.execute(f"DROP TABLE IF EXISTS {table}")
    await conn.execute("DELETE FROM vec_index_state")
    model = settings.embed_local_model if settings.embed_backend == "local" else settings.embed_model
    await conn.execute(
        """INSERT INTO embedding_meta (id, fingerprint, backend, model, dim, updated_at)
           VALUES (1, :fp, :backend, :model, NULL, :now)
           ON CONFLICT(id) DO UPDATE SET
             fingerprint = excluded.fingerprint, backend = excluded.backend,
             model = excluded.model, dim = NULL, updated_at = excluded.updated_at""",
        {"fp": fp, "backend": settings.embed_backend, "model": model, "now": _utcnow_iso()},
    )
    await conn.commit()


async def ensure_vec_table(conn, kind: str) -> None:
    """Create the vec0 virtual table for `kind` ("cases"|"items") sized to
    the active model's dimension, if it doesn't already exist. Cheap no-op
    on every call after the first. Persists the discovered dimension into
    embedding_meta so a restart doesn't need to re-probe it."""
    table = _VEC_TABLES[kind]
    if await _table_exists(conn, table):
        return
    dim = await embed_backend.active_dim()
    await conn.execute(
        f"CREATE VIRTUAL TABLE {table} USING vec0(ref_id INTEGER PRIMARY KEY, embedding FLOAT[{dim}])"
    )
    await conn.execute("UPDATE embedding_meta SET dim = :dim WHERE id = 1", {"dim": dim})
    await conn.commit()


async def upsert_vectors(conn, kind: str, rows: list[tuple[int, list[float]]]) -> None:
    """rows: [(ref_id, embedding), ...]. vec0 has no native upsert, so this
    deletes any existing vector for each ref_id before inserting the new
    one."""
    if not rows:
        return
    await ensure_vec_table(conn, kind)
    table = _VEC_TABLES[kind]
    for ref_id, vec in rows:
        await conn.execute(f"DELETE FROM {table} WHERE ref_id = :id", {"id": ref_id})
        await conn.execute(
            f"INSERT INTO {table} (ref_id, embedding) VALUES (:id, :emb)",
            {"id": ref_id, "emb": sqlite_vec.serialize_float32(vec)},
        )


async def search(conn, kind: str, query_vec: list[float], *, k: int = 50) -> list[tuple[int, float]]:
    """KNN search — returns [(ref_id, distance), ...] nearest-first. Empty
    list (not an error) if nothing has been indexed yet for `kind`."""
    table = _VEC_TABLES[kind]
    if not await _table_exists(conn, table):
        return []
    rows = await conn.execute_fetchall(
        f"SELECT ref_id, distance FROM {table} WHERE embedding MATCH :q ORDER BY distance LIMIT :k",
        {"q": sqlite_vec.serialize_float32(query_vec), "k": k},
    )
    return [(r["ref_id"], r["distance"]) for r in rows]


async def get_vector(conn, kind: str, ref_id: int) -> list[float] | None:
    """Fetch one already-indexed vector back out of vec_cases/vec_items by
    ref_id (agentic-coordination quick win C1) — lets
    pipeline/correlate.py's embedding-assisted candidate channel reuse an
    item's own indexed vector as its case-similarity query vector instead
    of always re-embedding on the fuzzy-merge path. None if `kind`'s vec
    table doesn't exist yet or `ref_id` isn't indexed."""
    table = _VEC_TABLES[kind]
    if not await _table_exists(conn, table):
        return None
    rows = await conn.execute_fetchall(
        f"SELECT embedding FROM {table} WHERE ref_id = :id", {"id": ref_id}
    )
    if not rows:
        return None
    raw = rows[0]["embedding"]
    # Inverse of sqlite_vec.serialize_float32 (pack("%sf" % len(vector), ...))
    # — native byte order/size, same process family that wrote it.
    if len(raw) % 4 != 0:
        return None
    count = len(raw) // 4
    return list(struct.unpack("%sf" % count, raw))


async def get_indexed_hashes(conn, kind: str) -> dict[int, str]:
    rows = await conn.execute_fetchall(
        "SELECT ref_id, content_hash FROM vec_index_state WHERE kind = :kind", {"kind": kind}
    )
    return {r["ref_id"]: r["content_hash"] for r in rows}


async def mark_indexed(conn, kind: str, ref_id: int, content_hash: str) -> None:
    await conn.execute(
        """INSERT INTO vec_index_state (kind, ref_id, content_hash, fingerprint)
           VALUES (:kind, :id, :hash, :fp)
           ON CONFLICT(kind, ref_id) DO UPDATE SET
             content_hash = excluded.content_hash, fingerprint = excluded.fingerprint""",
        {"kind": kind, "id": ref_id, "hash": content_hash, "fp": embed_backend.active_fingerprint()},
    )
