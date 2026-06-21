"""Scheduled embedding job — keeps vec_cases/vec_items in sync with the
cases/items tables. Mirrors llm/job.py's shape: find rows needing
(re)embedding, batch them through embed_texts, upsert vectors. Registered
in scheduler.py guarded by settings.embed_backend != "none" (same pattern
as the LLM extraction job's settings.llm_backend guard).

A row needs (re)embedding when it's missing from vec_index_state, OR its
content_hash no longer matches its current title/summary text (edited since
last indexed — e.g. a case's summary was enriched by research). The
fingerprint mismatch case (backend changed) is handled separately and
upstream by embeddings/index.py's init_vectors, which clears
vec_index_state entirely on drift — so by the time this job runs, every
row missing from vec_index_state already reflects "needs embedding under
the current backend," with no extra fingerprint check needed here.
"""
import hashlib
import logging

from ..settings import settings
from . import backend as embed_backend
from . import index as vec_index

log = logging.getLogger(__name__)


def _content_hash(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(p or "" for p in parts).encode()).hexdigest()


async def _candidates_cases(conn, indexed: dict[int, str], limit: int) -> list[tuple[int, str, str]]:
    rows = await conn.execute_fetchall("SELECT id, title, summary FROM cases ORDER BY id")
    out: list[tuple[int, str, str]] = []
    for r in rows:
        h = _content_hash(r["title"] or "", r["summary"] or "")
        if indexed.get(r["id"]) == h:
            continue
        text = f"{r['title'] or ''}\n\n{r['summary'] or ''}".strip()
        if not text:
            continue
        out.append((r["id"], text, h))
        if len(out) >= limit:
            break
    return out


async def _candidates_items(conn, indexed: dict[int, str], limit: int) -> list[tuple[int, str, str]]:
    # Snippet is truncated the same way llm/backend.py truncates it for
    # extraction (~800 chars) — embedding the full raw snippet buys little
    # semantic signal beyond that for a short news/forum item and costs
    # more per call.
    rows = await conn.execute_fetchall("SELECT id, title, snippet FROM items ORDER BY id")
    out: list[tuple[int, str, str]] = []
    for r in rows:
        h = _content_hash(r["title"] or "", r["snippet"] or "")
        if indexed.get(r["id"]) == h:
            continue
        text = f"{r['title'] or ''}\n\n{(r['snippet'] or '')[:800]}".strip()
        if not text:
            continue
        out.append((r["id"], text, h))
        if len(out) >= limit:
            break
    return out


async def _embed_kind(conn, kind: str, candidates_fn) -> int:
    indexed = await vec_index.get_indexed_hashes(conn, kind)
    candidates = await candidates_fn(conn, indexed, settings.embed_batch_size)
    if not candidates:
        return 0
    texts = [c[1] for c in candidates]
    vectors = await embed_backend.embed_texts(texts)
    await vec_index.upsert_vectors(conn, kind, list(zip((c[0] for c in candidates), vectors)))
    for ref_id, _text, content_hash in candidates:
        await vec_index.mark_indexed(conn, kind, ref_id, content_hash)
    await conn.commit()
    return len(candidates)


async def run_embedding_batch(db_conn) -> None:
    if settings.embed_backend == "none":
        return
    try:
        n_cases = await _embed_kind(db_conn, "cases", _candidates_cases)
        n_items = await _embed_kind(db_conn, "items", _candidates_items)
    except embed_backend.EmbeddingUnavailable as e:
        # Same posture as the LLM job's unreachable-backend handling: skip
        # this tick and retry next interval rather than crashing the
        # scheduler — but never silently mark rows as indexed.
        log.warning("[embeddings] backend unavailable this tick, skipping: %s", e)
        return
    except Exception:
        log.exception("[embeddings] batch failed")
        return
    if n_cases or n_items:
        log.info("[embeddings] indexed %d case(s), %d item(s)", n_cases, n_items)
