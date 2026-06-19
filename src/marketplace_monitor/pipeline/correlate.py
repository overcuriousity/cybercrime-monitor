"""Semantic dedup → case correlation. Runs on its own APScheduler interval
(see scheduler.py's "_correlate" job), decoupled from both ingest and
extraction so a slow LLM adjudication call never blocks either.

For each item that has a usable (non-false-positive) extraction but isn't
linked into a case yet:
  1. Compute a blocking key from normalized victim+actor (or content_key, or
     a per-item fallback when neither is available).
  2. Exact case_key match → merge deterministically, no LLM call needed.
  3. Otherwise, fuzzy candidates (shared victim/actor/CVE, recent) → ask the
     LLM to adjudicate "same incident?" only when genuinely ambiguous.
  4. No match → create a new case.

Deliberately conservative: a missed merge just leaves two cases that should
be one (visible as duplicate cards, harmless); a wrong merge corrupts
attribution by blending two different incidents. See
llm/backend.adjudicate_merge's docstring.
"""
import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import timedelta, timezone, datetime

from .. import db
from ..api.sse import broadcaster
from ..enrich import cve as cve_enrich
from ..enrich import kev as kev_enrich
from ..llm import backend as llm_backend
from ..settings import settings

log = logging.getLogger(__name__)


# ── Runtime health registry (mirrors llm/health.py) ───────────────────────────
# Surfaced via /api/status so the dashboard can show what the correlator is
# doing right now and whether it is keeping up with the extraction queue.

@dataclass
class CorrelationHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_processed_count: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0


_health = CorrelationHealth()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(payload: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcaster.broadcast_status("correlation", payload))
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


def get() -> CorrelationHealth:
    return _health

_OVERFETCH_MULTIPLIER = 5
_BATCH_SIZE = 10
# How far back to look for a fuzzy-candidate case to merge into — an old,
# long-closed case shouldn't silently reopen just because a new report
# happens to share a victim name.
_CANDIDATE_WINDOW_DAYS = 30
# Below this adjudication confidence, treat the LLM's "same_incident" verdict
# as untrusted and create a new case instead — a low-confidence merge risks
# blending two different incidents' attribution.
_MERGE_MIN_CONFIDENCE = 0.6

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _normalize(value: str | None) -> str:
    if not value:
        return ""
    return _NON_ALNUM.sub("", value.lower())


def _case_key_for(item: dict) -> str:
    """Mirrors collectors/base.py's _content_key reasoning: prefer the most
    specific identifying signal available. Two items normalize to the same
    key only if they plausibly describe the same incident; an item with
    neither a named victim/actor nor a content_key gets a key derived from
    its own item id, so it never accidentally merges with anything (a
    standalone case is the safe default, not a silent over-merge)."""
    victim = _normalize(item.get("victim"))
    actor = _normalize(item.get("actor"))
    if victim and actor:
        raw = f"victim:{victim}|actor:{actor}"
    elif victim:
        raw = f"victim:{victim}"
    elif item.get("content_key"):
        raw = f"content:{item['content_key']}"
    else:
        raw = f"item:{item['id']}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _case_title(item: dict) -> str:
    victim = item.get("victim")
    actor = item.get("actor")
    if actor and victim:
        return f"{actor} → {victim}"
    if victim:
        return victim
    if actor:
        return f"{actor} (unattributed victim)"
    return item["title"][:200]


async def _resolve_cve_kev(db_conn, item: dict) -> tuple[list[str], bool]:
    regex_cves = cve_enrich.extract_cve_ids(item.get("title", ""), item.get("snippet", ""))
    all_cves = cve_enrich.merge_cve_ids(item.get("cve_ids") or [], regex_cves)
    if not all_cves:
        return [], False
    kev_hits = await kev_enrich.lookup_cves(db_conn, all_cves)
    return all_cves, bool(kev_hits)


async def run_correlation_batch(db_conn) -> int:
    """One tick: correlate a bounded batch of uncorrelated items. Returns
    the number of items processed (merged or turned into new cases)."""
    record_run_start()
    pool = await db.get_uncorrelated_extracted_items(
        db_conn, limit=_BATCH_SIZE * _OVERFETCH_MULTIPLIER
    )
    batch = pool[:_BATCH_SIZE]
    processed = 0

    try:
        for item in batch:
            try:
                await _correlate_one(db_conn, item)
                processed += 1
            except Exception as exc:
                log.error("[correlate] item %s failed: %s", item["id"], exc)

        if processed:
            log.info("[correlate] processed %d item(s)", processed)
        record_success(processed)
    except Exception as exc:
        log.error("[correlate] batch failed: %s", exc)
        record_error(str(exc) or repr(exc))
        raise

    return processed


async def _correlate_one(db_conn, item: dict) -> None:
    cve_ids, in_kev = await _resolve_cve_kev(db_conn, item)
    case_key = _case_key_for(item)

    existing = await db.get_case_by_key(db_conn, case_key)
    if existing is not None:
        await db.merge_item_into_case(
            db_conn,
            case_id=existing["id"],
            item_id=item["id"],
            significance=item["significance"],
            cve_ids=cve_ids,
            in_kev=in_kev,
            crime_type=item.get("crime_type"),
            attribution=item.get("actor"),
            attribution_confidence=item.get("confidence"),
            damaged_party_sector=item.get("victim_sector"),
            damaged_party_country=item.get("victim_country"),
        )
        return

    merged = await _try_fuzzy_merge(db_conn, item, cve_ids=cve_ids, in_kev=in_kev)
    if merged:
        return

    await db.create_case(
        db_conn,
        case_key=case_key,
        title=_case_title(item),
        summary=str(item.get("snippet", ""))[:500],
        crime_type=item.get("crime_type") or "other",
        attribution=item.get("actor"),
        attribution_confidence=item.get("confidence"),
        damaged_party=item.get("victim"),
        damaged_party_sector=item.get("victim_sector"),
        damaged_party_country=item.get("victim_country"),
        significance=item["significance"],
        significance_score={"info": 1, "warn": 2, "critical": 3}.get(item["significance"], 1) / 3.0,
        cve_ids=cve_ids,
        in_kev=in_kev,
        item_id=item["id"],
    )


async def _try_fuzzy_merge(db_conn, item: dict, *, cve_ids: list[str], in_kev: bool) -> bool:
    since_iso = (datetime.now(timezone.utc) - timedelta(days=_CANDIDATE_WINDOW_DAYS)).isoformat()
    candidates = await db.find_candidate_cases(
        db_conn,
        victim=item.get("victim"),
        actor=item.get("actor"),
        cve_ids=cve_ids,
        since_iso=since_iso,
    )
    if not candidates:
        return False

    if settings.llm_backend == "none":
        # No adjudicator available — stay conservative and let this become
        # its own case rather than guessing at a merge.
        return False

    for case in candidates:
        verdict = await llm_backend.adjudicate_merge(case, item)
        if verdict is None:
            continue
        same_incident, confidence = verdict
        if same_incident and confidence >= _MERGE_MIN_CONFIDENCE:
            await db.merge_item_into_case(
                db_conn,
                case_id=case["id"],
                item_id=item["id"],
                significance=item["significance"],
                cve_ids=cve_ids,
                in_kev=in_kev,
                crime_type=item.get("crime_type"),
                attribution=item.get("actor"),
                attribution_confidence=item.get("confidence"),
                damaged_party_sector=item.get("victim_sector"),
                damaged_party_country=item.get("victim_country"),
            )
            return True
    return False
