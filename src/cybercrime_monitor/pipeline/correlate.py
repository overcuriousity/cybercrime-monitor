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
from .. import significance as sig
from ..api.sse import broadcaster
from ..embeddings import backend as embed_backend
from ..embeddings import index as vec_index
from ..enrich import cve as cve_enrich
from ..enrich import cve_meta as cve_meta_enrich
from ..enrich import ioc as ioc_enrich
from ..enrich import kev as kev_enrich
from ..enrich import mitre as mitre_enrich
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


async def _log_activity(
    db_conn, *, action: str, summary: str, detail: dict | None = None,
    status: str = "ok", ref_id: int | str | None = None, model: str | None = None,
) -> None:
    """Write to ai_activity and fan it out over SSE — see db.log_ai_activity's
    docstring. Swallows its own errors: activity logging must never be the
    reason a correlation pass fails. Per-item case_created/merged events
    (not a batch summary) since each one is a meaningfully distinct decision
    an analyst would want to audit individually — unlike the classifier's
    high-volume per-item verdicts."""
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem="correlator", action=action, summary=summary,
            detail=detail, status=status, ref_type="case", ref_id=ref_id, model=model,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[correlate] activity log failed: %s", exc)

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


async def _resolve_cve_meta(db_conn, cve_ids: list[str]) -> tuple[float | None, list[str], float | None]:
    """CVSS/CWE/EPSS for this item's CVEs (issue #18) — deterministic,
    token-free HTTP enrichment via enrich/cve_meta.py, cached per-CVE.
    Returns (cvss_max, cwe_ids, epss_max) across all of `cve_ids`; values are
    None/[] when there's nothing cached yet (e.g. a brand-new CVE whose
    lookup is still pending — see get_or_fetch's per-call fetch cap)."""
    if not cve_ids:
        return None, [], None
    meta = await cve_meta_enrich.get_or_fetch(db_conn, cve_ids)
    scores = [m["cvss_score"] for m in meta.values() if m.get("cvss_score") is not None]
    epss = [m["epss"] for m in meta.values() if m.get("epss") is not None]
    cwe_ids = list(dict.fromkeys(c for m in meta.values() for c in (m.get("cwe_ids") or [])))
    return (max(scores) if scores else None, cwe_ids, max(epss) if epss else None)


def _resolve_mitre(item: dict) -> list[str]:
    """ATT&CK technique IDs mentioned in this item's text (issue #18) —
    deterministic regex backstop, same reasoning as _resolve_iocs."""
    return mitre_enrich.extract_mitre_ids(item.get("title", ""), item.get("snippet", ""))


def _resolve_iocs(item: dict) -> list[str]:
    """LLM-extracted iocs unioned with a deterministic regex backstop over
    title+snippet — same don't-trust-one-source-alone reasoning as
    _resolve_cve_kev, scoped to the high-precision indicator types
    enrich/ioc.py handles (crypto addresses, IPs, onion addresses, hashes)."""
    regex_iocs = ioc_enrich.extract_iocs(item.get("title", ""), item.get("snippet", ""))
    return ioc_enrich.merge_iocs(item.get("iocs") or [], regex_iocs)


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
    cvss_max, cwe_ids, epss_max = await _resolve_cve_meta(db_conn, cve_ids)
    mitre_techniques = _resolve_mitre(item)
    case_key = _case_key_for(item)

    iocs = _resolve_iocs(item)
    # The item's real-world date: published_at when the collector captured
    # one (RSS/Mastodon/HIBP/ransomware.live/dated forum posts), else
    # seen_at — see db.create_case/merge_item_into_case's docstrings for why
    # this drives case first_seen/last_seen instead of "now."
    event_at = item.get("published_at") or item["seen_at"]

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
            event_at=event_at,
            iocs=iocs,
            cvss_max=cvss_max,
            cwe_ids=cwe_ids,
            epss_max=epss_max,
            mitre_techniques=mitre_techniques,
        )
        return

    merged = await _try_fuzzy_merge(
        db_conn, item, cve_ids=cve_ids, in_kev=in_kev, event_at=event_at, iocs=iocs,
        cvss_max=cvss_max, cwe_ids=cwe_ids, epss_max=epss_max, mitre_techniques=mitre_techniques,
    )
    if merged:
        return

    title = _case_title(item)
    case_id = await db.create_case(
        db_conn,
        case_key=case_key,
        title=title,
        summary=str(item.get("snippet", ""))[:500],
        crime_type=item.get("crime_type") or "other",
        attribution=item.get("actor"),
        attribution_confidence=item.get("confidence"),
        damaged_party=item.get("victim"),
        damaged_party_sector=item.get("victim_sector"),
        damaged_party_country=item.get("victim_country"),
        significance=item["significance"],
        significance_score=sig.significance_score(item["significance"]),
        cve_ids=cve_ids,
        in_kev=in_kev,
        item_id=item["id"],
        event_at=event_at,
        iocs=iocs,
        cvss_max=cvss_max,
        cwe_ids=cwe_ids,
        epss_max=epss_max,
        mitre_techniques=mitre_techniques,
    )
    await _log_activity(
        db_conn, action="case_created",
        summary=f"New case #{case_id}: {title}",
        detail={
            "crime_type": item.get("crime_type"), "victim": item.get("victim"),
            "actor": item.get("actor"), "significance": item["significance"], "in_kev": in_kev,
        },
        ref_id=case_id,
    )


async def _embedding_candidates(db_conn, item: dict, *, exclude_ids: set[int]) -> list[dict]:
    """Embedding-assisted correlation blocking (quick win C1) — top-k
    nearest vec_cases neighbors of this item, as ADDITIONAL fuzzy-merge
    candidates alongside db.find_candidate_cases' exact/fuzzy-victim
    blocking. Catches paraphrased/differently-spelled victims ("Acme Corp"
    vs "Acme Corporation Inc") that string blocking misses — the same
    conservative adjudicate_merge LLM gate still decides every merge, this
    only widens which cases get a chance to be adjudicated.

    Reuses the item's own already-indexed vec_items vector when available
    (the embed job runs on its own tick, so this is usually a free cache
    hit); falls back to embedding the item's title+snippet on demand
    otherwise (one embedding call, not an LLM call — cheap relative to
    adjudicate_merge, and only happens on this already-ambiguous fuzzy
    path). No-ops cleanly when disabled or embed_backend == "none"."""
    if not settings.correlate_embedding_candidates_enabled or settings.embed_backend == "none":
        return []
    try:
        qvec = await vec_index.get_vector(db_conn, "items", item["id"])
        if qvec is None:
            text = f"{item.get('title') or ''}\n\n{(item.get('snippet') or '')[:800]}".strip()
            if not text:
                return []
            vectors = await embed_backend.embed_texts([text])
            qvec = vectors[0] if vectors else None
        if not qvec:
            return []
        hits = await vec_index.search(db_conn, "cases", qvec, k=settings.correlate_embedding_topk)
    except Exception as exc:
        log.info("[correlate] embedding candidate lookup failed: %s", exc)
        return []

    out = []
    for case_id, _distance in hits:
        if case_id in exclude_ids:
            continue
        case = await db.get_case_by_id(db_conn, case_id)
        if case is not None:
            out.append(case)
    return out


async def _try_fuzzy_merge(
    db_conn, item: dict, *, cve_ids: list[str], in_kev: bool, event_at: str, iocs: list[str],
    cvss_max: float | None = None, cwe_ids: list[str] | None = None,
    epss_max: float | None = None, mitre_techniques: list[str] | None = None,
) -> bool:
    since_iso = (datetime.now(timezone.utc) - timedelta(days=_CANDIDATE_WINDOW_DAYS)).isoformat()
    candidates = await db.find_candidate_cases(
        db_conn,
        victim=item.get("victim"),
        actor=item.get("actor"),
        cve_ids=cve_ids,
        # Shared IoCs (a hash, onion address, crypto wallet) are as strong a
        # same-incident signal as a shared CVE, and let an item merge into
        # the right case even when victim/actor weren't extracted — e.g. a
        # technical write-up that names the malware but not the victim.
        iocs=iocs,
        since_iso=since_iso,
    )

    embedding_candidate_ids: set[int] = set()
    extra = await _embedding_candidates(db_conn, item, exclude_ids={c["id"] for c in candidates})
    for case in extra:
        candidates.append(case)
        embedding_candidate_ids.add(case["id"])

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
                event_at=event_at,
                iocs=iocs,
                cvss_max=cvss_max,
                cwe_ids=cwe_ids,
                epss_max=epss_max,
                mitre_techniques=mitre_techniques,
            )
            await _log_activity(
                db_conn, action="item_merged",
                summary=f"Merged item #{item['id']} into case #{case['id']} ({case.get('title', '')})",
                detail={
                    "confidence": confidence,
                    "item_title": item.get("title"),
                    "candidate_source": "embedding" if case["id"] in embedding_candidate_ids else "fuzzy",
                },
                ref_id=case["id"],
            )
            return True
    return False
