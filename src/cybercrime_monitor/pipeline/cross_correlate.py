"""Algorithmic (non-LLM) case-to-case correlation — separate from
pipeline/correlate.py, which dedupes raw *items* into cases. This module
links already-distinct *cases* that plausibly describe the same actor,
campaign, or victim cluster, surfaced in the case detail pane as "Related
cases" (see db.get_case_links / db.save_case_link).

Deliberately algorithmic, not LLM-adjudicated: case-to-case linking is a
much larger pairwise search space than per-item correlation, and "these two
cases might be related" is a softer, browsable signal than "these two items
are the same incident" — a Jaccard-style overlap score on normalized
victim/actor/CVE/IoC sets is cheap, deterministic, and good enough for a
"related cases" rail. Runs on its own interval (scheduler.py's
"_cross_correlate" job), fully decoupled from item correlation.
"""
import logging
from datetime import datetime, timedelta, timezone

from .. import db
from ..api.sse import broadcaster
from .correlate import _normalize

log = logging.getLogger(__name__)

_WINDOW_DAYS = 30
# Below this score a pair isn't worth recording — avoids a case_links table
# that's just noise (every case touching "ransomware" linked to every other).
# Set just below the weight of a single strong signal (same victim 0.4,
# same actor 0.3, full IoC overlap 0.3) so any ONE of those alone is enough
# to link two cases, but a shared CVE alone (weight 0.2 — CVEs are commonly
# shared across many unrelated incidents, e.g. a popular RCE) is not.
_MIN_LINK_SCORE = 0.3


def _set_overlap(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _score_pair(case_a: dict, case_b: dict) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0

    victim_a, victim_b = _normalize(case_a.get("damaged_party")), _normalize(case_b.get("damaged_party"))
    if victim_a and victim_a == victim_b:
        score += 0.4
        reasons.append("same victim")

    actor_a, actor_b = _normalize(case_a.get("attribution")), _normalize(case_b.get("attribution"))
    if actor_a and actor_a == actor_b:
        score += 0.3
        reasons.append("same actor")

    cve_overlap = _set_overlap(set(case_a.get("cve_ids") or []), set(case_b.get("cve_ids") or []))
    if cve_overlap:
        score += 0.2 * cve_overlap
        reasons.append("shared CVE(s)")

    ioc_overlap = _set_overlap(set(case_a.get("iocs") or []), set(case_b.get("iocs") or []))
    if ioc_overlap:
        score += 0.3 * ioc_overlap
        reasons.append("shared IoC(s)")

    return min(1.0, score), reasons


async def _log_link(db_conn, *, case_a: dict, case_b: dict, score: float, reasons: list[str]) -> None:
    """Write to ai_activity and fan it out over SSE — see db.log_ai_activity's
    docstring. Only called for genuinely new links (see case_link_exists),
    so this doesn't fire every tick for the same already-known pair.
    Swallows its own errors: activity logging must never be the reason a
    cross-correlation pass fails."""
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem="cross_correlator", action="cases_linked",
            summary=(
                f"Linked case #{case_a['id']} ({case_a.get('title', '')}) <-> "
                f"#{case_b['id']} ({case_b.get('title', '')}) — {', '.join(reasons)}"
            ),
            detail={"score": score, "reasons": reasons, "case_a": case_a["id"], "case_b": case_b["id"]},
            ref_type="case", ref_id=case_a["id"],
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[cross_correlate] activity log failed: %s", exc)


async def run_cross_correlation(db_conn) -> int:
    """One tick: pairwise-score all cases active within the window and
    persist links above the threshold. O(n^2) in the window's case count —
    fine at the scale this tool operates at (a single analyst's feed); if
    that stops being true, blocking on shared victim/actor first (like
    pipeline/correlate.py's case_key) would be the next step, not a
    rewrite."""
    since_iso = (datetime.now(timezone.utc) - timedelta(days=_WINDOW_DAYS)).isoformat()
    cases = await db.get_cases_for_cross_correlation(db_conn, since_iso=since_iso)
    linked = 0
    for i, case_a in enumerate(cases):
        for case_b in cases[i + 1:]:
            score, reasons = _score_pair(case_a, case_b)
            if score >= _MIN_LINK_SCORE:
                is_new = not await db.case_link_exists(db_conn, case_a=case_a["id"], case_b=case_b["id"])
                await db.save_case_link(
                    db_conn, case_a=case_a["id"], case_b=case_b["id"], score=score, reasons=reasons
                )
                if is_new:
                    await _log_link(db_conn, case_a=case_a, case_b=case_b, score=score, reasons=reasons)
                linked += 1
    if linked:
        log.info("[cross_correlate] recorded/updated %d case link(s)", linked)
    return linked
