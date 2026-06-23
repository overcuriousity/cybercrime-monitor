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
from .. import significance as sig
from ..api.sse import broadcaster
from ..settings import settings
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


async def _log_link(db_conn, *, case_a: dict, case_b: dict, score: float, reasons: list[str]) -> dict | None:
    """Write to ai_activity and fan it out over SSE — see db.log_ai_activity's
    docstring. Only called for genuinely new links (see case_link_exists),
    so this doesn't fire every tick for the same already-known pair.
    Swallows its own errors: activity logging must never be the reason a
    cross-correlation pass fails. Returns the logged event (so callers can
    stamp it as a downstream escalation's caused_by — see _maybe_escalate),
    or None if logging itself failed."""
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
        return event
    except Exception as exc:
        log.error("[cross_correlate] activity log failed: %s", exc)
        return None


def _is_severe_peer(case: dict) -> bool:
    """Does this case, on its own, justify pulling a linked case toward
    research (quick win C2)? Confirmed status, critical significance, or a
    KEV-listed CVE are each independently a strong "this matters" signal."""
    return case.get("status") == "confirmed" or case.get("significance") == "critical" or bool(case.get("in_kev"))


def _peer_outranks(case: dict, peer: dict) -> bool:
    """Is `peer` meaningfully more severe than `case`? `peer` must qualify
    as severe in its own right (_is_severe_peer) AND strictly outrank `case`
    — by significance rank, or by confirmed status at equal rank. Avoids
    escalating a case that's already at (or above) its peer's level just
    because the peer happens to also be severe."""
    if not _is_severe_peer(peer):
        return False
    case_rank = sig.SIG_RANK.get(case.get("significance"), 1)
    peer_rank = sig.SIG_RANK.get(peer.get("significance"), 1)
    if peer_rank > case_rank:
        return True
    if peer_rank == case_rank:
        return peer.get("status") == "confirmed" and case.get("status") != "confirmed"
    return False


async def _maybe_escalate(db_conn, *, case: dict, peer: dict, link_event: dict | None) -> None:
    """Cross-correlation → escalation (quick win C2) — a case freshly linked
    into a more-severe cluster is nudged toward research (db.nudge_case)
    and, optionally, has its significance bumped one rung (capped at the
    peer's level). Gated well above _MIN_LINK_SCORE
    (cross_correlate_escalation_min_score) so a single weak link can't
    trigger it. The significance bump defaults off — reversible by
    run_significance_decay, but kept behind its own flag until proven out.
    """
    if not _peer_outranks(case, peer):
        return
    await db.nudge_case(
        db_conn, case_id=case["id"], boost=settings.cross_correlate_escalation_boost,
        requested_by="cross_correlator",
    )
    bumped = False
    if settings.cross_correlate_escalation_bump_enabled:
        bumped = await db.bump_case_significance_one_rung(
            db_conn, case_id=case["id"], cap=peer.get("significance") or "info"
        )
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem="cross_correlator", action="case_escalated",
            summary=(
                f"Escalated case #{case['id']} ({case.get('title', '')}) toward research — "
                f"linked to more-severe case #{peer['id']} ({peer.get('title', '')})"
            ),
            detail={
                "linked_to": peer["id"],
                "boost": settings.cross_correlate_escalation_boost,
                "bumped": bumped,
            },
            ref_type="case", ref_id=case["id"],
            caused_by=link_event["id"] if link_event else None,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[cross_correlate] escalation activity log failed: %s", exc)


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
                is_new = await db.save_case_link(
                    db_conn, case_a=case_a["id"], case_b=case_b["id"], score=score, reasons=reasons
                )
                if is_new:
                    link_event = await _log_link(db_conn, case_a=case_a, case_b=case_b, score=score, reasons=reasons)
                    if settings.cross_correlate_escalation_enabled and score >= settings.cross_correlate_escalation_min_score:
                        try:
                            await _maybe_escalate(db_conn, case=case_a, peer=case_b, link_event=link_event)
                            await _maybe_escalate(db_conn, case=case_b, peer=case_a, link_event=link_event)
                        except Exception as exc:
                            log.error("[cross_correlate] escalation failed: %s", exc)
                linked += 1
    if linked:
        log.info("[cross_correlate] recorded/updated %d case link(s)", linked)
    return linked
