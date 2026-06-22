"""Autonomous OSINT research, delegated to hermes-agent — see
hermes/runner.py's docstring for the verified `hermes -z` contract this
builds on. Hermes drives its own web search/scrape/browser toolsets; this
module's job is only to build the prompt, dispatch a bounded batch of cases
per tick concurrently (actual parallelism capped by runner.py's
process-wide semaphore, not here — a research run can legitimately take
minutes), and parse the structured result back into each case.

Runs on its own APScheduler interval (scheduler.py's "_research" job),
fully decoupled from ingest/extraction/correlation — a slow or hung Hermes
run must never stall the rest of the pipeline.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from .. import db
from .. import significance as sig
from ..api.sse import broadcaster
from ..hermes.runner import run_agent
from ..settings import settings

log = logging.getLogger(__name__)


# ── Runtime health registry ───────────────────────────────────────────────────
# Surfaced via /api/status so the dashboard can show whether hermes-agent is
# currently researching a case or if the research queue is backing up.

@dataclass
class ResearchHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_processed_count: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0


_health = ResearchHealth()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(payload: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcaster.broadcast_status("research", payload))
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


def get() -> ResearchHealth:
    return _health


async def _log_activity(
    db_conn, *, action: str, summary: str, detail: dict | None = None,
    status: str = "ok", ref_id: int | str | None = None,
) -> None:
    """Write to ai_activity and fan it out over SSE in one call — see
    db.log_ai_activity's docstring. Swallows its own errors: activity
    logging must never be the reason a research run fails."""
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem="research", action=action, summary=summary,
            detail=detail, status=status, ref_type="case", ref_id=ref_id,
            model=settings.hermes_model or None,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[research] activity log failed: %s", exc)

_RESEARCH_PROMPT_TEMPLATE = """\
You are assisting a cybercrime intelligence monitor. Research the following \
incident using web search and any pages you need to fetch. Try to: confirm \
the incident is real and ongoing/recent, identify the threat actor or \
seller if not already known, identify the victim organization if not \
already known, find any concrete indicators of compromise (domains, \
hashes, IPs, onion addresses, leak-site URLs, ransom/extortion \
cryptocurrency wallet addresses) tied to this incident, and find \
corroborating independent sources (not just the original report below).

Actively look for a technical malware/incident write-up of this case, not \
just news coverage — the kind of deep-dive analysis BleepingComputer, The \
DFIR Report, vendor threat-intel blogs (Mandiant, Recorded Future, Talos, \
etc.), or the actor's own leak-site posting would publish. These write-ups \
are the best source of concrete IoCs and CVEs, often in a table or list — \
if you find one, pull every IoC and CVE it publishes into this incident's \
record rather than just summarizing the prose.

Also judge the case's CURRENT significance based on everything you found —
this re-classifies the case (it can move up or down from where it started):
- "critical": there is a clear victim AND the crime is still ongoing — new \
information is still being produced (an active sale, a live extortion \
countdown, exploitation still happening, the actor still posting updates). \
Set "ongoing": true whenever you call it "critical" — critical requires \
ongoing.
- "warn": a clear victim and a clear act of crime (breach/sale/ransomware, \
possibly a CVE) with real consequences, but it is NOT ongoing anymore — a \
closed/past incident.
- "info": on closer inspection this case is irrelevant, stale, unconfirmed, \
or too insignificant to track closely.
Be honest about degrading a case — if you find nothing to corroborate it or \
it's clearly old news with no new developments, say so; that's exactly what \
this judgment is for.

INCIDENT:
Title: {title}
Crime type: {crime_type}
Known victim: {victim}
Known attribution: {attribution}
CVEs: {cve_ids}
Known IoCs: {iocs}
Summary so far: {summary}
{gap_note}
When you are done, respond with ONLY a single-line JSON object as your \
final message, no markdown fencing, no commentary, exactly these keys:
{{"confirmed": true|false, "attribution": <string|null>, "damaged_party": <string|null>, \
"summary": "<2-3 sentence summary of what you found>", "sources": [<url>...], \
"iocs": [<string>...], "confidence": <0.0-1.0>, \
"significance": "info"|"warn"|"critical", "ongoing": true|false}}
"""


def _gap_note(case: dict) -> str:
    """Built only for forced re-research (research_requested_at set) — names
    what's actually missing so a re-trigger digs into gaps instead of
    repeating the same generic pass. A naturally-queued first pass has no
    history to diff against, so it gets no gap note (the base prompt already
    asks for everything)."""
    if not case.get("research_requested_at"):
        return ""
    missing = []
    if not case.get("attribution"):
        missing.append("threat actor / seller attribution")
    if not case.get("damaged_party"):
        missing.append("victim organization")
    if not case.get("damaged_party_sector"):
        missing.append("victim sector")
    if not case.get("damaged_party_country"):
        missing.append("victim country")
    if not case.get("iocs"):
        missing.append("indicators of compromise")
    if not missing:
        return (
            "\nThis case has already been researched before but was re-queued for "
            "deeper research — dig further than a surface-level search. Specifically "
            "look for a technical malware/incident write-up (BleepingComputer, The "
            "DFIR Report, vendor threat-intel blogs, the actor's own leak-site post) "
            "beyond what's already known, and pull any IoCs/CVEs it publishes.\n"
        )
    return (
        "\nThis case was specifically re-queued for deeper research because the "
        f"following is still missing: {', '.join(missing)}. Focus your search on "
        "filling these gaps.\n"
    )


def _reconcile_verdict(verdict, ongoing: bool) -> str | None:
    """Validate and reconcile the researcher's significance/ongoing verdict
    before it's allowed to reclassify a case. Returns None when the verdict
    shouldn't be applied at all (this research pass leaves the case's
    current level untouched — see _research_one's confidence gate for the
    other half of that decision).

    "critical" requires "ongoing": true by definition (see the case-level
    rubric in _RESEARCH_PROMPT_TEMPLATE) — a model that returns critical
    without confirming the crime is still active is downgraded to "warn"
    rather than trusted at face value or discarded outright."""
    if not isinstance(verdict, str):
        return None
    verdict = verdict.lower()
    if verdict not in sig.VALID_SIGNIFICANCE:
        return None
    if verdict == "critical" and not ongoing:
        return "warn"
    return verdict


def _build_prompt(case: dict) -> str:
    return _RESEARCH_PROMPT_TEMPLATE.format(
        title=case.get("title") or "",
        crime_type=case.get("crime_type") or "other",
        victim=case.get("damaged_party") or "unknown",
        attribution=case.get("attribution") or "unknown",
        cve_ids=", ".join(case.get("cve_ids") or []) or "none",
        iocs=", ".join(case.get("iocs") or []) or "none",
        summary=case.get("summary") or "(none yet)",
        gap_note=_gap_note(case),
    )


async def run_research_batch(db_conn) -> int:
    """One tick: dispatch hermes-agent research for a bounded number of
    significant, not-recently-researched cases, concurrently. Returns the
    number of cases processed (regardless of outcome — a failed/timed-out
    run still counts, since it consumed a research_runs row and won't be
    retried until its cooldown elapses). The cooldown is significance-scaled,
    not a flat window: a completed run blocks re-research for
    settings.research_critical_interval_seconds (critical, daily by default)
    or settings.research_warn_interval_seconds (warn, weekly by default), and
    an info case is researched exactly once and never again automatically.
    A *failed* run instead uses the much shorter
    settings.research_failure_retry_hours, regardless of level — see
    db._research_eligibility_sql's docstring for the exact predicate.

    Cases are fetched settings.hermes_research_batch_size at a time and
    dispatched together via asyncio.gather, but actual parallelism is capped
    by hermes/runner.py's process-wide semaphore
    (settings.hermes_max_concurrent_runs) — the batch size just needs to be
    large enough that the semaphore's workers always have a next case ready
    rather than the tick going idle. See settings.py for why the concurrency
    cap, not this batch size, is what's sized against the upstream rate
    limit."""
    if settings.hermes_research_interval_seconds <= 0:
        return 0

    record_run_start()
    now = datetime.now(timezone.utc)
    cases = await db.get_cases_needing_research(
        db_conn, limit=settings.hermes_research_batch_size, now=now,
    )

    async def _one(case: dict) -> bool:
        try:
            await _research_one(db_conn, case)
            return True
        except Exception as exc:
            log.error("[research] case %s failed: %s", case["id"], exc)
            return False

    try:
        results = await asyncio.gather(*(_one(case) for case in cases))
        processed = sum(results)

        if processed:
            log.info("[research] processed %d case(s)", processed)
        record_success(processed)
    except Exception as exc:
        log.error("[research] batch failed: %s", exc)
        record_error(str(exc) or repr(exc))
        raise

    return processed


async def _research_one(db_conn, case: dict) -> None:
    run_id = await db.start_research_run(db_conn, case_id=case["id"], model=settings.hermes_model or None)

    prompt = _build_prompt(case)
    result = await run_agent(
        prompt,
        toolsets=settings.hermes_toolsets,
        timeout=settings.hermes_timeout_seconds,
        model=settings.hermes_model or None,
        expect_json=True,
    )

    if not result.ok or result.data is None:
        await db.finish_research_run(
            db_conn,
            run_id=run_id,
            status="failed",
            findings={},
            sources=[],
            error=result.error or "no parseable result",
        )
        # A forced re-research request must not retry every tick forever if
        # Hermes is down — clear it; the analyst can re-request.
        await db.clear_case_research_request(db_conn, case_id=case["id"])
        log.warning("[research] case %s: hermes run failed (%s)", case["id"], result.error)
        await _log_activity(
            db_conn, action="research_failed", status="error",
            summary=f"Research failed on case #{case['id']} ({case.get('title') or 'untitled'})",
            detail={"error": result.error}, ref_id=case["id"],
        )
        return

    data = result.data
    sources = data.get("sources") if isinstance(data.get("sources"), list) else []
    sources = [str(s) for s in sources][:20]

    await db.finish_research_run(
        db_conn, run_id=run_id, status="completed", findings=data, sources=sources, error=None
    )

    confirmed = bool(data.get("confirmed"))
    confidence = data.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else 0.0
    except (TypeError, ValueError):
        confidence = 0.0

    # Conservative: only let a research run promote a case to "confirmed" —
    # never "dismissed". A research run that found nothing just leaves the
    # case as-is; only a human (or a future, more deliberate verification
    # step) should mark something dismissed.
    new_status = "confirmed" if (confirmed and confidence >= 0.5) else "researching"
    attribution = data.get("attribution") if isinstance(data.get("attribution"), str) else None
    damaged_party = data.get("damaged_party") if isinstance(data.get("damaged_party"), str) else None
    summary = data.get("summary") if isinstance(data.get("summary"), str) else None
    iocs = data.get("iocs") if isinstance(data.get("iocs"), list) else []
    iocs = [str(x) for x in iocs][:50]

    # The researcher may escalate OR degrade the case's significance (e.g.
    # critical -> info if it turned out stale/irrelevant, or info -> critical
    # if it's a significant ongoing crime) — see _reconcile_verdict's
    # docstring and db.apply_research_findings's significance-precedence
    # note. Gated on the same confidence>=0.5 bar as status promotion so a
    # weak pass can't flap a case's level on shaky evidence.
    reconciled = _reconcile_verdict(data.get("significance"), bool(data.get("ongoing")))
    new_significance = reconciled if (reconciled and confidence >= 0.5) else None

    await db.apply_research_findings(
        db_conn,
        iocs=iocs,
        case_id=case["id"],
        status=new_status,
        attribution=attribution,
        damaged_party=damaged_party,
        summary_addendum=summary,
        significance=new_significance,
    )
    log.info(
        "[research] case %s -> status=%s confirmed=%s confidence=%.2f significance=%s",
        case["id"], new_status, confirmed, confidence, new_significance or "(unchanged)",
    )
    await _log_activity(
        db_conn, action="research_completed",
        summary=(
            f"Researched case #{case['id']} ({case.get('title') or 'untitled'}) -> "
            f"{new_status} (confidence {confidence:.2f})"
            + (f", significance -> {new_significance}" if new_significance else "")
        ),
        detail={
            "confirmed": confirmed, "confidence": confidence, "new_status": new_status,
            "attribution": attribution, "damaged_party": damaged_party,
            "iocs": iocs, "sources": sources, "significance": new_significance,
        },
        ref_id=case["id"],
    )
