"""Autonomous source self-improvement loop, delegated to hermes-agent — same
dispatch pattern as research/agent.py: build a prompt, let Hermes drive its
own web/browser toolsets to investigate, parse a structured proposal back.
See hermes/runner.py's docstring for the verified `hermes -z` contract.

This used to be advisory-only (never touched sources.yaml — see git history
for the original docstring's reasoning). That stance has changed: every
change this module makes is still gated by a real check (a reachability
probe for heal fixes; sources/value.py's relative investigation-value
judgement for everything) and is fully audited (source_heal_proposals'
action/applied/before_value/after_value columns) and reversible
(sources/writer.py backs up sources.yaml before every write) — so the loop
can run unattended while still being reviewable after the fact. Set
settings.source_autoapply_enabled=False to fall back to logging proposals
without applying them.

Three behaviors, one tick each (bounded — a Hermes run can take minutes):
  1. heal    — investigate a broken/disabled source, probe a proposed fix,
               apply it (URL swap and/or re-enable) if the probe passes and
               the source is worth restoring. Runs against ANY disabled
               source (auto-disabled or hand-disabled in sources.yaml) on a
               cooldown, so a manually-disabled `# needs: ...` entry gets
               periodically re-investigated too, not just left alone.
  2. prune   — disable a source sources/value.py judges "dead" (never
               produced a successful fetch) or "marginal" with corroborating
               zero-value evidence (no case contribution + negative analyst
               feedback); remove ANY disabled source outright (auto- or
               hand-disabled — see _maybe_remove_source) after a grace
               period of continued non-recovery
               (settings.source_prune_grace_days). A hand-disabled source
               has no prior proposal to read a "disabled since" timestamp
               from, so the first prune pass that observes it starts the
               clock right there instead of leaving it disabled forever.
  3. (discovery is a separate job — see research/discover.py — since it's a
     different kind of Hermes run: open-ended search vs. investigate-one-
     source.)

Runs on its own APScheduler interval (scheduler.py's "_heal" job).
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .. import db
from .. import health
from ..api.sse import broadcaster
from ..hermes.runner import run_agent
from ..http import clearnet_client, tor_client
from ..scheduler import load_sources, reschedule_source, unschedule_source
from ..settings import settings
from ..sources import value as source_value
from ..sources import writer as source_writer

log = logging.getLogger(__name__)


# ── Runtime health registry ───────────────────────────────────────────────────
# Surfaced via /api/status so the dashboard can show whether hermes-agent is
# currently investigating a broken source.

@dataclass
class HealHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_processed_count: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0


_health = HealHealth()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(payload: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcaster.broadcast_status("heal", payload))
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


def get() -> HealHealth:
    return _health


async def _log_activity(
    db_conn, *, subsystem: str, action: str, summary: str, detail: dict | None = None,
    status: str = "ok", ref_id: str | None = None,
) -> None:
    """Write to ai_activity and fan it out over SSE — see db.log_ai_activity's
    docstring. subsystem is a parameter (not hardcoded "heal") because this
    module also drives the "prune" subsystem label. Swallows its own errors:
    activity logging must never be the reason a heal/prune action fails."""
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem=subsystem, action=action, summary=summary,
            detail=detail, status=status, ref_type="source", ref_id=ref_id,
            model=settings.hermes_model or None,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[%s] activity log failed: %s", subsystem, exc)

# A source that already has a pending/recent proposal isn't re-investigated
# every tick — same cooldown reasoning as research/agent.py's case cooldown.
_HEAL_COOLDOWN_HOURS = 24
_SOURCES_PER_TICK = 1

_HEAL_PROMPT_TEMPLATE = """\
You are assisting in maintaining a cybercrime OSINT monitor's data \
collectors. The following source has stopped working — its current \
configured URL is dead, redirected, or blocked, or it requires JavaScript \
that the current scraper can't handle. Investigate using web search and \
browsing: find out what happened (domain moved? site down? needs a \
different mirror or instance?) and, if possible, find a working \
replacement URL or mirror for the same type of content.

SOURCE:
id: {source_id}
name: {name}
type: {type}
current config: {config}
status: {status_note}
{feedback_note}
When you are done, respond with ONLY a single-line JSON object as your \
final message, no markdown fencing, no commentary, exactly these keys:
{{"found_fix": true|false, "proposed_url": <string|null>, \
"proposed_config_notes": "<what should change in sources.yaml and why, or \
why no fix was found>", "confidence": <0.0-1.0>}}
"""


def _status_note(source: dict) -> str:
    if not source.get("enabled", True):
        return "disabled (presumed broken at config time)"
    h = health.get(source["id"])
    if h and h.consecutive_errors:
        return f"{h.consecutive_errors} consecutive errors, last: {h.last_error}"
    return "unknown"


def _feedback_note(value: dict | None) -> str:
    """Digests sources/value.py's cached feedback component into the prompt
    so Hermes knows *why* a source is being reconsidered, not just that it
    is — per the "agent consumes user feedback" requirement."""
    if not value:
        return ""
    feedback_score = value.get("components", {}).get("feedback")
    if feedback_score is None:
        return ""
    if feedback_score < 0.5:
        return (
            "\nNote: the analyst has flagged recent reports from this source as "
            "noise/not useful/misattributed more often than useful — if you find "
            "a replacement, prefer one less likely to repeat that problem.\n"
        )
    return ""


async def _candidates(db_conn) -> list[dict]:
    sources = load_sources()
    cooldown_iso = (
        datetime.now(timezone.utc) - timedelta(hours=_HEAL_COOLDOWN_HOURS)
    ).isoformat()

    out = []
    for src in sources:
        broken = not src.get("enabled", True)
        if not broken:
            h = health.get(src["id"])
            broken = bool(h and h.consecutive_errors >= settings.hermes_heal_error_threshold)
        if not broken:
            continue
        if await db.source_recently_proposed(db_conn, source_id=src["id"], since_iso=cooldown_iso):
            continue
        out.append(src)
    return out


async def run_heal_batch(db_conn, scheduler=None, sse_broadcaster=None) -> int:
    """One tick: investigate a bounded number of broken/disabled sources via
    hermes-agent (auto-applying validated fixes), then run a prune pass over
    every source's cached investigation-value. Returns the number of heal
    investigations processed (prune actions are logged separately, not
    counted here — they don't consume a Hermes run)."""
    if settings.hermes_heal_interval_seconds <= 0:
        return 0

    record_run_start()
    candidates = (await _candidates(db_conn))[:_SOURCES_PER_TICK]
    processed = 0
    try:
        for src in candidates:
            try:
                await _heal_one(db_conn, src, scheduler=scheduler, sse_broadcaster=sse_broadcaster)
                processed += 1
            except Exception as exc:
                log.error("[heal] source %s failed: %s", src["id"], exc)

        if processed:
            log.info("[heal] processed %d source(s)", processed)

        try:
            await _prune_pass(db_conn, scheduler=scheduler, sse_broadcaster=sse_broadcaster)
        except Exception as exc:
            log.error("[heal] prune pass failed: %s", exc)

        record_success(processed)
    except Exception as exc:
        log.error("[heal] batch failed: %s", exc)
        record_error(str(exc) or repr(exc))
        raise

    return processed


async def _heal_one(db_conn, source: dict, *, scheduler, sse_broadcaster) -> None:
    value = (await db.get_source_value(db_conn, source["id"]))
    prompt = _HEAL_PROMPT_TEMPLATE.format(
        source_id=source["id"],
        name=source.get("name", source["id"]),
        type=source.get("type", "unknown"),
        config={k: v for k, v in source.items() if k not in ("id",)},
        status_note=_status_note(source),
        feedback_note=_feedback_note(value),
    )
    result = await run_agent(
        prompt,
        toolsets=settings.hermes_toolsets,
        timeout=settings.hermes_timeout_seconds,
        model=settings.hermes_model or None,
        expect_json=True,
    )

    if not result.ok or result.data is None:
        await db.create_heal_proposal(
            db_conn,
            source_id=source["id"],
            proposal={},
            notes=f"hermes run failed: {result.error}",
            action="heal",
        )
        log.warning("[heal] source %s: hermes run failed (%s)", source["id"], result.error)
        return

    data = result.data
    proposal_id = await db.create_heal_proposal(
        db_conn,
        source_id=source["id"],
        proposal=data,
        notes=data.get("proposed_config_notes") if isinstance(data, dict) else None,
        action="heal",
    )

    proposed_url = data.get("proposed_url") if isinstance(data, dict) else None
    if not data.get("found_fix") or not proposed_url:
        await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="rejected")
        await _log_activity(
            db_conn, subsystem="heal", action="no_fix_found", status="skipped",
            summary=f"No fix found for source '{source['id']}'",
            detail={"notes": data.get("proposed_config_notes") if isinstance(data, dict) else None},
            ref_id=source["id"],
        )
        return

    await _probe_and_apply(
        db_conn, proposal_id=proposal_id, url=proposed_url, source=source, value=value,
        scheduler=scheduler, sse_broadcaster=sse_broadcaster,
    )


async def _probe_and_apply(
    db_conn, *, proposal_id: int, url: str, source: dict, value: dict | None, scheduler, sse_broadcaster
) -> None:
    """Lightweight reachability check — not a full collector run (that would
    need dynamically constructing the right collector instance per type). A
    2xx response, combined with sources/value.py's should_apply_heal()
    judgement, is what gates actually writing sources.yaml — see that
    function's docstring for why there's no static confidence cutoff here."""
    use_tor = source.get("type") == "tor_forum" or "tor" in (source.get("tags") or [])
    probe_ok = False
    try:
        client_cm = tor_client(timeout=60.0) if use_tor else clearnet_client(timeout=30.0)
        async with client_cm as client:
            resp = await client.get(url)
        probe_ok = 200 <= resp.status_code < 300
        if not probe_ok:
            await db.update_heal_proposal_status(
                db_conn, proposal_id=proposal_id, status="probe_failed",
                error=f"HTTP {resp.status_code}",
            )
            await _log_activity(
                db_conn, subsystem="heal", action="probe_failed", status="error",
                summary=f"Proposed fix for '{source['id']}' failed probe (HTTP {resp.status_code})",
                detail={"url": url}, ref_id=source["id"],
            )
    except Exception as exc:
        await db.update_heal_proposal_status(
            db_conn, proposal_id=proposal_id, status="probe_failed", error=str(exc) or repr(exc)
        )
        await _log_activity(
            db_conn, subsystem="heal", action="probe_failed", status="error",
            summary=f"Proposed fix for '{source['id']}' failed probe",
            detail={"url": url, "error": str(exc) or repr(exc)}, ref_id=source["id"],
        )
        return

    if not probe_ok:
        return

    await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="validated")
    log.info("[heal] source %s: proposal validated (%s)", source["id"], url)

    if not settings.source_autoapply_enabled:
        return
    if not source_value.should_apply_heal(value=value, probe_ok=probe_ok):
        log.info("[heal] source %s: not applying — value judgement declined", source["id"])
        await _log_activity(
            db_conn, subsystem="heal", action="apply_declined", status="skipped",
            summary=f"Validated fix for '{source['id']}' not applied — value judgement declined",
            detail={"url": url, "value": value}, ref_id=source["id"],
        )
        return

    try:
        before, after = source_writer.update_field(
            source["id"], reason="hermes-agent heal fix", url=url, enabled=True
        )
    except source_writer.SourceWriteError as exc:
        log.error("[heal] source %s: apply failed: %s", source["id"], exc)
        await _log_activity(
            db_conn, subsystem="heal", action="apply_failed", status="error",
            summary=f"Failed to write heal fix for '{source['id']}' to sources.yaml",
            detail={"url": url, "error": str(exc) or repr(exc)}, ref_id=source["id"],
        )
        return

    await db.record_applied_change(db_conn, proposal_id=proposal_id, before=before, after=after)
    log.info("[heal] source %s: auto-applied fix to sources.yaml", source["id"])
    await _log_activity(
        db_conn, subsystem="heal", action="source_fixed",
        summary=f"Auto-applied fix to source '{source['id']}' ({url})",
        detail={"before": before, "after": after}, ref_id=source["id"],
    )

    if scheduler is not None:
        fresh = next((s for s in load_sources() if s["id"] == source["id"]), None)
        if fresh is not None:
            reschedule_source(scheduler, db_conn, sse_broadcaster, fresh)


# ── Prune pass ────────────────────────────────────────────────────────────────
# Every heal tick also sweeps the cached investigation-value snapshot
# (sources/value.py, refreshed independently on its own interval) and acts
# on sources judged not worth keeping. Two-stage so an autonomous disable is
# never instantly destructive: disable first, only remove the entry after
# source_prune_grace_days of continued non-value.

def _min_history(source_id: str) -> bool:
    """A source has "earned an opinion" once it's actually been tried
    multiple times — never prune a source on the strength of a single tick
    (health.py has no first-seen timestamp to measure tenure directly, so
    this uses observed attempt volume as the proxy instead)."""
    h = health.get(source_id)
    if h is None or h.last_run_at is None:
        return False
    return h.total_items_fetched > 0 or h.consecutive_errors >= 3 or h.consecutive_empty >= 3


async def _prune_pass(db_conn, *, scheduler, sse_broadcaster) -> None:
    if not settings.source_autoapply_enabled:
        return
    values = await db.get_all_source_values(db_conn)
    sources_by_id = {s["id"]: s for s in load_sources()}

    for source_id, src in sources_by_id.items():
        value = values.get(source_id)

        if not src.get("enabled", True):
            # Already disabled — whether by this loop's value judgement or
            # by hand (a `# needs:` entry in sources.yaml). Removal-eligibility
            # is intentionally NOT gated on should_prune/min_history here: a
            # disabled source produces no fresh run history to ever satisfy
            # that gate, which is exactly why hand-disabled sources used to
            # sit forever. _heal_one already gets a crack at fixing it every
            # _HEAL_COOLDOWN_HOURS; if that never pans out, age it out after
            # the grace period regardless of why it was disabled.
            await _maybe_remove_source(db_conn, src, value)
            continue

        if value is None:
            continue
        min_history = _min_history(source_id)
        if not source_value.should_prune(value=value, min_history=min_history):
            continue
        await _disable_source(db_conn, src, value, scheduler=scheduler, sse_broadcaster=sse_broadcaster)


async def _disable_source(db_conn, source: dict, value: dict, *, scheduler, sse_broadcaster) -> None:
    reason = f"investigation-value classification={value['classification']} (auto-prune)"
    try:
        before, after = source_writer.disable(source["id"], reason=reason)
    except source_writer.SourceWriteError as exc:
        log.error("[heal] prune %s: disable failed: %s", source["id"], exc)
        return
    proposal_id = await db.create_heal_proposal(
        db_conn, source_id=source["id"], proposal={"classification": value["classification"]},
        notes=reason, action="prune",
    )
    await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="validated")
    await db.record_applied_change(db_conn, proposal_id=proposal_id, before=before, after=after)
    log.info("[heal] auto-disabled low-value source %s (%s)", source["id"], value["classification"])
    await _log_activity(
        db_conn, subsystem="prune", action="source_disabled",
        summary=f"Auto-disabled source '{source['id']}' ({value['classification']})",
        detail={"before": before, "after": after, "value": value}, ref_id=source["id"],
    )
    if scheduler is not None:
        unschedule_source(scheduler, source["id"])


async def _maybe_remove_source(db_conn, source: dict, value: dict | None) -> None:
    """Already disabled — by a prior prune pass, or by hand (a `# needs:`
    entry someone added directly to sources.yaml, which has no proposal
    history at all). Remove outright once the grace period has elapsed with
    no recovery (a heal investigation that found a fix would have
    re-enabled it before this runs).

    If there's no existing prune-applied proposal to read a disabled_at
    from — true for every hand-disabled source, and for any source disabled
    before this clock-starting logic existed — start the clock now instead
    of leaving it disabled forever. This is what makes manually-disabled
    sources eventually get cleaned up at all.

    The clock-start proposal is deliberately NOT marked applied=1: that
    column means "writer.py actually touched sources.yaml" (see the
    source_heal_proposals schema comment in db.py) and this step writes
    nothing — it only observes that the source is already disabled. The
    proposal payload's removal_clock_started flag is what disabled_at is
    read from instead, so the audit trail stays honest about what actually
    happened to the file."""
    proposals = await db.get_heal_proposals(db_conn, status="validated")
    disabled_at = None
    for p in proposals:
        if p["source_id"] != source["id"] or p.get("action") != "prune":
            continue
        if p.get("applied") or p.get("proposal", {}).get("removal_clock_started"):
            disabled_at = p["created_at"]
            break

    if disabled_at is None:
        classification = value["classification"] if value else "unknown"
        reason = f"already disabled, no prior prune record — starting removal grace clock (value={classification})"
        proposal_id = await db.create_heal_proposal(
            db_conn, source_id=source["id"],
            proposal={"classification": classification, "removal_clock_started": True},
            notes=reason, action="prune",
        )
        await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="validated")
        log.info("[heal] prune %s: starting removal grace clock for already-disabled source", source["id"])
        await _log_activity(
            db_conn, subsystem="prune", action="removal_clock_started",
            summary=(
                f"Source '{source['id']}' is disabled with no tracked prune history — "
                f"will be removed in {settings.source_prune_grace_days}d if not recovered by heal"
            ),
            detail={"value": value}, ref_id=source["id"],
        )
        return
    try:
        elapsed = datetime.now(timezone.utc) - datetime.fromisoformat(disabled_at)
    except ValueError:
        return
    if elapsed < timedelta(days=settings.source_prune_grace_days):
        return

    try:
        before = source_writer.remove(source["id"], reason="grace period elapsed, no recovery")
    except source_writer.SourceWriteError as exc:
        log.error("[heal] prune %s: remove failed: %s", source["id"], exc)
        return
    proposal_id = await db.create_heal_proposal(
        db_conn, source_id=source["id"], proposal={}, notes="removed after grace period", action="prune",
    )
    await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="validated")
    await db.record_applied_change(db_conn, proposal_id=proposal_id, before=before, after={})
    log.info("[heal] removed pruned source %s after grace period", source["id"])
    await _log_activity(
        db_conn, subsystem="prune", action="source_removed",
        summary=f"Removed source '{source['id']}' after {settings.source_prune_grace_days}d grace period",
        detail={
            "before": {
                "id": before.get("id", source["id"]),
                "name": before.get("name"),
                "type": before.get("type"),
                "url": before.get("url"),
                "enabled": before.get("enabled"),
                "interval_seconds": before.get("interval_seconds"),
                "source_tags": before.get("source_tags"),
            },
        },
        ref_id=source["id"],
    )
