"""Self-healing for broken/disabled collectors, delegated to hermes-agent —
same dispatch pattern as research/agent.py: build a prompt, let Hermes drive
its own web/browser toolsets to investigate, parse a structured proposal
back. See hermes/runner.py's docstring for the verified `hermes -z`
contract.

Deliberately does NOT auto-apply proposals to sources.yaml — that's a
config-on-disk + collector-behavior change with no human in the loop, which
is a different risk class than a database write. A proposal is "validated"
once a lightweight reachability probe confirms the proposed URL responds;
applying it to sources.yaml is left to a human reviewing
source_heal_proposals (surfaced however the operator chooses — direct DB
query today; a dashboard/admin view is a natural follow-up, not required for
the proposal pipeline itself to be useful).

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
from ..scheduler import load_sources
from ..settings import settings

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


async def run_heal_batch(db_conn) -> int:
    """One tick: investigate a bounded number of broken/disabled sources via
    hermes-agent and record proposals. Returns the number processed."""
    if settings.hermes_heal_interval_seconds <= 0:
        return 0

    record_run_start()
    candidates = (await _candidates(db_conn))[:_SOURCES_PER_TICK]
    processed = 0
    try:
        for src in candidates:
            try:
                await _heal_one(db_conn, src)
                processed += 1
            except Exception as exc:
                log.error("[heal] source %s failed: %s", src["id"], exc)

        if processed:
            log.info("[heal] processed %d source(s)", processed)
        record_success(processed)
    except Exception as exc:
        log.error("[heal] batch failed: %s", exc)
        record_error(str(exc) or repr(exc))
        raise

    return processed


async def _heal_one(db_conn, source: dict) -> None:
    prompt = _HEAL_PROMPT_TEMPLATE.format(
        source_id=source["id"],
        name=source.get("name", source["id"]),
        type=source.get("type", "unknown"),
        config={k: v for k, v in source.items() if k not in ("id",)},
        status_note=_status_note(source),
    )
    result = await run_agent(
        prompt,
        toolsets=settings.hermes_toolsets,
        timeout=settings.hermes_timeout_seconds,
        model=settings.hermes_model or None,
    )

    if not result.ok or result.data is None:
        await db.create_heal_proposal(
            db_conn,
            source_id=source["id"],
            proposal={},
            notes=f"hermes run failed: {result.error}",
        )
        log.warning("[heal] source %s: hermes run failed (%s)", source["id"], result.error)
        return

    data = result.data
    proposal_id = await db.create_heal_proposal(
        db_conn,
        source_id=source["id"],
        proposal=data,
        notes=data.get("proposed_config_notes") if isinstance(data, dict) else None,
    )

    proposed_url = data.get("proposed_url") if isinstance(data, dict) else None
    if not data.get("found_fix") or not proposed_url:
        await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="rejected")
        return

    await _probe_and_update(db_conn, proposal_id=proposal_id, url=proposed_url, source=source)


async def _probe_and_update(db_conn, *, proposal_id: int, url: str, source: dict) -> None:
    """Lightweight reachability check — not a full collector run (that would
    need dynamically constructing the right collector instance per type).
    A 2xx response is "worth a human looking at"; anything else means the
    proposal itself didn't pan out and shouldn't be surfaced as actionable."""
    use_tor = source.get("type") == "tor_forum" or "tor" in (source.get("tags") or [])
    try:
        client_cm = tor_client(timeout=60.0) if use_tor else clearnet_client(timeout=30.0)
        async with client_cm as client:
            resp = await client.get(url)
        if 200 <= resp.status_code < 300:
            await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="validated")
            log.info("[heal] source %s: proposal validated (%s)", source["id"], url)
        else:
            await db.update_heal_proposal_status(
                db_conn, proposal_id=proposal_id, status="probe_failed",
                error=f"HTTP {resp.status_code}",
            )
    except Exception as exc:
        await db.update_heal_proposal_status(
            db_conn, proposal_id=proposal_id, status="probe_failed", error=str(exc) or repr(exc)
        )
