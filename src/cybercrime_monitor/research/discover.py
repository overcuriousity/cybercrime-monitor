"""Source discovery — the "add better sources" half of the autonomous
self-improvement loop (see research/heal.py for "remove"/"research[fix]").
Same dispatch pattern as the rest of research/: build a prompt, let Hermes
drive its own web toolsets, parse a structured result, probe before
applying.

Scoped to RSS/Atom feeds only — deliberately, not a limitation to lift
later. sources.yaml.example's own comments note that HTML/Tor-forum
scraping is fragile (CSS selectors drift, see the disabled-by-default
entries there) and an LLM guessing selectors for a site it's never run a
scrape against has no way to validate they're even close to right; an RSS
feed needs only a URL to be immediately useful and testable by the same
lightweight probe heal.py already uses. If Hermes finds a promising
non-RSS source, that goes in the proposal notes for a human to act on
manually rather than being auto-added — same probe-and-judge contract as
everything else in this loop, just one type narrower for the auto-add path.

Newly added sources are tagged "probationary": sources/value.py treats them
cautiously (no history yet ⇒ "marginal", not "valuable") until they've
accumulated enough run history for the prune pass to fairly judge them —
see research/heal.py's _min_history.

Runs on its own APScheduler interval (scheduler.py's "_discover" job).
"""
import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .. import db
from ..api.sse import broadcaster
from ..hermes.runner import run_agent
from ..http import clearnet_client
from ..matcher import matcher
from ..scheduler import load_sources, reschedule_source
from ..settings import settings
from ..sources import writer as source_writer

log = logging.getLogger(__name__)


@dataclass
class DiscoverHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_processed_count: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0


_health = DiscoverHealth()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(payload: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcaster.broadcast_status("discover", payload))
    except RuntimeError:
        pass


def record_run_start() -> None:
    _health.last_run_at = _now_iso()


def record_success(added_count: int) -> None:
    _health.last_success_at = _now_iso()
    _health.last_processed_count = added_count
    _health.consecutive_errors = 0
    _emit({"last_processed_count": added_count})


def record_error(error: str) -> None:
    _health.last_error = error[:300]
    _health.last_error_at = _now_iso()
    _health.consecutive_errors += 1
    _emit({"error": error[:300], "consecutive_errors": _health.consecutive_errors})


def get() -> DiscoverHealth:
    return _health


_DISCOVER_PROMPT_TEMPLATE = """\
You are assisting in expanding a cybercrime OSINT monitor's data sources. \
The monitor currently tracks these topics: {topics}. It already has these \
sources (do not suggest duplicates of these domains): {existing_domains}.

Search the clearnet web for 1-3 RSS or Atom feeds (NOT general web pages — \
specifically a feed URL that returns valid RSS/Atom XML) from sites that \
regularly publish content about: data breaches, ransomware attacks, \
cybercrime forums/marketplaces, leaked databases, or exploited \
vulnerabilities. Prefer sites with a track record of being first to report \
incidents over general security news aggregators.

When you are done, respond with ONLY a single-line JSON object as your \
final message, no markdown fencing, no commentary, exactly these keys:
{{"candidates": [{{"name": "<short site name>", "feed_url": "<RSS/Atom feed URL>", \
"reason": "<why this is a good fit>"}}, ...]}}
Use an empty "candidates" array if you find nothing suitable.
"""

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    slug = _SLUG_RE.sub("_", name.lower()).strip("_")
    return f"discovered_{slug[:40]}" or "discovered_source"


def _topics() -> str:
    tags = matcher.all_tags
    return ", ".join(tags) if tags else "data breaches, ransomware, cybercrime"


def _existing_domains(sources: list[dict]) -> set[str]:
    domains = set()
    for s in sources:
        url = s.get("url") or ""
        m = re.search(r"://([^/]+)/?", url)
        if m:
            domains.add(m.group(1).lower())
    return domains


async def run_discover_batch(db_conn, scheduler=None, sse_broadcaster=None) -> int:
    """One tick: ask hermes-agent for new RSS/Atom candidates, probe each,
    and auto-add the ones that pass. Returns the number of sources added."""
    if settings.hermes_discover_interval_seconds <= 0:
        return 0

    record_run_start()
    added = 0
    try:
        existing = load_sources()
        prompt = _DISCOVER_PROMPT_TEMPLATE.format(
            topics=_topics(),
            existing_domains=", ".join(sorted(_existing_domains(existing))) or "none",
        )
        result = await run_agent(
            prompt,
            toolsets=settings.hermes_toolsets,
            timeout=settings.hermes_timeout_seconds,
            model=settings.hermes_model or None,
        )
        if not result.ok or result.data is None:
            record_error(result.error or "no parseable result")
            log.warning("[discover] hermes run failed: %s", result.error)
            return 0

        candidates = result.data.get("candidates") if isinstance(result.data, dict) else None
        candidates = candidates if isinstance(candidates, list) else []

        existing_domains = _existing_domains(existing)
        existing_ids = {s["id"] for s in existing}

        for cand in candidates[:3]:
            try:
                if await _try_add_candidate(db_conn, cand, existing_domains, existing_ids, scheduler, sse_broadcaster):
                    added += 1
            except Exception as exc:
                log.error("[discover] candidate %r failed: %s", cand, exc)

        record_success(added)
    except Exception as exc:
        record_error(str(exc) or repr(exc))
        raise
    return added


async def _try_add_candidate(
    db_conn, cand: dict, existing_domains: set[str], existing_ids: set[str], scheduler, sse_broadcaster
) -> bool:
    if not isinstance(cand, dict):
        return False
    name = str(cand.get("name") or "").strip()[:100]
    feed_url = str(cand.get("feed_url") or "").strip()
    if not name or not feed_url.startswith(("http://", "https://")):
        return False

    m = re.search(r"://([^/]+)/?", feed_url)
    domain = m.group(1).lower() if m else ""
    if not domain or domain in existing_domains:
        return False

    source_id = _slugify(name)
    while source_id in existing_ids:
        source_id += "_2"

    # Probe: a 2xx response that looks like a feed (XML/RSS content-type or
    # body) — same "reachable and plausible" bar as heal.py's URL probe.
    try:
        async with clearnet_client(timeout=20.0) as client:
            resp = await client.get(feed_url)
        probe_ok = 200 <= resp.status_code < 300 and (
            "xml" in resp.headers.get("content-type", "").lower()
            or "rss" in resp.headers.get("content-type", "").lower()
            or "<rss" in resp.text[:500].lower()
            or "<feed" in resp.text[:500].lower()
        )
    except Exception as exc:
        probe_ok = False
        log.info("[discover] probe failed for %s: %s", feed_url, exc)

    proposal = {"name": name, "feed_url": feed_url, "reason": cand.get("reason"), "probe_ok": probe_ok}
    proposal_id = await db.create_heal_proposal(
        db_conn, source_id=source_id, proposal=proposal, notes=cand.get("reason"), action="discover"
    )

    if not probe_ok:
        await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="probe_failed")
        return False

    await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="validated")

    if not settings.source_autoapply_enabled:
        return False

    entry = {
        "id": source_id,
        "name": name,
        "type": "rss",
        "url": feed_url,
        "interval_seconds": 900,
        "jitter": 120,
        "enabled": True,
        "source_tags": ["discovered", "probationary"],
    }
    try:
        after = source_writer.add(entry, reason="hermes-agent discovery")
    except source_writer.SourceWriteError as exc:
        log.error("[discover] add failed for %s: %s", source_id, exc)
        return False

    await db.record_applied_change(db_conn, proposal_id=proposal_id, before={}, after=after)
    log.info("[discover] added new probationary source %s (%s)", source_id, feed_url)

    if scheduler is not None:
        fresh = next((s for s in load_sources() if s["id"] == source_id), None)
        if fresh is not None:
            reschedule_source(scheduler, db_conn, sse_broadcaster, fresh)
    return True
