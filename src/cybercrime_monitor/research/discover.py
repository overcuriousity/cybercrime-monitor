"""Source discovery — the "add better sources" half of the autonomous
self-improvement loop (see research/heal.py for "remove"/"research[fix]").
Same dispatch pattern as the rest of research/: build a prompt, let Hermes
drive its own web toolsets, parse a structured result, probe before
applying.

Fully autonomous, multi-channel discovery — no human-in-the-loop step.
Hermes is asked to prioritize, in order: (1) darknet forums/marketplaces/
leak sites (.onion — found via clearnet directories like dark.fail/
Tor.taxi and CTI write-ups that publish onion addresses, since Hermes
itself has no guaranteed Tor route), (2) cybersecurity researcher feeds,
(3) press feeds (heise, KrebsOnSecurity, etc.). RSS/Atom candidates are
probed and added exactly as before. Forum candidates (tor_forum/
html_forum — no feed, just an HTML listing page) go through a second,
local leg: fetch the listing page ourselves (via Tor for .onion), ask
Hermes (tool-free, given the fetched HTML) to propose CSS selectors, then
*validate by actually scraping with them* — the same probe-before-apply
contract as everything else in this loop, just extended to a type that
needs a generated config instead of a bare URL. A local Tor daemon
(SOCKS proxy, see settings.tor_socks / README) is required for the onion
leg; without one, onion candidates simply fail their probe and are logged
as proposals instead of applied.

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

from selectolax.parser import HTMLParser

from .. import db
from ..api.sse import broadcaster
from ..hermes.runner import run_agent
from ..http import clearnet_client, tor_client
from ..scheduler import load_sources, reschedule_source
from ..settings import settings
from ..sources import value as source_value
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


async def _log_activity(
    db_conn, *, action: str, summary: str, detail: dict | None = None,
    status: str = "ok", ref_id: str | None = None,
) -> None:
    """Write to ai_activity and fan it out over SSE — see db.log_ai_activity's
    docstring. Swallows its own errors: activity logging must never be the
    reason a discover tick fails."""
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem="discover", action=action, summary=summary,
            detail=detail, status=status, ref_type="source", ref_id=ref_id,
            model=settings.hermes_model or None,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[discover] activity log failed: %s", exc)


_DISCOVER_PROMPT_TEMPLATE = """\
You are assisting in expanding a cybercrime OSINT monitor's data sources. \
The monitor currently tracks these topics: {topics}. It already has these \
sources (do not suggest duplicates of these domains): {existing_domains}.

{underrepresented}

Search for new sources, in this priority order:
1. Darknet forums, marketplaces, or leak sites (.onion addresses) — find \
   these via clearnet darknet directories/mirror lists (e.g. dark.fail, \
   Tor.taxi) or via cybersecurity write-ups and CTI reports that publish \
   onion addresses for ransomware leak sites or cybercrime forums. You do \
   not need to be able to browse the .onion address yourself — reporting \
   the address and what it is, as found in clearnet text, is enough. This \
   is always the single most valuable kind of source this monitor can add \
   — first-hand actor chatter, not someone else's writeup of it — so \
   actively look for one even when the balance note above doesn't call \
   for it.
2. Cybersecurity researcher feeds/blogs that publish their own incident \
   analysis or threat intel (vendor blogs, independent researchers).
3. General press/news feeds that cover data breaches and cybercrime \
   promptly (e.g. heise, KrebsOnSecurity, and similar outlets).

Within that priority order, prefer candidates that help fill the \
under-represented regions/media kinds noted above over ones that pile \
onto an already well-covered bucket.

For each candidate, determine its "kind":
- "rss": you found a working RSS/Atom feed URL for it (NOT a general web \
  page — the feed_url must return valid RSS/Atom XML).
- "tor_forum": a darknet (.onion) forum/marketplace/leak-site with no \
  feed — give its listing_url (the page that lists threads/posts/leaks).
- "html_forum": a clearnet forum/leak-site with no feed — give its \
  listing_url likewise.

Also classify each candidate's region (where its primary operator/\
publisher is based or oriented: "eu", "us", "ru_cn" for Russia/China or \
that sphere including Russian-language cybercrime forums, or "other") and \
media_kind ("darknet_forum" for first-hand forum/marketplace data, \
"forensic" for incident-response/malware-analysis writeups, "press" for \
mainstream news, "blog" for independent researcher/hobbyist blogs, or \
"feed" for government/vendor advisory or alert feeds).

Find up to {batch_size} candidate(s) total, prioritized as above (darknet \
first). Prefer sites with a track record of being first to report \
incidents over general security news aggregators.

When you are done, respond with ONLY a single-line JSON object as your \
final message, no markdown fencing, no commentary, exactly these keys:
{{"candidates": [{{"name": "<short site name>", "kind": "rss"|"tor_forum"|"html_forum", \
"feed_url": <"<RSS/Atom feed URL>"|null>, "listing_url": <"<forum listing page URL>"|null>, \
"region": "eu"|"us"|"ru_cn"|"other", \
"media_kind": "darknet_forum"|"forensic"|"press"|"blog"|"feed", \
"reason": "<why this is a good fit>"}}, ...]}}
Use an empty "candidates" array if you find nothing suitable.
"""

# Second, tool-free leg for forum candidates: given the actual fetched HTML
# of a listing page, ask Hermes to propose selectors — same no-tools/JSON
# contract as llm/backend.py's adjudicate_merge (_NO_TOOLS_TOOLSET="memory"),
# reused here so selector generation doesn't need its own LLM integration.
_SELECTOR_PROMPT_TEMPLATE = """\
You are helping configure a CSS-selector-based scraper for a forum/listing \
page. Below is the raw HTML of the page (truncated). Identify the repeating \
row/item that represents one thread, post, or listing, and propose CSS \
selectors:
- row_selector: selects each repeating row/item element.
- title_selector: within a row, selects the element containing the \
  title/subject text.
- url_selector: within a row, selects the <a> element whose href points to \
  the individual thread/post/listing.
- date_selector: within a row, selects the element containing a \
  post/listing date, or null if none is reliably present.

URL: {url}

HTML (truncated):
{html}

Respond with ONLY a single-line JSON object as your final message, no \
markdown fencing, no commentary, exactly these keys:
{{"row_selector": "<css>", "title_selector": "<css>", "url_selector": "<css>", \
"date_selector": <"<css>"|null>}}
Do not search the web, browse, or use any tools for this task — base your \
answer ONLY on the HTML given above and respond immediately.
"""

# A validated selector set must extract at least this many usable rows
# (title + url both present) from the listing page before it's trusted
# enough to auto-add — one matching row could be a coincidence (e.g. a
# single nav link), several in a row is a real repeating structure.
_MIN_VALID_ROWS = 3
# Selector-generation HTML is truncated to keep the (tool-free, cheap)
# Hermes call fast — a listing page's repeating structure is almost always
# evident well within the page's first chunk of markup.
_SELECTOR_HTML_CHARS = 12000

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    slug = _SLUG_RE.sub("_", name.lower()).strip("_")
    return f"discovered_{slug[:40]}" if slug else "discovered_source"


async def _topics(db_conn) -> str:
    """What this monitor cares about, derived from recent LLM extractions
    (crime types + top mentioned actors) — replaces the old static regex-tag
    list now that the keyword matcher is gone. Falls back to a generic
    description when there's no extraction history yet (fresh install)."""
    topics = await db.get_recent_topics(db_conn)
    return ", ".join(topics) if topics else "data breaches, ransomware, cybercrime"


def _existing_domains(sources: list[dict]) -> set[str]:
    domains = set()
    for s in sources:
        url = s.get("url") or ""
        m = re.search(r"://([^/]+)/?", url)
        if m:
            domains.add(m.group(1).lower())
    return domains


_TARGET_REGIONS = ("eu", "us", "ru_cn")
# Ordered for the "thinnest first" pick below — darknet_forum listed first
# so it wins ties (it's always wanted regardless of balance).
_MEDIA_KINDS_BY_PRIORITY = ("darknet_forum", "forensic", "press", "blog", "feed")


def _underrepresented_summary(sources: list[dict]) -> str:
    """Digests sources/value.py's bucket_counts into a short note steering
    Hermes toward the regions/media kinds the corpus is currently thin on
    — the discovery half of convergence's diversity steer (pruning gets the
    same signal implicitly, via _component_diversity feeding the score it
    ranks on)."""
    buckets = source_value.bucket_counts(sources)
    notes = []
    if buckets["region_total"]:
        even_share = buckets["region_total"] / len(_TARGET_REGIONS)
        thin = [r for r in _TARGET_REGIONS if buckets["region"].get(r, 0) < even_share]
        if thin:
            notes.append(f"under-represented regions: {', '.join(thin)}")
    if buckets["media_kind_total"]:
        thin_kinds = sorted(_MEDIA_KINDS_BY_PRIORITY, key=lambda k: buckets["media_kind"].get(k, 0))[:2]
        notes.append(f"under-represented media kinds: {', '.join(thin_kinds)}")
    if not notes:
        return (
            "No region/media-kind balance data yet — no particular bias needed beyond "
            "the priority order above."
        )
    return (
        "Balance note — " + "; ".join(notes) + ". Prefer filling these where a good "
        "candidate exists, but darknet first-hand data is always top priority regardless."
    )


def _discover_batch_size(existing: list[dict]) -> int:
    """Convergence steer: how many candidates to ask for and accept this
    tick, based on the gap between the current enabled-source count and
    settings.source_target_count. Clearly below target (gap >= the
    deadband) scales up to fill the gap (capped at 5 per tick — still one
    Hermes run); at or near target, keep a slow trickle of 1 so a
    genuinely better candidate can still displace the weakest existing
    source via convergence pruning (research/heal.py), rather than freezing
    the corpus solid once it hits the number."""
    enabled_count = sum(1 for s in existing if s.get("enabled", True))
    gap = settings.source_target_count - enabled_count
    if gap >= settings.source_target_band:
        return min(5, max(1, gap))
    return 1


async def run_discover_batch(db_conn, scheduler=None, sse_broadcaster=None) -> int:
    """One tick: ask hermes-agent for new source candidates (RSS first, then
    forum-type), probe/validate each, and auto-add the ones that pass.
    Batch size and acceptance count are steered toward
    settings.source_target_count (see _discover_batch_size). Returns the
    number of sources added."""
    if settings.hermes_discover_interval_seconds <= 0:
        return 0

    record_run_start()
    added = 0
    try:
        existing = load_sources()
        batch_size = _discover_batch_size(existing)
        prompt = _DISCOVER_PROMPT_TEMPLATE.format(
            topics=await _topics(db_conn),
            existing_domains=", ".join(sorted(_existing_domains(existing))) or "none",
            underrepresented=_underrepresented_summary(existing),
            batch_size=batch_size,
        )
        result = await run_agent(
            prompt,
            toolsets=settings.hermes_toolsets,
            timeout=settings.hermes_timeout_seconds,
            model=settings.hermes_model or None,
            expect_json=True,
        )
        if not result.ok or result.data is None:
            record_error(result.error or "no parseable result")
            log.warning("[discover] hermes run failed: %s", result.error)
            return 0

        candidates = result.data.get("candidates") if isinstance(result.data, dict) else None
        candidates = candidates if isinstance(candidates, list) else []

        existing_domains = _existing_domains(existing)
        existing_ids = {s["id"] for s in existing}

        for cand in candidates[:batch_size]:
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


def _cand_classification(cand: dict) -> dict:
    """Pull validated region/media_kind off a Hermes candidate, if present
    and well-formed — omitted (not defaulted) when missing/invalid so
    research/classify.py's backfill pass still picks it up rather than
    silently locking in a wrong guess."""
    out = {}
    region = cand.get("region")
    if region in source_value.VALID_REGIONS:
        out["region"] = region
    media_kind = cand.get("media_kind")
    if media_kind in source_value.VALID_MEDIA_KINDS:
        out["media_kind"] = media_kind
    return out


def _candidate_url(cand: dict, kind: str) -> str:
    if kind == "rss":
        return str(cand.get("feed_url") or "").strip()
    return str(cand.get("listing_url") or "").strip()


async def _try_add_candidate(
    db_conn, cand: dict, existing_domains: set[str], existing_ids: set[str], scheduler, sse_broadcaster
) -> bool:
    """Dispatch by candidate kind — see _DISCOVER_PROMPT_TEMPLATE's contract.
    Unrecognized/missing kind defaults to "rss" for backward compatibility
    with any in-flight proposal shaped by the old prompt."""
    if not isinstance(cand, dict):
        return False
    kind = str(cand.get("kind") or "rss").strip().lower()
    if kind not in ("rss", "tor_forum", "html_forum"):
        return False

    name = str(cand.get("name") or "").strip()[:100]
    url = _candidate_url(cand, kind)
    if not name or not url.startswith(("http://", "https://")):
        return False

    m = re.search(r"://([^/]+)/?", url)
    domain = m.group(1).lower() if m else ""
    if not domain or domain in existing_domains:
        if domain:
            await _log_activity(
                db_conn, action="candidate_skipped", status="skipped",
                summary=f"Skipped discovered candidate '{name}' — domain already a source",
                detail={"url": url, "domain": domain, "kind": kind},
            )
        return False

    source_id = _slugify(name)
    while source_id in existing_ids:
        source_id += "_2"

    if kind == "rss":
        return await _try_add_rss_candidate(db_conn, cand, name=name, source_id=source_id, feed_url=url,
                                             scheduler=scheduler, sse_broadcaster=sse_broadcaster)
    return await _try_add_forum_candidate(db_conn, cand, name=name, source_id=source_id, listing_url=url,
                                           kind=kind, scheduler=scheduler, sse_broadcaster=sse_broadcaster)


async def _try_add_rss_candidate(
    db_conn, cand: dict, *, name: str, source_id: str, feed_url: str, scheduler, sse_broadcaster
) -> bool:
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
        await _log_activity(
            db_conn, action="probe_failed", status="error",
            summary=f"Discovered candidate '{name}' failed feed probe ({feed_url})",
            detail={"feed_url": feed_url, "reason": cand.get("reason")}, ref_id=source_id,
        )
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
        **_cand_classification(cand),
    }
    return await _apply_new_source(
        db_conn, entry=entry, reason="hermes-agent discovery", proposal_id=proposal_id,
        cand=cand, source_id=source_id, name=name, url=feed_url,
        scheduler=scheduler, sse_broadcaster=sse_broadcaster,
    )


async def _fetch_listing_html(url: str, *, kind: str) -> str | None:
    client_cm = tor_client(timeout=90.0) if kind == "tor_forum" else clearnet_client(timeout=30.0)
    try:
        async with client_cm as client:
            resp = await client.get(url)
            resp.raise_for_status()
        return resp.text
    except Exception as exc:
        log.info("[discover] listing fetch failed for %s (%s): %s", url, kind, exc)
        return None


async def _propose_selectors(url: str, html: str) -> dict | None:
    """Tool-free Hermes leg: given the already-fetched HTML, propose CSS
    selectors. Uses toolsets="memory" (see llm/backend.py's
    _NO_TOOLS_TOOLSET) since this is a closed-form text-in/JSON-out task —
    no need to re-spend a browsing budget on a page we already have."""
    prompt = _SELECTOR_PROMPT_TEMPLATE.format(url=url, html=html[:_SELECTOR_HTML_CHARS])
    result = await run_agent(prompt, toolsets="memory", timeout=settings.hermes_timeout_seconds,
                              model=settings.hermes_model or None, expect_json=True)
    if not result.ok or not isinstance(result.data, dict):
        return None
    data = result.data
    if not data.get("row_selector") or not data.get("title_selector") or not data.get("url_selector"):
        return None
    return {
        "row_selector": str(data["row_selector"]),
        "title_selector": str(data["title_selector"]),
        "url_selector": str(data["url_selector"]),
        "date_selector": str(data["date_selector"]) if data.get("date_selector") else "",
    }


def _count_valid_rows(html: str, selectors: dict) -> int:
    """Re-parse the already-fetched HTML with the proposed selectors and
    count rows that yield both a title and an href — the actual validation
    gate, not just "Hermes said so." Mirrors collectors/html_forum.py and
    collectors/tor_forum.py's extraction logic without needing a second
    network round-trip.

    Hermes can propose a syntactically invalid CSS selector (or omit one of
    the expected keys); that must read as "selectors didn't validate" (0
    rows, falls through to the normal probe_failed/audit-trail path), not as
    an unhandled exception that takes the whole discovery tick down with
    it — same reasoning as every other probe in this loop being wrapped."""
    try:
        tree = HTMLParser(html)
        rows = tree.css(selectors["row_selector"])
    except Exception as exc:
        log.info("[discover] selector validation failed to parse: %s", exc)
        return 0
    valid = 0
    for row in rows:
        try:
            title_node = row.css_first(selectors["title_selector"])
            url_node = row.css_first(selectors["url_selector"])
        except Exception as exc:
            log.info("[discover] selector validation failed on row: %s", exc)
            return 0
        if not title_node or not url_node:
            continue
        if not title_node.text(strip=True):
            continue
        if not url_node.attributes.get("href"):
            continue
        valid += 1
    return valid


async def _try_add_forum_candidate(
    db_conn, cand: dict, *, name: str, source_id: str, listing_url: str, kind: str, scheduler, sse_broadcaster
) -> bool:
    """tor_forum/html_forum candidate: fetch the listing page ourselves,
    have Hermes propose selectors against the real HTML (tool-free), then
    validate by actually extracting rows with them — only auto-add if that
    extraction clears _MIN_VALID_ROWS. No human review step; a failed probe
    just leaves a logged proposal instead of being applied."""
    html = await _fetch_listing_html(listing_url, kind=kind)
    if html is None:
        proposal_id = await db.create_heal_proposal(
            db_conn, source_id=source_id, proposal={"name": name, "listing_url": listing_url, "kind": kind},
            notes=cand.get("reason"), action="discover",
        )
        await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="probe_failed",
                                               error="listing page unreachable")
        await _log_activity(
            db_conn, action="probe_failed", status="error",
            summary=f"Discovered {kind} candidate '{name}' — listing page unreachable ({listing_url})",
            detail={"listing_url": listing_url, "kind": kind, "reason": cand.get("reason")}, ref_id=source_id,
        )
        return False

    selectors = await _propose_selectors(listing_url, html)
    valid_rows = _count_valid_rows(html, selectors) if selectors else 0
    probe_ok = valid_rows >= _MIN_VALID_ROWS

    proposal = {
        "name": name, "listing_url": listing_url, "kind": kind, "selectors": selectors,
        "valid_rows": valid_rows, "reason": cand.get("reason"), "probe_ok": probe_ok,
    }
    proposal_id = await db.create_heal_proposal(
        db_conn, source_id=source_id, proposal=proposal, notes=cand.get("reason"), action="discover"
    )

    if not probe_ok:
        await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="probe_failed")
        await _log_activity(
            db_conn, action="probe_failed", status="error",
            summary=(
                f"Discovered {kind} candidate '{name}' failed selector validation "
                f"({valid_rows} usable row(s) extracted, need {_MIN_VALID_ROWS})"
            ),
            detail={"listing_url": listing_url, "selectors": selectors, "valid_rows": valid_rows},
            ref_id=source_id,
        )
        return False

    await db.update_heal_proposal_status(db_conn, proposal_id=proposal_id, status="validated")

    if not settings.source_autoapply_enabled:
        return False

    entry = {
        "id": source_id,
        "name": name,
        "type": kind,
        "url": listing_url,
        "interval_seconds": 1800 if kind == "tor_forum" else 900,
        "jitter": 180,
        "enabled": True,
        "row_selector": selectors["row_selector"],
        "title_selector": selectors["title_selector"],
        "url_selector": selectors["url_selector"],
        "date_selector": selectors["date_selector"],
        "source_tags": ["discovered", "probationary"] + (["dark-web"] if kind == "tor_forum" else []),
        **_cand_classification(cand),
    }
    return await _apply_new_source(
        db_conn, entry=entry, reason="hermes-agent discovery (selector-validated)", proposal_id=proposal_id,
        cand=cand, source_id=source_id, name=name, url=listing_url,
        scheduler=scheduler, sse_broadcaster=sse_broadcaster,
    )


async def _apply_new_source(
    db_conn, *, entry: dict, reason: str, proposal_id: int, cand: dict, source_id: str, name: str, url: str,
    scheduler, sse_broadcaster,
) -> bool:
    try:
        after = source_writer.add(entry, reason=reason)
    except source_writer.SourceWriteError as exc:
        log.error("[discover] add failed for %s: %s", source_id, exc)
        return False

    await db.record_applied_change(db_conn, proposal_id=proposal_id, before={}, after=after)
    log.info("[discover] added new probationary source %s (%s)", source_id, url)
    await _log_activity(
        db_conn, action="source_added",
        summary=f"Discovered and added new source '{source_id}' ({name})",
        detail={"url": url, "reason": cand.get("reason"), "after": after}, ref_id=source_id,
    )

    if scheduler is not None:
        fresh = next((s for s in load_sources() if s["id"] == source_id), None)
        if fresh is not None:
            reschedule_source(scheduler, db_conn, sse_broadcaster, fresh)
    return True
