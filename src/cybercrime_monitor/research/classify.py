"""One-time backfill: classify every configured source's `region` and
`media_kind` so sources/value.py's diversity/media-prior components (and
research/discover.py's under-represented-bucket steer) have something to
read. Same dispatch pattern as research/heal.py — build a prompt, let
Hermes judge, write the result straight to sources.yaml via
sources/writer.py (backed up, audited the same way as a heal/prune write).

Sources live in config/sources.yaml, not SQLite, so there's no
PRAGMA user_version to gate a one-time migration on (the trick
db._migrate_normalize_countries uses). Instead this is naturally
idempotent and cheap to no-op: each tick only classifies sources still
missing the fields, and once every source has them the candidate list is
empty and the job becomes a fast no-op forever after. Safe to run on every
"_classify" tick rather than needing a separate "ran once" flag.

Runs on its own APScheduler interval (scheduler.py's "_classify" job).
"""
import logging

from .. import db
from .. import prompts
from ..hermes.runner import run_agent
from ..scheduler import load_sources
from ..settings import settings
from ..sources import writer as source_writer
from ..sources.value import VALID_MEDIA_KINDS, VALID_REGIONS

log = logging.getLogger(__name__)

# Bounded per tick — a Hermes run can take a while, and there's no rush:
# unclassified sources just sit out of the diversity/media-prior components
# until their turn comes up.
_SOURCES_PER_TICK = 3

def _candidates() -> list[dict]:
    return [
        src for src in load_sources()
        if not src.get("region") or not src.get("media_kind")
    ][:_SOURCES_PER_TICK]


async def _log_activity(db_conn, *, action: str, summary: str, detail: dict | None, status: str, ref_id: str | None) -> None:
    try:
        from ..api.sse import broadcaster
        event = await db.log_ai_activity(
            db_conn, subsystem="classify", action=action, summary=summary,
            detail=detail, status=status, ref_type="source", ref_id=ref_id,
            model=settings.hermes_model or None,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[classify] activity log failed: %s", exc)


async def run_classify_batch(db_conn, scheduler=None, sse_broadcaster=None) -> int:
    """One tick: classify a bounded number of sources still missing
    region/media_kind. Returns the number successfully classified."""
    candidates = _candidates()
    if not candidates:
        return 0

    processed = 0
    for src in candidates:
        try:
            if await _classify_one(db_conn, src):
                processed += 1
        except Exception as exc:
            log.error("[classify] source %s failed: %s", src["id"], exc)

    if processed:
        log.info("[classify] classified %d source(s)", processed)
    return processed


async def _classify_one(db_conn, source: dict) -> bool:
    prompt = prompts.CLASSIFY_PROMPT_TEMPLATE.format(
        source_id=source["id"],
        name=source.get("name", source["id"]),
        type=source.get("type", "unknown"),
        url=source.get("url", ""),
        tags=source.get("source_tags") or source.get("tags") or [],
    )
    result = await run_agent(
        prompt,
        toolsets=settings.hermes_toolsets,
        timeout=settings.hermes_timeout_seconds,
        model=settings.hermes_model or None,
        expect_json=True,
    )

    if not result.ok or not isinstance(result.data, dict):
        await _log_activity(
            db_conn, action="classify_failed", status="error",
            summary=f"Failed to classify source '{source['id']}'",
            detail={"error": result.error}, ref_id=source["id"],
        )
        return False

    region = result.data.get("region")
    media_kind = result.data.get("media_kind")
    if region not in VALID_REGIONS or media_kind not in VALID_MEDIA_KINDS:
        await _log_activity(
            db_conn, action="classify_invalid", status="error",
            summary=f"Hermes returned an invalid classification for '{source['id']}'",
            detail={"data": result.data}, ref_id=source["id"],
        )
        return False

    # run_classify_batch selects sources missing region OR media_kind — only
    # write the field(s) actually missing, so a source already classified in
    # one dimension doesn't get its other, already-set field silently
    # overwritten by this backfill pass.
    fields: dict[str, str] = {}
    if not source.get("region"):
        fields["region"] = region
    if not source.get("media_kind"):
        fields["media_kind"] = media_kind
    if not fields:
        return True

    try:
        before, after = source_writer.update_field(
            source["id"], reason="hermes-agent region/media_kind classification", **fields
        )
    except source_writer.SourceWriteError as exc:
        log.error("[classify] source %s: write failed: %s", source["id"], exc)
        return False

    log.info("[classify] source %s: region=%s media_kind=%s", source["id"], region, media_kind)
    await _log_activity(
        db_conn, action="source_classified", status="ok",
        summary=f"Classified source '{source['id']}' as region={region}, media_kind={media_kind}",
        detail={"before": before, "after": after}, ref_id=source["id"],
    )
    return True
