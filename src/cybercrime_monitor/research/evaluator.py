"""Autonomous feedback generation, delegated to hermes-agent — same dispatch
pattern as research/agent.py and research/heal.py. Periodically picks a case
(db.get_case_for_evaluation, biased toward recent/under-covered cases),
hands Hermes up to settings.evaluator_items_per_run of its items, and asks
it to judge each one the way a human analyst clicking the feedback buttons
would: is this item genuinely on-topic and does it carry real information,
or is it noise/misattributed?

The verdicts are written to the same `feedback` table the UI's feedback
buttons write to, tagged origin="agent" (db.add_feedback) so
sources/value.py can tell the two apart and weigh agent verdicts at a
discount (settings.feedback_agent_weight) rather than letting synthetic
signal outrank a real analyst's call. This exists so the source
discovery/convergence/pruning loop (research/discover.py, research/heal.py)
has an actionable quality signal even on a deployment where no human has
clicked a single feedback button yet.

Runs on its own APScheduler interval (scheduler.py's "_evaluator" job).
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from .. import db
from .. import prompts
from ..api.sse import broadcaster
from ..hermes.runner import run_agent
from ..settings import settings

log = logging.getLogger(__name__)


# ── Runtime health registry ───────────────────────────────────────────────────
# Same shape as research/agent.py and research/heal.py's registries, but
# unlike those it is NOT currently surfaced via /api/status — only via the
# "evaluator" SSE status broadcast (_emit below). Add it to api_status if/when
# it needs to show up in the unified status payload too.

@dataclass
class EvaluatorHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_processed_count: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0


_health = EvaluatorHealth()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(payload: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcaster.broadcast_status("evaluator", payload))
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


def get() -> EvaluatorHealth:
    return _health


async def _log_activity(
    db_conn, *, action: str, summary: str, detail: dict | None = None,
    status: str = "ok", ref_id: int | str | None = None,
) -> None:
    try:
        event = await db.log_ai_activity(
            db_conn, subsystem="evaluator", action=action, summary=summary,
            detail=detail, status=status, ref_type="case", ref_id=ref_id,
            model=settings.hermes_model or None,
        )
        await broadcaster.broadcast_activity(event)
    except Exception as exc:
        log.error("[evaluator] activity log failed: %s", exc)


def _items_block(items: list[dict]) -> str:
    lines = []
    for item in items:
        lines.append(
            f"- item_id={item['id']} source={item.get('source_name') or item.get('source_id')} "
            f"title={(item.get('title') or '').strip()!r} "
            f"snippet={(item.get('snippet') or '').strip()[:300]!r}"
        )
    return "\n".join(lines)


async def run_evaluator_batch(db_conn, scheduler=None, sse_broadcaster=None) -> int:
    """One tick: pick a case, judge every one of its items via hermes-agent,
    write each verdict as origin="agent" feedback. Returns the number of
    feedback rows written (0 if there was no case to evaluate, or no items,
    or the hermes run failed)."""
    if settings.hermes_evaluator_interval_seconds <= 0:
        return 0

    record_run_start()
    try:
        written = await _evaluate_one(db_conn)
        record_success(written)
        return written
    except Exception as exc:
        log.error("[evaluator] batch failed: %s", exc)
        record_error(str(exc) or repr(exc))
        raise


async def _evaluate_one(db_conn) -> int:
    case = await db.get_case_for_evaluation(db_conn)
    if case is None:
        return 0

    items = await db.get_case_items(db_conn, case["id"])
    items = items[: settings.evaluator_items_per_run]
    if not items:
        return 0

    prompt = prompts.EVALUATE_PROMPT_TEMPLATE.format(
        case_title=case.get("title") or f"case {case['id']}",
        items_block=_items_block(items),
    )
    result = await run_agent(
        prompt,
        toolsets="memory",  # judgement call from the supplied text, no browsing needed
        timeout=settings.hermes_timeout_seconds,
        model=settings.hermes_model or None,
        expect_json=True,
    )

    if not result.ok or not isinstance(result.data, dict):
        await _log_activity(
            db_conn, action="evaluate_failed", status="error",
            summary=f"Failed to evaluate case {case['id']}",
            detail={"error": result.error}, ref_id=case["id"],
        )
        return 0

    verdicts = result.data.get("verdicts")
    if not isinstance(verdicts, list):
        await _log_activity(
            db_conn, action="evaluate_invalid", status="error",
            summary=f"Hermes returned no verdicts list for case {case['id']}",
            detail={"data": result.data}, ref_id=case["id"],
        )
        return 0

    valid_item_ids = {item["id"] for item in items}
    written = 0
    for v in verdicts:
        if not isinstance(v, dict):
            continue
        item_id = v.get("item_id")
        verdict = v.get("verdict")
        if item_id not in valid_item_ids or verdict not in db.VALID_FEEDBACK_VERDICTS:
            continue
        try:
            await db.add_feedback(
                db_conn, case_id=None, item_id=item_id, verdict=verdict,
                note=v.get("reason"), origin="agent",
            )
            written += 1
        except ValueError as exc:
            log.warning("[evaluator] case %s item %s: %s", case["id"], item_id, exc)

    log.info("[evaluator] case %s: wrote %d/%d verdict(s)", case["id"], written, len(items))
    await _log_activity(
        db_conn, action="case_evaluated",
        summary=f"Evaluated case {case['id']} ({written}/{len(items)} item(s) judged)",
        detail={"case_id": case["id"], "verdicts": verdicts[:50]}, ref_id=case["id"],
    )
    return written
