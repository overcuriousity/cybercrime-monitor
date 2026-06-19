"""Process-local health tracking for the LLM extraction backend — mirrors the
top-level `health.py` pattern for source collectors, kept as a separate
single-instance registry since the extraction backend isn't a sources.yaml
entry and joining it into the source-keyed dict would mean nothing (routes.py:
api_sources joins against load_sources(), which has no "llm" id).
"""
import asyncio

from dataclasses import dataclass
from datetime import datetime, timezone

from ..api.sse import broadcaster


@dataclass
class LLMHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_batch_size: int = 0
    total_classified: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0
    # True while extraction is transparently running through the hermes-agent
    # CLI because settings.llm_backend="openai" is configured but that
    # endpoint is unreachable (see llm/backend.py's auto-fallback). Surfaced
    # so the dashboard can show "running on hermes fallback" instead of
    # silently reporting the configured backend while actually using a
    # different one.
    using_fallback: bool = False


_health = LLMHealth()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(payload: dict) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcaster.broadcast_status("classifier", payload))
    except RuntimeError:
        pass


def record_run_start() -> None:
    _health.last_run_at = _now_iso()


def record_success(items_classified: int) -> None:
    _health.last_success_at = _now_iso()
    _health.last_batch_size = items_classified
    _health.total_classified += items_classified
    _health.consecutive_errors = 0
    _emit({"backlog": None, "last_batch_size": items_classified})


def record_error(error: str) -> None:
    _health.last_error = error[:300]
    _health.last_error_at = _now_iso()
    _health.consecutive_errors += 1
    _emit({"error": error[:300], "consecutive_errors": _health.consecutive_errors})


def set_using_fallback(active: bool) -> None:
    if _health.using_fallback != active:
        _health.using_fallback = active
        _emit({"using_fallback": active})


def get() -> LLMHealth:
    return _health
