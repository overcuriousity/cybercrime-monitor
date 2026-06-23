"""Shared base for the "agentic" runtime health registries — research/agent.py,
research/heal.py, research/discover.py, research/investigate.py,
research/evaluator.py, and pipeline/correlate.py each track a single
in-process run-loop's health (last run/success/error, consecutive error
streak) and broadcast it over SSE under their own channel name. The shape was
identical six times over with no shared definition; this module is that
shared definition.

Deliberately NOT used by llm/health.py (extra fields: last_batch_size,
total_classified, using_fallback) or the top-level health.py (a per-source
dict keyed registry with no SSE emit) — those are structurally different
registries, not copies of this one.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

from .api.sse import broadcaster

# Error strings are truncated before storing/broadcasting — keeps health
# payloads and logs bounded regardless of what a backend/agent raises.
_ERROR_TRUNCATE = 300


@dataclass
class RunHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_processed_count: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class HealthRegistry:
    """One instance per subsystem, parameterized by its SSE status channel.
    Usage (mirrors the previous per-module module-level functions):

        _registry = HealthRegistry("research")
        record_run_start = _registry.record_run_start
        record_success = _registry.record_success
        record_error = _registry.record_error
        get = _registry.get
    """

    def __init__(self, channel: str) -> None:
        self._channel = channel
        self._health = RunHealth()

    def _emit(self, payload: dict) -> None:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(broadcaster.broadcast_status(self._channel, payload))
        except RuntimeError:
            pass

    def record_run_start(self) -> None:
        self._health.last_run_at = _now_iso()

    def record_success(self, processed_count: int) -> None:
        self._health.last_success_at = _now_iso()
        self._health.last_processed_count = processed_count
        self._health.consecutive_errors = 0
        self._emit({"last_processed_count": processed_count})

    def record_error(self, error: str) -> None:
        truncated = error[:_ERROR_TRUNCATE]
        self._health.last_error = truncated
        self._health.last_error_at = _now_iso()
        self._health.consecutive_errors += 1
        self._emit({"error": truncated, "consecutive_errors": self._health.consecutive_errors})

    def get(self) -> RunHealth:
        return self._health
