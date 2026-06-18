"""Process-local health tracking for the classifier backend — mirrors the
top-level `health.py` pattern for source collectors, kept as a separate
single-instance registry since the classifier isn't a sources.yaml entry and
joining it into the source-keyed dict would mean nothing (routes.py:
api_sources joins against load_sources(), which has no "classifier" id).
"""
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ClassifierHealth:
    last_run_at: str | None = None
    last_success_at: str | None = None
    last_batch_size: int = 0
    total_classified: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_errors: int = 0


_health = ClassifierHealth()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_run_start() -> None:
    _health.last_run_at = _now_iso()


def record_success(items_classified: int) -> None:
    _health.last_success_at = _now_iso()
    _health.last_batch_size = items_classified
    _health.total_classified += items_classified
    _health.consecutive_errors = 0


def record_error(error: str) -> None:
    _health.last_error = error[:300]
    _health.last_error_at = _now_iso()
    _health.consecutive_errors += 1


def get() -> ClassifierHealth:
    return _health
