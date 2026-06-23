"""health_registry.py — the shared base behind research/agent.py's,
research/heal.py's, research/discover.py's, research/investigate.py's,
research/evaluator.py's, and pipeline/correlate.py's runtime health
registries (previously six independent, byte-identical copies). Exercised
once here against the shared implementation directly; each module's own
record_run_start/record_success/record_error/get are just bound methods of a
HealthRegistry instance, so a behavior check here covers all six."""
from cybercrime_monitor.health_registry import HealthRegistry


def test_record_success_resets_error_streak_and_sets_count():
    reg = HealthRegistry("test-channel")
    reg.record_error("boom")
    reg.record_error("boom again")
    assert reg.get().consecutive_errors == 2

    reg.record_success(7)
    h = reg.get()
    assert h.last_processed_count == 7
    assert h.consecutive_errors == 0
    assert h.last_success_at is not None


def test_record_error_increments_streak_and_truncates_message():
    reg = HealthRegistry("test-channel")
    long_error = "x" * 1000
    reg.record_error(long_error)
    h = reg.get()
    assert h.consecutive_errors == 1
    assert len(h.last_error) == 300
    assert h.last_error_at is not None


def test_record_run_start_sets_timestamp_without_touching_counts():
    reg = HealthRegistry("test-channel")
    reg.record_run_start()
    h = reg.get()
    assert h.last_run_at is not None
    assert h.last_processed_count == 0
    assert h.consecutive_errors == 0


def test_registries_are_independent_per_instance():
    a = HealthRegistry("a")
    b = HealthRegistry("b")
    a.record_error("only a")
    assert a.get().consecutive_errors == 1
    assert b.get().consecutive_errors == 0
