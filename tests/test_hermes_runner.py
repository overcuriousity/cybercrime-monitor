"""hermes/runner.py's bounded in-process retry for transient failures — see
that module's docstring. Added after a live incident (2026-06-21) where a
broken link in the hermes fallback chain turned a single rate-limited
provider hop into a hard "no final response was produced" failure on every
call; run_agent now retries that class of failure once before giving up."""
import pytest

from cybercrime_monitor.hermes import runner
from cybercrime_monitor.hermes.runner import HermesResult, _is_transient, run_agent
from cybercrime_monitor.settings import settings as app_settings


@pytest.fixture(autouse=True)
def _retry_settings(monkeypatch):
    monkeypatch.setattr(app_settings, "hermes_max_retries", 1)
    monkeypatch.setattr(app_settings, "hermes_retry_backoff_seconds", 0)


@pytest.mark.parametrize(
    "error,expected",
    [
        ("hermes -z: no final response was produced; treating the run as failed.", True),
        ("HTTP 429: Error code: 429 - {'status': 429, 'title': 'Too Many Requests'}", True),
        ("no parseable result", True),
        ("RateLimitError: slow down", True),
        ("hermes binary not found: 'hermes'", False),
        ("timeout", False),
        (None, False),
        ("", False),
    ],
)
def test_is_transient_classification(error, expected):
    assert _is_transient(error) is expected


async def _fake_once_sequence(results):
    """Returns an async stand-in for _run_agent_once that yields each result
    in order, recording call count via a mutable list passed by the caller."""
    calls = []

    async def _fake(prompt, *, toolsets=None, timeout=None, model=None):
        calls.append(prompt)
        return results[len(calls) - 1]

    return _fake, calls


@pytest.mark.asyncio
async def test_run_agent_retries_transient_failure_then_succeeds(monkeypatch):
    results = [
        HermesResult(ok=False, text="", data=None, error="no final response was produced", duration_seconds=1.0),
        HermesResult(ok=True, text="ok", data={"found": True}, error=None, duration_seconds=1.0),
    ]
    fake, calls = await _fake_once_sequence(results)
    monkeypatch.setattr(runner, "_run_agent_once", fake)

    result = await run_agent("prompt")

    assert len(calls) == 2
    assert result.ok is True
    assert result.data == {"found": True}


@pytest.mark.asyncio
async def test_run_agent_does_not_retry_permanent_failure(monkeypatch):
    results = [
        HermesResult(ok=False, text="", data=None, error="hermes binary not found: 'hermes'", duration_seconds=0.1),
    ]
    fake, calls = await _fake_once_sequence(results)
    monkeypatch.setattr(runner, "_run_agent_once", fake)

    result = await run_agent("prompt")

    assert len(calls) == 1
    assert result.ok is False
    assert "binary not found" in result.error


@pytest.mark.asyncio
async def test_run_agent_does_not_retry_timeout(monkeypatch):
    results = [HermesResult(ok=False, text="", data=None, error="timeout", duration_seconds=900.0)]
    fake, calls = await _fake_once_sequence(results)
    monkeypatch.setattr(runner, "_run_agent_once", fake)

    result = await run_agent("prompt")

    assert len(calls) == 1
    assert result.error == "timeout"


@pytest.mark.asyncio
async def test_run_agent_returns_last_result_after_exhausting_retries(monkeypatch):
    results = [
        HermesResult(ok=False, text="", data=None, error="429 too many requests", duration_seconds=1.0),
        HermesResult(ok=False, text="", data=None, error="429 too many requests", duration_seconds=1.0),
    ]
    fake, calls = await _fake_once_sequence(results)
    monkeypatch.setattr(runner, "_run_agent_once", fake)

    result = await run_agent("prompt")

    assert len(calls) == 2  # 1 initial + hermes_max_retries(1) retry, then gives up
    assert result.ok is False


@pytest.mark.asyncio
async def test_run_agent_retries_empty_json_when_expect_json(monkeypatch):
    results = [
        HermesResult(ok=True, text="no json here", data=None, error=None, duration_seconds=1.0),
        HermesResult(ok=True, text='{"found": false}', data={"found": False}, error=None, duration_seconds=1.0),
    ]
    fake, calls = await _fake_once_sequence(results)
    monkeypatch.setattr(runner, "_run_agent_once", fake)

    result = await run_agent("prompt", expect_json=True)

    assert len(calls) == 2
    assert result.data == {"found": False}


@pytest.mark.asyncio
async def test_run_agent_does_not_retry_empty_json_when_not_expected(monkeypatch):
    results = [HermesResult(ok=True, text="no json here", data=None, error=None, duration_seconds=1.0)]
    fake, calls = await _fake_once_sequence(results)
    monkeypatch.setattr(runner, "_run_agent_once", fake)

    result = await run_agent("prompt")  # expect_json defaults to False

    assert len(calls) == 1
    assert result.data is None
