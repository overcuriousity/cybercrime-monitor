"""Async wrapper over the locally-installed hermes-agent CLI (Nous Research's
self-improving agent — NOT the "Hermes" language model; see settings.py).

Verified contract (2026-06-19, hermes v0.16.0): `hermes -z "<prompt>" -t
<toolsets>` is a one-shot headless invocation that writes ONLY the model's
final response text to stdout — no banner, no spinner, no tool-call
previews — and exits 0 on success. That makes it safe to treat stdout as the
entire payload rather than needing to scrape a transcript.

This module is the single integration point for both agentic roles
(research/agent.py and research/heal.py) — neither builds its own
tool-calling loop; they hand Hermes a prompt and let it drive its own web
search/scrape/browser toolsets, then parse whatever JSON comes back.
"""
import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass

from ..settings import settings

log = logging.getLogger(__name__)

# Local models/agents routinely wrap JSON in prose or markdown fences despite
# being asked not to — same salvage approach as llm/backend.py's
# _JSON_OBJECT: grab the first {...} block instead of requiring the whole
# stdout to be valid JSON.
_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)

# Substrings of a HermesResult.error (or "empty data despite ok=True") that
# mark a single bad provider hop rather than a real outage — worth one
# in-process retry. Observed live (2026-06-21): a rate-limited free primary
# falling through a fallback chain with one broken link (wrong model id —
# 404) ends the agent loop with no final message at all, which oneshot.py
# reports as "no final response was produced" with exit 1; that's the same
# class of failure as a transient 429, not a permanent misconfiguration.
# Deliberately NOT retried here: "binary not found" / invalid toolsets
# (permanent, retrying just repeats the same failure) and "timeout" (a
# 900s+ run is too expensive to redo in-process — left to the caller's own
# scheduler/cooldown, e.g. research/investigate.py's failure-retry).
_TRANSIENT_ERROR_MARKERS = (
    "no final response was produced",
    "no parseable result",
    "too many requests",
    "rate limit",
    "ratelimit",  # e.g. hermes' own error_type=RateLimitError (no space)
    "429",
)


def _is_transient(error: str | None) -> bool:
    if not error:
        return False
    low = error.lower()
    return any(marker in low for marker in _TRANSIENT_ERROR_MARKERS)


# Process-wide cap on concurrently-running hermes-agent subprocesses, shared
# by every caller (research/agent.py, research/investigate.py,
# research/heal.py) since they all ultimately hit the same primary backend
# and its published rate limit — see settings.hermes_max_concurrent_runs's
# docstring for the sizing rationale. Created lazily so it binds to whatever
# event loop is actually running (module import happens before the app's
# loop starts).
_concurrency_guard: asyncio.Semaphore | None = None


def _guard() -> asyncio.Semaphore:
    global _concurrency_guard
    if _concurrency_guard is None:
        n = settings.hermes_max_concurrent_runs
        if n < 1:
            log.error("[hermes] invalid hermes_max_concurrent_runs=%s; must be >= 1", n)
            n = 1
        _concurrency_guard = asyncio.Semaphore(n)
    return _concurrency_guard


@dataclass
class HermesResult:
    ok: bool
    text: str
    data: dict | None  # parsed JSON, if the response contained any
    error: str | None
    duration_seconds: float


async def run_agent(
    prompt: str,
    *,
    toolsets: str | None = None,
    timeout: float | None = None,
    model: str | None = None,
    expect_json: bool = False,
) -> HermesResult:
    """Run one headless hermes-agent turn and return its result.

    Always returns a HermesResult rather than raising — callers (research and
    self-healing jobs) treat a sustained Hermes failure exactly like an
    unreachable LLM backend: log it, record health, leave the case/source as-
    is for the next tick. The caller's own scheduler interval (or, for
    investigate.py, an explicit failure-retry/cooldown) remains the retry
    loop for real outages, same pattern as llm/job.py's unclassified-items
    query being naturally self-healing.

    What this function DOES retry, in-process, bounded by
    settings.hermes_max_retries: clearly transient failures (see
    _is_transient) — a single bad provider hop (rate limit, a broken link in
    the fallback chain) that ends the run with no final message, or a run
    that exits 0 but produces no parseable JSON when expect_json=True. A
    backoff sleep (hermes_retry_backoff_seconds * attempt) separates
    attempts. Anything else (timeout, permanent misconfiguration, a real
    outage that survives the retry budget) is returned as-is for the caller
    to handle.

    expect_json: when True, a 0-exit run whose stdout has no parseable JSON
    object is treated as transient and retried too (an agent that "completed"
    but ignored the requested output format is often just a bad sample, not
    a permanent contract violation) — see research/agent.py and
    research/investigate.py, both of which require JSON back.

    toolsets: None means "use settings.hermes_toolsets" (the default for
    agentic callers). Pass an explicit minimal toolset (e.g. "memory") to
    scope a closed-form call down from whatever's globally enabled — verified
    that `-t <name>` replaces rather than adds to the default set, and that
    an invalid/empty toolset value (e.g. "none" or "") makes hermes abort
    with no output at all rather than running tool-free, so "" is NOT a
    usable way to request "no tools"; callers must name a real, narrow
    toolset instead (see llm/backend.py's _NO_TOOLS_TOOLSET).
    """
    async def _run_once_guarded() -> HermesResult:
        # Only the actual subprocess run holds the concurrency slot — the
        # backoff sleep between retries deliberately happens outside the
        # semaphore so a transient failure's wait doesn't block another
        # queued case from starting its own run in the meantime.
        async with _guard():
            return await _run_agent_once(prompt, toolsets=toolsets, timeout=timeout, model=model)

    result = await _run_once_guarded()
    attempts = 1
    while attempts <= settings.hermes_max_retries:
        retryable = _is_transient(result.error) or (result.ok and expect_json and result.data is None)
        if not retryable:
            break
        backoff = settings.hermes_retry_backoff_seconds * attempts
        log.warning(
            "[hermes] transient failure (attempt %d/%d), retrying in %.0fs: %s",
            attempts, settings.hermes_max_retries, backoff, result.error or "empty/unparseable response",
        )
        await asyncio.sleep(backoff)
        result = await _run_once_guarded()
        attempts += 1
    return result


async def _run_agent_once(
    prompt: str,
    *,
    toolsets: str | None = None,
    timeout: float | None = None,
    model: str | None = None,
) -> HermesResult:
    """Single headless hermes-agent turn, no retry — see run_agent."""
    toolsets = settings.hermes_toolsets if toolsets is None else toolsets
    timeout = timeout or settings.hermes_timeout_seconds
    model = model or settings.hermes_model

    cmd = [settings.hermes_bin, "-z", prompt]
    if toolsets:
        cmd += ["-t", toolsets]
    if model:
        cmd += ["-m", model]

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            duration = time.monotonic() - start
            log.warning("[hermes] timed out after %.0fs: %r", duration, prompt[:120])
            return HermesResult(ok=False, text="", data=None, error="timeout", duration_seconds=duration)

        duration = time.monotonic() - start
        text = stdout.decode("utf-8", errors="replace").strip()

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace").strip()[:500] or f"exit {proc.returncode}"
            log.warning("[hermes] failed (exit %s): %s", proc.returncode, err)
            return HermesResult(ok=False, text=text, data=None, error=err, duration_seconds=duration)

        data = _extract_json(text)
        return HermesResult(ok=True, text=text, data=data, error=None, duration_seconds=duration)

    except FileNotFoundError:
        duration = time.monotonic() - start
        err = f"hermes binary not found: {settings.hermes_bin!r}"
        log.error("[hermes] %s", err)
        return HermesResult(ok=False, text="", data=None, error=err, duration_seconds=duration)
    except Exception as exc:
        duration = time.monotonic() - start
        log.error("[hermes] unexpected error: %s", exc)
        return HermesResult(ok=False, text="", data=None, error=str(exc) or repr(exc), duration_seconds=duration)


def _extract_json(text: str) -> dict | None:
    match = _JSON_OBJECT.search(text)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None
