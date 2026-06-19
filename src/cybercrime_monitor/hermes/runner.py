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
) -> HermesResult:
    """Run one headless hermes-agent turn and return its result.

    Always returns a HermesResult rather than raising — callers (research and
    self-healing jobs) treat a Hermes failure exactly like an unreachable LLM
    backend: log it, record health, leave the case/source as-is for the next
    tick. No internal retry; the caller's own scheduler interval is the retry
    loop, same pattern as llm/job.py's unclassified-items query being
    naturally self-healing.

    toolsets: None means "use settings.hermes_toolsets" (the default for
    agentic callers). Pass an explicit minimal toolset (e.g. "memory") to
    scope a closed-form call down from whatever's globally enabled — verified
    that `-t <name>` replaces rather than adds to the default set, and that
    an invalid/empty toolset value (e.g. "none" or "") makes hermes abort
    with no output at all rather than running tool-free, so "" is NOT a
    usable way to request "no tools"; callers must name a real, narrow
    toolset instead (see llm/backend.py's _NO_TOOLS_TOOLSET).
    """
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
