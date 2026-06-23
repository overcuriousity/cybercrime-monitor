"""Extraction backend — two interchangeable transports behind one API,
selected by settings.llm_backend:
  - "openai": a plain OpenAI-compatible /chat/completions endpoint (local
    LMStudio/vLLM, `hermes proxy`, or any hosted API). Uses strict
    json-schema response_format — essential for small/edge models (see
    extract_batch's docstring).
  - "hermes_cli": shells out to the locally-installed hermes-agent CLI via
    hermes/runner.run_agent, scoped to a narrow toolset (see
    _NO_TOOLS_TOOLSET) plus a prompt instruction (prompts.NO_TOOLS_NOTE) —
    this is plain text-in/JSON-out extraction, not agentic research, so it should
    never need to search the web or touch the filesystem. Useful when
    there's no separate OpenAI-compatible endpoint running but `hermes` is
    already configured and working (see settings.hermes_model).
  - "none": extraction layer disabled entirely.

When llm_backend="openai" and the configured endpoint is simply unreachable
(connection refused/timeout — no dedicated LLM server running) but `hermes`
is installed, extraction transparently falls back to the hermes_cli
transport instead of leaving every item permanently unextracted (see
settings.llm_auto_fallback_to_hermes, _fallback_eligible, and
_BackendUnreachable below). This only triggers on genuine unreachability,
not on a bad/rejected response — a misconfigured endpoint that's up but
returning errors stays a visible failure rather than being silently masked
by switching transports. llm/health.py's `using_fallback` flag (surfaced via
/api/classifier/health) reflects when this is active.

This replaces the old triage-only classifier: instead of a single priority
label, each item is run through a richer schema that pulls out the
structured fields the case layer needs — crime type, victim, attribution,
CVEs, IOCs — alongside the same significance/false-positive/confidence
signal the old classifier produced. See db.py's `extractions` table.
"""
import json
import logging
import re
import shutil
import time
from dataclasses import dataclass, field

import httpx

from .. import prompts
from .. import significance as sig
from ..db import log_token_usage
from ..hermes.runner import run_agent
from ..settings import settings
from . import health as llm_health

log = logging.getLogger(__name__)


class _BackendUnreachable(Exception):
    """Raised internally when the configured openai-compatible endpoint
    can't be reached at all (connection refused/timeout) — distinct from a
    malformed/rejected response, which means "this call failed," not "this
    transport is gone." Only this case triggers the hermes-agent fallback
    below; a 401 or a schema-violating response stays a real, visible
    failure rather than being silently papered over by switching backends."""


# ── Automatic hermes-agent fallback for llm_backend="openai" ────────────────
# See settings.llm_auto_fallback_to_hermes's docstring. Process-local cooldown
# state, mirroring the backoff pattern in llm/job.py — once the openai
# endpoint is found unreachable, stop spending a request probing it every
# single batch and just use hermes until the cooldown elapses, then try
# openai again so a since-restarted local server gets picked back up
# automatically.
_openai_unreachable_until = 0.0


def _hermes_available() -> bool:
    return bool(settings.hermes_bin) and shutil.which(settings.hermes_bin) is not None


def _fallback_eligible() -> bool:
    return settings.llm_backend == "openai" and settings.llm_auto_fallback_to_hermes and _hermes_available()


def _in_fallback_cooldown() -> bool:
    return time.monotonic() < _openai_unreachable_until


def _enter_fallback_cooldown() -> None:
    global _openai_unreachable_until
    _openai_unreachable_until = time.monotonic() + settings.llm_fallback_cooldown_seconds
    llm_health.set_using_fallback(True)
    log.warning(
        "[llm] openai-compatible endpoint %s unreachable — falling back to "
        "hermes-agent for the next %ds",
        settings.llm_base_url, settings.llm_fallback_cooldown_seconds,
    )


def _maybe_exit_fallback_cooldown() -> None:
    if llm_health.get().using_fallback and not _in_fallback_cooldown():
        llm_health.set_using_fallback(False)
        log.info("[llm] retrying openai-compatible endpoint %s after fallback cooldown", settings.llm_base_url)

# Passed as hermes_cli's -t value to scope the call down from whatever
# toolsets are globally enabled (which may include browser/terminal/file/
# code_execution — real risk surface to expose to a call that processes
# untrusted scraped text every 30s). "memory" is a real, narrow, harmless
# toolset — verified that an empty/invalid value (e.g. "none") makes hermes
# abort with no output instead of running tool-free, so this can't just be
# "" (see hermes/runner.run_agent's docstring).
_NO_TOOLS_TOOLSET = "memory"


@dataclass
class Extraction:
    crime_type: str
    victim: str | None
    victim_sector: str | None
    victim_country: str | None
    actor: str | None
    cve_ids: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    significance: str = "info"
    false_positive: bool = False
    confidence: float | None = None
    reasoning: str | None = None
    model: str = ""


def _build_user_prompt(title: str, snippet: str, source_name: str) -> str:
    return f"Source: {source_name}\nTitle: {title}\nSnippet: {snippet[:800]}"


_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)
_VALID_SIGNIFICANCE = sig.VALID_SIGNIFICANCE


def _coerce_str_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None][:50]


def _coerce_optional_str(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s[:200] or None


def _parse_extraction(data: dict, *, model: str) -> Extraction | None:
    significance = str(data.get("significance", "")).lower()
    if significance not in _VALID_SIGNIFICANCE:
        return None

    confidence = data.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None

    return Extraction(
        crime_type=str(data.get("crime_type", "other"))[:50] or "other",
        victim=_coerce_optional_str(data.get("victim")),
        victim_sector=_coerce_optional_str(data.get("victim_sector")),
        victim_country=_coerce_optional_str(data.get("victim_country")),
        actor=_coerce_optional_str(data.get("actor")),
        cve_ids=_coerce_str_list(data.get("cve_ids")),
        iocs=_coerce_str_list(data.get("iocs")),
        significance=significance,
        false_positive=bool(data.get("false_positive", False)),
        confidence=confidence,
        reasoning=str(data.get("reasoning", ""))[:500] or None,
        model=model,
    )


def _parse_json_block(content: str) -> dict | None:
    # Local models often wrap JSON in markdown fences or add stray text
    # despite instructions — extract the first {...} block rather than
    # requiring the whole response to be valid JSON.
    match = _JSON_OBJECT.search(content)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


async def _log_usage(conn, *, subsystem: str, model: str | None, data: dict) -> None:
    """Capture the OpenAI-compatible response's own `usage` object — real,
    measured token counts, not an estimate — into token_usage. `conn` is
    optional (callers that don't hold a db connection, e.g. ad-hoc/no-op
    paths, just skip logging) and any unexpected usage shape is swallowed —
    see log_token_usage's own try/except for the same reasoning."""
    if conn is None:
        return
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return
    await log_token_usage(
        conn,
        source="direct-llm",
        subsystem=subsystem,
        model=model,
        input_tokens=int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0),
        output_tokens=int(usage.get("completion_tokens") or usage.get("output_tokens") or 0),
    )


def _auth_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if settings.llm_api_key:
        headers["Authorization"] = f"Bearer {settings.llm_api_key}"
    return headers


def _build_batch_user_prompt(items: list[dict]) -> str:
    blocks = []
    for i, it in enumerate(items):
        blocks.append(
            f"[{i}] Source: {it['source_name']}\n"
            f"[{i}] Title: {it['title']}\n"
            f"[{i}] Snippet: {it['snippet'][:800]}"
        )
    return "\n\n".join(blocks)


def _extractions_from_data(data: dict, *, model: str, n: int) -> dict[int, Extraction]:
    raw = data.get("extractions")
    if not isinstance(raw, list):
        return {}

    out: dict[int, Extraction] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            idx = int(entry.get("index"))
        except (TypeError, ValueError):
            continue
        if idx < 0 or idx >= n or idx in out:
            continue  # out-of-range or duplicate index — skip rather than guess

        extraction = _parse_extraction(entry, model=model)
        if extraction is not None:
            out[idx] = extraction
    return out


def _parse_batch_extractions(content: str, *, model: str, n: int) -> dict[int, Extraction]:
    data = _parse_json_block(content)
    if data is None:
        return {}
    return _extractions_from_data(data, model=model, n=n)


async def extract_batch(items: list[dict], *, conn=None) -> list[Extraction | None]:
    """Extract structured fields for N items in one call. Returns a list
    parallel to `items` — entries are None where the model omitted that
    item's extraction or the whole call failed, so llm/job.py's per-item
    backoff logic can retry just that item next batch. Transport (HTTP vs
    hermes CLI) is chosen by settings.llm_backend — see module docstring,
    with an automatic one-way fallback to hermes when llm_backend="openai"
    but nothing is listening there (see _fallback_eligible).

    conn: optional db connection — when given, the openai transport logs the
    response's own usage object (real token counts) to token_usage (see
    _log_usage). The hermes transport doesn't take usage from here at all;
    its token counts are captured separately by hermes/usage_ingest.py."""
    if not items:
        return []
    if settings.llm_backend == "hermes_cli":
        return await _extract_batch_via_hermes(items)
    if not _fallback_eligible():
        return await _extract_batch_via_openai(items, conn=conn)

    if _in_fallback_cooldown():
        return await _extract_batch_via_hermes(items)
    try:
        result = await _extract_batch_via_openai(items, conn=conn)
    except _BackendUnreachable:
        _enter_fallback_cooldown()
        return await _extract_batch_via_hermes(items)
    _maybe_exit_fallback_cooldown()
    return result


async def _extract_batch_via_openai(items: list[dict], *, conn=None) -> list[Extraction | None]:
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    headers = _auth_headers()

    payload = {
        "model": settings.llm_model or "local-model",
        "messages": [
            {"role": "system", "content": prompts.BATCH_SYSTEM_PROMPT},
            {"role": "user", "content": _build_batch_user_prompt(items)},
        ],
        "temperature": 0,
        "max_tokens": 400 * len(items),
        # Strict structured output — the server enforces this shape rather
        # than just being asked nicely for JSON in the prompt, which matters
        # a lot for small/edge models (verified against LM Studio: without
        # this, a 2B-class model reliably returned empty content for every
        # request; with it, well-formed results came back immediately).
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "batch_extraction", "strict": True, "schema": prompts.BATCH_EXTRACTION_SCHEMA},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        model_name = data.get("model") or settings.llm_model or "unknown"
        await _log_usage(conn, subsystem="classifier", model=model_name, data=data)
        extractions_by_idx = _parse_batch_extractions(content, model=model_name, n=len(items))
        if not extractions_by_idx:
            llm_health.record_error(f"unparseable batch response: {content[:200]!r}")
        return [extractions_by_idx.get(i) for i in range(len(items))]
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        llm_health.record_error(str(exc) or repr(exc))
        raise _BackendUnreachable(str(exc)) from exc
    except Exception as exc:
        llm_health.record_error(str(exc) or repr(exc))
        return [None] * len(items)


async def _extract_batch_via_hermes(items: list[dict]) -> list[Extraction | None]:
    prompt = prompts.BATCH_SYSTEM_PROMPT + "\n\n" + _build_batch_user_prompt(items) + prompts.NO_TOOLS_NOTE
    result = await run_agent(
        prompt,
        toolsets=_NO_TOOLS_TOOLSET,
        timeout=settings.llm_timeout_seconds,
        model=settings.hermes_model or None,
    )
    if not result.ok or result.data is None:
        llm_health.record_error(result.error or f"unparseable hermes response: {result.text[:200]!r}")
        return [None] * len(items)
    model_name = settings.hermes_model or "hermes-agent"
    extractions_by_idx = _extractions_from_data(result.data, model=model_name, n=len(items))
    if not extractions_by_idx:
        llm_health.record_error(f"unparseable hermes batch response: {result.text[:200]!r}")
    return [extractions_by_idx.get(i) for i in range(len(items))]


async def extract_one(*, title: str, snippet: str, source_name: str, conn=None) -> Extraction | None:
    """Single-item variant of extract_batch — used where batching doesn't
    apply (e.g. ad-hoc re-extraction). Returns None on any failure. Transport
    chosen by settings.llm_backend — see module docstring — with the same
    automatic hermes fallback as extract_batch. conn: see extract_batch's
    docstring."""
    if settings.llm_backend == "hermes_cli":
        return await _extract_one_via_hermes(title, snippet, source_name)
    if not _fallback_eligible():
        return await _extract_one_via_openai(title, snippet, source_name, conn=conn)

    if _in_fallback_cooldown():
        return await _extract_one_via_hermes(title, snippet, source_name)
    try:
        result = await _extract_one_via_openai(title, snippet, source_name, conn=conn)
    except _BackendUnreachable:
        _enter_fallback_cooldown()
        return await _extract_one_via_hermes(title, snippet, source_name)
    _maybe_exit_fallback_cooldown()
    return result


async def _extract_one_via_openai(title: str, snippet: str, source_name: str, *, conn=None) -> Extraction | None:
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    headers = _auth_headers()

    payload = {
        "model": settings.llm_model or "local-model",
        "messages": [
            {"role": "system", "content": prompts.SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(title, snippet, source_name)},
        ],
        "temperature": 0,
        "max_tokens": 400,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "extraction", "strict": True, "schema": prompts.EXTRACTION_SCHEMA},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        model_name = data.get("model") or settings.llm_model or "unknown"
        await _log_usage(conn, subsystem="classifier", model=model_name, data=data)
        block = _parse_json_block(content)
        extraction = _parse_extraction(block, model=model_name) if block is not None else None
        if extraction is None:
            llm_health.record_error(f"unparseable response: {content[:200]!r}")
            return None
        return extraction
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        llm_health.record_error(str(exc) or repr(exc))
        raise _BackendUnreachable(str(exc)) from exc
    except Exception as exc:
        llm_health.record_error(str(exc) or repr(exc))
        return None


async def _extract_one_via_hermes(title: str, snippet: str, source_name: str) -> Extraction | None:
    prompt = prompts.SYSTEM_PROMPT + "\n\n" + _build_user_prompt(title, snippet, source_name) + prompts.NO_TOOLS_NOTE
    result = await run_agent(
        prompt, toolsets=_NO_TOOLS_TOOLSET, timeout=settings.llm_timeout_seconds, model=settings.hermes_model or None
    )
    if not result.ok or result.data is None:
        llm_health.record_error(result.error or f"unparseable hermes response: {result.text[:200]!r}")
        return None
    model_name = settings.hermes_model or "hermes-agent"
    extraction = _parse_extraction(result.data, model=model_name)
    if extraction is None:
        llm_health.record_error(f"unparseable hermes response: {result.text[:200]!r}")
    return extraction


# ── Semantic dedup adjudication ─────────────────────────────────────────────
# Used by pipeline/correlate.py only for ambiguous candidates (blocking by
# normalized victim/actor/CVE already resolves the unambiguous majority
# deterministically — see db.find_candidate_cases) — this call is reserved
# for the cases where two records share a blocking key but it's genuinely
# unclear whether they're the same underlying incident (e.g. a victim
# named once but reported by two sources with different actor names, or two
# items sharing one CVE among several).

def _build_merge_prompt(case: dict, item: dict) -> str:
    return (
        f"EXISTING CASE:\nTitle: {case.get('title')}\nSummary: {case.get('summary')}\n"
        f"Victim: {case.get('damaged_party')}\nActor: {case.get('attribution')}\n"
        f"CVEs: {case.get('cve_ids')}\nFirst seen: {case.get('first_seen')}\n\n"
        f"NEW REPORT:\nTitle: {item.get('title')}\nSnippet: {str(item.get('snippet', ''))[:500]}\n"
        f"Victim: {item.get('victim')}\nActor: {item.get('actor')}\nCVEs: {item.get('cve_ids')}"
    )


async def adjudicate_merge(case: dict, item: dict, *, conn=None) -> tuple[bool, float] | None:
    """Ask the LLM whether `item` (a dict from db.get_uncorrelated_extracted_
    items) describes the same incident as `case` (a dict from db.fetch_cases
    /get_case_by_id). Returns (same_incident, confidence), or None on
    failure — callers should treat None as "don't merge" (the conservative
    default; a missed merge just means two cases stay separate, while a
    wrong merge corrupts attribution). Transport chosen by settings.
    llm_backend — see module docstring. conn: see extract_batch's docstring."""
    if settings.llm_backend == "hermes_cli":
        return await _adjudicate_merge_via_hermes(case, item)
    return await _adjudicate_merge_via_openai(case, item, conn=conn)


def _parse_merge_block(block: dict | None) -> tuple[bool, float] | None:
    if block is None or "same_incident" not in block:
        return None
    confidence = block.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else 0.0
    except (TypeError, ValueError):
        confidence = 0.0
    return bool(block["same_incident"]), confidence


async def _adjudicate_merge_via_openai(case: dict, item: dict, *, conn=None) -> tuple[bool, float] | None:
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    headers = _auth_headers()

    payload = {
        "model": settings.llm_model or "local-model",
        "messages": [
            {"role": "system", "content": prompts.MERGE_SYSTEM_PROMPT},
            {"role": "user", "content": _build_merge_prompt(case, item)},
        ],
        "temperature": 0,
        "max_tokens": 200,
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "merge_verdict", "strict": True, "schema": prompts.MERGE_SCHEMA},
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        await _log_usage(conn, subsystem="correlator", model=data.get("model") or settings.llm_model, data=data)
        verdict = _parse_merge_block(_parse_json_block(content))
        if verdict is None:
            llm_health.record_error(f"unparseable merge response: {content[:200]!r}")
        return verdict
    except Exception as exc:
        llm_health.record_error(str(exc) or repr(exc))
        return None


async def _adjudicate_merge_via_hermes(case: dict, item: dict) -> tuple[bool, float] | None:
    prompt = prompts.MERGE_SYSTEM_PROMPT + "\n\n" + _build_merge_prompt(case, item) + prompts.NO_TOOLS_NOTE
    result = await run_agent(
        prompt, toolsets=_NO_TOOLS_TOOLSET, timeout=settings.llm_timeout_seconds, model=settings.hermes_model or None
    )
    if not result.ok:
        llm_health.record_error(result.error or f"unparseable hermes merge response: {result.text[:200]!r}")
        return None
    verdict = _parse_merge_block(result.data)
    if verdict is None:
        llm_health.record_error(f"unparseable hermes merge response: {result.text[:200]!r}")
    return verdict
